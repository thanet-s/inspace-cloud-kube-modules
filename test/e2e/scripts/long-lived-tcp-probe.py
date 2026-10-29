#!/usr/bin/env python3
"""Hold one TCP connection open through firewall changes and fail on a reset.

The client opens a single connection to an echo endpoint, sends a
sequence-numbered line, waits for it to come back, and repeats. It logs every
stall longer than --log-stall to stderr. It exits non-zero when the connection
is reset or closed, or when the echo is silent for longer than --max-stall.

A per-VM firewall PUT must not touch an established flow on a port whose rule
did not change, so this probe has to survive every Service add, change and
removal on the same VM.

--self-test runs the probe against a local echo server and proves each outcome.
"""

import argparse
import json
import pathlib
import socket
import sys
import threading
import time
from typing import Callable


class ProbeFailure(Exception):
    """The connection was reset, closed, mismatched, or stalled too long."""


def run_probe(
    *,
    connection: socket.socket,
    stopped: Callable[[], bool],
    mark_ready: Callable[[], None],
    interval: float,
    log_stall: float,
    max_stall: float,
    overall_timeout: float,
    log: Callable[[str], None],
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    started = monotonic()
    connection.settimeout(0.25)
    buffer = b""
    sequence = 0
    longest_stall = 0.0
    stalls = 0
    last_progress = started
    while not stopped():
        if monotonic() - started >= overall_timeout:
            raise ProbeFailure(f"probe timed out after {monotonic() - started:.3f}s")
        sequence += 1
        line = f"seq {sequence}\n".encode()
        send_started = monotonic()
        try:
            connection.sendall(line)
        except (ConnectionError, BrokenPipeError) as error:
            raise ProbeFailure(f"connection reset while sending seq {sequence}: {error}") from error
        except socket.timeout:
            # The send buffer is full: the peer is not reading. Count it as a stall.
            pass
        while b"\n" not in buffer:
            now = monotonic()
            if now - last_progress > max_stall:
                raise ProbeFailure(
                    f"no echo for {now - last_progress:.3f}s waiting for seq {sequence} "
                    f"(max stall {max_stall}s)"
                )
            if stopped():
                break
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                continue
            except ConnectionError as error:
                raise ProbeFailure(f"connection reset waiting for seq {sequence}: {error}") from error
            if chunk == b"":
                raise ProbeFailure(f"connection closed by the peer waiting for seq {sequence}")
            buffer += chunk
        if b"\n" not in buffer:
            break
        echoed, _, buffer = buffer.partition(b"\n")
        if echoed + b"\n" != line:
            raise ProbeFailure(f"echo mismatch for seq {sequence}: got {echoed!r}")
        now = monotonic()
        stall = now - last_progress
        last_progress = now
        if stall > log_stall:
            stalls += 1
            longest_stall = max(longest_stall, stall)
            log(f"stall of {stall:.3f}s before seq {sequence} was echoed")
        if sequence == 4:
            mark_ready()
        elapsed = monotonic() - send_started
        if elapsed < interval:
            sleep(interval - elapsed)
    if sequence < 4:
        raise ProbeFailure(f"probe stopped too early after {sequence} lines")
    return {
        "durationSeconds": round(monotonic() - started, 3),
        "lines": sequence,
        "longestStallSeconds": round(longest_stall, 3),
        "stalls": stalls,
    }


def connect(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


class EchoServer:
    """A local echo server whose behaviour the self-test can script."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.pause_after: int | None = None
        self.pause_seconds = 0.0
        self.reset_after: int | None = None
        self.close_after: int | None = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        try:
            client, _ = self.listener.accept()
        except OSError:
            return
        served = 0
        buffer = b""
        with client:
            while True:
                try:
                    data = client.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                buffer += data
                while b"\n" in buffer:
                    line, _, buffer = buffer.partition(b"\n")
                    served += 1
                    if self.reset_after is not None and served > self.reset_after:
                        # SO_LINGER 0 turns the close into a TCP RST.
                        client.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00"
                        )
                        return
                    if self.close_after is not None and served > self.close_after:
                        return
                    if self.pause_after is not None and served == self.pause_after:
                        time.sleep(self.pause_seconds)
                    try:
                        client.sendall(line + b"\n")
                    except OSError:
                        return

    def close(self) -> None:
        self.listener.close()


def self_test() -> None:
    def probe_against(server: EchoServer, duration: float, max_stall: float, log_stall: float = 0.2):
        messages: list[str] = []
        deadline = time.monotonic() + duration
        ready = threading.Event()
        connection = connect("127.0.0.1", server.port, 2.0)
        try:
            result = run_probe(
                connection=connection,
                stopped=lambda: time.monotonic() >= deadline,
                mark_ready=ready.set,
                interval=0.02,
                log_stall=log_stall,
                max_stall=max_stall,
                overall_timeout=30.0,
                log=messages.append,
            )
        finally:
            connection.close()
        return result, messages, ready.is_set()

    def expect_failure(server: EchoServer, duration: float, max_stall: float, fragment: str) -> None:
        try:
            probe_against(server, duration, max_stall)
        except ProbeFailure as error:
            assert fragment in str(error), f"wrong failure: {error}"
            return
        raise AssertionError(f"probe did not fail with {fragment!r}")

    # 1. A healthy connection passes and reports readiness and no stall.
    server = EchoServer()
    result, messages, ready = probe_against(server, 0.6, max_stall=2.0)
    server.close()
    assert ready and result["lines"] >= 4 and result["stalls"] == 0 and not messages, result

    # 2. A stall above --log-stall but below --max-stall is logged and tolerated.
    server = EchoServer()
    server.pause_after, server.pause_seconds = 5, 0.6
    result, messages, _ = probe_against(server, 1.5, max_stall=2.0)
    server.close()
    assert result["stalls"] == 1 and result["longestStallSeconds"] >= 0.5 and len(messages) == 1, (result, messages)

    # 3. A stall above --max-stall fails.
    server = EchoServer()
    server.pause_after, server.pause_seconds = 5, 1.5
    expect_failure(server, 3.0, 0.5, "no echo for")
    server.close()

    # 4. A TCP reset fails.
    server = EchoServer()
    server.reset_after = 6
    expect_failure(server, 3.0, 2.0, "reset")
    server.close()

    # 5. A clean close by the peer fails too.
    server = EchoServer()
    server.close_after = 6
    expect_failure(server, 3.0, 2.0, "closed by the peer")
    server.close()

    # 6. A probe that is stopped before it saw four echoes fails.
    server = EchoServer()
    try:
        probe_against(server, 0.0, max_stall=2.0)
    except ProbeFailure as error:
        assert "stopped too early" in str(error)
    else:
        raise AssertionError("an immediately stopped probe must fail")
    finally:
        server.close()
    print("long-lived-tcp-probe self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="run against a local echo server and exit")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--stop-file")
    parser.add_argument("--ready-file")
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--log-stall", type=float, default=1.0, help="log a stall longer than this many seconds")
    parser.add_argument("--max-stall", type=float, default=10.0, help="fail after this many seconds without an echo")
    parser.add_argument("--overall-timeout", type=float, default=7200.0)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    for name in ("host", "port", "stop_file", "ready_file"):
        if getattr(args, name) in (None, ""):
            parser.error(f"--{name.replace('_', '-')} is required")
    if min(args.interval, args.connect_timeout, args.log_stall, args.max_stall, args.overall_timeout) <= 0:
        parser.error("probe intervals and timeouts must be positive")

    stop_file = pathlib.Path(args.stop_file)
    ready_file = pathlib.Path(args.ready_file)

    def log(message: str) -> None:
        print(f"{time.strftime('%H:%M:%S')} {message}", file=sys.stderr, flush=True)

    try:
        connection = connect(args.host, args.port, args.connect_timeout)
    except OSError as error:
        raise SystemExit(f"long-lived probe could not connect to {args.host}:{args.port}: {error}") from error
    try:
        result = run_probe(
            connection=connection,
            stopped=stop_file.exists,
            mark_ready=lambda: ready_file.touch(mode=0o600, exist_ok=True),
            interval=args.interval,
            log_stall=args.log_stall,
            max_stall=args.max_stall,
            overall_timeout=args.overall_timeout,
            log=log,
        )
    except ProbeFailure as error:
        raise SystemExit(f"long-lived TCP flow broke: {error}") from error
    finally:
        connection.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

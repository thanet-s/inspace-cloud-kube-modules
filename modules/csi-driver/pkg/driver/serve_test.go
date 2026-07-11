package driver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestServeCreatesGroupWritableSocketAndCleansUp(t *testing.T) {
	d, err := New(Config{Mode: ModeController, Location: "bkk01"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	tempDir, err := os.MkdirTemp("/tmp", "inspace-csi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })
	socketPath := filepath.Join(tempDir, "csi.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- d.Serve(ctx, "unix://"+socketPath)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var info os.FileInfo
	for {
		info, err = os.Lstat(socketPath)
		if err == nil && info.Mode().Perm() == 0o660 {
			break
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspect CSI socket: %v", err)
		}
		select {
		case err := <-serveErr:
			t.Fatalf("Serve exited before creating the socket: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			if err == nil {
				t.Fatalf("timed out waiting for CSI socket permissions 0660; got %#o", info.Mode().Perm())
			}
			t.Fatal("timed out waiting for CSI socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("endpoint mode = %v, want Unix socket", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("CSI socket permissions = %#o, want 0660", got)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := grpc.DialContext(
		dialCtx,
		"passthrough:///csi",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial CSI socket: %v", err)
	}
	response, err := csi.NewIdentityClient(conn).GetPluginInfo(dialCtx, &csi.GetPluginInfoRequest{})
	if err != nil {
		conn.Close()
		t.Fatalf("call CSI identity service: %v", err)
	}
	if response.GetName() != DefaultPluginName {
		conn.Close()
		t.Fatalf("plugin name = %q, want %q", response.GetName(), DefaultPluginName)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close CSI client: %v", err)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve returned after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Serve to stop")
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("CSI socket was not removed after shutdown: %v", err)
	}
}

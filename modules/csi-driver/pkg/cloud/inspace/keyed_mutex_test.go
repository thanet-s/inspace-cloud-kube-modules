package inspace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKeyedMutexSerializesSameKey(t *testing.T) {
	locks := newKeyedMutex()
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := locks.Lock(context.Background(), "vm-a")
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			now := active.Add(1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent holders of one key = %d, want 1", got)
	}
}

func TestKeyedMutexRunsDifferentKeysInParallel(t *testing.T) {
	locks := newKeyedMutex()
	unlockA, err := locks.Lock(context.Background(), "vm-a")
	if err != nil {
		t.Fatal(err)
	}
	defer unlockA()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	unlockB, err := locks.Lock(ctx, "vm-b")
	if err != nil {
		t.Fatalf("lock of a different key blocked: %v", err)
	}
	unlockB()
}

func TestKeyedMutexWaiterHonorsContextCancellation(t *testing.T) {
	locks := newKeyedMutex()
	unlock, err := locks.Lock(context.Background(), "vm-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := locks.Lock(ctx, "vm-a")
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("waiter returned while the lock was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter never returned")
	}
	unlock()
	// The abandoned waiter must not leave the key locked.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	again, err := locks.Lock(ctx2, "vm-a")
	if err != nil {
		t.Fatalf("lock after canceled waiter: %v", err)
	}
	again()
}

func TestKeyedMutexAlreadyCanceledContext(t *testing.T) {
	locks := newKeyedMutex()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A busy key is never waited for with a done context.
	unlock, err := locks.Lock(context.Background(), "vm-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locks.Lock(ctx, "vm-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("busy key error = %v, want context.Canceled", err)
	}
	unlock()
	if n := locks.size(); n != 0 {
		t.Fatalf("entries after canceled lock = %d, want 0", n)
	}

	// An uncontended key is granted so the caller's own cleanup still runs.
	free, err := locks.Lock(ctx, "vm-b")
	if err != nil {
		t.Fatalf("uncontended key with done context: %v", err)
	}
	free()
	if n := locks.size(); n != 0 {
		t.Fatalf("entries = %d, want 0", n)
	}
}

func TestKeyedMutexReleasesUnusedEntries(t *testing.T) {
	locks := newKeyedMutex()
	for _, key := range []string{"a", "b", "c", "a"} {
		unlock, err := locks.Lock(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		unlock()
	}
	if n := locks.size(); n != 0 {
		t.Fatalf("entries after all unlocks = %d, want 0", n)
	}

	// Canceled waiters also drop their reference.
	unlock, err := locks.Lock(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := locks.Lock(ctx, "a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want DeadlineExceeded", err)
	}
	unlock()
	if n := locks.size(); n != 0 {
		t.Fatalf("entries after canceled waiter = %d, want 0", n)
	}
}

func TestKeyedMutexUnlockIsIdempotent(t *testing.T) {
	locks := newKeyedMutex()
	unlock, err := locks.Lock(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock()
	second, err := locks.Lock(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	second()
	if n := locks.size(); n != 0 {
		t.Fatalf("entries = %d, want 0", n)
	}
}

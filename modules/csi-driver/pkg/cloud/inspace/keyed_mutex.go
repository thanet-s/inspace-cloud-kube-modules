package inspace

import (
	"context"
	"sync"
)

// keyedMutex is an in-process mutual-exclusion lock per string key. Waiting
// honors context cancellation, and an entry exists only while some caller
// holds or waits for its key, so the map does not grow with the key space.
type keyedMutex struct {
	mu      sync.Mutex
	entries map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	// held is a one-slot semaphore: a send acquires, a receive releases.
	held chan struct{}
	// refs counts holders and waiters; guarded by keyedMutex.mu.
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{entries: map[string]*keyedMutexEntry{}}
}

// Lock blocks until the caller owns key or ctx is done. On success it returns
// an idempotent unlock function. If the key is busy and ctx ends first, it
// returns ctx.Err() and owns nothing.
func (m *keyedMutex) Lock(ctx context.Context, key string) (func(), error) {
	m.mu.Lock()
	entry, ok := m.entries[key]
	if !ok {
		entry = &keyedMutexEntry{held: make(chan struct{}, 1)}
		m.entries[key] = entry
	}
	entry.refs++
	m.mu.Unlock()

	// An uncontended key is granted even when ctx is already done, so callers
	// keep their own cancellation handling (for example pre-dispatch cleanup).
	// Only waiting for a busy key is abandoned on cancellation.
	select {
	case entry.held <- struct{}{}:
	default:
		select {
		case entry.held <- struct{}{}:
		case <-ctx.Done():
			m.release(key, entry)
			return nil, ctx.Err()
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-entry.held
			m.release(key, entry)
		})
	}, nil
}

func (m *keyedMutex) release(key string, entry *keyedMutexEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.refs--
	if entry.refs == 0 {
		delete(m.entries, key)
	}
}

// size reports the number of live entries; it exists for tests.
func (m *keyedMutex) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

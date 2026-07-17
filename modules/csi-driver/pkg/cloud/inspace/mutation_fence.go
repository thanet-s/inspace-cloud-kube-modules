package inspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// mutationFence is a durable authorization for one cloud mutation. Receipt and
// Observation may advance by compare-and-swap, but Key, Intent, and Attempt
// never change. A fence is removed only after authoritative
// readback proves the desired state, or the current invocation proves that the
// cloud mutation method was never reached (for example, a typed local guard or
// a failed authority read before the call). Every HTTP status returned by a
// mutation remains post-dispatch ambiguous and therefore retains the fence.
// A controller crash after Lease creation but before the cloud POST is
// deliberately indistinguishable from a lost POST response: the Lease remains
// fail-closed until an operator inspects cloud state and removes that exact
// Lease. This trades liveness for never duplicating a paid or stateful resource.
type mutationFence struct {
	Key         string `json:"key"`
	Intent      string `json:"intent"`
	Attempt     string `json:"attempt"`
	Receipt     string `json:"receipt,omitempty"`
	Observation string `json:"observation,omitempty"`
}

type mutationFenceStore interface {
	Get(context.Context, string) (*mutationFence, error)
	List(context.Context, string) ([]mutationFence, error)
	Create(context.Context, mutationFence) (*mutationFence, bool, error)
	SetReceipt(context.Context, mutationFence, string) (*mutationFence, error)
	SetObservation(context.Context, mutationFence, string) (*mutationFence, error)
	Delete(context.Context, mutationFence) error
}

var errMutationFenceChanged = errors.New("CSI mutation fence changed")

func newMutationFence(key string, intent any) (mutationFence, error) {
	if key == "" {
		return mutationFence{}, errors.New("CSI mutation fence key is required")
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return mutationFence{}, fmt.Errorf("encode CSI mutation intent: %w", err)
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return mutationFence{}, fmt.Errorf("generate CSI mutation attempt token: %w", err)
	}
	return mutationFence{Key: key, Intent: string(encoded), Attempt: hex.EncodeToString(token)}, nil
}

func decodeMutationIntent[T any](fence mutationFence) (T, error) {
	var intent T
	if fence.Key == "" || fence.Intent == "" || fence.Attempt == "" {
		return intent, errors.New("CSI mutation fence is incomplete")
	}
	if err := json.Unmarshal([]byte(fence.Intent), &intent); err != nil {
		return intent, fmt.Errorf("decode CSI mutation intent: %w", err)
	}
	return intent, nil
}

// memoryMutationFenceStore is used by adapter unit/live tests that do not run
// in Kubernetes. Production controller mode supplies KubernetesNodeResolver,
// which implements mutationFenceStore with coordination.k8s.io Leases.
type memoryMutationFenceStore struct {
	mu     sync.Mutex
	fences map[string]mutationFence
}

func newMemoryMutationFenceStore() *memoryMutationFenceStore {
	return &memoryMutationFenceStore{fences: map[string]mutationFence{}}
}

func (s *memoryMutationFenceStore) Get(_ context.Context, key string) (*mutationFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, ok := s.fences[key]
	if !ok {
		return nil, nil
	}
	copy := fence
	return &copy, nil
}

func (s *memoryMutationFenceStore) List(_ context.Context, prefix string) ([]mutationFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]mutationFence, 0, len(s.fences))
	for key, fence := range s.fences {
		if strings.HasPrefix(key, prefix) {
			result = append(result, fence)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func (s *memoryMutationFenceStore) Create(_ context.Context, fence mutationFence) (*mutationFence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.fences[fence.Key]; ok {
		copy := current
		return &copy, false, nil
	}
	s.fences[fence.Key] = fence
	copy := fence
	return &copy, true, nil
}

func (s *memoryMutationFenceStore) SetReceipt(_ context.Context, fence mutationFence, receipt string) (*mutationFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.fences[fence.Key]
	if !ok {
		return nil, errors.New("CSI mutation fence disappeared before receipt persistence")
	}
	if !sameMutationFenceState(current, fence) {
		return nil, errors.New("CSI mutation fence changed before receipt persistence")
	}
	current.Receipt = receipt
	s.fences[fence.Key] = current
	copy := current
	return &copy, nil
}

func (s *memoryMutationFenceStore) SetObservation(_ context.Context, fence mutationFence, observation string) (*mutationFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.fences[fence.Key]
	if !ok {
		return nil, fmt.Errorf("%w: CSI mutation fence disappeared before observation persistence", errMutationFenceChanged)
	}
	if current.Observation == observation && sameMutationFenceAuthority(current, fence) {
		copy := current
		return &copy, nil
	}
	if !sameMutationFenceState(current, fence) {
		return nil, fmt.Errorf("%w before observation persistence", errMutationFenceChanged)
	}
	if observation != "" {
		if _, err := decodeMutationObservation(observation); err != nil {
			return nil, err
		}
	}
	current.Observation = observation
	s.fences[fence.Key] = current
	copy := current
	return &copy, nil
}

func (s *memoryMutationFenceStore) Delete(_ context.Context, fence mutationFence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.fences[fence.Key]
	if !ok {
		return nil
	}
	if !sameMutationFenceState(current, fence) {
		return errors.New("CSI mutation fence changed before completion")
	}
	delete(s.fences, fence.Key)
	return nil
}

func sameMutationFenceAuthority(left, right mutationFence) bool {
	return sameMutationFenceAttempt(left, right) && left.Receipt == right.Receipt
}

func sameMutationFenceAttempt(left, right mutationFence) bool {
	return left.Key == right.Key && left.Intent == right.Intent && left.Attempt == right.Attempt
}

func sameMutationFenceState(left, right mutationFence) bool {
	return sameMutationFenceAuthority(left, right) && left.Observation == right.Observation
}

var _ mutationFenceStore = (*memoryMutationFenceStore)(nil)

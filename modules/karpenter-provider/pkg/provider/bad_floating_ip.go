package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// badFloatingIPRetention bounds how long a floating IPv4 address observed
	// to have no working internet egress is remembered. InSpace floating IPs
	// are drawn from a shared pool and can be reassigned to a later VM; a
	// persistently bad address is far more likely to repeat within this
	// window than a genuinely transient one.
	badFloatingIPRetention = 30 * 24 * time.Hour
	// badFloatingIPConfigMapName is the single shared ConfigMap recording
	// recently bad addresses. It lives in the controller's own namespace
	// (the same namespace passed to NewKubernetesCreateFenceStore).
	badFloatingIPConfigMapName = "inspace-bad-floating-ips"
	badFloatingIPCreateRetries = 5
)

// BadFloatingIPStore remembers floating IPv4 addresses that a previous
// provisioning attempt found to have no working internet egress, so a later
// Create() assigned the exact same address can skip straight to a fresh
// retry instead of waiting for the new VM to boot, fail its on-guest
// connectivity gate, and only then be caught by Karpenter's own NodeClaim
// registration-liveness timeout.
//
// This is a best-effort speed optimization, not a correctness or safety
// mechanism: callers must fail open (proceed as if unknown) on any error
// from this store rather than blocking node provisioning on its
// availability.
type BadFloatingIPStore interface {
	IsRecentlyBad(ctx context.Context, address string) (bool, error)
	RecordBad(ctx context.Context, address string) error
}

type kubernetesBadFloatingIPStore struct {
	writer    client.Client
	reader    client.Reader
	namespace string
	clock     func() time.Time
}

// NewKubernetesBadFloatingIPStore returns a BadFloatingIPStore backed by a
// single ConfigMap. Reads use the uncached API reader so this dedicated,
// exact-name GET never causes controller-runtime to list/watch every
// ConfigMap in the namespace into its shared cache.
func NewKubernetesBadFloatingIPStore(writer client.Client, reader client.Reader, namespace string) (BadFloatingIPStore, error) {
	if writer == nil || reader == nil {
		return nil, fmt.Errorf("bad floating-IP store: writer and reader clients are required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("bad floating-IP store: namespace is required")
	}
	return &kubernetesBadFloatingIPStore{writer: writer, reader: reader, namespace: namespace, clock: time.Now}, nil
}

func (s *kubernetesBadFloatingIPStore) IsRecentlyBad(ctx context.Context, address string) (bool, error) {
	if address == "" {
		return false, nil
	}
	var configMap corev1.ConfigMap
	err := s.reader.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: badFloatingIPConfigMapName}, &configMap)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading bad floating-IP cache: %w", err)
	}
	raw, ok := configMap.Data[address]
	if !ok {
		return false, nil
	}
	badAt, parseErr := time.Parse(time.RFC3339, raw)
	if parseErr != nil {
		return false, nil
	}
	return s.clock().Sub(badAt) < badFloatingIPRetention, nil
}

func (s *kubernetesBadFloatingIPStore) RecordBad(ctx context.Context, address string) error {
	if address == "" {
		return nil
	}
	now := s.clock().UTC().Format(time.RFC3339)
	var lastErr error
	for attempt := 0; attempt < badFloatingIPCreateRetries; attempt++ {
		var configMap corev1.ConfigMap
		err := s.reader.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: badFloatingIPConfigMapName}, &configMap)
		switch {
		case apierrors.IsNotFound(err):
			configMap = corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: badFloatingIPConfigMapName, Namespace: s.namespace},
				Data:       map[string]string{address: now},
			}
			if createErr := s.writer.Create(ctx, &configMap); createErr != nil {
				if apierrors.IsAlreadyExists(createErr) {
					lastErr = createErr
					continue
				}
				return fmt.Errorf("creating bad floating-IP cache: %w", createErr)
			}
			return nil
		case err != nil:
			return fmt.Errorf("reading bad floating-IP cache: %w", err)
		}
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		configMap.Data[address] = now
		pruneBadFloatingIPs(configMap.Data, s.clock())
		if updateErr := s.writer.Update(ctx, &configMap); updateErr != nil {
			if apierrors.IsConflict(updateErr) {
				lastErr = updateErr
				continue
			}
			return fmt.Errorf("updating bad floating-IP cache: %w", updateErr)
		}
		return nil
	}
	return fmt.Errorf("recording bad floating IP %s: exhausted retries: %w", address, lastErr)
}

type memoryBadFloatingIPStore struct {
	mu    sync.Mutex
	bad   map[string]time.Time
	clock func() time.Time
}

// NewMemoryBadFloatingIPStore returns an in-process BadFloatingIPStore for
// tests. It is not durable across restarts.
func NewMemoryBadFloatingIPStore() BadFloatingIPStore {
	return &memoryBadFloatingIPStore{bad: map[string]time.Time{}, clock: time.Now}
}

func (s *memoryBadFloatingIPStore) IsRecentlyBad(_ context.Context, address string) (bool, error) {
	if address == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	badAt, ok := s.bad[address]
	if !ok {
		return false, nil
	}
	return s.clock().Sub(badAt) < badFloatingIPRetention, nil
}

func (s *memoryBadFloatingIPStore) RecordBad(_ context.Context, address string) error {
	if address == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.bad[address] = now
	for existing, badAt := range s.bad {
		if now.Sub(badAt) >= badFloatingIPRetention {
			delete(s.bad, existing)
		}
	}
	return nil
}

func pruneBadFloatingIPs(data map[string]string, now time.Time) {
	for address, raw := range data {
		badAt, err := time.Parse(time.RFC3339, raw)
		if err != nil || now.Sub(badAt) >= badFloatingIPRetention {
			delete(data, address)
		}
	}
}

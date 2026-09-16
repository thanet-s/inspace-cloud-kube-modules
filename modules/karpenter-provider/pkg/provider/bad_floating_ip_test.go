package provider

import (
	"context"
	"testing"
	"time"

	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestKubernetesBadFloatingIPStoreRecordsAndExpires(t *testing.T) {
	ctx := context.Background()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).Build()
	store, err := NewKubernetesBadFloatingIPStore(kubeClient, kubeClient, "kube-system")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.(*kubernetesBadFloatingIPStore).clock = func() time.Time { return now }

	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.5"); err != nil || bad {
		t.Fatalf("unrecorded address reported bad: bad=%v err=%v", bad, err)
	}
	if err := store.RecordBad(ctx, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.5"); err != nil || !bad {
		t.Fatalf("just-recorded address not reported bad: bad=%v err=%v", bad, err)
	}
	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.6"); err != nil || bad {
		t.Fatalf("different address incorrectly reported bad: bad=%v err=%v", bad, err)
	}

	now = now.Add(badFloatingIPRetention - time.Minute)
	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.5"); err != nil || !bad {
		t.Fatalf("address just inside retention window not reported bad: bad=%v err=%v", bad, err)
	}

	now = now.Add(2 * time.Minute)
	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.5"); err != nil || bad {
		t.Fatalf("address past retention window still reported bad: bad=%v err=%v", bad, err)
	}
}

func TestKubernetesBadFloatingIPStoreRetainsMultipleAddressesAndPrunesStale(t *testing.T) {
	ctx := context.Background()
	kubeClient := fake.NewClientBuilder().WithScheme(kubescheme.Scheme).Build()
	store, err := NewKubernetesBadFloatingIPStore(kubeClient, kubeClient, "kube-system")
	if err != nil {
		t.Fatal(err)
	}
	impl := store.(*kubernetesBadFloatingIPStore)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	impl.clock = func() time.Time { return now }

	if err := store.RecordBad(ctx, "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(badFloatingIPRetention + time.Hour)
	if err := store.RecordBad(ctx, "203.0.113.2"); err != nil {
		t.Fatal(err)
	}

	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.1"); err != nil || bad {
		t.Fatalf("stale address should have been pruned on next write: bad=%v err=%v", bad, err)
	}
	if bad, err := store.IsRecentlyBad(ctx, "203.0.113.2"); err != nil || !bad {
		t.Fatalf("freshly recorded address should remain bad: bad=%v err=%v", bad, err)
	}
}

func TestMemoryBadFloatingIPStoreMatchesKubernetesSemantics(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBadFloatingIPStore().(*memoryBadFloatingIPStore)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.clock = func() time.Time { return now }

	if bad, _ := store.IsRecentlyBad(ctx, "198.51.100.9"); bad {
		t.Fatal("unrecorded address reported bad")
	}
	if err := store.RecordBad(ctx, "198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if bad, _ := store.IsRecentlyBad(ctx, "198.51.100.9"); !bad {
		t.Fatal("just-recorded address not reported bad")
	}
	now = now.Add(badFloatingIPRetention + time.Second)
	if bad, _ := store.IsRecentlyBad(ctx, "198.51.100.9"); bad {
		t.Fatal("address past retention window still reported bad")
	}
}

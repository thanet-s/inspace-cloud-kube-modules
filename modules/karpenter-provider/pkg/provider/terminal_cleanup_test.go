package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/catalog"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

// failingTerminalCleanupStore proves a marker write failure never blocks
// deletion: the marker is only an optimization for later cleanup.
type failingTerminalCleanupStore struct {
	CreateFenceStore
	calls int
}

func (s *failingTerminalCleanupStore) RecordTerminalCleanup(context.Context, *karpv1.NodeClaim, createFenceBinding, string, string) (*karpv1.NodeClaim, error) {
	s.calls++
	return nil, errors.New("simulated Kubernetes write failure")
}

// materializedProviderClaim creates a real materialized claim through
// Create(), so the NodeClaim carries the exact durable create fence that
// Delete() later reads.
func materializedProviderClaim(t *testing.T, store CreateFenceStore, cloud cloudapi.Cloud) (*CloudProvider, *karpv1.NodeClaim) {
	t.Helper()
	ctx := context.Background()
	nodeClass := readyProviderNodeClass()
	resolver := NewStaticResolver(nodeClass)
	resolver.SetToken(inspacev1.RKE2AgentTokenSecretName, inspacev1.RKE2AgentTokenSecretKey, "agent-token")
	opts := providerOptions(nodeClass)
	if store != nil {
		opts.CreateFenceStore = store
	}
	provider, err := New(cloud, resolver, opts)
	if err != nil {
		t.Fatal(err)
	}
	claim := &karpv1.NodeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "general-abc", UID: types.UID("claim-uid"), Labels: map[string]string{karpv1.NodePoolLabelKey: "general"}},
		Spec: karpv1.NodeClaimSpec{
			NodeClassRef: &karpv1.NodeClassReference{Group: inspacev1.Group, Kind: inspacev1.Kind, Name: nodeClass.Name},
			Requirements: []karpv1.NodeSelectorRequirementWithMinValues{
				{Key: catalog.LabelFamily, Operator: "In", Values: []string{"general"}},
				{Key: catalog.LabelHostClass, Operator: "In", Values: []string{inspacev1.HostClassAMDEPYC}},
			},
		},
	}
	created, err := provider.Create(ctx, claim)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	return provider, created
}

func storedCreateFenceRecord(t *testing.T, provider *CloudProvider, claim *karpv1.NodeClaim) createFenceRecord {
	t.Helper()
	store, ok := provider.fences.(*memoryCreateFenceStore)
	if !ok {
		t.Fatalf("provider fence store is %T, want the memory store", provider.fences)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.records[claim.UID]
	if !found {
		t.Fatal("no durable create fence stored")
	}
	return record
}

func TestDeleteRecordsTerminalCleanupMarkerOnlyOnFullConvergence(t *testing.T) {
	converged := fmt.Errorf("%w: %w", cloudapi.ErrNotFound, cloudapi.ErrDeletionConverged)
	cases := []struct {
		name       string
		deleteErr  error
		wantMarker bool
		wantNotFnd bool
	}{
		{name: "live VM deleted and every dependent proven absent", deleteErr: nil, wantMarker: true, wantNotFnd: true},
		{name: "missing VM whose dependents converged", deleteErr: converged, wantMarker: true, wantNotFnd: true},
		{name: "bare not-found carries no convergence guarantee", deleteErr: cloudapi.ErrNotFound, wantMarker: false, wantNotFnd: true},
		{name: "pending delete", deleteErr: fmt.Errorf("%w: floating IP still visible", cloudapi.ErrCreateAttemptPending), wantMarker: false},
		{name: "uncertain cleanup", deleteErr: errors.New("floating IP cleanup did not converge"), wantMarker: false},
		{name: "ownership mismatch", deleteErr: cloudapi.ErrOwnershipMismatch, wantMarker: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
			provider, created := materializedProviderClaim(t, nil, cloud)
			cloud.deleteErr = tc.deleteErr

			err := provider.Delete(context.Background(), created)
			if got := cloudprovider.IsNodeClaimNotFoundError(err); got != tc.wantNotFnd {
				t.Fatalf("Delete() = %v, NodeClaimNotFound=%t, want %t", err, got, tc.wantNotFnd)
			}
			record := storedCreateFenceRecord(t, provider, created)
			if got := record.TerminalCleanup != nil; got != tc.wantMarker {
				t.Fatalf("terminal cleanup marker present = %t, want %t (record=%#v)", got, tc.wantMarker, record.TerminalCleanup)
			}
			if !tc.wantMarker {
				return
			}
			if !record.terminalCleanupConverged() {
				t.Fatalf("marker %#v is not bound to the materialized identity (VM %q, FIP %q/%q, firewall %q)",
					record.TerminalCleanup, record.ObservedVMUUID, record.FloatingIPName, record.PublicIPv4, record.Cleanup.FirewallUUID)
			}
		})
	}
}

func TestDeleteRecordsNoMarkerWithoutAMaterializedFence(t *testing.T) {
	// A claim with no retained create fence (legacy or foreign) has nothing to
	// bind a marker to; Delete still works exactly as before.
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	provider, created := materializedProviderClaim(t, nil, cloud)
	legacy := created.DeepCopy()
	delete(legacy.Annotations, AnnotationCreateFence)

	if err := provider.Delete(context.Background(), legacy); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("Delete() = %v, want NodeClaimNotFound", err)
	}
	if record := storedCreateFenceRecord(t, provider, created); record.TerminalCleanup != nil {
		t.Fatalf("marker written for a claim whose delete had no retained fence: %#v", record.TerminalCleanup)
	}
}

func TestDeleteSucceedsWhenTheTerminalMarkerCannotBeWritten(t *testing.T) {
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	store := &failingTerminalCleanupStore{CreateFenceStore: NewMemoryCreateFenceStore()}
	provider, created := materializedProviderClaim(t, store, cloud)

	if err := provider.Delete(context.Background(), created); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("Delete() = %v, want NodeClaimNotFound even though the marker write failed", err)
	}
	if store.calls != 1 {
		t.Fatalf("marker writes attempted = %d, want 1", store.calls)
	}
}

func TestRecordTerminalCleanupIsBoundToTheExactMaterializedIdentity(t *testing.T) {
	cloud := &recordingDeleteCloud{Cloud: cloudfake.New()}
	provider, created := materializedProviderClaim(t, nil, cloud)
	record := storedCreateFenceRecord(t, provider, created)
	binding := record.Binding
	ctx := context.Background()

	if _, err := provider.fences.RecordTerminalCleanup(ctx, created, binding, "not-the-token", record.ObservedVMUUID); err == nil {
		t.Fatal("RecordTerminalCleanup() accepted a different attempt token")
	}
	if _, err := provider.fences.RecordTerminalCleanup(ctx, created, binding, record.Token, "99999999-9999-4999-8999-999999999999"); err == nil {
		t.Fatal("RecordTerminalCleanup() accepted a VM that is not the materialized VM")
	}
	if storedCreateFenceRecord(t, provider, created).TerminalCleanup != nil {
		t.Fatal("a rejected RecordTerminalCleanup() still wrote a marker")
	}
	if _, err := provider.fences.RecordTerminalCleanup(ctx, created, binding, record.Token, record.ObservedVMUUID); err != nil {
		t.Fatalf("RecordTerminalCleanup() = %v", err)
	}
	first := storedCreateFenceRecord(t, provider, created).TerminalCleanup
	if first == nil || first.ObservedAt.IsZero() {
		t.Fatalf("marker = %#v, want a timestamped marker", first)
	}
	// Recording again is idempotent and never rewrites the first observation.
	time.Sleep(2 * time.Millisecond)
	if _, err := provider.fences.RecordTerminalCleanup(ctx, created, binding, record.Token, record.ObservedVMUUID); err != nil {
		t.Fatal(err)
	}
	if again := storedCreateFenceRecord(t, provider, created).TerminalCleanup; again == nil || !again.ObservedAt.Equal(first.ObservedAt) {
		t.Fatalf("second RecordTerminalCleanup() changed the marker: %#v -> %#v", first, again)
	}
}

func TestKubernetesStoreRecordsTerminalCleanupMarkerOnMaterializedClaimOnly(t *testing.T) {
	ctx := context.Background()
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	kubeClient := createFenceControllerClient(t, claim)
	store, err := NewKubernetesCreateFenceStore(kubeClient, kubeClient)
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.RecordTerminalCleanup(ctx, claim, record.Binding, record.Token, "99999999-9999-4999-8999-999999999999"); err == nil {
		t.Fatal("RecordTerminalCleanup() accepted a VM that is not the materialized VM")
	}
	updated, err := store.RecordTerminalCleanup(ctx, claim, record.Binding, record.Token, record.ObservedVMUUID)
	if err != nil {
		t.Fatalf("RecordTerminalCleanup() = %v", err)
	}
	stored, err := decodeCreateFence(updated.Annotations[AnnotationCreateFence])
	if err != nil || !stored.terminalCleanupConverged() {
		t.Fatalf("stored record = %#v, %v; want a converged, exactly bound marker", stored.TerminalCleanup, err)
	}
	if !controllerutil.ContainsFinalizer(updated, CreateFenceFinalizer) {
		t.Fatal("recording the marker dropped the create-fence finalizer")
	}

	issued := createFenceControllerClaim(t, createFenceIssued)
	issuedClient := createFenceControllerClient(t, issued)
	issuedStore, _ := NewKubernetesCreateFenceStore(issuedClient, issuedClient)
	issuedRecord, _ := decodeCreateFence(issued.Annotations[AnnotationCreateFence])
	if _, err := issuedStore.RecordTerminalCleanup(ctx, issued, issuedRecord.Binding, issuedRecord.Token, "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("RecordTerminalCleanup() accepted a claim that never materialized")
	}
}

func TestTerminalCleanupMarkerMustMatchEveryBoundField(t *testing.T) {
	base := func() createFenceRecord {
		claim := createFenceControllerClaim(t, createFenceMaterialized)
		record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
		if err != nil {
			t.Fatal(err)
		}
		record.TerminalCleanup = newTerminalCleanupRecord(record, time.Now())
		return record
	}
	if !base().terminalCleanupConverged() {
		t.Fatal("a marker built from the record itself must match")
	}
	for name, mutate := range map[string]func(*createFenceRecord){
		"no marker":            func(r *createFenceRecord) { r.TerminalCleanup = nil },
		"zero timestamp":       func(r *createFenceRecord) { r.TerminalCleanup.ObservedAt = time.Time{} },
		"other VM":             func(r *createFenceRecord) { r.TerminalCleanup.VMUUID = "99999999-9999-4999-8999-999999999999" },
		"other FIP name":       func(r *createFenceRecord) { r.TerminalCleanup.FloatingIPName = "someone-else" },
		"other FIP address":    func(r *createFenceRecord) { r.TerminalCleanup.PublicIPv4 = "203.0.113.99" },
		"other firewall":       func(r *createFenceRecord) { r.TerminalCleanup.FirewallUUID = "99999999-9999-4999-8999-999999999999" },
		"empty VM":             func(r *createFenceRecord) { r.TerminalCleanup.VMUUID = ""; r.ObservedVMUUID = "" },
		"not yet materialized": func(r *createFenceRecord) { r.Phase = createFenceIssued },
	} {
		record := base()
		mutate(&record)
		if record.terminalCleanupConverged() {
			t.Fatalf("%s: marker was accepted as converged", name)
		}
	}
}

// capturedLog collects every message logged through a logr.Logger.
type capturedLog struct {
	messages []string
}

func (c *capturedLog) logger() logr.Logger { return logr.New(&capturedLogSink{log: c}) }

type capturedLogSink struct {
	log    *capturedLog
	values []any
}

func (s *capturedLogSink) Init(logr.RuntimeInfo) {}
func (s *capturedLogSink) Enabled(int) bool      { return true }
func (s *capturedLogSink) WithValues(kv ...any) logr.LogSink {
	return &capturedLogSink{log: s.log, values: append(append([]any(nil), s.values...), kv...)}
}
func (s *capturedLogSink) WithName(string) logr.LogSink { return s }
func (s *capturedLogSink) Error(err error, msg string, kv ...any) {
	s.Info(0, msg+": "+err.Error(), kv...)
}
func (s *capturedLogSink) Info(_ int, msg string, kv ...any) {
	line := fmt.Sprintf("%s %v %v", msg, s.values, kv)
	s.log.messages = append(s.log.messages, line)
}

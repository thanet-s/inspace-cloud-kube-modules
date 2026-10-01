package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

// deletingMaterializedClaim is a materialized NodeClaim whose Karpenter
// termination has finished with the provider (no ProviderID wait) and that now
// only awaits the create-protection finalizer.
func deletingMaterializedClaim(t *testing.T, mutate func(*createFenceRecord)) *karpv1.NodeClaim {
	t.Helper()
	claim := createFenceControllerClaim(t, createFenceMaterialized)
	record, err := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&record)
	}
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	now := metav1.NewTime(time.Now())
	claim.DeletionTimestamp = &now
	return claim
}

func withMatchingTerminalMarker(record *createFenceRecord) {
	record.TerminalCleanup = newTerminalCleanupRecord(*record, time.Now())
}

// adapterContractCloud models the adapter's documented behavior for the
// request the controller builds: a receipt that is not Converged is replayed
// through a destructive DeleteVM, a converged one is only audited.
type adapterContractCloud struct {
	*recordingFenceCleanupCloud
	deleteReplays int
	auditErr      error
}

func newAdapterContractCloud() *adapterContractCloud {
	cloud := &adapterContractCloud{recordingFenceCleanupCloud: &recordingFenceCleanupCloud{Cloud: cloudfake.New()}}
	cloud.cleanup = func(request cloudapi.FencedCreateCleanupRequest) (cloudapi.FencedCreateCleanupResult, error) {
		for _, resolution := range request.Resolutions {
			if !resolution.Converged {
				cloud.deleteReplays++
			}
		}
		return cloudapi.FencedCreateCleanupResult{}, cloud.auditErr
	}
	return cloud
}

func storedClaim(t *testing.T, kubeClient client.Reader, name string) *karpv1.NodeClaim {
	t.Helper()
	var stored karpv1.NodeClaim
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: name}, &stored); err != nil {
		t.Fatal(err)
	}
	return &stored
}

func TestCreateFenceControllerSkipsDeleteReplayForConvergedMarkerAndReleasesAfterAudit(t *testing.T) {
	claim := deletingMaterializedClaim(t, withMatchingTerminalMarker)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := newAdapterContractCloud()
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	if cloud.calls != 1 {
		t.Fatalf("CleanupFencedCreate calls = %d, want the one read-only audit", cloud.calls)
	}
	if cloud.deleteReplays != 0 {
		t.Fatalf("destructive DeleteVM replays = %d, want none for a converged receipt", cloud.deleteReplays)
	}
	if len(cloud.request.Resolutions) != 1 || !cloud.request.Resolutions[0].Converged {
		t.Fatalf("cleanup request resolutions = %#v, want one Converged receipt", cloud.request.Resolutions)
	}
	if got := cloud.request.Resolutions[0]; got.VMUUID != "22222222-2222-4222-8222-222222222222" || got.FloatingIPName != "fenced-public" || got.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("converged receipt = %#v, want the exact materialized identity", got)
	}
	stored := storedClaim(t, kubeClient, claim.Name)
	if containsString(stored.Finalizers, CreateFenceFinalizer) || stored.Annotations[AnnotationCreateFence] != "" {
		t.Fatalf("finalizer not released after the audit passed: finalizers=%v", stored.Finalizers)
	}
}

func TestCreateFenceControllerKeepsFinalizerWhenConvergedAuditSeesReappearance(t *testing.T) {
	claim := deletingMaterializedClaim(t, withMatchingTerminalMarker)
	kubeClient := createFenceControllerClient(t, claim)
	cloud := newAdapterContractCloud()
	cloud.auditErr = errors.Join(cloudapi.ErrCreateAttemptPending, errors.New("durably resolved VM reappeared in cleanup discovery"))
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	result, err := controller.Reconcile(context.Background(), claim.DeepCopy())
	if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
		t.Fatalf("Reconcile() = %#v, %v; want a requeue while the audit is pending", result, err)
	}
	if stored := storedClaim(t, kubeClient, claim.Name); !containsString(stored.Finalizers, CreateFenceFinalizer) {
		t.Fatal("finalizer released although the converged audit reported a reappearance")
	}
	if cloud.deleteReplays != 0 {
		t.Fatalf("a reappearance triggered %d destructive replays; the converged path must stay read-only", cloud.deleteReplays)
	}
}

func TestCreateFenceControllerRunsFullPathWhenMarkerDoesNotMatchReceipt(t *testing.T) {
	cases := map[string]func(*createFenceRecord){
		"no marker": nil,
		"other VM": func(r *createFenceRecord) {
			withMatchingTerminalMarker(r)
			r.TerminalCleanup.VMUUID = "99999999-9999-4999-8999-999999999999"
		},
		"other floating IP address": func(r *createFenceRecord) {
			withMatchingTerminalMarker(r)
			r.TerminalCleanup.PublicIPv4 = "203.0.113.99"
		},
		"other floating IP name": func(r *createFenceRecord) {
			withMatchingTerminalMarker(r)
			r.TerminalCleanup.FloatingIPName = "someone-else"
		},
		"other firewall": func(r *createFenceRecord) {
			withMatchingTerminalMarker(r)
			r.TerminalCleanup.FirewallUUID = "99999999-9999-4999-8999-999999999999"
		},
		"no observation time": func(r *createFenceRecord) {
			withMatchingTerminalMarker(r)
			r.TerminalCleanup.ObservedAt = time.Time{}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claim := deletingMaterializedClaim(t, mutate)
			kubeClient := createFenceControllerClient(t, claim)
			cloud := newAdapterContractCloud()
			controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

			if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
				t.Fatal(err)
			}
			if cloud.deleteReplays != 1 {
				t.Fatalf("destructive DeleteVM replays = %d, want the full path for an unmatched marker", cloud.deleteReplays)
			}
			if len(cloud.request.Resolutions) != 1 || cloud.request.Resolutions[0].Converged {
				t.Fatalf("cleanup request resolutions = %#v, want one unconverged receipt", cloud.request.Resolutions)
			}
		})
	}
}

func TestCreateFenceControllerNeverTrustsMarkerOnNonMaterializedClaim(t *testing.T) {
	claim := createFenceControllerClaim(t, createFenceIssued)
	record, _ := decodeCreateFence(claim.Annotations[AnnotationCreateFence])
	record.TerminalCleanup = &terminalCleanupRecord{
		ObservedAt: time.Now(), VMUUID: "22222222-2222-4222-8222-222222222222", FloatingIPName: "fenced-public",
		PublicIPv4: "203.0.113.10", FirewallUUID: record.Cleanup.FirewallUUID,
	}
	claim.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)
	now := metav1.NewTime(time.Now())
	claim.DeletionTimestamp = &now
	kubeClient := createFenceControllerClient(t, claim)
	cloud := newAdapterContractCloud()
	controller, _ := NewCreateFenceController(kubeClient, kubeClient, cloud)

	if _, err := controller.Reconcile(context.Background(), claim.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	for _, resolution := range cloud.request.Resolutions {
		if resolution.Converged {
			t.Fatalf("an issued claim's receipt %#v was marked converged", resolution)
		}
	}
}

func TestCreateFenceControllerLogsWhyCleanupIsPending(t *testing.T) {
	cases := []struct {
		name   string
		claim  func(t *testing.T) *karpv1.NodeClaim
		cloud  func() *adapterContractCloud
		expect string
	}{
		{
			name: "cloud reports the create attempt pending",
			claim: func(t *testing.T) *karpv1.NodeClaim {
				return deletingMaterializedClaim(t, withMatchingTerminalMarker)
			},
			cloud: func() *adapterContractCloud {
				cloud := newAdapterContractCloud()
				cloud.auditErr = errors.Join(cloudapi.ErrCreateAttemptPending, errors.New("floating IP 203.0.113.10 reappeared"))
				return cloud
			},
			expect: "floating IP 203.0.113.10 reappeared",
		},
		{
			name: "waiting for Karpenter termination to release the NodeClaim",
			claim: func(t *testing.T) *karpv1.NodeClaim {
				claim := deletingMaterializedClaim(t, withMatchingTerminalMarker)
				claim.Status.ProviderID = "inspace://bkk01/22222222-2222-4222-8222-222222222222"
				return claim
			},
			cloud:  newAdapterContractCloud,
			expect: "Karpenter termination",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim := tc.claim(t)
			kubeClient := createFenceControllerClient(t, claim)
			controller, _ := NewCreateFenceController(kubeClient, kubeClient, tc.cloud())
			var captured capturedLog
			ctx := ctrllog.IntoContext(context.Background(), captured.logger())

			result, err := controller.Reconcile(ctx, claim.DeepCopy())
			if err != nil || result.RequeueAfter != createFenceCleanupRequeue {
				t.Fatalf("Reconcile() = %#v, %v; want a silent-looking requeue", result, err)
			}
			joined := strings.Join(captured.messages, "\n")
			if !strings.Contains(joined, tc.expect) || !strings.Contains(joined, claim.Name) {
				t.Fatalf("pending requeue logged %q, want the reason %q and the NodeClaim name", joined, tc.expect)
			}
		})
	}
}

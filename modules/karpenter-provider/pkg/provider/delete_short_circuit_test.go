package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
	"sigs.k8s.io/karpenter/pkg/cloudprovider"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/fake"
)

// shortCircuitCloud wraps the fake cloud and counts the two calls that decide
// whether a repeated Delete may return early.
type shortCircuitCloud struct {
	*cloudfake.Cloud
	deleteCalls int
	getCalls    int
	getErr      error // returned instead of the fake's answer when set
	reappeared  bool  // GetVM reports the VM as present again
	deleteErr   error
}

func (c *shortCircuitCloud) DeleteVM(ctx context.Context, location, uuid, clusterName, nodeClaimName string, identity cloudapi.DeleteVMIdentity) error {
	c.deleteCalls++
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return c.Cloud.DeleteVM(ctx, location, uuid, clusterName, nodeClaimName, identity)
}

func (c *shortCircuitCloud) GetVM(ctx context.Context, location, uuid, clusterName string) (*cloudapi.VM, error) {
	c.getCalls++
	if c.getErr != nil {
		return nil, c.getErr
	}
	if c.reappeared {
		return &cloudapi.VM{UUID: uuid, Location: location, ClusterName: clusterName}, nil
	}
	return c.Cloud.GetVM(ctx, location, uuid, clusterName)
}

// deletedAndMarkedClaim runs a first, fully converged Delete (which records the
// terminal marker) and returns the NodeClaim as Karpenter would read it on its
// second Delete call.
func deletedAndMarkedClaim(t *testing.T, cloud *shortCircuitCloud) (*CloudProvider, *karpv1.NodeClaim) {
	t.Helper()
	provider, created := materializedProviderClaim(t, nil, cloud)
	if err := provider.Delete(context.Background(), created); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("first Delete() = %v, want NodeClaimNotFound", err)
	}
	record := storedCreateFenceRecord(t, provider, created)
	if !record.terminalCleanupConverged() {
		t.Fatalf("first Delete() left no terminal marker: %#v", record.TerminalCleanup)
	}
	cloud.deleteCalls, cloud.getCalls = 0, 0
	return provider, claimWithCreateFence(created, record)
}

func TestSecondDeleteReturnsAtOnceWhenMarkerMatchesAndVMIsExactly404(t *testing.T) {
	cloud := &shortCircuitCloud{Cloud: cloudfake.New()}
	provider, marked := deletedAndMarkedClaim(t, cloud)
	var captured capturedLog
	ctx := ctrllog.IntoContext(context.Background(), captured.logger())

	err := provider.Delete(ctx, marked)
	if !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("second Delete() = %v, want NodeClaimNotFound", err)
	}
	if cloud.getCalls != 1 || cloud.deleteCalls != 0 {
		t.Fatalf("GetVM calls=%d DeleteVM calls=%d, want one exact read and no DeleteVM", cloud.getCalls, cloud.deleteCalls)
	}
	if joined := strings.Join(captured.messages, "\n"); !strings.Contains(joined, "terminal cleanup marker") {
		t.Fatalf("short-circuit left no log line: %q", joined)
	}
}

func TestSecondDeleteFallsBackToFullDeleteWhenTheVMReappeared(t *testing.T) {
	cloud := &shortCircuitCloud{Cloud: cloudfake.New()}
	provider, marked := deletedAndMarkedClaim(t, cloud)
	cloud.reappeared = true

	if err := provider.Delete(context.Background(), marked); err == nil && cloud.deleteCalls == 0 {
		t.Fatal("a reappeared VM was treated as already deleted")
	}
	if cloud.deleteCalls != 1 {
		t.Fatalf("DeleteVM calls = %d, want the full path to run once", cloud.deleteCalls)
	}
}

func TestSecondDeleteFallsBackToFullDeleteOnAnyOtherGetVMOutcome(t *testing.T) {
	for name, getErr := range map[string]error{
		"transient server error": errors.New("HTTP 500"),
		"ownership mismatch":     cloudapi.ErrOwnershipMismatch,
		"timeout":                context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			cloud := &shortCircuitCloud{Cloud: cloudfake.New()}
			provider, marked := deletedAndMarkedClaim(t, cloud)
			cloud.getErr = getErr

			_ = provider.Delete(context.Background(), marked)
			if cloud.deleteCalls != 1 {
				t.Fatalf("DeleteVM calls = %d, want the full path after a non-404 read", cloud.deleteCalls)
			}
		})
	}
}

func TestDeleteNeverReadsEarlyWithoutAMatchingMarker(t *testing.T) {
	cases := map[string]func(*createFenceRecord){
		"no marker": func(r *createFenceRecord) { r.TerminalCleanup = nil },
		"other VM": func(r *createFenceRecord) {
			r.TerminalCleanup.VMUUID = "99999999-9999-4999-8999-999999999999"
		},
		"other floating IP address": func(r *createFenceRecord) { r.TerminalCleanup.PublicIPv4 = "203.0.113.99" },
		"other floating IP name":    func(r *createFenceRecord) { r.TerminalCleanup.FloatingIPName = "someone-else" },
		"other firewall": func(r *createFenceRecord) {
			r.TerminalCleanup.FirewallUUID = "99999999-9999-4999-8999-999999999999"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cloud := &shortCircuitCloud{Cloud: cloudfake.New()}
			provider, marked := deletedAndMarkedClaim(t, cloud)
			record, err := decodeCreateFence(marked.Annotations[AnnotationCreateFence])
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			marked.Annotations[AnnotationCreateFence] = mustEncodeCreateFence(record)

			_ = provider.Delete(context.Background(), marked)
			if cloud.getCalls != 0 || cloud.deleteCalls != 1 {
				t.Fatalf("GetVM calls=%d DeleteVM calls=%d, want no early read and the full path", cloud.getCalls, cloud.deleteCalls)
			}
		})
	}
}

func TestFirstDeleteNeverShortCircuitsBeforeItsOwnConvergence(t *testing.T) {
	cloud := &shortCircuitCloud{Cloud: cloudfake.New()}
	provider, created := materializedProviderClaim(t, nil, cloud)

	if err := provider.Delete(context.Background(), created); !cloudprovider.IsNodeClaimNotFoundError(err) {
		t.Fatalf("first Delete() = %v", err)
	}
	if cloud.getCalls != 0 || cloud.deleteCalls != 1 {
		t.Fatalf("GetVM calls=%d DeleteVM calls=%d, want the first Delete to run the full path without a marker", cloud.getCalls, cloud.deleteCalls)
	}
}

package fake

import (
	"context"
	"errors"
	"testing"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

func TestCreateAndDeleteDesiredStateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	cloud := New()
	request := cloudapi.CreateVMRequest{IdempotencyKey: "claim-uid", Name: "worker-1", ClusterName: "test", NodeClaimName: "worker-1", Location: "bkk01"}
	first, err := cloud.CreateVM(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cloud.CreateVM(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.UUID != second.UUID {
		t.Fatalf("retry created a different VM: %s != %s", first.UUID, second.UUID)
	}
	if first.FirewallProfile != inspacev1.FirewallProfilePrivateWorker {
		t.Fatalf("default firewall profile = %q, want %q", first.FirewallProfile, inspacev1.FirewallProfilePrivateWorker)
	}
	vms, _ := cloud.ListVMs(ctx, "bkk01", "test")
	if len(vms) != 1 {
		t.Fatalf("expected one VM after create retry, got %d", len(vms))
	}
	if err := cloud.DeleteVM(ctx, "bkk01", first.UUID, "test", "worker-1", cloudapi.DeleteVMIdentity{}); err != nil {
		t.Fatal(err)
	}
	if err := cloud.DeleteVM(ctx, "bkk01", first.UUID, "test", "worker-1", cloudapi.DeleteVMIdentity{}); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("repeated delete should report desired not-found state, got %v", err)
	}
}

func TestNodeClassValidationRequiresPrivateControlPlaneVIP(t *testing.T) {
	cloud := New()
	if err := cloud.ValidateNodeClass(context.Background(), "bkk01", 1, "network-1", "10.0.0.10", "10.0.0.200", "10.0.0.219", "pool-1", "firewall-1"); err != nil {
		t.Fatalf("valid private VIP rejected: %v", err)
	}
	for _, vip := range []string{"", "registration.example", "203.0.113.10", "fd00::10", "10.42.0.10", "10.43.0.10"} {
		if err := cloud.ValidateNodeClass(context.Background(), "bkk01", 1, "network-1", vip, "10.0.0.200", "10.0.0.219", "pool-1", "firewall-1"); err == nil {
			t.Fatalf("invalid control-plane VIP %q accepted", vip)
		}
	}
}

package fake

import (
	"context"
	"errors"
	"testing"

	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/karpenter-provider-inspace/pkg/cloud"
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
	vms, _ := cloud.ListVMs(ctx, "bkk01", "test")
	if len(vms) != 1 {
		t.Fatalf("expected one VM after create retry, got %d", len(vms))
	}
	if err := cloud.DeleteVM(ctx, "bkk01", first.UUID, "test", "worker-1"); err != nil {
		t.Fatal(err)
	}
	if err := cloud.DeleteVM(ctx, "bkk01", first.UUID, "test", "worker-1"); !errors.Is(err, cloudapi.ErrNotFound) {
		t.Fatalf("repeated delete should report desired not-found state, got %v", err)
	}
}

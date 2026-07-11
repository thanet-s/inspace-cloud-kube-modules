package live_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/bootstrap"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	inspacecloud "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/inspace"
)

func TestLiveAdapterCreateGetListDelete(t *testing.T) {
	if os.Getenv("INSPACE_RUN_LIVE_TESTS") != "true" || os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS") != "true" {
		t.Skip("live mutations require INSPACE_RUN_LIVE_TESTS=true and INSPACE_ALLOW_REMOTE_MUTATIONS=true")
	}
	requireEnv := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s is required for the gated live test", name)
		}
		return value
	}
	baseURL := os.Getenv("INSPACE_API_BASE_URL")
	if baseURL == "" {
		baseURL = "https://api.inspace.cloud"
	}
	client, err := sdk.NewClient(sdk.Options{
		BaseURL: baseURL, APIKey: requireEnv("INSPACE_API_TOKEN"),
		DangerouslyAllowMutations: true, UserAgent: "karpenter-provider-inspace/live-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := inspacecloud.New(client)
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	name := "inspace-e2e-karp-" + suffix
	clusterName := "inspace-e2e-" + suffix
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cloudInit, err := bootstrap.RenderCloudInit(bootstrap.Config{
		NodeName: name, Server: "https://192.0.2.1:6443", Token: "inspace-e2e-disposable-token", K3sVersion: "v1.35.6+k3s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	billingAccountID, err := strconv.ParseInt(requireEnv("INSPACE_BILLING_ACCOUNT_ID"), 10, 64)
	if err != nil || billingAccountID <= 0 {
		t.Fatalf("INSPACE_BILLING_ACCOUNT_ID must be a positive integer")
	}
	request := cloudapi.CreateVMRequest{
		IdempotencyKey: name, Name: name, ClusterName: clusterName, NodeClaimName: name,
		BillingAccountID: billingAccountID,
		Location:         "bkk01", NetworkUUID: requireEnv("INSPACE_NETWORK_UUID"), FirewallUUID: requireEnv("INSPACE_FIREWALL_UUID"),
		OSName: "ubuntu", OSVersion: "24.04", HostPoolUUID: requireEnv("INSPACE_INTEL_HOST_POOL_UUID"),
		HostClass: "intel-scalable", InstanceType: "is-compute-2c-2g", VCPU: 2, MemoryGiB: 2, RootDiskGiB: 30,
		PublicIPv4: true, CloudInitJSON: cloudInit, SpecHash: "inspace-e2e", BootstrapHash: "inspace-e2e",
	}

	var createdUUID string
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cleanupCancel()
		var cleanupErrors []error
		if vms, listErr := adapter.ListVMs(cleanupCtx, request.Location, clusterName); listErr == nil {
			for _, vm := range vms {
				if err := adapter.DeleteVM(cleanupCtx, request.Location, vm.UUID, clusterName, name); err != nil && !errors.Is(err, cloudapi.ErrNotFound) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("adapter cleanup VM %s: %w", vm.UUID, err))
				}
			}
		} else {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("list owned VMs during cleanup: %w", listErr))
		}
		if createdUUID != "" {
			if _, err := client.GetVM(cleanupCtx, request.Location, createdUUID); err == nil {
				if err := client.DeleteVM(cleanupCtx, request.Location, createdUUID); err != nil && !sdk.IsNotFound(err) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("direct cleanup VM %s: %w", createdUUID, err))
				}
			} else if !sdk.IsNotFound(err) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("check VM %s during cleanup: %w", createdUUID, err))
			}
		}
		if addresses, listErr := client.ListFloatingIPs(cleanupCtx, request.Location, &sdk.FloatingIPFilters{BillingAccountID: billingAccountID}); listErr == nil {
			for _, address := range addresses {
				if strings.HasPrefix(address.Name, name) {
					if address.AssignedTo != "" {
						if _, err := client.UnassignFloatingIP(cleanupCtx, request.Location, address.Address); err != nil && !sdk.IsNotFound(err) {
							cleanupErrors = append(cleanupErrors, fmt.Errorf("unassign cleanup floating IP %s: %w", address.Address, err))
						}
					}
					if err := client.DeleteFloatingIP(cleanupCtx, request.Location, address.Address); err != nil && !sdk.IsNotFound(err) {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("delete cleanup floating IP %s: %w", address.Address, err))
					}
				}
			}
		} else {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("list floating IPs during cleanup: %w", listErr))
		}

		var auditErr error
		for {
			vms, vmErr := client.ListVMs(cleanupCtx, request.Location)
			addresses, ipErr := client.ListFloatingIPs(cleanupCtx, request.Location, &sdk.FloatingIPFilters{BillingAccountID: billingAccountID})
			var vmLeft, ipLeft bool
			for _, vm := range vms {
				vmLeft = vmLeft || vm.Name == name
			}
			for _, address := range addresses {
				ipLeft = ipLeft || strings.HasPrefix(address.Name, name)
			}
			if vmErr == nil && ipErr == nil && !vmLeft && !ipLeft {
				auditErr = nil
				break
			}
			auditErr = errors.Join(vmErr, ipErr)
			if vmLeft || ipLeft {
				auditErr = errors.Join(auditErr, fmt.Errorf("prefixed leftovers remain: vm=%t floatingIP=%t", vmLeft, ipLeft))
			}
			select {
			case <-cleanupCtx.Done():
				auditErr = errors.Join(auditErr, cleanupCtx.Err())
				break
			case <-time.After(5 * time.Second):
				continue
			}
			break
		}
		if auditErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("leftover audit: %w", auditErr))
		}
		if err := errors.Join(cleanupErrors...); err != nil {
			t.Errorf("live cleanup failed: %v", err)
		}
	})

	created, err := adapter.CreateVM(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	createdUUID = created.UUID
	if _, err := adapter.GetVM(ctx, request.Location, created.UUID, clusterName); err != nil {
		t.Fatal(err)
	}
	listed, err := adapter.ListVMs(ctx, request.Location, clusterName)
	if err != nil || len(listed) != 1 || listed[0].UUID != created.UUID {
		t.Fatalf("ListVMs = %#v, %v", listed, err)
	}
	if err := adapter.DeleteVM(ctx, request.Location, created.UUID, clusterName, name); err != nil {
		t.Fatal(err)
	}
}

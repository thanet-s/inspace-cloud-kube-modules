//go:build live

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// TestLiveLifecycle is intentionally excluded from ordinary test and smoke
// targets. It creates only resources whose names begin with inspace-e2e- and
// registers cleanup before the first mutation.
func TestLiveLifecycle(t *testing.T) {
	if os.Getenv("INSPACE_RUN_LIVE_TESTS") != "true" || os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS") != "true" {
		t.Skip("live mutations require both explicit safety gates")
	}
	token := firstNonEmpty(os.Getenv("INSPACE_API_TOKEN"), os.Getenv("INSPACE_API_KEY"))
	if token == "" {
		t.Fatal("INSPACE_API_TOKEN is required")
	}
	location := defaultValue(os.Getenv("INSPACE_LOCATION"), "bkk01")
	networkUUID := requiredEnv(t, "INSPACE_NETWORK_UUID")
	hostPoolUUID := requiredEnv(t, "INSPACE_HOST_POOL_UUID")
	billingID := requiredInt64Env(t, "INSPACE_BILLING_ACCOUNT_ID")
	baseURL := defaultValue(os.Getenv("INSPACE_API_URL"), "https://api.inspace.cloud")
	client, err := inspace.NewClient(inspace.Options{
		BaseURL: baseURL, APIKey: token, DangerouslyAllowMutations: true,
		UserAgent: "cloud-provider-inspace-live-test/dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	prefix := fmt.Sprintf("inspace-e2e-%d", time.Now().UTC().UnixNano())

	var (
		vmUUID, diskUUID, firewallUUID, loadBalancerUUID string
		floatingAddress                                  string
		diskAttached                                     bool
	)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cleanupCancel()
		if loadBalancerUUID != "" {
			cleanupError(t, "delete load balancer", client.DeleteLoadBalancer(cleanupCtx, location, loadBalancerUUID))
		}
		if diskAttached && vmUUID != "" && diskUUID != "" {
			cleanupError(t, "detach disk", client.DetachDisk(cleanupCtx, location, vmUUID, diskUUID))
		}
		if diskUUID != "" {
			cleanupError(t, "delete disk", client.DeleteDisk(cleanupCtx, location, diskUUID))
		}
		if floatingAddress != "" {
			if _, err := client.UnassignFloatingIP(cleanupCtx, location, floatingAddress); err != nil && !inspace.IsNotFound(err) {
				cleanupError(t, "unassign floating IP", err)
			}
		}
		vmDeleted := vmUUID == ""
		if vmUUID != "" {
			err := client.DeleteVM(cleanupCtx, location, vmUUID)
			if err == nil || inspace.IsNotFound(err) {
				vmDeleted = true
			} else {
				cleanupError(t, "delete VM", err)
			}
		}
		if vmDeleted && firewallUUID != "" && vmUUID != "" {
			cleanupError(t, "unassign firewall after VM deletion", client.UnassignFirewallFromVM(cleanupCtx, location, firewallUUID, vmUUID))
		}
		if floatingAddress != "" {
			cleanupError(t, "delete floating IP", client.DeleteFloatingIP(cleanupCtx, location, floatingAddress))
		}
		if vmDeleted && firewallUUID != "" {
			cleanupError(t, "delete firewall", client.DeleteFirewall(cleanupCtx, location, firewallUUID))
		}
	})

	// Read-only contract checks precede mutation and validate configured scope.
	network, err := client.GetNetwork(ctx, location, networkUUID)
	if err != nil || network.UUID != networkUUID || network.Subnet == "" {
		t.Fatalf("GetNetwork() = %#v, %v", network, err)
	}
	images, err := client.ListVMImages(ctx)
	if err != nil || !hasPublishedImage(images, defaultValue(os.Getenv("INSPACE_OS_NAME"), "ubuntu"), defaultValue(os.Getenv("INSPACE_OS_VERSION"), "24.04")) {
		t.Fatalf("configured stock image is not published: %v", err)
	}

	firewall, err := client.CreateFirewall(ctx, location, inspace.CreateFirewallRequest{
		DisplayName: prefix + "-fw", BillingAccountID: billingID,
		Rules: liveFirewallRules(network.Subnet),
	})
	if err != nil {
		t.Fatal(err)
	}
	firewallUUID = firewall.UUID

	floatingIP, err := client.CreateFloatingIP(ctx, location, inspace.CreateFloatingIPRequest{Name: prefix + "-ip", BillingAccountID: billingID})
	if err != nil {
		t.Fatal(err)
	}
	floatingAddress = floatingIP.Address

	password := randomSecret(t)
	reservePublicIP := false
	vmName := prefix + "-vm"
	vm, err := client.CreateVM(ctx, location, inspace.CreateVMRequest{
		Name: vmName, Description: "ephemeral SDK lifecycle conformance resource",
		OSName: defaultValue(os.Getenv("INSPACE_OS_NAME"), "ubuntu"), OSVersion: defaultValue(os.Getenv("INSPACE_OS_VERSION"), "24.04"),
		DiskGiB: 30, VCPU: 2, MemoryMiB: 2048, DesignatedPoolUUID: hostPoolUUID,
		Username: "inspacee2e", Password: password, BillingAccountID: billingID, NetworkUUID: networkUUID,
		CloudInit: `{"runcmd":["true"]}`, ReservePublicIP: &reservePublicIP,
	})
	if err != nil {
		createErr := err
		recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer recoveryCancel()
		vm, err = waitForVMByName(recoveryCtx, client, location, vmName)
		if err != nil {
			t.Fatalf("VM create outcome was ambiguous (%v) and recovery failed: %v", createErr, err)
		}
		t.Log("recovered VM by its unique owned name after an ambiguous create response")
	}
	vmUUID = vm.UUID
	if err := client.AssignFirewallToVM(ctx, location, firewallUUID, vmUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AssignFloatingIP(ctx, location, floatingAddress, vmUUID, "virtual_machine"); err != nil {
		t.Fatal(err)
	}
	vm = waitForVM(t, ctx, client, location, vmUUID)
	if vm.PrivateIPv4 == "" {
		t.Fatal("VM never received a private IPv4")
	}

	disk, err := client.CreateDisk(ctx, location, inspace.CreateDiskRequest{DisplayName: prefix + "-disk", SizeGiB: 10, BillingAccountID: billingID, SourceImageType: "EMPTY"})
	if err != nil {
		t.Fatal(err)
	}
	diskUUID = disk.UUID
	waitForDisk(t, ctx, client, location, diskUUID)
	if _, err := client.AttachDisk(ctx, location, vmUUID, diskUUID); err != nil {
		t.Fatal(err)
	}
	diskAttached = true
	if err := client.DetachDisk(ctx, location, vmUUID, diskUUID); err != nil {
		t.Fatal(err)
	}
	diskAttached = false

	lb, err := client.CreateLoadBalancer(ctx, location, inspace.CreateLoadBalancerRequest{
		DisplayName: prefix + "-nlb", BillingAccountID: billingID, NetworkUUID: networkUUID, ReservePublicIP: false,
		Rules:   []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 8443, TargetPort: 8443}},
		Targets: []inspace.LoadBalancerTarget{{TargetUUID: vmUUID, TargetType: "vm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	loadBalancerUUID = lb.UUID
	if got, err := client.GetLoadBalancer(ctx, location, loadBalancerUUID); err != nil || got.UUID != loadBalancerUUID || len(got.ForwardingRules) == 0 {
		t.Fatalf("GetLoadBalancer() = %#v, %v", got, err)
	}

	t.Logf("live lifecycle succeeded for prefix %s", prefix)
}

func waitForVMByName(ctx context.Context, client *inspace.Client, location, name string) (*inspace.VM, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		vms, err := client.ListVMs(ctx, location)
		if err == nil {
			var found *inspace.VM
			for i := range vms {
				if vms[i].Name != name {
					continue
				}
				if found != nil {
					return nil, fmt.Errorf("multiple VMs have unique live-test name %q", name)
				}
				copy := vms[i]
				found = &copy
			}
			if found != nil {
				return found, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for VM name %q: %w (last list error: %v)", name, ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func waitForVM(t *testing.T, ctx context.Context, client *inspace.Client, location, uuid string) *inspace.VM {
	t.Helper()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		vm, err := client.GetVM(ctx, location, uuid)
		if err == nil && strings.EqualFold(vm.Status, "running") && vm.PrivateIPv4 != "" {
			return vm
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for VM: %v (last error %v)", ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func waitForDisk(t *testing.T, ctx context.Context, client *inspace.Client, location, uuid string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		disk, err := client.GetDisk(ctx, location, uuid)
		if err == nil && strings.EqualFold(disk.Status, "active") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for disk: %v (last error %v)", ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func liveFirewallRules(subnet string) []inspace.FirewallRule {
	var result []inspace.FirewallRule
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		result = append(result,
			inspace.FirewallRule{Protocol: protocol, Direction: "inbound", EndpointSpecType: "ip_prefixes", EndpointSpec: []string{subnet}},
			inspace.FirewallRule{Protocol: protocol, Direction: "outbound", EndpointSpecType: "any"},
		)
	}
	return result
}

func hasPublishedImage(images []inspace.VMImage, osName, osVersion string) bool {
	for _, image := range images {
		if image.OSName != osName {
			continue
		}
		for _, version := range image.Versions {
			if version.OSVersion == osVersion && version.Published {
				return true
			}
		}
	}
	return false
}

func randomSecret(t *testing.T) string {
	t.Helper()
	data := make([]byte, 24)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return "Aa1!" + base64.RawURLEncoding.EncodeToString(data)
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func requiredInt64Env(t *testing.T, name string) int64 {
	t.Helper()
	value := requiredEnv(t, name)
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 {
		t.Fatalf("%s must be a positive integer", name)
	}
	return parsed
}

func cleanupError(t *testing.T, operation string, err error) {
	t.Helper()
	if err != nil && !inspace.IsNotFound(err) {
		t.Errorf("cleanup %s: %v", operation, err)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

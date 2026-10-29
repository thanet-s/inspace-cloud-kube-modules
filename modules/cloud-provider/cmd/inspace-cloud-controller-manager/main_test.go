package main

import (
	"os"
	"strings"
	"testing"
	"time"

	inspaceprovider "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/cloudprovider"
)

func TestParseLocalFirewallMode(t *testing.T) {
	for _, test := range []struct {
		name, value string
		want        inspaceprovider.PublicNodeLocalFirewallMode
		wantErr     bool
	}{
		{name: "unset is perService", want: inspaceprovider.PublicNodeLocalFirewallModePerService},
		{name: "perService", value: "perService", want: inspaceprovider.PublicNodeLocalFirewallModePerService},
		{name: "perVM", value: " perVM ", want: inspaceprovider.PublicNodeLocalFirewallModePerVM},
		{name: "other value is fatal", value: "pervm", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("INSPACE_NODE_LOAD_BALANCER_LOCAL_FIREWALL_MODE", test.value)
			got, err := parseLocalFirewallMode()
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("parseLocalFirewallMode() = %q, %v", got, err)
			}
		})
	}
}

func TestParseVMFirewallMigration(t *testing.T) {
	for _, test := range []struct {
		name, value string
		want        inspaceprovider.VMFirewallMigrationMode
		wantErr     bool
	}{
		{name: "unset is manual", want: inspaceprovider.VMFirewallMigrationManual},
		{name: "manual", value: "manual", want: inspaceprovider.VMFirewallMigrationManual},
		{name: "auto", value: "auto", want: inspaceprovider.VMFirewallMigrationAuto},
		{name: "other value is fatal", value: "Auto", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("INSPACE_NODE_LOAD_BALANCER_VM_FIREWALL_MIGRATION", test.value)
			got, err := parseVMFirewallMigration()
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("parseVMFirewallMigration() = %q, %v", got, err)
			}
		})
	}
}

func TestParseVMFirewallSettle(t *testing.T) {
	for _, test := range []struct {
		name, value string
		want        time.Duration
		wantErr     bool
	}{
		{name: "unset means the default", want: 0},
		{name: "ten seconds", value: "10", want: 10 * time.Second},
		{name: "ceiling", value: "600", want: 600 * time.Second},
		{name: "below the floor", value: "9", wantErr: true},
		{name: "above the ceiling", value: "601", wantErr: true},
		{name: "zero when set", value: "0", wantErr: true},
		{name: "not an integer", value: "ten", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("INSPACE_NODE_LOAD_BALANCER_VM_FIREWALL_SETTLE_SECONDS", test.value)
			got, err := parseVMFirewallSettle()
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("parseVMFirewallSettle() = %v, %v", got, err)
			}
		})
	}
}

func TestPerVMRequiresNamespace(t *testing.T) {
	if err := requireNamespaceForPerVM(inspaceprovider.PublicNodeLocalFirewallModePerVM, ""); err == nil {
		t.Fatal("perVM without INSPACE_CCM_NAMESPACE must be fatal")
	}
	if err := requireNamespaceForPerVM(inspaceprovider.PublicNodeLocalFirewallModePerVM, "kube-system"); err != nil {
		t.Fatal(err)
	}
	if err := requireNamespaceForPerVM(inspaceprovider.PublicNodeLocalFirewallModePerService, ""); err != nil {
		t.Fatalf("perService does not need the namespace: %v", err)
	}
}

func TestManifestWiresReservedPrivateAddressEnvironment(t *testing.T) {
	data, err := os.ReadFile("../../config/ccm/cloud-controller-manager.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	for _, required := range []string{
		"controlPlaneVIP: REPLACE_WITH_CONTROL_PLANE_VIP",
		"name: INSPACE_CONTROL_PLANE_VIP",
		"key: controlPlaneVIP",
		"privateLoadBalancerPoolStart: REPLACE_WITH_PRIVATE_LOAD_BALANCER_POOL_START",
		"privateLoadBalancerPoolStop: REPLACE_WITH_PRIVATE_LOAD_BALANCER_POOL_STOP",
		"name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_START",
		"key: privateLoadBalancerPoolStart",
		"name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP",
		"key: privateLoadBalancerPoolStop",
		"billingAccountID: \"REPLACE_WITH_BILLING_ACCOUNT_ID\"",
		"name: INSPACE_BILLING_ACCOUNT_ID",
		"key: billingAccountID",
		"optional: false",
		"apiGroups: [\"discovery.k8s.io\"]",
		"resources: [\"endpointslices\"]",
		"verbs: [\"get\", \"list\", \"watch\"]",
	} {
		if !strings.Contains(manifest, required) {
			t.Errorf("CCM manifest lacks %q", required)
		}
	}
}

func TestParseRequiredPositiveInt64(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    int64
		wantErr bool
	}{
		{name: "missing", wantErr: true},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "not an integer", value: "account", wantErr: true},
		{name: "positive", value: " 42 ", want: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("INSPACE_BILLING_ACCOUNT_ID", test.value)
			got, err := parseRequiredPositiveInt64("INSPACE_BILLING_ACCOUNT_ID")
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("parseRequiredPositiveInt64() = %d, %v", got, err)
			}
		})
	}
}

func TestManifestKeepsTheTwoReplicasApartAndHealthChecked(t *testing.T) {
	data, err := os.ReadFile("../../config/ccm/cloud-controller-manager.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	for _, required := range []string{
		"podAntiAffinity:",
		"requiredDuringSchedulingIgnoredDuringExecution:",
		"topologyKey: kubernetes.io/hostname",
		"containerPort: 10258",
		"livenessProbe:",
		"path: /healthz",
		"scheme: HTTPS",
		"maxSurge: 0",
		"kind: PodDisruptionBudget",
		"  maxUnavailable: 1",
	} {
		if !strings.Contains(manifest, required) {
			t.Errorf("CCM manifest lacks %q", required)
		}
	}
}

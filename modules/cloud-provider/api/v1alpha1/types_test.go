package v1alpha1

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestControlPlaneReplicaValidation(t *testing.T) {
	spec := validSpec()
	spec.ControlPlane.Replicas = 3
	if errs := spec.Validate(); len(errs) != 0 {
		t.Errorf("replicas 3: unexpected validation errors: %v", errs)
	}
	for _, replicas := range []int32{0, 1, 2, 4, 5, 7} {
		spec.ControlPlane.Replicas = replicas
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("replicas %d: expected validation error", replicas)
		}
	}
}

func TestRKE2VersionValidationRequiresExactRelease(t *testing.T) {
	for _, version := range []string{"v1.35.6+rke2r1", "v1.35.6+rke2r12"} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("version %q: unexpected validation errors: %v", version, errs)
		}
	}
	for _, version := range []string{"", "latest", "v1.35.6", "v1.35.6+rke2", "1.35.6+rke2r1", "v1.35+rke2r1"} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("version %q: expected exact RKE2 release validation error", version)
		}
	}
}

func TestControlPlaneMachineRequiresRKE2MinimumsAndUbuntu2404(t *testing.T) {
	minimum := validSpec()
	minimum.ControlPlane.Machine.VCPU = 2
	minimum.ControlPlane.Machine.MemoryMiB = 4096
	if errs := minimum.Validate(); len(errs) != 0 {
		t.Fatalf("minimum supported control-plane machine: %v", errs)
	}

	tests := []struct {
		name  string
		field string
		edit  func(*MachineSpec)
	}{
		{name: "one vCPU", field: "spec.controlPlane.machine.vcpu", edit: func(m *MachineSpec) { m.VCPU = 1 }},
		{name: "too many vCPUs", field: "spec.controlPlane.machine.vcpu", edit: func(m *MachineSpec) { m.VCPU = 17 }},
		{name: "less than four GiB", field: "spec.controlPlane.machine.memoryMiB", edit: func(m *MachineSpec) { m.MemoryMiB = 4095 }},
		{name: "more than 64 GiB", field: "spec.controlPlane.machine.memoryMiB", edit: func(m *MachineSpec) { m.MemoryMiB = 65537 }},
		{name: "wrong OS", field: "spec.controlPlane.machine.image.osName", edit: func(m *MachineSpec) { m.Image.OSName = "debian" }},
		{name: "wrong Ubuntu release", field: "spec.controlPlane.machine.image.osVersion", edit: func(m *MachineSpec) { m.Image.OSVersion = "22.04" }},
		{name: "empty Ubuntu release", field: "spec.controlPlane.machine.image.osVersion", edit: func(m *MachineSpec) { m.Image.OSVersion = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec()
			test.edit(&spec.ControlPlane.Machine)
			errs := spec.Validate()
			found := false
			for _, err := range errs {
				found = found || strings.HasPrefix(err.Error(), test.field+":")
			}
			if !found {
				t.Fatalf("validation errors %v do not identify %s", errs, test.field)
			}
		})
	}
}

func TestEndpointAndRequiredCiliumValidation(t *testing.T) {
	for _, virtualIPv4 := range []string{"", "203.0.113.10", "not-an-ip", "2001:db8::10", "10.42.0.10", "10.43.0.10"} {
		spec := validSpec()
		spec.Endpoint.VirtualIPv4 = virtualIPv4
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("virtualIPv4 %q: expected validation error", virtualIPv4)
		}
	}
	spec := validSpec()
	spec.RKE2.Disable = []string{"rke2-ingress-nginx", "rke2-cilium"}
	if errs := spec.Validate(); len(errs) == 0 {
		t.Fatal("expected rke2-cilium disable rejection")
	}
	spec = validSpec()
	spec.Firewall.Managed = false
	if errs := spec.Validate(); len(errs) == 0 {
		t.Fatal("expected managed firewall requirement")
	}
}

func TestPrivateLoadBalancerPoolValidation(t *testing.T) {
	for _, bounds := range []PrivateLoadBalancerPoolSpec{
		{Start: "10.20.30.200", Stop: "10.20.30.215"},
		{Start: "10.20.31.0", Stop: "10.20.31.255"},
	} {
		spec := validSpec()
		spec.Network.PrivateLoadBalancerPool = bounds
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("valid %d-address pool %#v rejected: %v", inclusiveIPv4Count(mustAddress(t, bounds.Start), mustAddress(t, bounds.Stop)), bounds, errs)
		}
	}

	tests := []struct {
		name string
		pool PrivateLoadBalancerPoolSpec
	}{
		{name: "missing", pool: PrivateLoadBalancerPoolSpec{}},
		{name: "public", pool: PrivateLoadBalancerPoolSpec{Start: "203.0.113.10", Stop: "203.0.113.30"}},
		{name: "noncanonical", pool: PrivateLoadBalancerPoolSpec{Start: "010.20.30.200", Stop: "10.20.30.220"}},
		{name: "reversed", pool: PrivateLoadBalancerPoolSpec{Start: "10.20.30.220", Stop: "10.20.30.200"}},
		{name: "too small", pool: PrivateLoadBalancerPoolSpec{Start: "10.20.30.200", Stop: "10.20.30.214"}},
		{name: "too large", pool: PrivateLoadBalancerPoolSpec{Start: "10.20.31.0", Stop: "10.20.32.0"}},
		{name: "contains kube vip", pool: PrivateLoadBalancerPoolSpec{Start: "10.20.30.1", Stop: "10.20.30.16"}},
		{name: "overlaps pod cidr", pool: PrivateLoadBalancerPoolSpec{Start: "10.42.0.1", Stop: "10.42.0.16"}},
		{name: "overlaps service cidr", pool: PrivateLoadBalancerPoolSpec{Start: "10.43.0.1", Stop: "10.43.0.16"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec()
			spec.Network.PrivateLoadBalancerPool = test.pool
			if errs := spec.Validate(); len(errs) == 0 {
				t.Fatalf("pool %#v unexpectedly accepted", test.pool)
			}
		})
	}
}

func TestControlPlaneCRDMatchesMachineValidationContract(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/infrastructure.inspace.cloud_inspaceclusters.yaml")
	if err != nil {
		t.Fatal(err)
	}
	crd := string(data)
	for _, required := range []string{
		"vcpu:\n                          type: integer\n                          format: int32\n                          minimum: 2\n                          maximum: 16",
		"memoryMiB:\n                          type: integer\n                          format: int32\n                          minimum: 4096\n                          maximum: 65536",
		"osName:\n                              type: string\n                              enum: [ubuntu]",
		"osVersion:\n                              type: string\n                              enum: [\"24.04\"]",
		"required: [virtualIPv4, port]",
		"required: [uuid, podCIDR, serviceCIDR, privateLoadBalancerPool]",
		"required: [start, stop]",
		"privateLoadBalancerPool must contain between 16 and 256 addresses",
		"privateLoadBalancerPool must not overlap podCIDR or serviceCIDR",
		"privateLoadBalancerPool is immutable",
		"control-plane virtualIPv4 must not overlap podCIDR or serviceCIDR",
		"component != \"rke2-cilium\"",
	} {
		if !strings.Contains(crd, required) {
			t.Errorf("CRD does not contain validation contract fragment %q", required)
		}
	}
}

func TestSourceAndPackagedInSpaceClusterCRDsAreByteIdentical(t *testing.T) {
	source, err := os.ReadFile("../../config/crd/bases/infrastructure.inspace.cloud_inspaceclusters.yaml")
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := os.ReadFile("../../../../charts/inspace-cloud-kube-modules-crds/templates/infrastructure.inspace.cloud_inspaceclusters.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, packaged) {
		t.Fatal("source and packaged InSpaceCluster CRDs differ")
	}
}

func validSpec() InSpaceClusterSpec {
	return InSpaceClusterSpec{
		Location:             "bkk01",
		BillingAccountID:     12345,
		CredentialsSecretRef: SecretKeyReference{Name: "inspace-api", Key: "apikey"},
		ControlPlane: ControlPlaneSpec{Replicas: 3, Machine: MachineSpec{
			VCPU: 4, MemoryMiB: 8192, RootDiskGiB: 60,
			HostPoolUUID: "aac7dd66-f390-4edd-80c0-dd7cae49bd99",
			Image:        ImageSpec{OSName: "ubuntu", OSVersion: "24.04"},
		}},
		RKE2: RKE2Spec{Version: "v1.35.6+rke2r1", TokenSecretRef: SecretKeyReference{Name: "token", Key: "token"}},
		Network: NetworkSpec{
			UUID: "11111111-2222-3333-4444-555555555555", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
			PrivateLoadBalancerPool: PrivateLoadBalancerPoolSpec{Start: "10.20.30.200", Stop: "10.20.30.239"},
		},
		Firewall:   FirewallSpec{Managed: true},
		PublicIPv4: PublicIPv4Spec{Managed: true},
		Endpoint:   ControlPlaneEndpoint{VirtualIPv4: "10.20.30.10", Port: 6443},
	}
}

func mustAddress(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

package v1alpha1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestControlPlaneReplicaValidation(t *testing.T) {
	for _, replicas := range []int32{1, 3} {
		spec := validSpec()
		spec.ControlPlane.Replicas = replicas
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("replicas %d: unexpected validation errors: %v", replicas, errs)
		}
	}
	for _, replicas := range []int32{0, 2, 4, 5, 7} {
		spec := validSpec()
		spec.ControlPlane.Replicas = replicas
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("replicas %d: expected validation error", replicas)
		}
	}
}

func TestClusterNameFitsFixedNodeHostnames(t *testing.T) {
	valid := []string{"a", "unit", strings.Repeat("a", 55)}
	for _, name := range valid {
		cluster := InSpaceCluster{Metadata: ObjectMeta{Name: name}, Spec: validSpec()}
		if errs := cluster.Validate(); len(errs) != 0 {
			t.Errorf("name %q: unexpected validation errors: %v", name, errs)
		}
	}
	if got := len(strings.Repeat("a", 55) + "-bastion"); got != 63 {
		t.Fatalf("maximum cluster name produces bastion hostname length %d, want 63", got)
	}
	for _, name := range []string{"", "UPPER", "contains.dot", "-leading", "trailing-", strings.Repeat("a", 56)} {
		cluster := InSpaceCluster{Metadata: ObjectMeta{Name: name}, Spec: validSpec()}
		errs := cluster.Validate()
		found := false
		for _, err := range errs {
			found = found || strings.HasPrefix(err.Error(), "metadata.name:")
		}
		if !found {
			t.Errorf("name %q: validation errors %v do not identify metadata.name", name, errs)
		}
	}
}

func TestRKE2VersionValidationRequiresExactRelease(t *testing.T) {
	for _, version := range []string{"v1.36.4+rke2r1", "v1.36.4+rke2r12", "v1.36.5+rke2r1"} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("version %q: unexpected validation errors: %v", version, errs)
		}
	}
	for _, version := range []string{
		"", "latest", "v1.35.6", "v1.35.6+rke2", "1.35.6+rke2r1", "v1.35+rke2r1",
		// Release candidates are never accepted.
		"v1.36.5-rc1+rke2r1", "v1.36.5-rc2+rke2r1", "v1.36.5-rc2+rke2r2", "v1.37.1-rc2+rke2r1", "v1.36.5-rc2", "v1.36.5+rke2r1x",
	} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("version %q: expected exact RKE2 release validation error", version)
		}
	}
}

func TestPersistedSpecValidationAlsoAcceptsReleasedCandidates(t *testing.T) {
	for _, version := range []string{"v1.36.4+rke2r1", "v1.36.5+rke2r1", "v1.36.5-rc2+rke2r1"} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.ValidatePersisted(); len(errs) != 0 {
			t.Errorf("persisted version %q: unexpected validation errors: %v", version, errs)
		}
	}
	// A new spec stays GA-only, and only released candidates are tolerated.
	spec := validSpec()
	spec.RKE2.Version = "v1.36.5-rc2+rke2r1"
	if errs := spec.Validate(); !validationFieldReported(errs, "spec.rke2.version") {
		t.Errorf("new spec naming a release candidate accepted: %v", errs)
	}
	for _, version := range []string{"v1.36.5-rc1+rke2r1", "v1.36.5-rc2+rke2r2", "v1.37.1-rc2+rke2r1", "v1.36.5-rc2", "v1.36.5-rc2+rke2r1x", ""} {
		spec := validSpec()
		spec.RKE2.Version = version
		if errs := spec.ValidatePersisted(); !validationFieldReported(errs, "spec.rke2.version") {
			t.Errorf("persisted version %q accepted: %v", version, errs)
		}
	}
}

func TestBootstrapCacheModesAreValid(t *testing.T) {
	for _, directDownload := range []bool{false, true} {
		spec := validSpec()
		spec.BootstrapCache.DirectDownload = directDownload
		if errs := spec.Validate(); len(errs) != 0 {
			t.Fatalf("directDownload=%t: unexpected validation errors: %v", directDownload, errs)
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
		`self.metadata.name.matches("^[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?$") || (oldSelf.hasValue() && self.metadata.name == oldSelf.value().metadata.name)`,
		"optionalOldSelf: true",
		"metadata.name must be a lowercase DNS label of at most 55 characters",
		"vcpu:\n                          type: integer\n                          format: int32\n                          minimum: 2\n                          maximum: 16",
		"memoryMiB:\n                          type: integer\n                          format: int32\n                          minimum: 4096\n                          maximum: 65536",
		"osName:\n                              type: string\n                              enum: [ubuntu]",
		"osVersion:\n                              type: string\n                              enum: [\"24.04\", \"26.04\"]",
		"required: [virtualIPv4, port]",
		"required: [uuid, podCIDR, serviceCIDR, privateLoadBalancerPool]",
		"required: [start, stop]",
		"privateLoadBalancerPool must contain between 16 and 256 addresses",
		"privateLoadBalancerPool must not overlap podCIDR or serviceCIDR",
		"privateLoadBalancerPool is immutable",
		"control-plane virtualIPv4 must not overlap podCIDR or serviceCIDR",
		"disable:\n                      type: array\n                      x-kubernetes-list-type: set\n                      maxItems:",
		"component != \"rke2-cilium\"",
		"required: [location, billingAccountID, credentialsSecretRef, controlPlane, bootstrapCache, rke2, network, firewall, publicIPv4, endpoint]",
		"bootstrapCache:\n                  type: object",
		"directDownload:\n                      type: boolean\n                      default: false",
		"skipOSUpgrade:\n                      type: boolean\n                      default: false",
		"replicas:\n                      type: integer\n                      format: int32\n                      enum:\n                        - 1\n                        - 3",
		"rule: self == oldSelf\n                          message: control-plane replica count is immutable after cluster creation",
		"gatewayAPI:\n                      type: object",
		// No CRD default: an omitted value must never be persisted as a new field.
		"enabled:\n                          type: boolean\n                firewall:",
		"rule: '(has(self.gatewayAPI) && self.gatewayAPI.enabled) == (has(oldSelf.gatewayAPI) && oldSelf.gatewayAPI.enabled)'",
		"message: gatewayAPI.enabled is fixed at cluster creation",
		`rule: '!has(self.network.gatewayAPI) || !self.network.gatewayAPI.enabled || (has(self.rke2.disable) && self.rke2.disable.exists(component, component == "rke2-traefik") && self.rke2.disable.exists(component, component == "rke2-traefik-crd"))'`,
		"message: network.gatewayAPI.enabled requires rke2.disable to include rke2-traefik and rke2-traefik-crd",
		`!self.rke2.disable.exists(component, component == "rke2-gateway-api-crd" || component == "inspace-gateway-api-crds")`,
		"message: network.gatewayAPI.enabled forbids disabling its CRD owner rke2-gateway-api-crd or inspace-gateway-api-crds",
	} {
		if !strings.Contains(crd, required) {
			t.Errorf("CRD does not contain validation contract fragment %q", required)
		}
	}
	if want := "pattern: '" + rke2VersionPattern.String() + "'"; strings.Count(crd, want) != 1 {
		t.Errorf("CRD RKE2 version pattern must equal the Go validator %q", want)
	}
	cacheStart := strings.Index(crd, "\n                bootstrapCache:")
	cacheEnd := strings.Index(crd[cacheStart+1:], "\n                rke2:")
	if cacheStart < 0 || cacheEnd < 0 {
		t.Fatal("CRD does not contain a bounded bootstrapCache schema")
	}
	cacheSchema := crd[cacheStart : cacheStart+1+cacheEnd]
	if strings.Contains(cacheSchema, "virtualIPv4") || strings.Contains(cacheSchema, "x-kubernetes-validations") {
		t.Fatalf("bootstrapCache schema must contain only the directDownload mode switch:\n%s", cacheSchema)
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
		BootstrapCache: BootstrapCacheSpec{},
		RKE2:           RKE2Spec{Version: "v1.36.5+rke2r1", TokenSecretRef: SecretKeyReference{Name: "token", Key: "token"}},
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

func TestGatewayAPIIsOptionalAndOmittedByDefault(t *testing.T) {
	spec := validSpec()
	if spec.Network.GatewayAPI.Enabled {
		t.Fatal("Gateway API must default to disabled")
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "gatewayAPI") {
		t.Fatalf("a default spec must serialize without gatewayAPI so persisted specs stay byte-stable:\n%s", data)
	}
	spec.Network.GatewayAPI.Enabled = true
	spec.RKE2.Version = "v1.36.5+rke2r1"
	spec.RKE2.Disable = []string{"rke2-ingress-nginx", "rke2-traefik"}
	data, err = json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"gatewayAPI":{"enabled":true}`) {
		t.Fatalf("an enabled spec must serialize network.gatewayAPI.enabled:\n%s", data)
	}
}

func TestGatewayAPIRequiresCilium120AndNoTraefikCRDs(t *testing.T) {
	enabled := func(version string, disable ...string) InSpaceClusterSpec {
		spec := validSpec()
		spec.Network.GatewayAPI.Enabled = true
		spec.RKE2.Version = version
		spec.RKE2.Disable = disable
		return spec
	}
	for _, version := range []string{
		"v1.34.12+rke2r1", "v1.35.9+rke2r1", "v1.36.5+rke2r1", "v1.36.12+rke2r2",
		"v1.37.0+rke2r1", "v1.38.1+rke2r1",
	} {
		if errs := enabled(version, "rke2-traefik", "rke2-traefik-crd").Validate(); len(errs) != 0 {
			t.Errorf("Gateway API on %s rejected: %v", version, errs)
		}
	}
	for _, version := range []string{"v1.33.9+rke2r1", "v1.34.11+rke2r1", "v1.35.8+rke2r1", "v1.36.4+rke2r1"} {
		errs := enabled(version, "rke2-traefik", "rke2-traefik-crd").Validate()
		if !validationFieldReported(errs, "spec.network.gatewayAPI.enabled") {
			t.Errorf("Gateway API on %s (bundled Cilium < 1.20) accepted: %v", version, errs)
		}
	}
	errs := enabled("v1.36.5+rke2r1", "rke2-ingress-nginx").Validate()
	if !validationFieldReported(errs, "spec.network.gatewayAPI.enabled") {
		t.Fatalf("Gateway API with the packaged Traefik Gateway API CRDs accepted: %v", errs)
	}
	// Disabling rke2-traefik alone still installs rke2-traefik-crd, whose bundled
	// Gateway API CRDs collide with ours and crash-loop its helm-install job
	// (seen live on v1.36.5-rc2 in the v1.1.0-rc.7 E2E).
	errs = enabled("v1.36.5+rke2r1", "rke2-traefik").Validate()
	if !validationFieldReported(errs, "spec.network.gatewayAPI.enabled") {
		t.Fatalf("Gateway API with rke2-traefik-crd enabled accepted: %v", errs)
	}
	for _, owner := range []string{"rke2-gateway-api-crd", "inspace-gateway-api-crds"} {
		errs := enabled("v1.37.0+rke2r1", "rke2-traefik", "rke2-traefik-crd", owner).Validate()
		if !validationFieldReported(errs, "spec.rke2.disable") {
			t.Errorf("Gateway API with its CRD owner %s disabled accepted: %v", owner, errs)
		}
	}
	disabled := validSpec()
	disabled.RKE2.Version = "v1.36.4+rke2r1"
	if errs := disabled.Validate(); len(errs) != 0 {
		t.Fatalf("disabled Gateway API must not constrain RKE2: %v", errs)
	}
}

// The Gateway API CEL rules scan spec.rke2.disable, so the list and its items
// are bounded for the Kubernetes CEL cost budget; Go enforces the same bounds.
func TestRKE2DisableListIsBounded(t *testing.T) {
	spec := validSpec()
	spec.RKE2.Disable = make([]string, MaxRKE2DisabledComponents)
	for index := range spec.RKE2.Disable {
		spec.RKE2.Disable[index] = strings.Repeat("a", MaxRKE2ComponentNameLength-3) + fmt.Sprintf("%03d", index)
	}
	if errs := spec.Validate(); len(errs) != 0 {
		t.Fatalf("maximum disable list rejected: %v", errs)
	}
	for name, disable := range map[string][]string{
		"too many":   append(append([]string(nil), spec.RKE2.Disable...), "rke2-extra"),
		"too long":   {strings.Repeat("a", MaxRKE2ComponentNameLength+1)},
		"empty name": {""},
	} {
		invalid := validSpec()
		invalid.RKE2.Disable = disable
		if !validationFieldReported(invalid.Validate(), "spec.rke2.disable") {
			t.Errorf("%s disable list accepted", name)
		}
	}
	crd, err := os.ReadFile("../../config/crd/bases/infrastructure.inspace.cloud_inspaceclusters.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("disable:\n                      type: array\n                      x-kubernetes-list-type: set\n                      maxItems: %d\n                      items:\n                        type: string\n                        minLength: 1\n                        maxLength: %d\n",
		MaxRKE2DisabledComponents, MaxRKE2ComponentNameLength)
	if !strings.Contains(string(crd), want) {
		t.Fatalf("CRD disable schema lacks the Go bounds:\n%s", want)
	}
}

func TestRKE2OwnsGatewayAPICRDsFromV137(t *testing.T) {
	for version, want := range map[string]bool{
		"v1.34.12+rke2r1": false, "v1.35.9+rke2r1": false, "v1.36.5+rke2r1": false, "v1.36.9+rke2r1": false,
		"v1.37.0+rke2r1": true, "v1.37.1+rke2r2": true, "v1.38.0+rke2r1": true, "": false, "latest": false,
	} {
		if got := RKE2BundlesGatewayAPICRDs(version); got != want {
			t.Errorf("RKE2BundlesGatewayAPICRDs(%q) = %t, want %t", version, got, want)
		}
	}
}

func validationFieldReported(errs []error, field string) bool {
	for _, err := range errs {
		if strings.HasPrefix(err.Error(), field+":") {
			return true
		}
	}
	return false
}

func TestControlPlaneImageAcceptsSupportedUbuntuReleases(t *testing.T) {
	for _, version := range []string{"24.04", "26.04"} {
		spec := validSpec()
		spec.ControlPlane.Machine.Image.OSVersion = version
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("Ubuntu %s rejected: %v", version, errs)
		}
	}
	for _, version := range []string{"22.04", "26.10", ""} {
		spec := validSpec()
		spec.ControlPlane.Machine.Image.OSVersion = version
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("unsupported Ubuntu %q accepted", version)
		}
	}
}

func TestLoadBalancerAlgorithmIsOptionalRandomOrMaglev(t *testing.T) {
	for _, algorithm := range []string{"", LoadBalancerAlgorithmRandom, LoadBalancerAlgorithmMaglev} {
		spec := validSpec()
		spec.Network.LoadBalancerAlgorithm = algorithm
		if errs := spec.Validate(); len(errs) != 0 {
			t.Errorf("loadBalancerAlgorithm %q rejected: %v", algorithm, errs)
		}
	}
	for _, algorithm := range []string{"Maglev", "MAGLEV", "round_robin", "least_request", " maglev", "maglev "} {
		spec := validSpec()
		spec.Network.LoadBalancerAlgorithm = algorithm
		if errs := spec.Validate(); len(errs) == 0 {
			t.Errorf("unsupported loadBalancerAlgorithm %q accepted", algorithm)
		}
	}
}

func TestLoadBalancerAlgorithmCRDIsOptionalEnumAndImmutable(t *testing.T) {
	data, err := os.ReadFile("../../config/crd/bases/infrastructure.inspace.cloud_inspaceclusters.yaml")
	if err != nil {
		t.Fatal(err)
	}
	crd := string(data)
	for _, required := range []string{
		"loadBalancerAlgorithm:\n                      type: string\n                      enum: [random, maglev]",
		"(has(self.loadBalancerAlgorithm) ? self.loadBalancerAlgorithm : '') == (has(oldSelf.loadBalancerAlgorithm) ? oldSelf.loadBalancerAlgorithm : '')",
		"loadBalancerAlgorithm is immutable after cluster creation",
		"serviceTopology:\n                      type: boolean",
		"(has(self.serviceTopology) && self.serviceTopology) == (has(oldSelf.serviceTopology) && oldSelf.serviceTopology)",
		"serviceTopology is immutable after cluster creation",
	} {
		if !strings.Contains(crd, required) {
			t.Errorf("CRD does not contain loadBalancerAlgorithm contract fragment %q", required)
		}
	}
	if !strings.Contains(crd, "required: [uuid, podCIDR, serviceCIDR, privateLoadBalancerPool]\n") {
		t.Fatal("loadBalancerAlgorithm and serviceTopology must stay optional so existing clusters keep Cilium's defaults")
	}
	topologyStart := strings.Index(crd, "\n                    serviceTopology:")
	topologyEnd := strings.Index(crd[topologyStart+1:], "\n                firewall:")
	if topologyStart < 0 || topologyEnd < 0 || strings.Contains(crd[topologyStart:topologyStart+1+topologyEnd], "default:") {
		t.Fatal("serviceTopology must have no CRD default; an omitted value must not be persisted as a new field")
	}
}

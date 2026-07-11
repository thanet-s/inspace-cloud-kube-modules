package v1alpha1

import "testing"

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
		K3s:        K3sSpec{Version: "v1.35.0+k3s1", TokenSecretRef: SecretKeyReference{Name: "token", Key: "token"}},
		Network:    NetworkSpec{UUID: "11111111-2222-3333-4444-555555555555", PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16"},
		Firewall:   FirewallSpec{Managed: true},
		PublicIPv4: PublicIPv4Spec{Managed: true},
		Endpoint:   ControlPlaneEndpoint{Host: "api.example.invalid", Port: 6443, Public: true},
	}
}

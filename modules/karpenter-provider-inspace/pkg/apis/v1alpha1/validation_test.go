package v1alpha1

import "testing"

func TestValidate(t *testing.T) {
	nodeClass := validNodeClass()
	if errs := nodeClass.Validate(); len(errs) != 0 {
		t.Fatalf("expected valid NodeClass, got %v", errs)
	}

	nodeClass.Spec.Location = "hkg01"
	nodeClass.Spec.RootDiskGiB = 20
	nodeClass.Spec.HostPoolSelector.Class = "unknown"
	nodeClass.Spec.K3s.Server = "http://cluster.example:6443/path"
	if errs := nodeClass.Validate(); len(errs) != 4 {
		t.Fatalf("expected four independent errors, got %d: %v", len(errs), errs)
	}
}

func TestHostPoolSelectorUUID(t *testing.T) {
	tests := map[string]string{
		HostClassIntelScalable: IntelScalableHostPoolUUID,
		HostClassAMDEPYC:       AMDEPYCHostPoolUUID,
	}
	for class, expected := range tests {
		actual, ok := (HostPoolSelector{Class: class}).UUID()
		if !ok || actual != expected {
			t.Fatalf("class %q resolved to %q, %t; expected %q", class, actual, ok, expected)
		}
	}
}

func TestValidateRejectsCloudAPICredentialAsAgentToken(t *testing.T) {
	nodeClass := validNodeClass()
	nodeClass.Spec.K3s.TokenSecretRef = SecretKeySelector{Name: "inspace-api", Key: "token"}
	if errs := nodeClass.Validate(); len(errs) != 1 || errs[0].Field != "spec.k3s.tokenSecretRef.name" {
		t.Fatalf("expected dedicated agent-token Secret rejection, got %v", errs)
	}
}

func validNodeClass() *InSpaceNodeClass {
	return &InSpaceNodeClass{Spec: InSpaceNodeClassSpec{
		ClusterName:       "test-cluster",
		BillingAccountID:  1,
		Location:          LocationBangkok,
		NetworkUUID:       "11111111-1111-4111-8111-111111111111",
		ReservePublicIPv4: true,
		FirewallUUID:      "22222222-2222-4222-8222-222222222222",
		ImageSelector:     ImageSelector{OSName: OSNameUbuntu, OSVersion: OSVersionUbuntu},
		RootDiskGiB:       40,
		HostPoolSelector:  HostPoolSelector{Class: HostClassIntelScalable},
		K3s: K3sConfig{
			Version:        "v1.35.6+k3s1",
			Server:         "https://api.test.example:6443",
			TokenSecretRef: SecretKeySelector{Name: K3sAgentTokenSecretName, Key: K3sAgentTokenSecretKey},
		},
	}}
}

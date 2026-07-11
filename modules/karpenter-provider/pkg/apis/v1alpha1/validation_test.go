package v1alpha1

import "testing"

const validTestSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test@example"

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

func TestValidateSSHAccess(t *testing.T) {
	tests := map[string]struct {
		username  string
		publicKey string
		wantError bool
	}{
		"disabled":              {},
		"valid":                 {username: "inspacee2e", publicKey: validTestSSHPublicKey},
		"max username length":   {username: "a12345678901234567890123456789", publicKey: validTestSSHPublicKey},
		"missing username":      {publicKey: validTestSSHPublicKey, wantError: true},
		"missing public key":    {username: "inspacee2e", wantError: true},
		"invalid username":      {username: "Bad User", publicKey: validTestSSHPublicKey, wantError: true},
		"username too long":     {username: "a123456789012345678901234567890", publicKey: validTestSSHPublicKey, wantError: true},
		"multiple lines":        {username: "inspacee2e", publicKey: validTestSSHPublicKey + "\n" + validTestSSHPublicKey, wantError: true},
		"key options":           {username: "inspacee2e", publicKey: "from=\"192.0.2.1\" " + validTestSSHPublicKey, wantError: true},
		"unsupported algorithm": {username: "inspacee2e", publicKey: "ssh-dss AAAA", wantError: true},
		"invalid base64":        {username: "inspacee2e", publicKey: "ssh-ed25519 not-base64", wantError: true},
		"mismatched prefix":     {username: "inspacee2e", publicKey: "ssh-rsa " + validTestSSHPublicKey[len("ssh-ed25519 "):], wantError: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateSSHAccess(test.username, test.publicKey)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateSSHAccess() error = %v, wantError = %t", err, test.wantError)
			}
		})
	}
}

func TestNodeClassValidationAcceptsPairedSSHAccess(t *testing.T) {
	nodeClass := validNodeClass()
	nodeClass.Spec.SSHUsername = "inspacee2e"
	nodeClass.Spec.SSHPublicKey = validTestSSHPublicKey
	if errs := nodeClass.Validate(); len(errs) != 0 {
		t.Fatalf("expected valid SSH access, got %v", errs)
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

package v1alpha1

import (
	"strings"
	"testing"
)

const validTestSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test@example"

func TestValidate(t *testing.T) {
	nodeClass := validNodeClass()
	if errs := nodeClass.Validate(); len(errs) != 0 {
		t.Fatalf("expected valid NodeClass, got %v", errs)
	}

	nodeClass.Spec.Location = "hkg01"
	nodeClass.Spec.RootDiskGiB = 20
	nodeClass.Spec.HostPoolSelector.Class = "unknown"
	nodeClass.Spec.RKE2.Server = "http://cluster.example:9345/path"
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
	nodeClass.Spec.RKE2.TokenSecretRef = SecretKeySelector{Name: "inspace-api", Key: "token"}
	if errs := nodeClass.Validate(); len(errs) != 1 || errs[0].Field != "spec.rke2.tokenSecretRef.name" {
		t.Fatalf("expected dedicated agent-token Secret rejection, got %v", errs)
	}
}

func TestValidateRejectsLegacyK3sBootstrapContract(t *testing.T) {
	nodeClass := validNodeClass()
	nodeClass.Spec.RKE2.Version = "v1.35.6+k3s1"
	nodeClass.Spec.RKE2.Server = "https://api.test.example:6443"
	nodeClass.Spec.RKE2.TokenSecretRef.Name = "inspace-k3s-agent-token"
	errs := nodeClass.Validate()
	if len(errs) != 3 {
		t.Fatalf("expected version, supervisor endpoint, and token errors, got %v", errs)
	}
	wantFields := map[string]bool{
		"spec.rke2.version":             false,
		"spec.rke2.server":              false,
		"spec.rke2.tokenSecretRef.name": false,
	}
	for _, err := range errs {
		if _, ok := wantFields[err.Field]; ok {
			wantFields[err.Field] = true
		}
	}
	for fieldName, found := range wantFields {
		if !found {
			t.Errorf("missing validation error for %s: %v", fieldName, errs)
		}
	}
}

func TestValidateRequiresLiteralPrivateSupervisorVIP(t *testing.T) {
	tests := map[string]string{
		"DNS name":        "https://registration.example:9345",
		"public IPv4":     "https://203.0.113.10:9345",
		"IPv6":            "https://[fd00::10]:9345",
		"Cilium pod CIDR": "https://10.42.1.10:9345",
		"Service CIDR":    "https://10.43.1.10:9345",
		"wrong port":      "https://10.0.0.10:6443",
		"path":            "https://10.0.0.10:9345/join",
		"empty fragment":  "https://10.0.0.10:9345#",
	}
	for name, server := range tests {
		t.Run(name, func(t *testing.T) {
			nodeClass := validNodeClass()
			nodeClass.Spec.RKE2.Server = server
			errs := nodeClass.Validate()
			if len(errs) != 1 || errs[0].Field != "spec.rke2.server" {
				t.Fatalf("server %q validation errors = %v, want one server error", server, errs)
			}
		})
	}
}

func TestValidateRejectsServicePoolOutsideSizeContract(t *testing.T) {
	nodeClass := validNodeClass()
	nodeClass.Spec.PrivateLoadBalancerPool.Stop = "10.0.0.214"
	errs := nodeClass.Validate()
	if len(errs) != 1 || errs[0].Field != "spec.privateLoadBalancerPool" || !strings.Contains(errs[0].Detail, "minimum is 16") {
		t.Fatalf("private Service pool validation errors = %v, want minimum-size field error", errs)
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
		ClusterName:             "test-cluster",
		BillingAccountID:        1,
		Location:                LocationBangkok,
		NetworkUUID:             "11111111-1111-4111-8111-111111111111",
		PrivateLoadBalancerPool: PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"},
		ReservePublicIPv4:       true,
		FirewallUUID:            "22222222-2222-4222-8222-222222222222",
		ImageSelector:           ImageSelector{OSName: OSNameUbuntu, OSVersion: OSVersionUbuntu},
		RootDiskGiB:             40,
		HostPoolSelector:        HostPoolSelector{Class: HostClassIntelScalable},
		RKE2: RKE2Config{
			Version:        "v1.35.6+rke2r1",
			Server:         "https://10.0.0.10:9345",
			TokenSecretRef: SecretKeySelector{Name: RKE2AgentTokenSecretName, Key: RKE2AgentTokenSecretKey},
		},
	}}
}

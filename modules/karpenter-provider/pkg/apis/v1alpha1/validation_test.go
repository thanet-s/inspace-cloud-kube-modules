package v1alpha1

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

const validTestSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test@example"

func TestValidate(t *testing.T) {
	nodeClass := validNodeClass()
	if errs := nodeClass.Validate(); len(errs) != 0 {
		t.Fatalf("expected valid NodeClass, got %v", errs)
	}

	nodeClass.Spec.Location = "hkg01"
	nodeClass.Spec.RootDiskGiB = 20
	nodeClass.Spec.RKE2.Server = "http://cluster.example:9345/path"
	if errs := nodeClass.Validate(); len(errs) != 3 {
		t.Fatalf("expected three independent errors, got %d: %v", len(errs), errs)
	}
}

func TestHostPoolUUIDForClass(t *testing.T) {
	tests := map[string]string{
		HostClassIntelScalable: IntelScalableHostPoolUUID,
		HostClassAMDEPYC:       AMDEPYCHostPoolUUID,
	}
	for class, expected := range tests {
		actual, ok := HostPoolUUIDForClass(class)
		if !ok || actual != expected {
			t.Fatalf("class %q resolved to %q, %t; expected %q", class, actual, ok, expected)
		}
	}
	if actual, ok := HostPoolUUIDForClass("future"); ok || actual != "" {
		t.Fatalf("unknown class resolved to %q, %t", actual, ok)
	}
}

func TestFirewallProfileDefaultsAndValidation(t *testing.T) {
	if got := EffectiveFirewallProfile(""); got != FirewallProfilePrivateWorker {
		t.Fatalf("EffectiveFirewallProfile(empty) = %q, want %q", got, FirewallProfilePrivateWorker)
	}
	for _, profile := range []FirewallProfile{"", FirewallProfilePrivateWorker, FirewallProfilePublicNodeLoadBalancer} {
		nodeClass := validNodeClass()
		nodeClass.Spec.FirewallProfile = profile
		if errs := nodeClass.Validate(); len(errs) != 0 {
			t.Fatalf("firewall profile %q validation errors = %v", profile, errs)
		}
		if got := nodeClass.Spec.EffectiveFirewallProfile(); got == "" {
			t.Fatalf("effective firewall profile is empty for %q", profile)
		}
	}
	nodeClass := validNodeClass()
	nodeClass.Spec.FirewallProfile = "future-profile"
	errs := nodeClass.Validate()
	if len(errs) != 1 || errs[0].Field != "spec.firewallProfile" {
		t.Fatalf("invalid firewall profile errors = %v, want one firewallProfile error", errs)
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

func TestValidateBootstrapCacheModes(t *testing.T) {
	caBundle := testBootstrapCacheCA(t)
	tests := map[string]struct {
		cache     BootstrapCacheSpec
		wantError string
	}{
		"private cache": {
			cache: BootstrapCacheSpec{Address: "10.20.30.20", CABundle: caBundle},
		},
		"direct download": {
			cache: BootstrapCacheSpec{DirectDownload: true},
		},
		"cache missing address": {
			cache: BootstrapCacheSpec{CABundle: caBundle}, wantError: "address",
		},
		"cache public address": {
			cache: BootstrapCacheSpec{Address: "203.0.113.10", CABundle: caBundle}, wantError: "RFC1918",
		},
		"cache noncanonical address": {
			cache: BootstrapCacheSpec{Address: "10.020.30.20", CABundle: caBundle}, wantError: "canonical",
		},
		"cache invalid PEM": {
			cache: BootstrapCacheSpec{Address: "10.20.30.20", CABundle: "not a certificate"}, wantError: "PEM",
		},
		"cache PEM with leading garbage": {
			cache: BootstrapCacheSpec{Address: "10.20.30.20", CABundle: "garbage\n" + caBundle}, wantError: "only PEM",
		},
		"cache non-CA certificate": {
			cache: BootstrapCacheSpec{Address: "10.20.30.20", CABundle: testCertificate(t, false)}, wantError: "not a CA",
		},
		"direct address ambiguity": {
			cache: BootstrapCacheSpec{DirectDownload: true, Address: "10.20.30.20"}, wantError: "requires address and caBundle to be empty",
		},
		"direct CA ambiguity": {
			cache: BootstrapCacheSpec{DirectDownload: true, CABundle: caBundle}, wantError: "requires address and caBundle to be empty",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateBootstrapCache(test.cache)
			if test.wantError == "" && err != nil {
				t.Fatalf("ValidateBootstrapCache() error = %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("ValidateBootstrapCache() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestBootstrapCacheEndpointIsDeterministic(t *testing.T) {
	if got := BootstrapCacheHost("test-cluster"); got != "cache.test-cluster.inspace.internal" {
		t.Fatalf("BootstrapCacheHost() = %q", got)
	}
	if got := BootstrapCacheRegistry("test-cluster"); got != "cache.test-cluster.inspace.internal:8443" {
		t.Fatalf("BootstrapCacheRegistry() = %q", got)
	}
	if got := BootstrapCacheHealthURL("test-cluster"); got != "https://cache.test-cluster.inspace.internal:8443/healthz" {
		t.Fatalf("BootstrapCacheHealthURL() = %q", got)
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
		RKE2: RKE2Config{
			Version:        "v1.35.6+rke2r1",
			Server:         "https://10.0.0.10:9345",
			TokenSecretRef: SecretKeySelector{Name: RKE2AgentTokenSecretName, Key: RKE2AgentTokenSecretKey},
		},
		BootstrapCache: BootstrapCacheSpec{DirectDownload: true},
	}}
}

func testBootstrapCacheCA(t *testing.T) string {
	t.Helper()
	return testCertificate(t, true)
}

func testCertificate(t *testing.T, isCA bool) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "InSpace bootstrap cache test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

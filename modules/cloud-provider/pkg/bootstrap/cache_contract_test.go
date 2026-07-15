package bootstrap

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCacheTLSContractIsStableP256AndBoundToPersistedInputs(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	owner := "default/unit:4d7ca80d"
	hostname := "cache.unit.inspace.internal"
	// A leap-day start proves expiry uses calendar years rather than a fixed
	// 365-day duration.
	notBefore := time.Date(2028, time.February, 29, 12, 34, 56, 0, time.UTC)

	first, err := deriveCacheTLS(key, owner, hostname, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveCacheTLS(key, owner, hostname, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("identical persisted cache inputs produced different certificate bytes")
	}

	ca := cacheContractCertificate(t, first.CACertificate)
	server := cacheContractCertificate(t, first.ServerCertificate)
	if ca.NotBefore != notBefore || server.NotBefore != notBefore {
		t.Fatalf("certificate NotBefore changed: CA=%s server=%s want=%s", ca.NotBefore, server.NotBefore, notBefore)
	}
	wantNotAfter := time.Date(2043, time.March, 1, 12, 34, 56, 0, time.UTC)
	if ca.NotAfter != wantNotAfter || server.NotAfter != wantNotAfter || wantNotAfter != notBefore.AddDate(15, 0, 0) {
		t.Fatalf("certificate expiry is not exactly 15 calendar years: CA=%s server=%s want=%s", ca.NotAfter, server.NotAfter, wantNotAfter)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("unexpected CA contract: IsCA=%t basicConstraints=%t signature=%s", ca.IsCA, ca.BasicConstraintsValid, ca.SignatureAlgorithm)
	}
	if server.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(server.DNSNames) != 1 || server.DNSNames[0] != hostname {
		t.Fatalf("unexpected server certificate contract: signature=%s DNSNames=%v", server.SignatureAlgorithm, server.DNSNames)
	}
	for name, certificate := range map[string]*x509.Certificate{"CA": ca, "server": server} {
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve.Params().Name != "P-256" {
			t.Fatalf("%s certificate key=%T, want ECDSA P-256", name, certificate.PublicKey)
		}
	}

	expectedCAKey := deriveP256Key(cacheContractTLSSeed(key, owner, hostname, notBefore, "ca-key"))
	if !expectedCAKey.PublicKey.Equal(ca.PublicKey) {
		t.Fatal("CA certificate public key does not match the key derived from persisted inputs")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CA is not self-signed by its derived key: %v", err)
	}
	if err := server.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("server certificate is not signed by the derived CA: %v", err)
	}
	if err := server.VerifyHostname(hostname); err != nil {
		t.Fatalf("server certificate does not cover stable cache hostname: %v", err)
	}

	keyBlock, rest := pem.Decode([]byte(first.ServerPrivateKey))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		t.Fatal("server key is not exactly one PKCS#8 PEM block")
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := privateKeyValue.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve.Params().Name != "P-256" || !privateKey.PublicKey.Equal(server.PublicKey) {
		t.Fatalf("server private key %T does not match the ECDSA P-256 certificate", privateKeyValue)
	}

	changedKey := append([]byte(nil), key...)
	changedKey[0] ^= 0xff
	changes := []struct {
		name      string
		key       []byte
		owner     string
		hostname  string
		notBefore time.Time
	}{
		{name: "key", key: changedKey, owner: owner, hostname: hostname, notBefore: notBefore},
		{name: "owner", key: key, owner: owner + "-other", hostname: hostname, notBefore: notBefore},
		{name: "hostname", key: key, owner: owner, hostname: "cache.other.inspace.internal", notBefore: notBefore},
		{name: "notBefore", key: key, owner: owner, hostname: hostname, notBefore: notBefore.Add(time.Second)},
	}
	for _, change := range changes {
		t.Run("changes-with-"+change.name, func(t *testing.T) {
			material, err := deriveCacheTLS(change.key, change.owner, change.hostname, change.notBefore)
			if err != nil {
				t.Fatal(err)
			}
			if material == first {
				t.Fatalf("changing %s did not change derived cache TLS bytes", change.name)
			}
		})
	}
}

func TestCacheImageManifestContainsExactlyAuditedThirtyFourImages(t *testing.T) {
	const moduleVersion = "0.3.1-rc.2"
	manifest, err := renderCacheImageManifest(bootstrapCacheRKE2Version, moduleVersion, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(manifest, "\n"), "\n")
	if len(lines) != 34 || len(rke2CacheImages) != 26 || len(fixedCacheImages) != 5 {
		t.Fatalf("cache inventory counts: manifest=%d RKE2=%d fixed=%d, want 34/26/5", len(lines), len(rke2CacheImages), len(fixedCacheImages))
	}

	sources := make(map[string]struct{}, len(lines))
	targets := make(map[string]struct{}, len(lines))
	moduleTargets := 0
	for index, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			t.Fatalf("manifest line %d is not source<TAB>target: %q", index+1, line)
		}
		if _, duplicate := sources[fields[0]]; duplicate {
			t.Fatalf("duplicate source in cache manifest: %s", fields[0])
		}
		if _, duplicate := targets[fields[1]]; duplicate {
			t.Fatalf("duplicate target in cache manifest: %s", fields[1])
		}
		sources[fields[0]] = struct{}{}
		targets[fields[1]] = struct{}{}
		if strings.HasPrefix(fields[0], "docker://ghcr.io/thanet-s/") {
			moduleTargets++
			if !strings.HasSuffix(fields[0], ":"+moduleVersion) || !strings.HasSuffix(fields[1], ":"+moduleVersion) {
				t.Fatalf("module image is not exact-versioned: %q", line)
			}
		} else if !strings.Contains(fields[0], "@sha256:") {
			t.Fatalf("non-module source is not digest-pinned: %s", fields[0])
		}
		if strings.Contains(line, ":latest") {
			t.Fatalf("mutable latest tag entered cache inventory: %q", line)
		}
	}
	if moduleTargets != 3 {
		t.Fatalf("module image count=%d, want 3", moduleTargets)
	}
}

func TestCacheImageManifestExcludesDisabledRKE2Ingress(t *testing.T) {
	manifest, err := renderCacheImageManifest(bootstrapCacheRKE2Version, "0.4.1-rc.2", []string{"rke2-ingress-nginx"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(manifest, "\n"), "\n")
	if len(lines) != 32 {
		t.Fatalf("disabled-ingress cache manifest entries=%d, want 32", len(lines))
	}
	for _, forbidden := range []string{"rancher/kube-webhook-certgen:", "rancher/nginx-ingress-controller:"} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("disabled ingress cache manifest retains %q", forbidden)
		}
	}
}

func TestCacheBastionCloudInitIsPrivateBoundedAndReadOnly(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS(key, "default/unit:4d7ca80d", hostname, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
		NodeName: "unit-bastion", PrivateSubnet: "10.20.30.0/24", CacheHostname: hostname,
		RKE2Version: bootstrapCacheRKE2Version, ModuleVersion: "0.3.1-rc.2",
		CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := cacheContractDecodeCloudInit(t, raw)
	for _, path := range []string{
		"/usr/local/sbin/inspace-bootstrap-cache-bastion",
		"/usr/local/sbin/inspace-cache-start",
		"/usr/local/sbin/inspace-cache-maintain",
	} {
		file, ok := files[path]
		if !ok {
			t.Fatalf("cache cloud-init omitted script %s", path)
		}
		command := exec.Command("sh", "-n")
		command.Stdin = strings.NewReader(file.Content)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s is not valid POSIX shell: %v: %s", path, err, output)
		}
	}

	bootstrapScript := files["/usr/local/sbin/inspace-bootstrap-cache-bastion"].Content
	startScript := files["/usr/local/sbin/inspace-cache-start"].Content
	maintenanceScript := files["/usr/local/sbin/inspace-cache-maintain"].Content
	nginx := files["/etc/inspace-cache/nginx.conf"].Content
	compose := files["/opt/inspace-cache/compose.yaml"].Content
	registry := files["/etc/inspace-cache/registry.yml"].Content
	dockerDaemon := files["/etc/docker/daemon.json"].Content

	paths := make([]string, 0, len(files))
	var decoded strings.Builder
	for path, file := range files {
		paths = append(paths, path)
		decoded.WriteString(path)
		decoded.WriteByte('\n')
		decoded.WriteString(file.Content)
		decoded.WriteByte('\n')
	}
	sort.Strings(paths)
	all := strings.ToLower(decoded.String())
	for _, forbidden := range []string{"cache_vip", "cache-vip", "virtualipv4", "virtual_ipv4", "arping", "keepalived", "ip addr add", "ip address add"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("cache bastion unexpectedly contains VIP ownership primitive %q", forbidden)
		}
	}
	for _, path := range paths {
		if strings.Contains(strings.ToLower(path), "vip") {
			t.Fatalf("cache cloud-init creates a VIP-related file or service: %s", path)
		}
	}

	for _, required := range []string{
		`listen __PRIVATE_IP__:8443 ssl;`,
		`limit_except GET HEAD { deny all; }`,
		`client_body_temp_path /tmp/client_temp;`,
		`proxy_temp_path /tmp/proxy_temp;`,
		`fastcgi_temp_path /tmp/fastcgi_temp;`,
		`uwsgi_temp_path /tmp/uwsgi_temp;`,
		`scgi_temp_path /tmp/scgi_temp;`,
		`auth_request /registry-health;`,
		`location = /registry-health {`,
		`proxy_pass http://127.0.0.1:5000/v2/;`,
	} {
		if !strings.Contains(nginx, required) {
			t.Errorf("NGINX cache config lacks %q", required)
		}
	}
	if strings.Count(nginx, `limit_except GET HEAD { deny all; }`) != 2 || strings.Contains(nginx, "listen 0.0.0.0") {
		t.Fatalf("NGINX is not GET/HEAD-only and private-address-bound:\n%s", nginx)
	}
	for _, required := range []string{
		`node_name='unit-bastion'`,
		`printf '127.0.1.1\t%s\n' "$node_name" >>/etc/hosts`,
		`getent hosts "$node_name" | grep -Eq '^127\.0\.1\.1[[:space:]]'`,
		`hostname_attempt=$((hostname_attempt + 1))`,
		`[ "$hostname_attempt" -ge 30 ]`,
		`generated hostname did not resolve to 127.0.1.1`,
		`ip -o -4 addr show to "$vpc_subnet" scope global`,
		`sed -i "s/__PRIVATE_IP__/$private_ip/g" /etc/inspace-cache/nginx.conf`,
		`printf '%s %s\n' "$private_ip" "$cache_hostname" >>/etc/hosts`,
		`getent ahostsv4 "$cache_hostname"`,
		hostname,
		"https://download.docker.com/linux/ubuntu/gpg",
		"https://download.docker.com/linux/ubuntu %s stable",
		"9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
		"docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
		"fallocate -l 10000000000",
		`test "$(stat -c %s "$cache_image")" = 10000000000`,
		"/var/lib/inspace/bootstrap-cache/containerd /var/lib/containerd none bind",
	} {
		if !strings.Contains(bootstrapScript, required) {
			t.Errorf("cache bastion bootstrap lacks %q", required)
		}
	}
	if BootstrapCacheDiskBytes != 10_000_000_000 || strings.Contains(bootstrapScript, "get.docker.com") {
		t.Fatalf("cache disk or Docker repository contract changed: disk=%d", BootstrapCacheDiskBytes)
	}
	if !strings.Contains(dockerDaemon, `"data-root": "/var/lib/inspace/bootstrap-cache/docker"`) ||
		!strings.Contains(compose, "/var/lib/inspace/bootstrap-cache/registry:/var/lib/registry") ||
		strings.Count(compose, "read_only: true") != 2 ||
		!strings.Contains(compose, `REGISTRY_STORAGE_MAINTENANCE_READONLY: "{enabled: ${REGISTRY_READONLY:-true}}"`) ||
		strings.Contains(compose, "REGISTRY_STORAGE_MAINTENANCE_READONLY_ENABLED") ||
		strings.Contains(compose, "REGISTRY_CONFIGURATION_PATH") ||
		!strings.Contains(registry, "delete:\n    enabled: false") ||
		!strings.Contains(registry, "readonly:\n      enabled: true") {
		t.Fatalf("Docker/registry content is not bounded inside the cache image or read-only:\ndaemon=%s\ncompose=%s\nregistry=%s", dockerDaemon, compose, registry)
	}
	if !strings.Contains(startScript, "compose_up false registry") ||
		!strings.Contains(startScript, "compose_up true --force-recreate registry nginx") ||
		!strings.Contains(startScript, `test "$attempt" -lt 9`) {
		t.Fatalf("registry seed/read-only transition is absent:\n%s", startScript)
	}
	if BootstrapCacheMinFree != 1_000_000_000 ||
		!strings.Contains(startScript, `test "$available" -ge 1000000000`) ||
		!strings.Contains(maintenanceScript, `if [ "$available" -lt 1000000000 ]; then`) {
		t.Fatalf("one-gigabyte free-space reserve changed: constant=%d", BootstrapCacheMinFree)
	}
}

func TestControlPlaneCloudInitUsesPrivateCacheOrDirectUpstreamExclusively(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS(key, "default/unit:4d7ca80d", hostname, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	input := cacheContractControlPlaneInput()
	input.BootstrapCache = &NodeCacheConfig{Address: "10.20.30.21", Hostname: hostname, CABundle: material.CACertificate}
	cachedRaw, err := RenderCloudInitJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	cached := cacheContractDecodeCloudInit(t, cachedRaw)
	cachedScript := cached["/usr/local/sbin/inspace-bootstrap-rke2"].Content
	cachedConfig := cached["/var/lib/inspace/rke2-config"].Content
	cachedKubeVIP := cached["/var/lib/inspace/rke2-kube-vip"].Content
	cachedRegistries := cached["/etc/rancher/rke2/registries.yaml"].Content
	for _, required := range []string{
		`system-default-registry: "cache.unit.inspace.internal:8443"`,
		`https://cache.unit.inspace.internal:8443/rke2/v1.35.6+rke2r1`,
		`cache_address='10.20.30.21'`,
		`cache_hostname='cache.unit.inspace.internal'`,
		`printf '%s %s # inspace-bootstrap-cache\n' "$cache_address" "$cache_hostname" >>/etc/hosts`,
		`'https://cache.unit.inspace.internal:8443'/healthz`,
	} {
		if !strings.Contains(cachedConfig+cachedScript, required) {
			t.Errorf("cached control-plane cloud-init lacks %q", required)
		}
	}
	if cached["/etc/rancher/rke2/bootstrap-cache-ca.crt"].Content != material.CACertificate {
		t.Fatal("cached control-plane did not receive the derived public CA")
	}
	if !strings.Contains(cachedRegistries, `"cache.unit.inspace.internal:8443"`) ||
		!strings.Contains(cachedRegistries, "ca_file: /etc/rancher/rke2/bootstrap-cache-ca.crt") ||
		strings.Contains(cachedRegistries, "mirrors:") || strings.Contains(cachedRegistries, "ghcr.io") || strings.Contains(cachedRegistries, "registry.k8s.io") {
		t.Fatalf("cached registries.yaml violates the single private-registry contract:\n%s", cachedRegistries)
	}
	if !strings.Contains(cachedKubeVIP, "cache.unit.inspace.internal:8443/"+cachedKubeVIPImage) ||
		strings.Contains(cachedScript, "github.com/rancher/rke2/releases") {
		t.Fatalf("cached control-plane still uses an upstream bootstrap artifact:\nscript=%s\nkube-vip=%s", cachedScript, cachedKubeVIP)
	}
	cacheContractAssertShell(t, cachedScript)

	directInput := cacheContractControlPlaneInput()
	directRaw, err := RenderCloudInitJSON(directInput)
	if err != nil {
		t.Fatal(err)
	}
	direct := cacheContractDecodeCloudInit(t, directRaw)
	directScript := direct["/usr/local/sbin/inspace-bootstrap-rke2"].Content
	if _, found := direct["/etc/rancher/rke2/bootstrap-cache-ca.crt"]; found {
		t.Fatal("direct mode wrote a bootstrap cache CA")
	}
	if _, found := direct["/etc/rancher/rke2/registries.yaml"]; found {
		t.Fatal("direct mode wrote a private registry configuration")
	}
	if strings.Contains(direct["/var/lib/inspace/rke2-config"].Content, "system-default-registry") ||
		strings.Contains(directScript, ".inspace.internal") ||
		!strings.Contains(directScript, "https://github.com/rancher/rke2/releases/download/v1.35.6+rke2r1") ||
		!strings.Contains(direct["/var/lib/inspace/rke2-kube-vip"].Content, kubeVIPImage) {
		t.Fatalf("direct control-plane mode no longer uses exact upstream artifacts:\n%s", directScript)
	}
	cacheContractAssertShell(t, directScript)
}

func TestDirectControlPlaneCloudInitV7OwnershipBytes(t *testing.T) {
	raw, err := RenderCloudInitJSON(cacheContractControlPlaneInput())
	if err != nil {
		t.Fatal(err)
	}
	const v7DirectHash = "0e7f5739fbc75d0afe171840dc3e1a11dc276d11dc9675420ab77fa8531c2bd8"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(raw))); got != v7DirectHash {
		t.Fatalf("direct control-plane cloud-init hash=%s, want frozen v7 hash %s", got, v7DirectHash)
	}
}

type cacheContractDecodedFile struct {
	Content     string
	Permissions string
	Encoding    string
	Owner       string
}

func cacheContractDecodeCloudInit(t *testing.T, raw string) map[string]cacheContractDecodedFile {
	t.Helper()
	var payload struct {
		WriteFiles []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		} `json:"write_files"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	result := make(map[string]cacheContractDecodedFile, len(payload.WriteFiles))
	for _, file := range payload.WriteFiles {
		content, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			t.Fatalf("decode %s: %v", file.Path, err)
		}
		if _, duplicate := result[file.Path]; duplicate {
			t.Fatalf("duplicate cloud-init file %s", file.Path)
		}
		result[file.Path] = cacheContractDecodedFile{Content: string(content), Permissions: file.Permissions, Encoding: file.Encoding, Owner: file.Owner}
	}
	return result
}

func cacheContractCertificate(t *testing.T, value string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		t.Fatal("value is not exactly one certificate PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func cacheContractTLSSeed(key []byte, owner, hostname string, notBefore time.Time, label string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("inspace-bootstrap-cache-pki/v1\x00" + owner + "\x00" + hostname + "\x00" + notBefore.Format(time.RFC3339) + "\x00" + label))
	return mac.Sum(nil)
}

func cacheContractControlPlaneInput() CloudInitInput {
	return CloudInitInput{
		NodeName: "unit-cp0", PrivateSubnet: "10.20.30.0/24", VirtualIPv4: "10.20.30.10",
		RKE2Version: bootstrapCacheRKE2Version, RKE2Token: "unit-test-token", Initialize: true,
		PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
		PrivateLoadBalancerPoolStart: "10.20.30.200", PrivateLoadBalancerPoolStop: "10.20.30.239",
		TLSSubjectAltNames: []string{"10.20.30.10"}, Disable: []string{"rke2-ingress-nginx"},
	}
}

func cacheContractAssertShell(t *testing.T, script string) {
	t.Helper()
	command := exec.Command("sh", "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invalid generated shell: %v: %s", err, output)
	}
}

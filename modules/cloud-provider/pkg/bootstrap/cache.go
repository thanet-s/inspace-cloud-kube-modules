package bootstrap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	BootstrapCachePort      = 8443
	BootstrapCacheDiskBytes = 10_000_000_000
	BootstrapCacheMinFree   = 1_000_000_000

	bootstrapCacheRKE2Version = "v1.36.4+rke2r1"
	bootstrapCacheRKE2SHA256  = "7bcbd3167d6947e1d79cdf722acdc740b28021fefb50dd5b974a1980776d4079"

	cacheNginxImage    = "docker.io/library/nginx:1.30.1-alpine@sha256:c819f83c54b0361f5557601bf5eb4943d09360e7a7fdf426afc466570f45874d"
	cacheRegistryImage = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"

	cachedKubeVIPImage = "kube-vip/kube-vip:v1.2.1@sha256:44035f68040c9eb99103c65f1f9ab9698d93f9f272110825705338ac1926f3d9"
)

var (
	moduleVersionPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	imageDigestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	bootstrapCacheHostPattern = regexp.MustCompile(`^cache\.[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?\.inspace\.internal$`)
)

var moduleImageNames = []string{
	"inspace-cloud-controller-manager",
	"inspace-csi-driver",
	"karpenter-provider-inspace",
}

// NodeCacheConfig is the public trust and routing material injected into an
// RKE2 node. The cache's private key is deliberately absent.
type NodeCacheConfig struct {
	// Address is the bastion VM's allocator-assigned RFC1918 address. Nodes
	// bind Hostname to it in /etc/hosts; it is deliberately not a separate VIP.
	Address  string
	Hostname string
	CABundle string
}

func (c *NodeCacheConfig) Registry() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", c.Hostname, BootstrapCachePort)
}

func bootstrapCacheHostname(clusterName string) string {
	return "cache." + clusterName + ".inspace.internal"
}

func validateNodeCacheConfig(config *NodeCacheConfig, privateSubnet string) error {
	if config == nil {
		return nil
	}
	prefix, err := netip.ParsePrefix(privateSubnet)
	if err != nil {
		return fmt.Errorf("bootstrap cache private subnet is invalid: %w", err)
	}
	address, err := netip.ParseAddr(config.Address)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != config.Address || !prefix.Contains(address) {
		return fmt.Errorf("bootstrap cache address must be a canonical RFC1918 IPv4 inside the node subnet")
	}
	if !bootstrapCacheHostPattern.MatchString(config.Hostname) {
		return fmt.Errorf("bootstrap cache hostname is invalid")
	}
	block, rest := pem.Decode([]byte(config.CABundle))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return fmt.Errorf("bootstrap cache CA bundle must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		return fmt.Errorf("bootstrap cache CA bundle must contain one valid CA certificate")
	}
	return nil
}

func (c *NodeCacheConfig) Endpoint() string {
	if c == nil {
		return ""
	}
	return "https://" + c.Registry()
}

type cacheTLSMaterial struct {
	CACertificate     string
	ServerCertificate string
	ServerPrivateKey  string
}

// deriveCacheTLS deterministically derives a cluster-scoped ECDSA P-256 CA and
// server certificate from an operator-owned 256-bit cache key. Determinism is
// required because the infrastructure reconciler is stateless: restarting it
// must not rotate the cache certificate or change immutable VM ownership
// hashes. Only the public CA is copied to Kubernetes nodes.
func deriveCacheTLS(key []byte, owner, hostname string, notBefore time.Time) (cacheTLSMaterial, error) {
	if len(key) != 32 {
		return cacheTLSMaterial{}, fmt.Errorf("bootstrap cache key must contain exactly 32 bytes")
	}
	if !bootstrapCacheHostPattern.MatchString(hostname) {
		return cacheTLSMaterial{}, fmt.Errorf("bootstrap cache hostname is invalid")
	}
	if notBefore.IsZero() || notBefore.Location() != time.UTC || !notBefore.Equal(notBefore.Truncate(time.Second)) {
		return cacheTLSMaterial{}, fmt.Errorf("bootstrap cache certificate start must be a persisted UTC time with one-second precision")
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("inspace-bootstrap-cache-pki/v1\x00" + owner + "\x00" + hostname + "\x00" + notBefore.Format(time.RFC3339) + "\x00" + label))
		return mac.Sum(nil)
	}
	caPrivate := deriveP256Key(derive("ca-key"))
	serverPrivate := deriveP256Key(derive("server-key"))
	notAfter := notBefore.AddDate(15, 0, 0)
	serial := func(label string) *big.Int {
		value := new(big.Int).SetBytes(derive(label)[:20])
		value.SetBit(value, 159, 0)
		if value.Sign() == 0 {
			value.SetInt64(1)
		}
		return value
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial("ca-serial"),
		Subject:               pkix.Name{CommonName: "InSpace bootstrap cache " + owner},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	caDER, err := x509.CreateCertificate(repeatingByteReader(derive("ca-signature")[0]), caTemplate, caTemplate, &caPrivate.PublicKey, deterministicECDSASigner{caPrivate})
	if err != nil {
		return cacheTLSMaterial{}, fmt.Errorf("create bootstrap cache CA: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return cacheTLSMaterial{}, fmt.Errorf("parse bootstrap cache CA: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:       serial("server-serial"),
		Subject:            pkix.Name{CommonName: hostname},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		DNSNames:           []string{hostname},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	serverDER, err := x509.CreateCertificate(repeatingByteReader(derive("server-signature")[0]), serverTemplate, caCertificate, &serverPrivate.PublicKey, deterministicECDSASigner{caPrivate})
	if err != nil {
		return cacheTLSMaterial{}, fmt.Errorf("create bootstrap cache server certificate: %w", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		return cacheTLSMaterial{}, fmt.Errorf("marshal bootstrap cache server key: %w", err)
	}
	return cacheTLSMaterial{
		CACertificate:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		ServerCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})),
		ServerPrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})),
	}, nil
}

func deriveP256Key(seed []byte) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	orderMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, orderMinusOne)
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
}

// deterministicECDSASigner uses RFC 6979 so the stateless reconciler emits
// byte-identical P-256 certificates across restarts. Randomized ECDSA here
// would change immutable VM bootstrap hashes even when the spec is unchanged.
type deterministicECDSASigner struct{ key *ecdsa.PrivateKey }

func (s deterministicECDSASigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s deterministicECDSASigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, fmt.Errorf("bootstrap cache ECDSA signer requires SHA-256")
	}
	r, signatureS, err := signRFC6979(s.key, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, signatureS})
}

func signRFC6979(key *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int, error) {
	order := key.Curve.Params().N
	byteLen := (order.BitLen() + 7) / 8
	int2octets := func(value *big.Int) []byte {
		result := make([]byte, byteLen)
		value.FillBytes(result)
		return result
	}
	z := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - order.BitLen(); excess > 0 {
		z.Rsh(z, uint(excess))
	}
	z.Mod(z, order)
	hmacBytes := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(data)
		return mac.Sum(nil)
	}
	v := make([]byte, sha256.Size)
	for i := range v {
		v[i] = 1
	}
	k := make([]byte, sha256.Size)
	seed := append(int2octets(key.D), int2octets(z)...)
	k = hmacBytes(k, append(append(append([]byte(nil), v...), 0), seed...))
	v = hmacBytes(k, v)
	k = hmacBytes(k, append(append(append([]byte(nil), v...), 1), seed...))
	v = hmacBytes(k, v)
	for {
		var candidateBytes []byte
		for len(candidateBytes) < byteLen {
			v = hmacBytes(k, v)
			candidateBytes = append(candidateBytes, v...)
		}
		candidate := new(big.Int).SetBytes(candidateBytes[:byteLen])
		if excess := byteLen*8 - order.BitLen(); excess > 0 {
			candidate.Rsh(candidate, uint(excess))
		}
		if candidate.Sign() > 0 && candidate.Cmp(order) < 0 {
			x, _ := key.Curve.ScalarBaseMult(candidate.Bytes())
			r := new(big.Int).Mod(x, order)
			if r.Sign() != 0 {
				s := new(big.Int).Mul(r, key.D)
				s.Add(s, z)
				s.Mul(s, new(big.Int).ModInverse(candidate, order))
				s.Mod(s, order)
				if s.Sign() != 0 {
					return r, s, nil
				}
			}
		}
		k = hmacBytes(k, append(append([]byte(nil), v...), 0))
		v = hmacBytes(k, v)
	}
}

type repeatingByteReader byte

func (r repeatingByteReader) Read(buffer []byte) (int, error) {
	for i := range buffer {
		buffer[i] = byte(r)
	}
	return len(buffer), nil
}

type cachedImage struct {
	Source string
	Target string
}

// rke2CacheImages is the audited linux/amd64 inventory for the exact RKE2
// release supported by the default cache. Source manifests are digest-pinned;
// target tags match the names generated by system-default-registry.
var rke2CacheImages = []cachedImage{
	{source("rancher/rke2-runtime", "v1.36.4-rke2r1", "411f197f1085472909c6e5f7434b64f1bf78ac3f8b82fac5a4d86d7a0a831cd9"), "rancher/rke2-runtime:v1.36.4-rke2r1"},
	{source("rancher/hardened-kubernetes", "v1.36.4-rke2r1-build20260821", "c8e5263407ac439de1dcdde98c7623efb9e17050715a80259d8bd5e81b5a9289"), "rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821"},
	{source("rancher/hardened-coredns", "v1.14.7-build20260819", "e9435ef6526a98e8d01d98a85d23770859ca49028ebd282912ae5e76f92c0166"), "rancher/hardened-coredns:v1.14.7-build20260819"},
	{source("rancher/hardened-cluster-autoscaler", "v1.10.3-build20260819", "c9b9b027e4d2cf1731311f9714f4aa633d37d7b0a72c9d3e6fc7a0594350d27c"), "rancher/hardened-cluster-autoscaler:v1.10.3-build20260819"},
	{source("rancher/hardened-dns-node-cache", "1.26.8-build20260819", "54a53cb983d47579a8e7cdcd9ae38bc58ff85c28c63fd26de02ce332d5f988ee"), "rancher/hardened-dns-node-cache:1.26.8-build20260819"},
	{source("rancher/hardened-etcd", "v3.6.14-k3s1-build20260819", "4f7ffbb3399c9f8137f5d0dd3ca0eddc7909e5d0155b35f1b0449baf96d61bfa"), "rancher/hardened-etcd:v3.6.14-k3s1-build20260819"},
	{source("rancher/hardened-k8s-metrics-server", "v0.9.0-build20260819", "4935e86e846d75591113f64ad4e0402718a1eda08f6900a9325d54f1df64945c"), "rancher/hardened-k8s-metrics-server:v0.9.0-build20260819"},
	{source("rancher/hardened-addon-resizer", "1.8.23-build20260819", "8026310fc44d985bf7c02434ad11d5f826a1aa1567606eea121b24ba9b3b0590"), "rancher/hardened-addon-resizer:1.8.23-build20260819"},
	{source("rancher/klipper-helm", "v0.13.3-build20260820", "ba922718d919920b6b6168e3f55f8effa85032a38bf44d8cc5f4df79a2fe405d"), "rancher/klipper-helm:v0.13.3-build20260820"},
	{source("rancher/klipper-lb", "v0.4.17", "910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a"), "rancher/klipper-lb:v0.4.17"},
	{source("rancher/mirrored-pause", "3.10.2", "f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"), "rancher/mirrored-pause:3.10.2"},
	{source("rancher/kube-webhook-certgen", "v1.14.5-hardened2", "6bb869baf40b92a3300c14ff591b1aa6ddb26bb4fef972e7a6a673b852eede3e"), "rancher/kube-webhook-certgen:v1.14.5-hardened2"},
	{source("rancher/nginx-ingress-controller", "v1.14.5-hardened2", "6cbc1e932b5b1559e18c9890dc21ac63a07ca040286917ac53e67f1839888774"), "rancher/nginx-ingress-controller:v1.14.5-hardened2"},
	{source("rancher/rke2-cloud-provider", "v1.36.4-0.20260817193921-a2fc9574e060-build20260820", "95a33533d97b10502be19e4f3e60e7ce9c30f4879084709af96259a01253f044"), "rancher/rke2-cloud-provider:v1.36.4-0.20260817193921-a2fc9574e060-build20260820"},
	{source("rancher/hardened-snapshot-controller", "v8.6.0-build20260819", "8d5872d767f93393273cb1ecad81e4bc08af65311d206bc31ee8f48bc58e51c4"), "rancher/hardened-snapshot-controller:v8.6.0-build20260819"},
	{source("rancher/hardened-traefik", "v3.7.11-build20260819", "dff360a22c8a28c2af3e78b2b4cf09a6c8edc199e27eb9f7c417bfc1ac41078e"), "rancher/hardened-traefik:v3.7.11-build20260819"},
	{source("rancher/mirrored-cilium-certgen", "v0.4.6", "511cedee817713fdf72db7e32fffb4b90da7747661b95180064f18198877626c"), "rancher/mirrored-cilium-certgen:v0.4.6"},
	{source("rancher/mirrored-cilium-cilium", "v1.19.6", "0df5b2750b64c49843aba1d649e9eaf61467cb0645ad3171db6f6962c095ac92"), "rancher/mirrored-cilium-cilium:v1.19.6"},
	{source("rancher/mirrored-cilium-cilium-envoy", "v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc", "767101fb8a5e38f055778cb43b7aa8eed80450b37f8121effac3d9de9e06dc99"), "rancher/mirrored-cilium-cilium-envoy:v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc"},
	{source("rancher/mirrored-cilium-clustermesh-apiserver", "v1.19.6", "accab5fe6ab7134fcd6f916acc9e4c785382a022128ae5495ec4a45fbe18c9a6"), "rancher/mirrored-cilium-clustermesh-apiserver:v1.19.6"},
	{source("rancher/mirrored-cilium-hubble-relay", "v1.19.6", "6782a49e3f28eba015701c4410a5ec7fa096fe9a562f879b4372dbecd827ea44"), "rancher/mirrored-cilium-hubble-relay:v1.19.6"},
	{source("rancher/mirrored-cilium-hubble-ui", "v0.13.5", "f7d514fc54d784ed6df9d58cf0e97648b143f92b766dd1780ed3fc845bd4c516"), "rancher/mirrored-cilium-hubble-ui:v0.13.5"},
	{source("rancher/mirrored-cilium-hubble-ui-backend", "v0.13.5", "fac0c300ae119274edca11fd89b1ad23c788792d8bc4ea2ba631c709e8d3c688"), "rancher/mirrored-cilium-hubble-ui-backend:v0.13.5"},
	{source("rancher/mirrored-cilium-operator-aws", "v1.19.6", "546d13ac511cf82441b5e9e99e03d0e054b788513ceb1a883e620b8284d5ccc3"), "rancher/mirrored-cilium-operator-aws:v1.19.6"},
	{source("rancher/mirrored-cilium-operator-azure", "v1.19.6", "e555430b7f5e4c407daab1afbec3c431ec016a53f1f1b848f67b9242cd3adedd"), "rancher/mirrored-cilium-operator-azure:v1.19.6"},
	{source("rancher/mirrored-cilium-operator-generic", "v1.19.6", "0db4ca4e06969d8904ee036617795d0e9c3228cf7b8d902ba74fc2bb98d2d665"), "rancher/mirrored-cilium-operator-generic:v1.19.6"},
	{source("rancher/hardened-cni-plugins", "v1.9.1-build20260717", "e2eeda778144983b9dc2482c25872ba8ce19ba7eebc32d830791aeb33d7dd614"), "rancher/hardened-cni-plugins:v1.9.1-build20260717"},
}

var fixedCacheImages = []cachedImage{
	{Source: "docker://ghcr.io/kube-vip/kube-vip@sha256:44035f68040c9eb99103c65f1f9ab9698d93f9f272110825705338ac1926f3d9", Target: "kube-vip/kube-vip:v1.2.1"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-provisioner@sha256:67ee5137252811fd471b8571efe9e173145ec8af7b520861eeccf7c078a772f2", Target: "sig-storage/csi-provisioner:v5.2.0"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-attacher@sha256:8eb112854b025cacea3a0d04e9f8fbb46a7152258ada2437d8c80c70a823c3ac", Target: "sig-storage/csi-attacher:v4.8.1"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-node-driver-registrar@sha256:8e66117d3b5e336901fc2ff508b3eb6105f8cf3b70f631e8102441e9562c8875", Target: "sig-storage/csi-node-driver-registrar:v2.13.0"},
	{Source: "docker://registry.k8s.io/sig-storage/livenessprobe@sha256:7546934830d80d61e598e8e9b2c327b3e2ae14e69b4364120077e4a800736c3c", Target: "sig-storage/livenessprobe:v2.15.0"},
}

func source(repository, _ string, digest string) string {
	return "docker://docker.io/" + repository + "@sha256:" + digest
}

func renderCacheImageManifest(rke2Version, moduleVersion string, disabled []string) (string, error) {
	return renderCacheImageManifestWithDigests(rke2Version, moduleVersion, disabled, nil)
}

func renderCacheImageManifestWithDigests(rke2Version, moduleVersion string, disabled []string, moduleImageDigests map[string]string) (string, error) {
	if rke2Version != bootstrapCacheRKE2Version {
		return "", fmt.Errorf("bootstrap cache has no audited image inventory for RKE2 %s; use %s or set spec.bootstrapCache.directDownload=true", rke2Version, bootstrapCacheRKE2Version)
	}
	if !moduleVersionPattern.MatchString(moduleVersion) {
		return "", fmt.Errorf("bootstrap cache requires an exact released module version, got %q", moduleVersion)
	}
	if moduleImageDigests != nil {
		if len(moduleImageDigests) != len(moduleImageNames) {
			return "", fmt.Errorf("bootstrap cache module image digests must contain exactly %d entries", len(moduleImageNames))
		}
		for _, component := range moduleImageNames {
			digest, ok := moduleImageDigests[component]
			if !ok || !imageDigestPattern.MatchString(digest) {
				return "", fmt.Errorf("bootstrap cache module image digest for %s must be sha256:<64 lowercase hex>", component)
			}
		}
		for component := range moduleImageDigests {
			if !slices.Contains(moduleImageNames, component) {
				return "", fmt.Errorf("bootstrap cache module image digest contains unknown component %q", component)
			}
		}
	}
	disabledSet := make(map[string]struct{}, len(disabled))
	for _, component := range disabled {
		disabledSet[component] = struct{}{}
	}
	images := make([]cachedImage, 0, len(rke2CacheImages)+len(fixedCacheImages)+3)
	for _, image := range rke2CacheImages {
		if _, ingressDisabled := disabledSet["rke2-ingress-nginx"]; ingressDisabled &&
			(image.Target == "rancher/kube-webhook-certgen:v1.14.5-hardened2" ||
				image.Target == "rancher/nginx-ingress-controller:v1.14.5-hardened2") {
			continue
		}
		if _, traefikDisabled := disabledSet["rke2-traefik"]; traefikDisabled &&
			image.Target == "rancher/hardened-traefik:v3.7.11-build20260819" {
			continue
		}
		images = append(images, image)
	}
	images = append(images, fixedCacheImages...)
	for _, component := range moduleImageNames {
		sourceReference := "docker://ghcr.io/thanet-s/" + component + ":" + moduleVersion
		if moduleImageDigests != nil {
			sourceReference = "docker://ghcr.io/thanet-s/" + component + "@" + moduleImageDigests[component]
		}
		images = append(images, cachedImage{
			Source: sourceReference,
			Target: "thanet-s/" + component + ":" + moduleVersion,
		})
	}
	var result strings.Builder
	for _, image := range images {
		fmt.Fprintf(&result, "%s\t%s\n", image.Source, image.Target)
	}
	return result.String(), nil
}

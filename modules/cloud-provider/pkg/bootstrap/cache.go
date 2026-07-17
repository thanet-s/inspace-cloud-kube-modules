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

	bootstrapCacheRKE2Version = "v1.35.6+rke2r1"
	bootstrapCacheRKE2SHA256  = "110c1170861635f55857ee50422fecdbf5d24b49e089fccc397a04419db59497"

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
	{source("rancher/rke2-runtime", "v1.35.6-rke2r1", "301a003512aee865011efa22bbff50335233d5be3b5b80c0f53e0f992018882c"), "rancher/rke2-runtime:v1.35.6-rke2r1"},
	{source("rancher/hardened-kubernetes", "v1.35.6-rke2r1-build20260612", "ddc1a0cbd9d434f552ef3a06df963c7d00c21a4a3fddcf21dac59282e5b53d24"), "rancher/hardened-kubernetes:v1.35.6-rke2r1-build20260612"},
	{source("rancher/hardened-coredns", "v1.14.4-build20260610", "890c0edc97a2bcd98a9be325835c9095f534facc56448c7c8f6193e3c26176fd"), "rancher/hardened-coredns:v1.14.4-build20260610"},
	{source("rancher/hardened-cluster-autoscaler", "v1.10.3-build20260604", "c2d222f43391a9dbe627aa61e0f2c7e2eeb44624e969f76d551233910fc60a8f"), "rancher/hardened-cluster-autoscaler:v1.10.3-build20260604"},
	{source("rancher/hardened-dns-node-cache", "1.26.8-build20260608", "d455335e469daf2a31a6c292a36c5f8fd13c953c46caf6639964b94dd99ae9af"), "rancher/hardened-dns-node-cache:1.26.8-build20260608"},
	{source("rancher/hardened-etcd", "v3.6.12-k3s1-build20260603", "4da3c8c484db265b01de5384d5737c4aa14f64a3c1053b4c287dac7efd6601c2"), "rancher/hardened-etcd:v3.6.12-k3s1-build20260603"},
	{source("rancher/hardened-k8s-metrics-server", "v0.8.1-build20260604", "aaee19757597f3dde15e06907a130fe29f23a74d73d9df0f3ec787817dd5e476"), "rancher/hardened-k8s-metrics-server:v0.8.1-build20260604"},
	{source("rancher/hardened-addon-resizer", "1.8.23-build20260604", "5a9d927175c46986fcf99bc4bf513f6a309766bf662d2e258830147ce4d6eddf"), "rancher/hardened-addon-resizer:1.8.23-build20260604"},
	{source("rancher/klipper-helm", "v0.11.1-build20260615", "b58e71847fa5d0cf7ced32a7dc63aaecf4fecbadd9a8d1d3facdc4d9c8fd2519"), "rancher/klipper-helm:v0.11.1-build20260615"},
	{source("rancher/klipper-lb", "v0.4.17", "d64ea02dfa3a29433a754fe59b56c6e1a05877528bdd6e20da587841ef22b0ac"), "rancher/klipper-lb:v0.4.17"},
	{source("rancher/mirrored-pause", "3.6", "c2280d2f5f56cf9c9a01bb64b2db4651e35efd6d62a54dcfc12049fe6449c5e4"), "rancher/mirrored-pause:3.6"},
	{source("rancher/kube-webhook-certgen", "v1.14.5-hardened2", "84b0867755ce8246a32df9b5a8fd6a5bab2143c093826e44dc00e125268e1644"), "rancher/kube-webhook-certgen:v1.14.5-hardened2"},
	{source("rancher/nginx-ingress-controller", "v1.14.5-hardened2", "6757f2751749b50f03a8fa791134e5b4e28bec16ad4b8df05b639f8788ab9156"), "rancher/nginx-ingress-controller:v1.14.5-hardened2"},
	{source("rancher/rke2-cloud-provider", "v1.35.4-0.20260415195656-e51c0636351d-build20260415", "7d3ebab4777d785f2bd30fac059d86d7e6c02a24c09dfd85fb684ba55bafa81e"), "rancher/rke2-cloud-provider:v1.35.4-0.20260415195656-e51c0636351d-build20260415"},
	{source("rancher/hardened-snapshot-controller", "v8.6.0-build20260608", "923542128c8e091be843fc8601219cd20dd5a36c5b72d99a2a5a0c73e17d2976"), "rancher/hardened-snapshot-controller:v8.6.0-build20260608"},
	{source("rancher/mirrored-cilium-certgen", "v0.4.3", "e678cc3a7f370a335797ed0dc3784f2405616fcd6d933b48a1eda207d34b3739"), "rancher/mirrored-cilium-certgen:v0.4.3"},
	{source("rancher/mirrored-cilium-cilium", "v1.19.4", "475fdc115e6d7d5791e9be06273f7187aebc58b490601d6b4dd2e2672e8d9a7a"), "rancher/mirrored-cilium-cilium:v1.19.4"},
	{source("rancher/mirrored-cilium-cilium-envoy", "v1.36.6-1778235340-b87d1e32f522b33bd51701c6476d199326f01496", "edc99d9d41666fb2e8b7b20d63efd0de5874144ab1c3cd8a47624538cc320c08"), "rancher/mirrored-cilium-cilium-envoy:v1.36.6-1778235340-b87d1e32f522b33bd51701c6476d199326f01496"},
	{source("rancher/mirrored-cilium-clustermesh-apiserver", "v1.19.4", "0b77cb390fde558dea27cb9b2582babf444befc17845eace03e37000d4d83454"), "rancher/mirrored-cilium-clustermesh-apiserver:v1.19.4"},
	{source("rancher/mirrored-cilium-hubble-relay", "v1.19.4", "5da3a57ae08c6e85816e93cb4cd44abe7021b319da2a21d2c6e4e6560ac21135"), "rancher/mirrored-cilium-hubble-relay:v1.19.4"},
	{source("rancher/mirrored-cilium-hubble-ui", "v0.13.5", "408e0a5f8071390de674013990c4a3adfbf6b1de6a4a29d555ea8e6745569c23"), "rancher/mirrored-cilium-hubble-ui:v0.13.5"},
	{source("rancher/mirrored-cilium-hubble-ui-backend", "v0.13.5", "55c340fa9103ef96088319450426020032b4c33cb710a477496774c0269e4c2c"), "rancher/mirrored-cilium-hubble-ui-backend:v0.13.5"},
	{source("rancher/mirrored-cilium-operator-aws", "v1.19.4", "1d3eff73cebf25f5212f0bff33e4d91a2da5d206c9fe7cca51c6e4343a489afe"), "rancher/mirrored-cilium-operator-aws:v1.19.4"},
	{source("rancher/mirrored-cilium-operator-azure", "v1.19.4", "5f1742bc985dd92697fe271898885150821966aa23afb5e068ed526358857f0f"), "rancher/mirrored-cilium-operator-azure:v1.19.4"},
	{source("rancher/mirrored-cilium-operator-generic", "v1.19.4", "5b8290823545eb38d03f1756d099a43d804ddd72c13c616d0723fec458f63ac3"), "rancher/mirrored-cilium-operator-generic:v1.19.4"},
	{source("rancher/hardened-cni-plugins", "v1.9.1-build20260608", "18b388c773afb7b9206f67af226b513d1fb2284b5e6b9bf50fb6b236b71cee6d"), "rancher/hardened-cni-plugins:v1.9.1-build20260608"},
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

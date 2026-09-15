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
	bootstrapCacheRKE2SHA256  = "aa7eea8ec905b89ec9a91443cbe96ddb6cd0fc7d15e422380e192b011e4e130b"

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
	{source("rancher/rke2-runtime", "v1.36.4-rke2r1", "b259e466c7539f3b10209da1725c2176352a5cbb7adec9e3dafd9959585d4940"), "rancher/rke2-runtime:v1.36.4-rke2r1"},
	{source("rancher/hardened-kubernetes", "v1.36.4-rke2r1-build20260821", "a288b9525b2a82f3bece8e2a0cb2daa24a2fa1d90cbf98a7511e157bcfb07335"), "rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260821"},
	{source("rancher/hardened-coredns", "v1.14.7-build20260819", "905065e4b84f6f93c522940aea5ddedfa947a0ca7b1d4c4ccec8f7bb405d322b"), "rancher/hardened-coredns:v1.14.7-build20260819"},
	{source("rancher/hardened-cluster-autoscaler", "v1.10.3-build20260819", "36de22bfba3c86d52a2b0fbb1710964289a6d369eb98416604bd399765208944"), "rancher/hardened-cluster-autoscaler:v1.10.3-build20260819"},
	{source("rancher/hardened-dns-node-cache", "1.26.8-build20260819", "0941da5498f334c84cbfc6b650a6ba2aceb97b6973f2d062421a949437e624e9"), "rancher/hardened-dns-node-cache:1.26.8-build20260819"},
	{source("rancher/hardened-etcd", "v3.6.14-k3s1-build20260819", "cc4c1059cb838f8556dd5658035e381c8aded7e36bfed851a7415a1a5e40d44a"), "rancher/hardened-etcd:v3.6.14-k3s1-build20260819"},
	{source("rancher/hardened-k8s-metrics-server", "v0.9.0-build20260819", "592c433d39015eab04bd4d02861b863307912d0a8dc6b076887f234748f2381c"), "rancher/hardened-k8s-metrics-server:v0.9.0-build20260819"},
	{source("rancher/hardened-addon-resizer", "1.8.23-build20260819", "c8963f9325ba796dcda86504dd9a0c812202065e1a371bcffd0ee337a5a1d727"), "rancher/hardened-addon-resizer:1.8.23-build20260819"},
	{source("rancher/klipper-helm", "v0.13.3-build20260820", "2893fcbc460601bab023f405691fd4b17b1360bf5d9bcb06a347f0eaf6fc0df2"), "rancher/klipper-helm:v0.13.3-build20260820"},
	{source("rancher/klipper-lb", "v0.4.17", "d64ea02dfa3a29433a754fe59b56c6e1a05877528bdd6e20da587841ef22b0ac"), "rancher/klipper-lb:v0.4.17"},
	{source("rancher/mirrored-pause", "3.10.2", "412c4a7219cb8a299a37337f3d87810c5340095322e15594a1637785adad0f17"), "rancher/mirrored-pause:3.10.2"},
	{source("rancher/kube-webhook-certgen", "v1.14.5-hardened2", "84b0867755ce8246a32df9b5a8fd6a5bab2143c093826e44dc00e125268e1644"), "rancher/kube-webhook-certgen:v1.14.5-hardened2"},
	{source("rancher/nginx-ingress-controller", "v1.14.5-hardened2", "6757f2751749b50f03a8fa791134e5b4e28bec16ad4b8df05b639f8788ab9156"), "rancher/nginx-ingress-controller:v1.14.5-hardened2"},
	{source("rancher/rke2-cloud-provider", "v1.36.4-0.20260817193921-a2fc9574e060-build20260820", "f4ff1d7a4a3824736044adca9cd0a55041f888d11d711500210c74d8aaa46950"), "rancher/rke2-cloud-provider:v1.36.4-0.20260817193921-a2fc9574e060-build20260820"},
	{source("rancher/hardened-snapshot-controller", "v8.6.0-build20260819", "84d09882fd38a7b305b35ef1d09c263b0924219d2a530c089b32149a991794fd"), "rancher/hardened-snapshot-controller:v8.6.0-build20260819"},
	{source("rancher/hardened-traefik", "v3.7.11-build20260819", "69d07d641dae926027c5ffcd08a7bd3df3ccc163f1c65519ffa88814c7238df4"), "rancher/hardened-traefik:v3.7.11-build20260819"},
	{source("rancher/mirrored-cilium-certgen", "v0.4.6", "6a018dde6b4ec17c4d53f65a9ba4e0ce71063484b161d079b595495fe4dc865f"), "rancher/mirrored-cilium-certgen:v0.4.6"},
	{source("rancher/mirrored-cilium-cilium", "v1.19.6", "cc29e9c95791a0a90195844946ae99275e00514293a2114a07846aac87753577"), "rancher/mirrored-cilium-cilium:v1.19.6"},
	{source("rancher/mirrored-cilium-cilium-envoy", "v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc", "089df808952f10ba67e9dec7e44fe8944d9ce243de35f946503647b22ba246e8"), "rancher/mirrored-cilium-cilium-envoy:v1.36.9-1782267392-edeb3f2af56c37c407efa1f63f0b32f595399bbc"},
	{source("rancher/mirrored-cilium-clustermesh-apiserver", "v1.19.6", "08eb59e52e1780f91ae84c84ff109608cb71f5330a700114bd19e5825d46964b"), "rancher/mirrored-cilium-clustermesh-apiserver:v1.19.6"},
	{source("rancher/mirrored-cilium-hubble-relay", "v1.19.6", "aacc53e6fc6ec693cfb60d3c22e5ef4d08acc84b5ad9f47191d195b4cb4f596f"), "rancher/mirrored-cilium-hubble-relay:v1.19.6"},
	{source("rancher/mirrored-cilium-hubble-ui", "v0.13.5", "408e0a5f8071390de674013990c4a3adfbf6b1de6a4a29d555ea8e6745569c23"), "rancher/mirrored-cilium-hubble-ui:v0.13.5"},
	{source("rancher/mirrored-cilium-hubble-ui-backend", "v0.13.5", "55c340fa9103ef96088319450426020032b4c33cb710a477496774c0269e4c2c"), "rancher/mirrored-cilium-hubble-ui-backend:v0.13.5"},
	{source("rancher/mirrored-cilium-operator-aws", "v1.19.6", "75045f071b8a1d9d52a2bcb8233f9108f51adb8588f09ebc4ea83e6ae06c1576"), "rancher/mirrored-cilium-operator-aws:v1.19.6"},
	{source("rancher/mirrored-cilium-operator-azure", "v1.19.6", "50a784a208ffebac1bd8e9c452ce0561b2ca06a318f2bec37b170a7923bf6b9e"), "rancher/mirrored-cilium-operator-azure:v1.19.6"},
	{source("rancher/mirrored-cilium-operator-generic", "v1.19.6", "8bc32d975fedb2ab046bba58a89eede48c28d22c90f8a7efcd6512358cf78330"), "rancher/mirrored-cilium-operator-generic:v1.19.6"},
	{source("rancher/hardened-cni-plugins", "v1.9.1-build20260717", "a0b9549f6a833b295c5d5a235bfe1415918ab4441227e9f5e04397d27511a910"), "rancher/hardened-cni-plugins:v1.9.1-build20260717"},
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

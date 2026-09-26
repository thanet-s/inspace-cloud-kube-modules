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

	// bootstrapCacheRKE2Version is the one RKE2 release the cache serves.
	// bootstrapCacheRKE2SHA256 is rke2.linux-amd64.tar.gz from that release's
	// sha256sum-amd64.txt. Refresh both with rke2CacheImages; see
	// DEVELOPMENT.md "Refreshing the audited RKE2 release".
	bootstrapCacheRKE2Version = "v1.36.5-rc2+rke2r1"
	bootstrapCacheRKE2SHA256  = "d759229bd2d848a9f5a98e00617792ed7a4f93cec407e75a2b00f7e941bf6dd4"

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
// release supported by the default cache: the release's
// rke2-images-core, rke2-images-ingress-nginx, and rke2-images-cilium
// linux-amd64 lists, with the two ingress-nginx images placed after
// mirrored-pause. Each source pins the tag's top-level index digest (the
// sha256 of `docker buildx imagetools inspect --raw`); skopeo selects the
// linux/amd64 manifest at seed time. Target tags match the names generated by
// system-default-registry.
var rke2CacheImages = []cachedImage{
	{source("rancher/rke2-runtime", "v1.36.5-rc2-rke2r1", "012cd1ffe300cdb569413727b1ccf1497087e3ced2f94a6f7e91d64392666eb5"), "rancher/rke2-runtime:v1.36.5-rc2-rke2r1"},
	{source("rancher/hardened-kubernetes", "v1.36.5-rke2r1-build20260923", "620ebdbcd1287d7e55566d24b78361ee828b798aae9fd04981653ffa6e54b3be"), "rancher/hardened-kubernetes:v1.36.5-rke2r1-build20260923"},
	{source("rancher/hardened-coredns", "v1.14.7-build20260909", "7cfc2ec25ea65eb2fe572df5ead508279813088f4383210ead336b09f538962d"), "rancher/hardened-coredns:v1.14.7-build20260909"},
	{source("rancher/hardened-cluster-autoscaler", "v1.10.3-build20260819", "c9b9b027e4d2cf1731311f9714f4aa633d37d7b0a72c9d3e6fc7a0594350d27c"), "rancher/hardened-cluster-autoscaler:v1.10.3-build20260819"},
	{source("rancher/hardened-dns-node-cache", "1.27.0-r1-build20260923", "a39465fbdddaba4b95760342d2f748d0b58698f0e8b8394aa397e300e2f336ce"), "rancher/hardened-dns-node-cache:1.27.0-r1-build20260923"},
	{source("rancher/hardened-etcd", "v3.6.14-k3s3-build20260915", "d2c95c2d191e3e2005fb27aeee541f84f4450081a4c110a317a9bfac66e07760"), "rancher/hardened-etcd:v3.6.14-k3s3-build20260915"},
	{source("rancher/hardened-k8s-metrics-server", "v0.9.0-build20260909", "66d66121b3efa6588f5d3eb26b6c0ddaec775fdbcbf4f1b2cd73ca1fc2a0f264"), "rancher/hardened-k8s-metrics-server:v0.9.0-build20260909"},
	{source("rancher/hardened-addon-resizer", "1.8.23-build20260909", "8a993d863feb767ef99e08bbc37e88d88f3a0b59f38ee382c138010be2f765e9"), "rancher/hardened-addon-resizer:1.8.23-build20260909"},
	{source("rancher/klipper-helm", "v0.13.3-build20260909", "e89ce639d4e7aec131aaf7aecb7fd9b3b26f21f5604bdc37c2336b8901a2d9b0"), "rancher/klipper-helm:v0.13.3-build20260909"},
	{source("rancher/klipper-lb", "v0.4.17", "910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a"), "rancher/klipper-lb:v0.4.17"},
	{source("rancher/mirrored-pause", "3.10.2", "f548e0e8e3dc1896ca956272154dde3314e8cc4fde0a57577ee9fa1c63f5baf4"), "rancher/mirrored-pause:3.10.2"},
	{source("rancher/kube-webhook-certgen", "v1.14.5-hardened2", "6bb869baf40b92a3300c14ff591b1aa6ddb26bb4fef972e7a6a673b852eede3e"), "rancher/kube-webhook-certgen:v1.14.5-hardened2"},
	{source("rancher/nginx-ingress-controller", "v1.14.5-hardened2", "6cbc1e932b5b1559e18c9890dc21ac63a07ca040286917ac53e67f1839888774"), "rancher/nginx-ingress-controller:v1.14.5-hardened2"},
	{source("rancher/rke2-cloud-provider", "v1.36.5-0.20260915232631-dca49392c395-build20260916", "78e041fd4c7e1e74b5ea0ea548452a14bc23a9e0fe6c46225245298f784b896e"), "rancher/rke2-cloud-provider:v1.36.5-0.20260915232631-dca49392c395-build20260916"},
	{source("rancher/hardened-snapshot-controller", "v8.6.0-build20260909", "7b122b30e5c62f55889e7d2d2fb6565c7d8cdc749c7fc5dc7690b1d213dbe271"), "rancher/hardened-snapshot-controller:v8.6.0-build20260909"},
	{source("rancher/hardened-traefik", "v3.7.13-build20260910", "72dacd6919c408d6bdb619c3df5a2ccb68235d3150d3e118929a7320ab2b2d43"), "rancher/hardened-traefik:v3.7.13-build20260910"},
	{source("rancher/mirrored-cilium-certgen", "v0.4.11", "14d29a176fc96d15b154559ce1a5baf01367c10baabfa7bb8028b72f087a56f0"), "rancher/mirrored-cilium-certgen:v0.4.11"},
	{source("rancher/mirrored-cilium-cilium", "v1.20.2", "2939231d0d3e3ebddcd80fffa168b7ddcc78fdf0dc864d1c8c126ff523c54f01"), "rancher/mirrored-cilium-cilium:v1.20.2"},
	{source("rancher/mirrored-cilium-cilium-envoy", "v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82", "af7382699576b9e65e9184efa52eeca0b58aea70ad6e511bf260c91d9f740463"), "rancher/mirrored-cilium-cilium-envoy:v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82"},
	{source("rancher/mirrored-cilium-clustermesh-apiserver", "v1.20.2", "e9ffc79baf76bb98efb87c01be3bca8da998779f4ccdafc97c74132b307305ce"), "rancher/mirrored-cilium-clustermesh-apiserver:v1.20.2"},
	{source("rancher/mirrored-cilium-hubble-relay", "v1.20.2", "d309c977870e9dbede7122a10eee09a4c9d66685e8d52af62d9c3c113f815b0f"), "rancher/mirrored-cilium-hubble-relay:v1.20.2"},
	{source("rancher/mirrored-cilium-hubble-ui", "v0.13.6", "049a80a03585c043d0c3121bdc518c72b0fd42bae07e4bcce0fdb8f1e88041d0"), "rancher/mirrored-cilium-hubble-ui:v0.13.6"},
	{source("rancher/mirrored-cilium-hubble-ui-backend", "v0.13.6", "83b3fc763f3d49948c306bf49b08277383e195904b9ca5c0c0022b2112628787"), "rancher/mirrored-cilium-hubble-ui-backend:v0.13.6"},
	{source("rancher/mirrored-cilium-operator-aws", "v1.20.2", "0df92d10d2ec548052678b67809c1e613429931b2d5c1d6741fcef096bb0d2a3"), "rancher/mirrored-cilium-operator-aws:v1.20.2"},
	{source("rancher/mirrored-cilium-operator-azure", "v1.20.2", "b304dc1ad8dd06abb2103bdb91c87dcc302d904e1e4cbe0afd231885d1f0194a"), "rancher/mirrored-cilium-operator-azure:v1.20.2"},
	{source("rancher/mirrored-cilium-operator-generic", "v1.20.2", "64d8798350e8569b8e7622563fed6e44dce2625f311e4651b774816516c744fc"), "rancher/mirrored-cilium-operator-generic:v1.20.2"},
	{source("rancher/hardened-cni-plugins", "v1.9.1-build20260903", "cfc3c7284882f1931ddb3d881651f81a7728542401aa294c6c058b67f71c70b8"), "rancher/hardened-cni-plugins:v1.9.1-build20260903"},
}

var fixedCacheImages = []cachedImage{
	{Source: "docker://ghcr.io/kube-vip/kube-vip@sha256:44035f68040c9eb99103c65f1f9ab9698d93f9f272110825705338ac1926f3d9", Target: "kube-vip/kube-vip:v1.2.1"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-provisioner@sha256:67ee5137252811fd471b8571efe9e173145ec8af7b520861eeccf7c078a772f2", Target: "sig-storage/csi-provisioner:v5.2.0"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-attacher@sha256:8eb112854b025cacea3a0d04e9f8fbb46a7152258ada2437d8c80c70a823c3ac", Target: "sig-storage/csi-attacher:v4.8.1"},
	{Source: "docker://registry.k8s.io/sig-storage/csi-resizer@sha256:9175c28d3db85da73d9d9286c0a2934f73be5b0b985b7d3069bbf1babda95318", Target: "sig-storage/csi-resizer:v1.13.2"},
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
	// Disabled add-ons are matched by repository, not tag, so a release
	// refresh cannot silently re-admit an add-on image whose tag moved.
	for _, image := range rke2CacheImages {
		if _, ingressDisabled := disabledSet["rke2-ingress-nginx"]; ingressDisabled &&
			(strings.HasPrefix(image.Target, "rancher/kube-webhook-certgen:") ||
				strings.HasPrefix(image.Target, "rancher/nginx-ingress-controller:")) {
			continue
		}
		if _, traefikDisabled := disabledSet["rke2-traefik"]; traefikDisabled &&
			strings.HasPrefix(image.Target, "rancher/hardened-traefik:") {
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

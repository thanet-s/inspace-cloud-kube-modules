package v1alpha1

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	rke2VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$`)
	sshUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,29}$`)
)

const maxSSHPublicKeyLength = 16384
const maxBootstrapCacheCABundleLength = 65536

// Validate returns all local, deterministic validation failures. It performs no
// network lookup and is also used by tests and the NodeClass reconciler.
func (n *InSpaceNodeClass) Validate() field.ErrorList {
	var errs field.ErrorList
	p := field.NewPath("spec")

	if messages := validation.IsDNS1123Subdomain(n.Spec.ClusterName); len(messages) != 0 {
		errs = append(errs, field.Invalid(p.Child("clusterName"), n.Spec.ClusterName, strings.Join(messages, "; ")))
	}
	if n.Spec.BillingAccountID <= 0 {
		errs = append(errs, field.Invalid(p.Child("billingAccountID"), n.Spec.BillingAccountID, "must be positive"))
	}
	if n.Spec.Location != LocationBangkok {
		errs = append(errs, field.NotSupported(p.Child("location"), n.Spec.Location, []string{LocationBangkok}))
	}
	if err := ValidateNetworkUUID(n.Spec.NetworkUUID); err != nil {
		errs = append(errs, field.Invalid(p.Child("networkUUID"), n.Spec.NetworkUUID, "must be a UUID"))
	}
	if supervisorVIP, err := n.Spec.RKE2.ServerVIP(); err == nil {
		if err := n.Spec.PrivateLoadBalancerPool.ValidateForSupervisor(supervisorVIP); err != nil {
			errs = append(errs, field.Invalid(p.Child("privateLoadBalancerPool"), n.Spec.PrivateLoadBalancerPool, err.Error()))
		}
	} else if _, _, poolErr := n.Spec.PrivateLoadBalancerPool.Range(); poolErr != nil {
		errs = append(errs, field.Invalid(p.Child("privateLoadBalancerPool"), n.Spec.PrivateLoadBalancerPool, poolErr.Error()))
	}
	if !n.Spec.ReservePublicIPv4 {
		errs = append(errs, field.NotSupported(p.Child("reservePublicIPv4"), false, []string{"true"}))
	}
	if !uuidPattern.MatchString(n.Spec.FirewallUUID) {
		errs = append(errs, field.Invalid(p.Child("firewallUUID"), n.Spec.FirewallUUID, "must be a UUID"))
	}
	if n.Spec.ImageSelector.OSName != OSNameUbuntu {
		errs = append(errs, field.NotSupported(p.Child("imageSelector", "osName"), n.Spec.ImageSelector.OSName, []string{OSNameUbuntu}))
	}
	if n.Spec.ImageSelector.OSVersion != OSVersionUbuntu {
		errs = append(errs, field.NotSupported(p.Child("imageSelector", "osVersion"), n.Spec.ImageSelector.OSVersion, []string{OSVersionUbuntu}))
	}
	if n.Spec.RootDiskGiB < 30 || n.Spec.RootDiskGiB > 2000 {
		errs = append(errs, field.Invalid(p.Child("rootDiskGiB"), n.Spec.RootDiskGiB, "must be between 30 and 2000 GiB"))
	}
	if !rke2VersionPattern.MatchString(n.Spec.RKE2.Version) {
		errs = append(errs, field.Invalid(p.Child("rke2", "version"), n.Spec.RKE2.Version, "must look like v1.35.6+rke2r1"))
	}
	if _, err := n.Spec.RKE2.ServerVIP(); err != nil {
		errs = append(errs, field.Invalid(p.Child("rke2", "server"), n.Spec.RKE2.Server, err.Error()))
	}
	if messages := validation.IsDNS1123Subdomain(n.Spec.RKE2.TokenSecretRef.Name); len(messages) != 0 {
		errs = append(errs, field.Invalid(p.Child("rke2", "tokenSecretRef", "name"), n.Spec.RKE2.TokenSecretRef.Name, strings.Join(messages, "; ")))
	} else if n.Spec.RKE2.TokenSecretRef.Name != RKE2AgentTokenSecretName {
		errs = append(errs, field.NotSupported(p.Child("rke2", "tokenSecretRef", "name"), n.Spec.RKE2.TokenSecretRef.Name, []string{RKE2AgentTokenSecretName}))
	}
	if n.Spec.RKE2.TokenSecretRef.Key == "" {
		errs = append(errs, field.Required(p.Child("rke2", "tokenSecretRef", "key"), "must not be empty"))
	} else if messages := validation.IsConfigMapKey(n.Spec.RKE2.TokenSecretRef.Key); len(messages) != 0 {
		errs = append(errs, field.Invalid(p.Child("rke2", "tokenSecretRef", "key"), n.Spec.RKE2.TokenSecretRef.Key, strings.Join(messages, "; ")))
	} else if n.Spec.RKE2.TokenSecretRef.Key != RKE2AgentTokenSecretKey {
		errs = append(errs, field.NotSupported(p.Child("rke2", "tokenSecretRef", "key"), n.Spec.RKE2.TokenSecretRef.Key, []string{RKE2AgentTokenSecretKey}))
	}
	if err := ValidateBootstrapCache(n.Spec.BootstrapCache); err != nil {
		errs = append(errs, field.Invalid(p.Child("bootstrapCache"), n.Spec.BootstrapCache, err.Error()))
	}
	if err := ValidateSSHAccess(n.Spec.SSHUsername, n.Spec.SSHPublicKey); err != nil {
		errs = append(errs, field.Invalid(p.Child("sshPublicKey"), "", err.Error()))
	}
	if len(n.Spec.AdditionalUserData) > 65536 {
		errs = append(errs, field.TooLong(p.Child("additionalUserData"), "", 65536))
	}
	return errs
}

// ValidateBootstrapCache enforces an unambiguous choice between the private
// cache and direct upstream downloads. Cached mode trusts only explicitly
// supplied CA certificates and never falls back to public registry mirrors.
func ValidateBootstrapCache(cache BootstrapCacheSpec) error {
	if cache.DirectDownload {
		if cache.Address != "" || cache.CABundle != "" {
			return fmt.Errorf("directDownload requires address and caBundle to be empty")
		}
		return nil
	}
	address, err := netip.ParseAddr(cache.Address)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != cache.Address {
		return fmt.Errorf("address must be a canonical RFC1918 IPv4 address")
	}
	if err := ValidateBootstrapCacheCABundle(cache.CABundle); err != nil {
		return fmt.Errorf("caBundle %w", err)
	}
	return nil
}

// ValidateBootstrapCacheCABundle accepts only PEM CERTIFICATE blocks whose
// parsed certificates are marked as CAs. Whitespace between blocks is allowed,
// but unrelated PEM blocks or trailing non-PEM data are rejected.
func ValidateBootstrapCacheCABundle(bundle string) error {
	if bundle == "" {
		return fmt.Errorf("must contain at least one PEM CA certificate")
	}
	if len(bundle) > maxBootstrapCacheCABundleLength {
		return fmt.Errorf("must not exceed %d bytes", maxBootstrapCacheCABundleLength)
	}
	rest := []byte(bundle)
	certificates := 0
	for len(strings.TrimSpace(string(rest))) != 0 {
		rest = bytes.TrimLeftFunc(rest, unicode.IsSpace)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("must contain only PEM CERTIFICATE blocks")
		}
		block, remainder := pem.Decode(rest)
		if block == nil {
			return fmt.Errorf("must contain only PEM CERTIFICATE blocks")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("must contain only headerless PEM CERTIFICATE blocks")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("contains an invalid certificate: %v", err)
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return fmt.Errorf("contains a certificate that is not a CA")
		}
		certificates++
		rest = remainder
	}
	if certificates == 0 {
		return fmt.Errorf("must contain at least one PEM CA certificate")
	}
	return nil
}

// ServerVIP returns the literal private IPv4 address from the fixed RKE2
// supervisor endpoint. Requiring a literal address keeps worker bootstrap and
// collision checks independent of DNS and prevents a public registration
// endpoint from entering the NodeClass contract.
func (r RKE2Config) ServerVIP() (netip.Addr, error) {
	u, err := url.Parse(r.Server)
	if err != nil || u.Scheme != "https" || u.Port() != "9345" || u.Path != "" || u.RawPath != "" ||
		u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return netip.Addr{}, fmt.Errorf("must be https://<RFC1918-IPv4>:9345 without a path, query, fragment, or userinfo")
	}
	vip, err := ParseControlPlaneVIP(u.Hostname())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("host %w", err)
	}
	if r.Server != "https://"+vip.String()+":9345" {
		return netip.Addr{}, fmt.Errorf("must use the canonical form https://<RFC1918-IPv4>:9345")
	}
	return vip, nil
}

// ValidateNetworkUUID validates the exact controller/NodeClass VPC identity.
func ValidateNetworkUUID(value string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("must be a UUID")
	}
	return nil
}

// ValidateSSHAccess accepts either no operator access or one username and one
// supported OpenSSH authorized_keys line. It deliberately rejects key options,
// multiple lines, private key material, and mismatched embedded key types.
func ValidateSSHAccess(username, publicKey string) error {
	if username == "" && publicKey == "" {
		return nil
	}
	if username == "" || publicKey == "" {
		return fmt.Errorf("sshUsername and sshPublicKey must be configured together")
	}
	if !sshUsernamePattern.MatchString(username) {
		return fmt.Errorf("sshUsername must be a safe Linux username of at most 30 characters")
	}
	if len(publicKey) > maxSSHPublicKeyLength {
		return fmt.Errorf("sshPublicKey must not exceed %d bytes", maxSSHPublicKeyLength)
	}
	if strings.TrimSpace(publicKey) != publicKey || strings.ContainsAny(publicKey, "\r\n") {
		return fmt.Errorf("sshPublicKey must be exactly one authorized_keys line")
	}
	fields := strings.Fields(publicKey)
	if len(fields) < 2 || !supportedSSHKeyType(fields[0]) {
		return fmt.Errorf("sshPublicKey must use ssh-rsa, ssh-ed25519, or a supported ecdsa-sha2 key")
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(fields[1])
	}
	if err != nil || len(decoded) < 4 {
		return fmt.Errorf("sshPublicKey payload must be valid base64-encoded SSH key data")
	}
	algorithm, remainder, ok := readSSHString(decoded)
	if !ok || string(algorithm) != fields[0] {
		return fmt.Errorf("sshPublicKey payload key type must match its authorized_keys prefix")
	}
	if !validSSHKeyPayload(fields[0], remainder) {
		return fmt.Errorf("sshPublicKey payload is malformed for key type %s", fields[0])
	}
	return nil
}

func supportedSSHKeyType(value string) bool {
	switch value {
	case "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return true
	default:
		return false
	}
}

func validSSHKeyPayload(algorithm string, data []byte) bool {
	first, remainder, ok := readSSHString(data)
	if !ok || len(first) == 0 {
		return false
	}
	switch algorithm {
	case "ssh-ed25519":
		return len(first) == 32 && len(remainder) == 0
	case "ssh-rsa":
		second, remainder, ok := readSSHString(remainder)
		return ok && len(second) != 0 && len(remainder) == 0
	default:
		second, remainder, ok := readSSHString(remainder)
		curve := strings.TrimPrefix(algorithm, "ecdsa-sha2-")
		return ok && string(first) == curve && len(second) != 0 && len(remainder) == 0
	}
}

func readSSHString(data []byte) ([]byte, []byte, bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	length := uint64(binary.BigEndian.Uint32(data[:4]))
	if length > uint64(len(data)-4) {
		return nil, nil, false
	}
	end := 4 + int(length)
	return data[4:end], data[end:], true
}

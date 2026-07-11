package v1alpha1

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	k3sVersionPattern  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$`)
	serverHostPattern  = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	sshUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,29}$`)
)

const maxSSHPublicKeyLength = 16384

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
	if !uuidPattern.MatchString(n.Spec.NetworkUUID) {
		errs = append(errs, field.Invalid(p.Child("networkUUID"), n.Spec.NetworkUUID, "must be a UUID"))
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
	if _, ok := n.Spec.HostPoolSelector.UUID(); !ok {
		errs = append(errs, field.NotSupported(p.Child("hostPoolSelector", "class"), n.Spec.HostPoolSelector.Class, []string{HostClassIntelScalable, HostClassAMDEPYC}))
	}
	if n.Spec.RootDiskGiB < 30 || n.Spec.RootDiskGiB > 2000 {
		errs = append(errs, field.Invalid(p.Child("rootDiskGiB"), n.Spec.RootDiskGiB, "must be between 30 and 2000 GiB"))
	}
	if !k3sVersionPattern.MatchString(n.Spec.K3s.Version) {
		errs = append(errs, field.Invalid(p.Child("k3s", "version"), n.Spec.K3s.Version, "must look like v1.35.1+k3s1"))
	}
	if u, err := url.Parse(n.Spec.K3s.Server); err != nil || u.Scheme != "https" || !serverHostPattern.MatchString(u.Hostname()) || u.Port() != "6443" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, field.Invalid(p.Child("k3s", "server"), n.Spec.K3s.Server, "must be an https URL on port 6443 without a path"))
	}
	if messages := validation.IsDNS1123Subdomain(n.Spec.K3s.TokenSecretRef.Name); len(messages) != 0 {
		errs = append(errs, field.Invalid(p.Child("k3s", "tokenSecretRef", "name"), n.Spec.K3s.TokenSecretRef.Name, strings.Join(messages, "; ")))
	} else if n.Spec.K3s.TokenSecretRef.Name != K3sAgentTokenSecretName {
		errs = append(errs, field.NotSupported(p.Child("k3s", "tokenSecretRef", "name"), n.Spec.K3s.TokenSecretRef.Name, []string{K3sAgentTokenSecretName}))
	}
	if n.Spec.K3s.TokenSecretRef.Key == "" {
		errs = append(errs, field.Required(p.Child("k3s", "tokenSecretRef", "key"), "must not be empty"))
	} else if messages := validation.IsConfigMapKey(n.Spec.K3s.TokenSecretRef.Key); len(messages) != 0 {
		errs = append(errs, field.Invalid(p.Child("k3s", "tokenSecretRef", "key"), n.Spec.K3s.TokenSecretRef.Key, strings.Join(messages, "; ")))
	} else if n.Spec.K3s.TokenSecretRef.Key != K3sAgentTokenSecretKey {
		errs = append(errs, field.NotSupported(p.Child("k3s", "tokenSecretRef", "key"), n.Spec.K3s.TokenSecretRef.Key, []string{K3sAgentTokenSecretKey}))
	}
	if err := ValidateSSHAccess(n.Spec.SSHUsername, n.Spec.SSHPublicKey); err != nil {
		errs = append(errs, field.Invalid(p.Child("sshPublicKey"), "", err.Error()))
	}
	if len(n.Spec.AdditionalUserData) > 65536 {
		errs = append(errs, field.TooLong(p.Child("additionalUserData"), "", 65536))
	}
	return errs
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

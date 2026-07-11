package v1alpha1

import (
	"net/url"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	k3sVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$`)
	serverHostPattern = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

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
	if len(n.Spec.AdditionalUserData) > 65536 {
		errs = append(errs, field.TooLong(p.Child("additionalUserData"), "", 65536))
	}
	return errs
}

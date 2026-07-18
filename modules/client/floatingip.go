package inspace

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var errSparseFloatingIPAssignment = errors.New("inspace: floating IP assignment tuple is sparse")

func (c *Client) ListFloatingIPs(ctx context.Context, location string, filters *FloatingIPFilters) ([]FloatingIP, error) {
	result, path, err := c.listFloatingIPsRaw(ctx, location, filters)
	result, err = validateFloatingIPCollectionShape(result, err, path)
	if err != nil {
		return result, err
	}
	for index := range result {
		identityErr := validateFloatingIPResponseIdentity(&result[index], "", true)
		if identityErr == nil {
			continue
		}
		if !errors.Is(identityErr, errSparseFloatingIPAssignment) {
			return nil, fmt.Errorf(
				"inspace: decode %s %s response: invalid list element %d identity: %w",
				http.MethodGet,
				path,
				index,
				identityErr,
			)
		}
		resolved, resolveErr := c.resolveSparseFloatingIPWithExactRead(ctx, location, result[index])
		if resolveErr != nil {
			return nil, fmt.Errorf(
				"inspace: decode %s %s response: sparse list element %d could not be authoritatively resolved: %w",
				http.MethodGet,
				path,
				index,
				resolveErr,
			)
		}
		result[index] = resolved
	}
	if filters != nil {
		for index := range result {
			if filters.BillingAccountID != 0 && result[index].BillingAccountID != filters.BillingAccountID {
				return nil, fmt.Errorf(
					"inspace: decode %s %s response: list element %d belongs to billing account %d, want filtered account %d",
					http.MethodGet,
					path,
					index,
					result[index].BillingAccountID,
					filters.BillingAccountID,
				)
			}
			if filters.VMUUID != "" &&
				(!strings.EqualFold(result[index].AssignedTo, filters.VMUUID) ||
					result[index].AssignedToResourceType != "virtual_machine") {
				return nil, fmt.Errorf(
					"inspace: decode %s %s response: list element %d does not belong to filtered VM %s",
					http.MethodGet,
					path,
					index,
					filters.VMUUID,
				)
			}
		}
	}
	return result, nil
}

func (c *Client) listFloatingIPsRaw(
	ctx context.Context,
	location string,
	filters *FloatingIPFilters,
) ([]FloatingIP, string, error) {
	path, err := c.locationPath(location, "network/ip_addresses")
	if err != nil {
		return nil, "", err
	}
	query := make(url.Values)
	if filters != nil {
		if filters.BillingAccountID != 0 {
			query.Set("billing_account_id", strconv.FormatInt(filters.BillingAccountID, 10))
		}
		if filters.VMUUID != "" {
			if err := validateUUID("VM", filters.VMUUID); err != nil {
				return nil, "", err
			}
			query.Set("vm_uuid", filters.VMUUID)
		}
	}
	var result []FloatingIP
	err = c.do(ctx, http.MethodGet, path, query, nil, &result)
	return result, path, err
}

func (c *Client) GetFloatingIP(ctx context.Context, location, address string) (*FloatingIP, error) {
	result, err := c.getFloatingIPRaw(ctx, location, address)
	if err != nil {
		return result, err
	}
	identityErr := validateFloatingIPResponseIdentity(result, address, true)
	if identityErr == nil {
		return result, nil
	}
	if !errors.Is(identityErr, errSparseFloatingIPAssignment) {
		return result, identityErr
	}
	resolved, resolveErr := c.resolveSparseFloatingIPWithListRead(ctx, location, *result)
	if resolveErr != nil {
		return result, fmt.Errorf(
			"inspace: exact floating IP %s returned a sparse assignment tuple that could not be authoritatively resolved: %w",
			address,
			resolveErr,
		)
	}
	return &resolved, nil
}

func (c *Client) getFloatingIPRaw(ctx context.Context, location, address string) (*FloatingIP, error) {
	if err := validatePublicIPv4(address); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/ip_addresses/"+address)
	if err != nil {
		return nil, err
	}
	var result FloatingIP
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	if err != nil {
		err = bindExactFloatingIPLookupError(err, address)
	}
	return &result, err
}

func (c *Client) CreateFloatingIP(ctx context.Context, location string, input CreateFloatingIPRequest) (*FloatingIP, error) {
	if input.BillingAccountID < 1 {
		return nil, errors.New("inspace: floating IP billing account ID is required")
	}
	path, err := c.locationPath(location, "network/ip_addresses")
	if err != nil {
		return nil, err
	}
	var result FloatingIP
	err = c.doJSON(ctx, http.MethodPost, path, nil, input, &result)
	if err != nil {
		return &result, err
	}
	identityErr := validateFloatingIPResponseIdentity(&result, "", false)
	if identityErr != nil && !errors.Is(identityErr, errSparseFloatingIPAssignment) {
		return &result, identityErr
	}
	if authorityErr := validateFloatingIPStableAuthority(&result, false); authorityErr != nil {
		return &result, fmt.Errorf("inspace: floating IP creation response is not authoritative: %w", authorityErr)
	}
	if result.BillingAccountID != input.BillingAccountID || result.Name != input.Name {
		return &result, fmt.Errorf(
			"inspace: floating IP creation response metadata %q/account-%d does not match requested metadata %q/account-%d",
			result.Name,
			result.BillingAccountID,
			input.Name,
			input.BillingAccountID,
		)
	}
	if identityErr == nil {
		if result.AssignedTo != "" || result.AssignedToResourceType != "" || result.AssignedToPrivateIP != "" {
			return &result, fmt.Errorf(
				"inspace: floating IP creation response unexpectedly reports assignment %q/%q/%q",
				result.AssignedTo,
				result.AssignedToResourceType,
				result.AssignedToPrivateIP,
			)
		}
		return &result, nil
	}
	readback, readbackErr := c.GetFloatingIP(ctx, location, result.Address)
	if readbackErr != nil {
		return &result, fmt.Errorf(
			"inspace: sparse floating IP creation response could not be corroborated by exact/list readback: %w",
			readbackErr,
		)
	}
	resolved, corroborationErr := corroborateSparseFloatingIP(result, *readback)
	if corroborationErr != nil {
		return &result, fmt.Errorf(
			"inspace: sparse floating IP creation response disagrees with readback: %w",
			corroborationErr,
		)
	}
	return &resolved, nil
}

// UpdateFloatingIP changes the stable display name and billing-account
// metadata for an existing address. InSpace auto-created VM addresses initially
// have no useful name, so controllers use this PATCH before adopting them.
func (c *Client) UpdateFloatingIP(ctx context.Context, location, address string, input UpdateFloatingIPRequest) (*FloatingIP, error) {
	if err := validatePublicIPv4(address); err != nil {
		return nil, err
	}
	if input.Name == "" {
		return nil, errors.New("inspace: floating IP name is required")
	}
	if input.BillingAccountID < 1 {
		return nil, errors.New("inspace: floating IP billing account ID is required")
	}
	path, err := c.locationPath(location, "network/ip_addresses/"+address)
	if err != nil {
		return nil, err
	}
	var result FloatingIP
	err = c.doJSON(ctx, http.MethodPatch, path, nil, input, &result)
	if err == nil {
		err = validateFloatingIPResponseIdentity(&result, address, false)
	}
	return &result, err
}

func (c *Client) AssignFloatingIP(ctx context.Context, location, address, resourceUUID, resourceType string) (*FloatingIP, error) {
	if err := validatePublicIPv4(address); err != nil {
		return nil, err
	}
	if err := validateUUID("resource", resourceUUID); err != nil {
		return nil, err
	}
	switch resourceType {
	case "virtual_machine", "service", "load_balancer":
	default:
		return nil, errors.New("inspace: floating IP resource type must be virtual_machine, service, or load_balancer")
	}
	path, err := c.locationPath(location, "network/ip_addresses/"+address+"/assign")
	if err != nil {
		return nil, err
	}
	var result FloatingIP
	err = c.doJSON(ctx, http.MethodPost, path, nil, map[string]string{
		"assigned_to": resourceUUID, "assigned_to_resource_type": resourceType,
	}, &result)
	if err == nil {
		err = validateFloatingIPResponseIdentity(&result, address, false)
	}
	if err == nil && (!strings.EqualFold(result.AssignedTo, resourceUUID) || result.AssignedToResourceType != resourceType) {
		err = fmt.Errorf(
			"inspace: floating IP assignment response does not match requested resource: got %q/%q, want %q/%q",
			result.AssignedTo,
			result.AssignedToResourceType,
			resourceUUID,
			resourceType,
		)
	}
	return &result, err
}

func (c *Client) UnassignFloatingIP(ctx context.Context, location, address string) (*FloatingIP, error) {
	if err := validatePublicIPv4(address); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/ip_addresses/"+address+"/unassign")
	if err != nil {
		return nil, err
	}
	var result FloatingIP
	err = c.doJSON(ctx, http.MethodPost, path, nil, nil, &result)
	if err != nil {
		return &result, err
	}
	identityErr := validateFloatingIPResponseIdentity(&result, address, false)
	if identityErr != nil {
		if !errors.Is(identityErr, errSparseFloatingIPAssignment) {
			return &result, identityErr
		}
		// The live unassign endpoint can omit the complete assignment tuple.
		// Treat that body only as a stable mutation receipt and require the
		// existing exact/list read path to prove the resulting relationship.
		if authorityErr := validateSparseFloatingIPAuthority(&result, false); authorityErr != nil {
			return &result, fmt.Errorf(
				"inspace: sparse floating IP unassignment response is not authoritative: %w",
				authorityErr,
			)
		}
		readback, readbackErr := c.GetFloatingIP(ctx, location, address)
		if readbackErr != nil {
			return &result, fmt.Errorf(
				"inspace: sparse floating IP unassignment response could not be corroborated by exact/list readback: %w",
				readbackErr,
			)
		}
		resolved, corroborationErr := corroborateSparseFloatingIP(result, *readback)
		if corroborationErr != nil {
			return &result, fmt.Errorf(
				"inspace: sparse floating IP unassignment response disagrees with readback: %w",
				corroborationErr,
			)
		}
		result = resolved
	}
	if result.AssignedTo != "" ||
		result.AssignedToResourceType != "" ||
		result.AssignedToPrivateIP != "" {
		return &result, fmt.Errorf(
			"inspace: floating IP unassignment response/readback still reports resource %q/%q/%q",
			result.AssignedTo,
			result.AssignedToResourceType,
			result.AssignedToPrivateIP,
		)
	}
	return &result, nil
}

func (c *Client) DeleteFloatingIP(ctx context.Context, location, address string) error {
	if err := validatePublicIPv4(address); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/ip_addresses/"+address)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func validatePublicIPv4(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return errors.New("inspace: floating IP address must be a public IPv4 address")
	}
	return nil
}

func validateFloatingIPResponseIdentity(result *FloatingIP, expectedAddress string, allowOmittedUnassigned bool) error {
	if err := validateFloatingIPBaseIdentity(result, expectedAddress); err != nil {
		return err
	}
	if !result.assignedToPresent {
		if result.AssignedTo != "" ||
			result.assignedTypePresent ||
			result.AssignedToResourceType != "" ||
			result.assignedPrivatePresent ||
			result.AssignedToPrivateIP != "" {
			return fmt.Errorf(
				"inspace: malformed omitted-assignment floating IP response: assigned resource/type/private IP is %q/%q/%q",
				result.AssignedTo,
				result.AssignedToResourceType,
				result.AssignedToPrivateIP,
			)
		}
		if allowOmittedUnassigned && result.UnassignedAt != "" {
			return nil
		}
		if allowOmittedUnassigned && result.assignmentCorroborated {
			return nil
		}
		// A complete tombstone does not need unassignment inference: callers
		// consume IsDeleted as deletion evidence and must not mutate it again.
		// Keep mutation responses strict by applying this only to read paths.
		if allowOmittedUnassigned && result.IsDeleted {
			if err := validateSparseFloatingIPAuthority(result, true); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf(
			"%w: assigned_to, assigned_to_resource_type, and assigned_to_private_ip are omitted without authoritative unassignment",
			errSparseFloatingIPAssignment,
		)
	}
	if result.AssignedTo == "" {
		if result.AssignedToResourceType != "" || result.AssignedToPrivateIP != "" {
			return fmt.Errorf(
				"inspace: malformed unassigned floating IP response: resource type/private IP is %q/%q",
				result.AssignedToResourceType,
				result.AssignedToPrivateIP,
			)
		}
		return nil
	}
	if !result.assignedTypePresent {
		return errors.New("inspace: malformed assigned floating IP response: assigned_to_resource_type field is omitted")
	}
	if err := validateResponseUUID("floating IP assigned resource", result.AssignedTo); err != nil {
		return err
	}
	switch result.AssignedToResourceType {
	case "virtual_machine", "service", "load_balancer":
	default:
		return fmt.Errorf(
			"inspace: malformed floating IP response resource type %q",
			result.AssignedToResourceType,
		)
	}
	if result.AssignedToPrivateIP != "" {
		privateAddress, err := netip.ParseAddr(result.AssignedToPrivateIP)
		if err != nil || !privateAddress.Is4() || !privateAddress.IsPrivate() {
			return fmt.Errorf(
				"inspace: malformed floating IP response private address %q",
				result.AssignedToPrivateIP,
			)
		}
	}
	return nil
}

func validateFloatingIPBaseIdentity(result *FloatingIP, expectedAddress string) error {
	if result == nil {
		return errors.New("inspace: floating IP response is nil")
	}
	if err := validatePublicIPv4(result.Address); err != nil {
		return fmt.Errorf("inspace: malformed floating IP response identity: %w", err)
	}
	if expectedAddress != "" && result.Address != expectedAddress {
		return fmt.Errorf("inspace: floating IP response address %q does not match expected address %q", result.Address, expectedAddress)
	}
	if result.UUID != "" {
		if err := validateResponseUUID("floating IP", result.UUID); err != nil {
			return err
		}
	}
	return nil
}

func validateFloatingIPCollectionShape(
	result []FloatingIP,
	err error,
	path string,
) ([]FloatingIP, error) {
	return validatedListResponse(result, err, http.MethodGet, path, func(address FloatingIP) (string, error) {
		if err := validateFloatingIPBaseIdentity(&address, ""); err != nil {
			return "", err
		}
		assignmentErr := validateFloatingIPResponseIdentity(&address, "", true)
		if assignmentErr != nil && !errors.Is(assignmentErr, errSparseFloatingIPAssignment) {
			return "", assignmentErr
		}
		return address.Address, nil
	})
}

func validateSparseFloatingIPAuthority(result *FloatingIP, allowDeleted bool) error {
	if err := validateFloatingIPStableAuthority(result, allowDeleted); err != nil {
		return err
	}
	if result.assignedToPresent ||
		result.assignedTypePresent ||
		result.assignedPrivatePresent ||
		result.AssignedTo != "" ||
		result.AssignedToResourceType != "" ||
		result.AssignedToPrivateIP != "" {
		return errors.New("inspace: floating IP response is not a wholly sparse assignment tuple")
	}
	return nil
}

func validateFloatingIPStableAuthority(result *FloatingIP, allowDeleted bool) error {
	if err := validateFloatingIPBaseIdentity(result, ""); err != nil {
		return err
	}
	if !result.stableIdentityPresent {
		return errors.New("inspace: floating IP response omits a required stable identity field")
	}
	if result.UUID == "" {
		return errors.New("inspace: floating IP response has no UUID authority")
	}
	if result.ID < 1 || result.UserID < 1 || result.BillingAccountID < 1 {
		return fmt.Errorf(
			"inspace: floating IP response has incomplete numeric identity %d/user-%d/account-%d",
			result.ID,
			result.UserID,
			result.BillingAccountID,
		)
	}
	if result.Type != "public" {
		return fmt.Errorf("inspace: floating IP response has non-public type %q", result.Type)
	}
	if !result.isIPv6Present || result.IsIPv6 {
		return errors.New("inspace: public IPv4 response has missing or true is_ipv6")
	}
	if result.IsDeleted && !allowDeleted {
		return errors.New("inspace: floating IP response is deleted")
	}
	if strings.TrimSpace(result.CreatedAt) == "" || strings.TrimSpace(result.UpdatedAt) == "" {
		return errors.New("inspace: floating IP response has incomplete creation/update identity")
	}
	return nil
}

// ValidateFloatingIPStableReadback verifies that one active read result carries
// the complete stable allocation identity and an authoritative assignment
// tuple. It is intentionally stricter than ordinary discovery, where sparse
// relationship fields can be corroborated by a second endpoint.
func ValidateFloatingIPStableReadback(result FloatingIP) error {
	return validateFloatingIPStableReadback(result, false)
}

func validateFloatingIPStableReadback(result FloatingIP, allowMissingIsVirtual bool) error {
	if err := validateFloatingIPStableAuthority(&result, false); err != nil {
		return err
	}
	if !result.isVirtualPresent && !allowMissingIsVirtual {
		return errors.New("inspace: floating IP response omits is_virtual")
	}
	if err := validateFloatingIPResponseIdentity(&result, result.Address, false); err != nil {
		return err
	}
	return nil
}

// ValidateFloatingIPStableReadbackMatch requires exact and list endpoints to
// agree on the full stable allocation identity and relationship state. Live
// reads can omit optional is_virtual from both endpoints; omission is accepted
// only with that two-source agreement, while standalone validation remains
// strict.
func ValidateFloatingIPStableReadbackMatch(exact, listed FloatingIP) error {
	if exact.isVirtualPresent != listed.isVirtualPresent {
		return fmt.Errorf(
			"inspace: exact and list floating IP identities disagree on is_virtual presence for %s",
			exact.Address,
		)
	}
	allowMissingIsVirtual := !exact.isVirtualPresent
	if err := validateFloatingIPStableReadback(exact, allowMissingIsVirtual); err != nil {
		return fmt.Errorf("exact floating IP identity is incomplete: %w", err)
	}
	if err := validateFloatingIPStableReadback(listed, allowMissingIsVirtual); err != nil {
		return fmt.Errorf("listed floating IP identity is incomplete: %w", err)
	}
	equal := exact.UUID == listed.UUID &&
		exact.ID == listed.ID &&
		exact.Address == listed.Address &&
		exact.UserID == listed.UserID &&
		exact.BillingAccountID == listed.BillingAccountID &&
		exact.Type == listed.Type &&
		exact.Name == listed.Name &&
		exact.Enabled == listed.Enabled &&
		exact.IsDeleted == listed.IsDeleted &&
		exact.IsIPv6 == listed.IsIPv6 &&
		exact.IsVirtual == listed.IsVirtual &&
		exact.AssignedTo == listed.AssignedTo &&
		exact.AssignedToResourceType == listed.AssignedToResourceType &&
		exact.AssignedToPrivateIP == listed.AssignedToPrivateIP &&
		exact.CreatedAt == listed.CreatedAt &&
		exact.UpdatedAt == listed.UpdatedAt &&
		exact.UnassignedAt == listed.UnassignedAt &&
		exact.assignedToPresent == listed.assignedToPresent &&
		exact.assignedTypePresent == listed.assignedTypePresent &&
		exact.assignedPrivatePresent == listed.assignedPrivatePresent &&
		exact.assignmentCorroborated == listed.assignmentCorroborated &&
		exact.stableIdentityPresent == listed.stableIdentityPresent &&
		exact.isIPv6Present == listed.isIPv6Present &&
		exact.isVirtualPresent == listed.isVirtualPresent
	if !equal {
		return fmt.Errorf(
			"inspace: exact and list floating IP identities disagree for %s (UUID/ID/name/VM %q/%d/%q/%q versus %q/%d/%q/%q)",
			exact.Address,
			exact.UUID,
			exact.ID,
			exact.Name,
			exact.AssignedTo,
			listed.UUID,
			listed.ID,
			listed.Name,
			listed.AssignedTo,
		)
	}
	return nil
}

func validateFloatingIPStableIdentityMatch(left, right FloatingIP) error {
	if err := validateSparseFloatingIPAuthority(&left, false); err != nil {
		return fmt.Errorf("primary sparse representation is not authoritative: %w", err)
	}
	if err := validateFloatingIPStableAuthority(&right, false); err != nil {
		return fmt.Errorf("corroborating floating IP representation is not authoritative: %w", err)
	}
	if left.Address != right.Address ||
		!strings.EqualFold(left.UUID, right.UUID) ||
		left.ID != right.ID ||
		left.UserID != right.UserID ||
		left.BillingAccountID != right.BillingAccountID ||
		left.Type != right.Type ||
		left.Name != right.Name ||
		left.Enabled != right.Enabled ||
		left.IsDeleted != right.IsDeleted ||
		left.IsIPv6 != right.IsIPv6 ||
		left.isIPv6Present != right.isIPv6Present ||
		left.IsVirtual != right.IsVirtual ||
		left.isVirtualPresent != right.isVirtualPresent ||
		left.CreatedAt != right.CreatedAt ||
		left.UpdatedAt != right.UpdatedAt {
		return fmt.Errorf(
			"inspace: floating IP sparse-read identity mismatch for address %s (UUID/name/account %q/%q/%d versus %q/%q/%d)",
			left.Address,
			left.UUID,
			left.Name,
			left.BillingAccountID,
			right.UUID,
			right.Name,
			right.BillingAccountID,
		)
	}
	return nil
}

func corroborateSparseFloatingIP(primary, corroborating FloatingIP) (FloatingIP, error) {
	if err := validateFloatingIPStableIdentityMatch(primary, corroborating); err != nil {
		return primary, err
	}
	assignmentErr := validateFloatingIPResponseIdentity(&corroborating, primary.Address, true)
	if assignmentErr == nil {
		return corroborating, nil
	}
	if !errors.Is(assignmentErr, errSparseFloatingIPAssignment) {
		return primary, assignmentErr
	}
	// Preserve a private proof bit on the returned value. Zero-value or
	// caller-constructed FloatingIP structs cannot acquire unassignment
	// authority merely by omitting the relationship fields.
	corroborating.assignmentCorroborated = true
	return corroborating, nil
}

func (c *Client) resolveSparseFloatingIPWithExactRead(
	ctx context.Context,
	location string,
	listed FloatingIP,
) (FloatingIP, error) {
	if err := validateSparseFloatingIPAuthority(&listed, false); err != nil {
		return listed, err
	}
	exact, err := c.getFloatingIPRaw(ctx, location, listed.Address)
	if err != nil {
		return listed, fmt.Errorf("reading exact floating IP: %w", err)
	}
	return corroborateSparseFloatingIP(listed, *exact)
}

func (c *Client) resolveSparseFloatingIPWithListRead(
	ctx context.Context,
	location string,
	exact FloatingIP,
) (FloatingIP, error) {
	if err := validateSparseFloatingIPAuthority(&exact, false); err != nil {
		return exact, err
	}
	listed, path, err := c.listFloatingIPsRaw(ctx, location, &FloatingIPFilters{
		BillingAccountID: exact.BillingAccountID,
	})
	listed, err = validateFloatingIPCollectionShape(listed, err, path)
	if err != nil {
		return exact, fmt.Errorf("reading floating IP collection for corroboration: %w", err)
	}
	var match *FloatingIP
	for index := range listed {
		if listed[index].Address != exact.Address {
			continue
		}
		if match != nil {
			return exact, fmt.Errorf("floating IP %s appears more than once in corroborating collection", exact.Address)
		}
		candidate := listed[index]
		match = &candidate
	}
	if match == nil {
		return exact, fmt.Errorf("floating IP %s is absent from corroborating collection", exact.Address)
	}
	return corroborateSparseFloatingIP(exact, *match)
}

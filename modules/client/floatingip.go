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

func (c *Client) ListFloatingIPs(ctx context.Context, location string, filters *FloatingIPFilters) ([]FloatingIP, error) {
	path, err := c.locationPath(location, "network/ip_addresses")
	if err != nil {
		return nil, err
	}
	query := make(url.Values)
	if filters != nil {
		if filters.BillingAccountID != 0 {
			query.Set("billing_account_id", strconv.FormatInt(filters.BillingAccountID, 10))
		}
		if filters.VMUUID != "" {
			if err := validateUUID("VM", filters.VMUUID); err != nil {
				return nil, err
			}
			query.Set("vm_uuid", filters.VMUUID)
		}
	}
	var result []FloatingIP
	err = c.do(ctx, http.MethodGet, path, query, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(address FloatingIP) (string, error) {
		if err := validateFloatingIPResponseIdentity(&address, ""); err != nil {
			return "", err
		}
		return address.Address, nil
	})
}

func (c *Client) GetFloatingIP(ctx context.Context, location, address string) (*FloatingIP, error) {
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
	} else {
		err = validateFloatingIPResponseIdentity(&result, address)
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
	if err == nil {
		err = validateFloatingIPResponseIdentity(&result, "")
	}
	return &result, err
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
		err = validateFloatingIPResponseIdentity(&result, address)
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
		err = validateFloatingIPResponseIdentity(&result, address)
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
	if err == nil {
		err = validateFloatingIPResponseIdentity(&result, address)
	}
	if err == nil && (result.AssignedTo != "" || result.AssignedToResourceType != "") {
		err = fmt.Errorf(
			"inspace: floating IP unassignment response still reports resource %q/%q",
			result.AssignedTo,
			result.AssignedToResourceType,
		)
	}
	return &result, err
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

func validateFloatingIPResponseIdentity(result *FloatingIP, expectedAddress string) error {
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
	if !result.assignedToPresent {
		return errors.New("inspace: malformed floating IP response: assigned_to field is omitted")
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

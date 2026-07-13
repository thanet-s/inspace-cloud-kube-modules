package inspace

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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
	return result, err
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

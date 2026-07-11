package inspace

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
)

func (c *Client) ListFirewalls(ctx context.Context, location string) ([]Firewall, error) {
	path, err := c.locationPath(location, "network/firewalls")
	if err != nil {
		return nil, err
	}
	var result []Firewall
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

func (c *Client) GetFirewall(ctx context.Context, location, firewallUUID string) (*Firewall, error) {
	if err := validateUUID("firewall", firewallUUID); err != nil {
		return nil, err
	}
	// InSpace documents no GET-by-ID firewall endpoint (it returns 405).
	// Preserve a convenient SDK lookup without relying on an undocumented route.
	items, err := c.ListFirewalls(ctx, location)
	if err != nil {
		return nil, err
	}
	for i := range items {
		if items[i].UUID == firewallUUID {
			return &items[i], nil
		}
	}
	return nil, &APIError{StatusCode: http.StatusNotFound, Method: http.MethodGet, Path: "/network/firewalls", Message: "firewall not found"}
}

func (c *Client) CreateFirewall(ctx context.Context, location string, input CreateFirewallRequest) (*Firewall, error) {
	if input.DisplayName == "" {
		return nil, errors.New("inspace: firewall display name is required")
	}
	if len(input.Rules) == 0 {
		return nil, errors.New("inspace: firewall must have at least one rule")
	}
	for _, rule := range input.Rules {
		if err := validateFirewallRule(rule); err != nil {
			return nil, err
		}
	}
	path, err := c.locationPath(location, "network/firewalls")
	if err != nil {
		return nil, err
	}
	var result Firewall
	err = c.doJSON(ctx, http.MethodPost, path, nil, input, &result)
	return &result, err
}

func (c *Client) DeleteFirewall(ctx context.Context, location, firewallUUID string) error {
	if err := validateUUID("firewall", firewallUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/firewalls/"+firewallUUID)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) AssignFirewallToVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if err := validateUUID("firewall", firewallUUID); err != nil {
		return err
	}
	if err := validateUUID("VM", vmUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/firewalls/"+firewallUUID+"/vms")
	if err != nil {
		return err
	}
	var result []FirewallResource
	err = c.doJSON(ctx, http.MethodPost, path, url.Values{"vm_uuid": {vmUUID}}, nil, &result)
	return err
}

func (c *Client) UnassignFirewallFromVM(ctx context.Context, location, firewallUUID, vmUUID string) error {
	if err := validateUUID("firewall", firewallUUID); err != nil {
		return err
	}
	if err := validateUUID("VM", vmUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/firewalls/"+firewallUUID+"/vms")
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, url.Values{"vm_uuid": {vmUUID}}, nil, nil)
}

func validateFirewallRule(rule FirewallRule) error {
	switch rule.Protocol {
	case "tcp", "udp", "icmp":
	default:
		return errors.New("inspace: firewall protocol must be tcp, udp, or icmp")
	}
	if rule.Direction != "inbound" && rule.Direction != "outbound" {
		return errors.New("inspace: firewall direction must be inbound or outbound")
	}
	if rule.EndpointSpecType != "any" && rule.EndpointSpecType != "ip_prefixes" {
		return errors.New("inspace: firewall endpoint spec type must be any or ip_prefixes")
	}
	if rule.EndpointSpecType == "ip_prefixes" && len(rule.EndpointSpec) == 0 {
		return errors.New("inspace: ip_prefixes firewall rule requires endpoint prefixes")
	}
	for _, endpoint := range rule.EndpointSpec {
		if _, err := netip.ParsePrefix(endpoint); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(endpoint); err != nil {
			return errors.New("inspace: firewall endpoint must be an IP address or CIDR prefix")
		}
	}
	if rule.PortStart != nil && (*rule.PortStart < 1 || *rule.PortStart > 65535) {
		return errors.New("inspace: firewall port_start must be between 1 and 65535")
	}
	if rule.PortEnd != nil && (*rule.PortEnd < 1 || *rule.PortEnd > 65535) {
		return errors.New("inspace: firewall port_end must be between 1 and 65535")
	}
	if rule.PortStart != nil && rule.PortEnd != nil && *rule.PortStart > *rule.PortEnd {
		return errors.New("inspace: firewall port_start must not exceed port_end")
	}
	return nil
}

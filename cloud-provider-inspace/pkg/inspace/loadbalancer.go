package inspace

import (
	"context"
	"errors"
	"net/http"
	"strconv"
)

func (c *Client) ListLoadBalancers(ctx context.Context, location string) ([]LoadBalancer, error) {
	path, err := c.locationPath(location, "network/load_balancers")
	if err != nil {
		return nil, err
	}
	var result []LoadBalancer
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

func (c *Client) GetLoadBalancer(ctx context.Context, location, loadBalancerUUID string) (*LoadBalancer, error) {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID)
	if err != nil {
		return nil, err
	}
	var result LoadBalancer
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return &result, err
}

func (c *Client) CreateLoadBalancer(ctx context.Context, location string, input CreateLoadBalancerRequest) (*LoadBalancer, error) {
	if input.DisplayName == "" {
		return nil, errors.New("inspace: load balancer display name is required")
	}
	if err := validateUUID("network", input.NetworkUUID); err != nil {
		return nil, err
	}
	if err := validateRules(input.Rules); err != nil {
		return nil, err
	}
	for _, target := range input.Targets {
		if target.TargetType != "vm" {
			return nil, errors.New("inspace: load balancer target type must be vm")
		}
		if err := validateUUID("target", target.TargetUUID); err != nil {
			return nil, err
		}
	}
	path, err := c.locationPath(location, "network/load_balancers")
	if err != nil {
		return nil, err
	}
	var result LoadBalancer
	err = c.doJSON(ctx, http.MethodPost, path, nil, input, &result)
	return &result, err
}

func (c *Client) DeleteLoadBalancer(ctx context.Context, location, loadBalancerUUID string) error {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) AddLoadBalancerTarget(ctx context.Context, location, loadBalancerUUID, vmUUID string) (*LoadBalancerTarget, error) {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return nil, err
	}
	if err := validateUUID("VM", vmUUID); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID+"/targets")
	if err != nil {
		return nil, err
	}
	var result LoadBalancerTarget
	err = c.doJSON(ctx, http.MethodPost, path, nil, LoadBalancerTarget{TargetUUID: vmUUID, TargetType: "vm"}, &result)
	return &result, err
}

func (c *Client) RemoveLoadBalancerTarget(ctx context.Context, location, loadBalancerUUID, vmUUID string) error {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return err
	}
	if err := validateUUID("VM", vmUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID+"/targets/"+vmUUID)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) AddLoadBalancerRule(ctx context.Context, location, loadBalancerUUID string, rule LoadBalancerRule) (*LoadBalancerRule, error) {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return nil, err
	}
	if err := validateRules([]LoadBalancerRule{rule}); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID+"/forwarding_rules")
	if err != nil {
		return nil, err
	}
	var result LoadBalancerRule
	err = c.doJSON(ctx, http.MethodPost, path, nil, rule, &result)
	return &result, err
}

func (c *Client) RemoveLoadBalancerRule(ctx context.Context, location, loadBalancerUUID, ruleUUID string) error {
	if err := validateUUID("load balancer", loadBalancerUUID); err != nil {
		return err
	}
	if err := validateUUID("forwarding rule", ruleUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "network/load_balancers/"+loadBalancerUUID+"/forwarding_rules/"+ruleUUID)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func validateRules(rules []LoadBalancerRule) error {
	seen := make(map[int32]struct{}, len(rules))
	for _, rule := range rules {
		if rule.SourcePort < 1 || rule.SourcePort > 65535 || rule.TargetPort < 1 || rule.TargetPort > 65535 {
			return errors.New("inspace: load balancer ports must be between 1 and 65535")
		}
		if rule.Protocol != "" && rule.Protocol != "TCP" {
			return errors.New("inspace: load balancer supports TCP only")
		}
		if _, ok := seen[rule.SourcePort]; ok {
			return errors.New("inspace: duplicate load balancer source port " + strconv.Itoa(int(rule.SourcePort)))
		}
		seen[rule.SourcePort] = struct{}{}
	}
	return nil
}

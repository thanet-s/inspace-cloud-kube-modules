package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) ListLocations(ctx context.Context) ([]Location, error) {
	var result []Location
	err := c.do(ctx, http.MethodGet, "/v1/config/locations", nil, nil, &result)
	return result, err
}

func (c *Client) ListHostPools(ctx context.Context, location string) ([]HostPool, error) {
	path, err := c.locationPath(location, "user-resource/host_pool/list")
	if err != nil {
		return nil, err
	}
	var result []HostPool
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

func (c *Client) ListVMs(ctx context.Context, location string) ([]VM, error) {
	path, err := c.locationPath(location, "user-resource/vm/list")
	if err != nil {
		return nil, err
	}
	var result []VM
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

func (c *Client) GetVM(ctx context.Context, location, uuid string) (*VM, error) {
	if err := validateUUID("VM", uuid); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "user-resource/vm")
	if err != nil {
		return nil, err
	}
	var result VM
	err = c.do(ctx, http.MethodGet, path, url.Values{"uuid": {uuid}}, nil, &result)
	return &result, err
}

func (c *Client) CreateVM(ctx context.Context, location string, input CreateVMRequest) (*VM, error) {
	if input.Name == "" || input.OSName == "" || input.OSVersion == "" {
		return nil, errors.New("inspace: VM name, OS name, and OS version are required")
	}
	if input.VCPU <= 0 || input.MemoryMiB <= 0 || input.DiskGiB <= 0 {
		return nil, errors.New("inspace: VM vCPU, memory, and disk must be positive")
	}
	if input.CloudInit != "" && input.CloudInitJSON != "" {
		return nil, errors.New("inspace: set only one of CloudInit or CloudInitJSON")
	}
	path, err := c.locationPath(location, "user-resource/vm")
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"name":       {input.Name},
		"os_name":    {input.OSName},
		"os_version": {input.OSVersion},
		"disks":      {strconv.Itoa(input.DiskGiB)},
		"vcpu":       {strconv.Itoa(input.VCPU)},
		"ram":        {strconv.Itoa(input.MemoryMiB)},
	}
	setOptional(form, "description", input.Description)
	setOptional(form, "designated_pool_uuid", input.DesignatedPoolUUID)
	setOptional(form, "username", input.Username)
	setOptional(form, "password", input.Password)
	setOptional(form, "public_key", input.PublicKey)
	setOptional(form, "network_uuid", input.NetworkUUID)
	cloudInit := input.CloudInit
	if cloudInit == "" {
		cloudInit = input.CloudInitJSON
	}
	if cloudInit != "" {
		var object map[string]any
		if err := json.Unmarshal([]byte(cloudInit), &object); err != nil || object == nil {
			return nil, errors.New("inspace: cloud init must be a JSON object")
		}
		form.Set("cloud_init", cloudInit)
	}
	if input.BillingAccountID != 0 {
		form.Set("billing_account_id", strconv.FormatInt(input.BillingAccountID, 10))
	}
	if input.ReservePublicIP != nil {
		form.Set("reserve_public_ip", strconv.FormatBool(*input.ReservePublicIP))
	}
	var result VM
	err = c.do(ctx, http.MethodPost, path, nil, form, &result)
	return &result, err
}

func (c *Client) DeleteVM(ctx context.Context, location, uuid string) error {
	if err := validateUUID("VM", uuid); err != nil {
		return err
	}
	path, err := c.locationPath(location, "user-resource/vm")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, path, nil, url.Values{"uuid": {uuid}}, nil)
}

func setOptional(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

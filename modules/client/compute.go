package inspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (c *Client) ListLocations(ctx context.Context) ([]Location, error) {
	const path = "/v1/config/locations"
	var result []Location
	err := c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(location Location) (string, error) {
		if !locationPattern.MatchString(location.Slug) {
			return "", errors.New("inspace: invalid location slug")
		}
		return location.Slug, nil
	})
}

func (c *Client) ListHostPools(ctx context.Context, location string) ([]HostPool, error) {
	path, err := c.locationPath(location, "user-resource/host_pool/list")
	if err != nil {
		return nil, err
	}
	var result []HostPool
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(pool HostPool) (string, error) {
		return validatedUUIDListIdentity("host pool", pool.UUID)
	})
}

func (c *Client) ListVMs(ctx context.Context, location string) ([]VM, error) {
	path, err := c.locationPath(location, "user-resource/vm/list")
	if err != nil {
		return nil, err
	}
	var result []VM
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(vm VM) (string, error) {
		if strings.TrimSpace(vm.Name) == "" {
			return "", errors.New("inspace: VM list row has an empty name")
		}
		if strings.TrimSpace(vm.Status) == "" {
			return "", errors.New("inspace: VM list row has an empty status")
		}
		return validatedUUIDListIdentity("VM", vm.UUID)
	})
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
	if err != nil {
		err = bindExactLookupError(err, uuid)
	} else if !strings.EqualFold(result.UUID, uuid) {
		err = fmt.Errorf("inspace: exact VM response UUID %q does not match requested UUID %q", result.UUID, uuid)
	}
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
	if err == nil {
		err = validateResponseUUID("created VM", result.UUID)
	}
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

// StopVM requests a graceful ACPI shutdown. It never forces: a forced stop can
// corrupt the guest, so the API's force flag is deliberately not exposed. The
// call can block past a minute while the guest shuts down, so a transport
// timeout is ambiguous and callers must read the VM status back instead.
func (c *Client) StopVM(ctx context.Context, location, uuid string) error {
	return c.vmPower(ctx, location, uuid, "stop")
}

// StartVM boots a stopped VM. Its private and floating addresses, UUID, and
// disks are unchanged. Like StopVM, a transport timeout is ambiguous.
func (c *Client) StartVM(ctx context.Context, location, uuid string) error {
	return c.vmPower(ctx, location, uuid, "start")
}

func (c *Client) vmPower(ctx context.Context, location, uuid, action string) error {
	if err := validateUUID("VM", uuid); err != nil {
		return err
	}
	path, err := c.locationPath(location, "user-resource/vm/"+action)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, nil, url.Values{"uuid": {uuid}}, nil)
}

// UpdateVMCompute sets the absolute vCPU count and memory of a VM. InSpace only
// accepts it while the VM is stopped. The response is verified so a silently
// ignored resize is never reported as applied.
func (c *Client) UpdateVMCompute(ctx context.Context, location, uuid string, vcpu, memoryMiB int) (*VM, error) {
	if vcpu <= 0 || memoryMiB <= 0 {
		return nil, errors.New("inspace: VM vCPU and memory must be positive")
	}
	if err := validateUUID("VM", uuid); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "user-resource/vm")
	if err != nil {
		return nil, err
	}
	var result VM
	err = c.do(ctx, http.MethodPatch, path, nil, url.Values{
		"uuid": {uuid},
		"vcpu": {strconv.Itoa(vcpu)},
		"ram":  {strconv.Itoa(memoryMiB)},
	}, &result)
	if err == nil {
		err = validateExpectedResponseUUID("resized VM", result.UUID, uuid)
	}
	if err == nil && (result.VCPU != vcpu || result.MemoryMiB != memoryMiB) {
		err = fmt.Errorf("inspace: resized VM %s reports %d vCPU and %d MiB, want %d vCPU and %d MiB", uuid, result.VCPU, result.MemoryMiB, vcpu, memoryMiB)
	}
	return &result, err
}

func setOptional(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

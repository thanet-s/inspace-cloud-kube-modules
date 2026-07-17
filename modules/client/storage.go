package inspace

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// CreateDisk creates location-scoped block storage. CSI currently uses EMPTY
// disks only, while the SDK retains the documented image-copy fields.
func (c *Client) CreateDisk(ctx context.Context, location string, input CreateDiskRequest) (*Disk, error) {
	if input.SizeGiB <= 0 {
		return nil, errors.New("inspace: disk size must be positive")
	}
	sourceType := strings.ToUpper(strings.TrimSpace(input.SourceImageType))
	if sourceType == "" {
		sourceType = "EMPTY"
	}
	switch sourceType {
	case "EMPTY", "OS_BASE", "DISK", "SNAPSHOT":
	default:
		return nil, errors.New("inspace: disk source image type must be EMPTY, OS_BASE, DISK, or SNAPSHOT")
	}
	if sourceType != "EMPTY" && input.SourceImage == "" {
		return nil, errors.New("inspace: source image is required for non-empty disks")
	}
	path, err := c.locationPath(location, "storage/disks")
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"size_gb":           {strconv.Itoa(input.SizeGiB)},
		"source_image_type": {sourceType},
	}
	setOptional(form, "display_name", input.DisplayName)
	setOptional(form, "source_image", input.SourceImage)
	if input.BillingAccountID != 0 {
		form.Set("billing_account_id", strconv.FormatInt(input.BillingAccountID, 10))
	}
	var result Disk
	err = c.do(ctx, http.MethodPost, path, nil, form, &result)
	if err == nil {
		err = validateResponseUUID("created disk", result.UUID)
	}
	return &result, err
}

func (c *Client) GetDisk(ctx context.Context, location, diskUUID string) (*Disk, error) {
	if err := validateUUID("disk", diskUUID); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "storage/disks/"+diskUUID)
	if err != nil {
		return nil, err
	}
	var result Disk
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	if err != nil {
		err = bindExactLookupError(err, diskUUID)
	} else if !strings.EqualFold(result.UUID, diskUUID) {
		err = fmt.Errorf("inspace: exact disk response UUID %q does not match requested UUID %q", result.UUID, diskUUID)
	}
	return &result, err
}

func (c *Client) ListDisks(ctx context.Context, location string) ([]Disk, error) {
	path, err := c.locationPath(location, "storage/disks")
	if err != nil {
		return nil, err
	}
	var result []Disk
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(disk Disk) (string, error) {
		return validatedUUIDListIdentity("disk", disk.UUID)
	})
}

func (c *Client) DeleteDisk(ctx context.Context, location, diskUUID string) error {
	if err := validateUUID("disk", diskUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "storage/disks/"+diskUUID)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *Client) AttachDisk(ctx context.Context, location, vmUUID, diskUUID string) (*VMStorage, error) {
	if err := validateUUID("VM", vmUUID); err != nil {
		return nil, err
	}
	if err := validateUUID("disk", diskUUID); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "user-resource/vm/storage/attach")
	if err != nil {
		return nil, err
	}
	var result VMStorage
	err = c.do(ctx, http.MethodPost, path, nil, url.Values{
		"uuid":         {vmUUID},
		"storage_uuid": {diskUUID},
	}, &result)
	if err == nil {
		err = validateExpectedResponseUUID("attached disk", result.UUID, diskUUID)
	}
	return &result, err
}

func (c *Client) DetachDisk(ctx context.Context, location, vmUUID, diskUUID string) error {
	if err := validateUUID("VM", vmUUID); err != nil {
		return err
	}
	if err := validateUUID("disk", diskUUID); err != nil {
		return err
	}
	path, err := c.locationPath(location, "user-resource/vm/storage/detach")
	if err != nil {
		return err
	}
	var result struct {
		Success bool `json:"success"`
	}
	if err := c.do(ctx, http.MethodPost, path, nil, url.Values{
		"uuid":         {vmUUID},
		"storage_uuid": {diskUUID},
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return errors.New("inspace: detach disk response reported failure")
	}
	return nil
}

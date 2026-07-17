package inspace

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func (c *Client) GetNetwork(ctx context.Context, location, networkUUID string) (*Network, error) {
	if err := validateUUID("network", networkUUID); err != nil {
		return nil, err
	}
	path, err := c.locationPath(location, "network/network/"+networkUUID)
	if err != nil {
		return nil, err
	}
	var result Network
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	if err != nil {
		err = bindExactLookupError(err, networkUUID)
	} else if !strings.EqualFold(result.UUID, networkUUID) {
		err = fmt.Errorf("inspace: exact network response UUID %q does not match requested UUID %q", result.UUID, networkUUID)
	}
	return &result, err
}

func (c *Client) ListNetworks(ctx context.Context, location string) ([]Network, error) {
	path, err := c.locationPath(location, "network/networks")
	if err != nil {
		return nil, err
	}
	var result []Network
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(network Network) (string, error) {
		return validatedUUIDListIdentity("network", network.UUID)
	})
}

// ListVMImages returns the global stock OS catalog. VM creation uses OSName
// and OSVersion from these entries rather than an image UUID.
func (c *Client) ListVMImages(ctx context.Context) ([]VMImage, error) {
	const path = "/v1/config/vm_images"
	var result []VMImage
	err := c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return validatedListResponse(result, err, http.MethodGet, path, func(image VMImage) (string, error) {
		return validatedRequiredListIdentity("VM image OS name", image.OSName)
	})
}

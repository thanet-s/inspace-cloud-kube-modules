package inspace

import (
	"context"
	"net/http"
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
	return &result, err
}

func (c *Client) ListNetworks(ctx context.Context, location string) ([]Network, error) {
	path, err := c.locationPath(location, "network/networks")
	if err != nil {
		return nil, err
	}
	var result []Network
	err = c.do(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

// ListVMImages returns the global stock OS catalog. VM creation uses OSName
// and OSVersion from these entries rather than an image UUID.
func (c *Client) ListVMImages(ctx context.Context) ([]VMImage, error) {
	var result []VMImage
	err := c.do(ctx, http.MethodGet, "/v1/config/vm_images", nil, nil, &result)
	return result, err
}

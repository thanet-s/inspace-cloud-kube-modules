package driver

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: d.cfg.PluginName, VendorVersion: d.cfg.PluginVersion}, nil
}

func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	capabilities := []*csi.PluginCapability{
		{Type: &csi.PluginCapability_Service_{Service: &csi.PluginCapability_Service{Type: csi.PluginCapability_Service_VOLUME_ACCESSIBILITY_CONSTRAINTS}}},
	}
	if d.controllerEnabled() {
		capabilities = append(capabilities,
			&csi.PluginCapability{Type: &csi.PluginCapability_Service_{Service: &csi.PluginCapability_Service{Type: csi.PluginCapability_Service_CONTROLLER_SERVICE}}},
		)
	}
	return &csi.GetPluginCapabilitiesResponse{Capabilities: capabilities}, nil
}

func (d *Driver) Probe(ctx context.Context, _ *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	if d.controllerEnabled() {
		if d.cloud == nil {
			return nil, status.Error(codes.Unavailable, "cloud adapter is not configured")
		}
		if err := d.cloud.Probe(ctx); err != nil {
			return nil, cloudStatus("probe cloud dependency", err)
		}
	}
	if d.nodeEnabled() {
		if d.mounter == nil {
			return nil, status.Error(codes.Unavailable, "host mounter is not configured")
		}
		if err := d.mounter.Probe(ctx); err != nil {
			return nil, hostStatus("probe host dependency", err)
		}
	}
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}

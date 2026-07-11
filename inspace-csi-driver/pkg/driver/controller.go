package driver

import (
	"context"
	"errors"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/cloud"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (d *Driver) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetName(), "name"); err != nil {
		return nil, err
	}
	if req.GetVolumeContentSource() != nil {
		return nil, status.Error(codes.InvalidArgument, "volume cloning and snapshot restore are not supported")
	}
	if len(req.GetMutableParameters()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "mutable_parameters are not supported")
	}
	if err := validateParameters(req.GetParameters()); err != nil {
		return nil, err
	}
	if err := validateVolumeCapabilities(req.GetVolumeCapabilities()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported volume capabilities: %v", err)
	}
	if err := d.validateAccessibility(req.GetAccessibilityRequirements()); err != nil {
		return nil, err
	}

	capacity, required, limit, err := d.requestedCapacity(req.GetCapacityRange())
	if err != nil {
		return nil, err
	}
	volume, err := d.cloud.EnsureVolume(ctx, cloud.VolumeSpec{
		Name: req.GetName(), Location: d.cfg.Location, CapacityBytes: capacity,
	})
	if err != nil {
		return nil, cloudStatus("create volume", err)
	}
	if volume.Location != d.cfg.Location || volume.ID == "" {
		return nil, status.Error(codes.Internal, "cloud adapter returned an invalid volume identity")
	}
	if volume.CapacityBytes <= 0 {
		return nil, status.Error(codes.Internal, "cloud adapter returned a non-positive volume capacity")
	}
	if volume.CapacityBytes < required || (limit > 0 && volume.CapacityBytes > limit) {
		return nil, incompatibility(req.GetName(), volume.CapacityBytes, required, limit)
	}
	handle, err := NewVolumeHandle(volume.Location, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cloud adapter returned invalid volume UUID: %v", err)
	}
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:           handle,
		CapacityBytes:      volume.CapacityBytes,
		VolumeContext:      map[string]string{"location": volume.Location, "fsType": "ext4"},
		AccessibleTopology: []*csi.Topology{topology(volume.Location)},
	}}, nil
}

func (d *Driver) validateAccessibility(requirements *csi.TopologyRequirement) error {
	if requirements == nil {
		return nil
	}
	if len(requirements.GetRequisite()) == 0 && len(requirements.GetPreferred()) == 0 {
		return status.Error(codes.InvalidArgument, "accessibility requirements contain no requisite or preferred topology")
	}
	validate := func(label string, candidates []*csi.Topology) (bool, error) {
		matched := false
		for _, candidate := range candidates {
			if candidate == nil || len(candidate.GetSegments()) == 0 {
				return false, status.Errorf(codes.InvalidArgument, "%s topology is empty", label)
			}
			for key := range candidate.GetSegments() {
				if key != TopologyLocationKey {
					return false, status.Errorf(codes.InvalidArgument, "%s topology contains unsupported segment %q", label, key)
				}
			}
			if candidate.GetSegments()[TopologyLocationKey] == d.cfg.Location {
				matched = true
			}
		}
		return matched, nil
	}
	requisiteMatched, err := validate("requisite", requirements.GetRequisite())
	if err != nil {
		return err
	}
	preferredMatched, err := validate("preferred", requirements.GetPreferred())
	if err != nil {
		return err
	}
	if len(requirements.GetRequisite()) > 0 && !requisiteMatched {
		return status.Errorf(codes.ResourceExhausted, "requested requisite topology does not include location %q", d.cfg.Location)
	}
	if len(requirements.GetRequisite()) == 0 && len(requirements.GetPreferred()) > 0 && !preferredMatched {
		return status.Errorf(codes.ResourceExhausted, "requested preferred topology does not include location %q", d.cfg.Location)
	}
	return nil
}

func validateParameters(parameters map[string]string) error {
	for key, value := range parameters {
		switch key {
		case "csi.storage.k8s.io/fstype":
			if value != "" && value != "ext4" {
				return status.Errorf(codes.InvalidArgument, "parameter %q supports only ext4", key)
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unsupported StorageClass parameter %q", key)
		}
	}
	return nil
}

func validateVolumeContext(volumeContext map[string]string, location string) error {
	for key, value := range volumeContext {
		switch key {
		case "location":
			if value != location {
				return status.Errorf(codes.InvalidArgument, "volume_context location %q does not match volume_id", value)
			}
		case "fsType":
			if value != "ext4" {
				return status.Errorf(codes.InvalidArgument, "volume_context fsType supports only ext4")
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unsupported volume_context key %q", key)
		}
	}
	return nil
}

func (d *Driver) requestedCapacity(capacityRange *csi.CapacityRange) (capacity, required, limit int64, err error) {
	if capacityRange != nil {
		required = capacityRange.GetRequiredBytes()
		limit = capacityRange.GetLimitBytes()
	}
	if required < 0 || limit < 0 {
		return 0, 0, 0, status.Error(codes.InvalidArgument, "capacity range cannot be negative")
	}
	if limit > 0 && required > limit {
		return 0, 0, 0, status.Error(codes.InvalidArgument, "required capacity exceeds limit")
	}
	capacity = required
	if capacity == 0 {
		capacity = d.cfg.DefaultVolumeSize
		if limit > 0 && capacity > limit {
			capacity = limit
		}
	}
	if capacity <= 0 {
		return 0, 0, 0, status.Error(codes.OutOfRange, "requested capacity must be greater than zero")
	}
	if d.cfg.MaxVolumeSize > 0 && capacity > d.cfg.MaxVolumeSize {
		return 0, 0, 0, status.Error(codes.OutOfRange, "requested capacity exceeds the configured maximum")
	}
	return capacity, required, limit, nil
}

func (d *Driver) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	err = d.cloud.DeleteVolume(ctx, ref.Location, ref.ID)
	if err != nil && !errors.Is(err, cloud.ErrNotFound) {
		return nil, cloudStatus("delete volume", err)
	}
	return &csi.DeleteVolumeResponse{}, nil
}

func (d *Driver) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if err := require(req.GetNodeId(), "node_id"); err != nil {
		return nil, err
	}
	if err := validateVolumeCapabilities([]*csi.VolumeCapability{req.GetVolumeCapability()}); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported volume capability: %v", err)
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	if _, err := d.cloud.GetVolume(ctx, ref.Location, ref.ID); err != nil {
		return nil, cloudStatus("get volume before attach", err)
	}
	if err := d.cloud.AttachVolume(ctx, ref.Location, ref.ID, req.GetNodeId()); err != nil {
		return nil, cloudStatus("attach volume", err)
	}
	devicePath, err := VirtioDevicePath(ref.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive device path: %v", err)
	}
	return &csi.ControllerPublishVolumeResponse{PublishContext: map[string]string{
		"devicePath": devicePath,
		"location":   ref.Location,
	}}, nil
}

func (d *Driver) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	err = d.cloud.DetachVolume(ctx, ref.Location, ref.ID, req.GetNodeId())
	if err != nil && !errors.Is(err, cloud.ErrNotFound) {
		return nil, cloudStatus("detach volume", err)
	}
	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

func (d *Driver) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	if _, err := d.cloud.GetVolume(ctx, ref.Location, ref.ID); err != nil {
		return nil, cloudStatus("validate volume", err)
	}
	if len(req.GetVolumeCapabilities()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "volume_capabilities is required")
	}
	if err := validateParameters(req.GetParameters()); err != nil {
		return nil, err
	}
	if len(req.GetMutableParameters()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "mutable_parameters are not supported")
	}
	if err := validateVolumeContext(req.GetVolumeContext(), ref.Location); err != nil {
		return nil, err
	}
	if err := validateVolumeCapabilities(req.GetVolumeCapabilities()); err != nil {
		return &csi.ValidateVolumeCapabilitiesResponse{Message: err.Error()}, nil
	}
	confirmedParameters := map[string]string{}
	if _, supplied := req.GetParameters()["csi.storage.k8s.io/fstype"]; supplied {
		confirmedParameters["csi.storage.k8s.io/fstype"] = "ext4"
	}
	confirmedContext := map[string]string{}
	if _, supplied := req.GetVolumeContext()["location"]; supplied {
		confirmedContext["location"] = ref.Location
	}
	if _, supplied := req.GetVolumeContext()["fsType"]; supplied {
		confirmedContext["fsType"] = "ext4"
	}
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
			VolumeCapabilities: req.GetVolumeCapabilities(),
			VolumeContext:      confirmedContext,
			Parameters:         confirmedParameters,
		},
	}, nil
}

func (d *Driver) ControllerGetCapabilities(context.Context, *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	capability := func(value csi.ControllerServiceCapability_RPC_Type) *csi.ControllerServiceCapability {
		return &csi.ControllerServiceCapability{Type: &csi.ControllerServiceCapability_Rpc{
			Rpc: &csi.ControllerServiceCapability_RPC{Type: value},
		}}
	}
	return &csi.ControllerGetCapabilitiesResponse{Capabilities: []*csi.ControllerServiceCapability{
		capability(csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME),
		capability(csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME),
	}}, nil
}

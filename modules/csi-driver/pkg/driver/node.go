package driver

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (d *Driver) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	if err := d.requireMounter(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.FailedPrecondition, "staging_target_path is required")
	}
	if err := validateVolumeCapabilities([]*csi.VolumeCapability{req.GetVolumeCapability()}); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported volume capability: %v", err)
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	devicePath, err := VirtioDevicePath(ref.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive device path: %v", err)
	}
	if published := req.GetPublishContext()["devicePath"]; published != "" && published != devicePath {
		return nil, status.Error(codes.InvalidArgument, "publish_context devicePath does not match volume_id")
	}
	if publishedLocation := req.GetPublishContext()["location"]; publishedLocation != "" && publishedLocation != ref.Location {
		return nil, status.Error(codes.InvalidArgument, "publish_context location does not match volume_id")
	}
	actualDevice, err := d.mounter.WaitForDevice(ctx, devicePath)
	if err != nil {
		return nil, hostStatus("wait for volume device", err)
	}
	mounted, present, err := d.mounter.GetMount(ctx, req.GetStagingTargetPath())
	if err != nil {
		return nil, hostStatus("inspect staging target", err)
	}
	if present {
		matches, err := d.mounter.SameSource(ctx, mounted, actualDevice)
		if err != nil {
			return nil, hostStatus("compare staging mount source", err)
		}
		if !matches || mounted.FSType != fsType(req.GetVolumeCapability()) || mounted.ReadOnly {
			return nil, status.Error(codes.FailedPrecondition, "staging target has a conflicting mount")
		}
		return &csi.NodeStageVolumeResponse{}, nil
	}
	mount := req.GetVolumeCapability().GetMount()
	if err := d.mounter.FormatAndMount(ctx, actualDevice, req.GetStagingTargetPath(), fsType(req.GetVolumeCapability()), mount.GetMountFlags()); err != nil {
		return nil, hostStatus("format and stage volume", err)
	}
	return &csi.NodeStageVolumeResponse{}, nil
}

func (d *Driver) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	if err := d.requireMounter(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.FailedPrecondition, "staging_target_path is required")
	}
	if _, err := d.volumeRef(req.GetVolumeId()); err != nil {
		return nil, err
	}
	if err := d.mounter.Unmount(ctx, req.GetStagingTargetPath()); err != nil {
		return nil, hostStatus("unstage volume", err)
	}
	return &csi.NodeUnstageVolumeResponse{}, nil
}

func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	if err := d.requireMounter(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if req.GetStagingTargetPath() == "" {
		return nil, status.Error(codes.FailedPrecondition, "staging_target_path is required")
	}
	if err := require(req.GetTargetPath(), "target_path"); err != nil {
		return nil, err
	}
	if err := validateVolumeCapabilities([]*csi.VolumeCapability{req.GetVolumeCapability()}); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported volume capability: %v", err)
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	devicePath, err := VirtioDevicePath(ref.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive device path: %v", err)
	}
	actualDevice, err := d.mounter.WaitForDevice(ctx, devicePath)
	if err != nil {
		return nil, hostStatus("wait for staged volume device", err)
	}
	stagedMount, staged, err := d.mounter.GetMount(ctx, req.GetStagingTargetPath())
	if err != nil {
		return nil, hostStatus("inspect staging target", err)
	}
	if !staged {
		return nil, status.Error(codes.FailedPrecondition, "volume is not staged")
	}
	stagedSourceMatches, err := d.mounter.SameSource(ctx, stagedMount, actualDevice)
	if err != nil {
		return nil, hostStatus("compare staged volume source", err)
	}
	if !stagedSourceMatches || stagedMount.FSType != fsType(req.GetVolumeCapability()) || stagedMount.ReadOnly {
		return nil, status.Error(codes.FailedPrecondition, "staging target belongs to a different volume")
	}
	publishedMount, published, err := d.mounter.GetMount(ctx, req.GetTargetPath())
	if err != nil {
		return nil, hostStatus("inspect publish target", err)
	}
	if published {
		matches, err := d.mounter.SameSource(ctx, publishedMount, req.GetStagingTargetPath())
		if err != nil {
			return nil, hostStatus("compare publish mount source", err)
		}
		if !matches || publishedMount.ReadOnly != req.GetReadonly() {
			return nil, status.Error(codes.FailedPrecondition, "publish target has a conflicting mount")
		}
		return &csi.NodePublishVolumeResponse{}, nil
	}
	flags := req.GetVolumeCapability().GetMount().GetMountFlags()
	if err := d.mounter.BindMount(ctx, req.GetStagingTargetPath(), req.GetTargetPath(), req.GetReadonly(), flags); err != nil {
		return nil, hostStatus("publish volume", err)
	}
	return &csi.NodePublishVolumeResponse{}, nil
}

func (d *Driver) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if err := d.requireMounter(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if err := require(req.GetTargetPath(), "target_path"); err != nil {
		return nil, err
	}
	if _, err := d.volumeRef(req.GetVolumeId()); err != nil {
		return nil, err
	}
	if err := d.mounter.Unmount(ctx, req.GetTargetPath()); err != nil {
		return nil, hostStatus("unpublish volume", err)
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	if d.cfg.NodeID == "" {
		return nil, status.Error(codes.FailedPrecondition, "node ID is not configured")
	}
	return &csi.NodeGetInfoResponse{
		NodeId:             d.cfg.NodeID,
		MaxVolumesPerNode:  d.cfg.MaxVolumesPerNode,
		AccessibleTopology: topology(d.cfg.Location),
	}, nil
}

func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{Capabilities: []*csi.NodeServiceCapability{
		{Type: &csi.NodeServiceCapability_Rpc{Rpc: &csi.NodeServiceCapability_RPC{Type: csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME}}},
	}}, nil
}

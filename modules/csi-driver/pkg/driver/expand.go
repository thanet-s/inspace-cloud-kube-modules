package driver

import (
	"context"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ControllerExpandVolume grows the InSpace disk. The provider can only resize
// an attached disk, so a detached volume fails with FailedPrecondition and the
// resizer retries once a Pod uses the volume again.
func (d *Driver) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	if err := d.requireCloud(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if capability := req.GetVolumeCapability(); capability != nil {
		if err := validateVolumeCapabilities([]*csi.VolumeCapability{capability}); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unsupported volume capability: %v", err)
		}
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	required, limit, err := d.expansionCapacity(req.GetCapacityRange())
	if err != nil {
		return nil, err
	}
	capacity, err := d.cloud.ExpandVolume(ctx, ref.Location, ref.ID, required)
	if err != nil {
		return nil, cloudStatus("expand volume", err)
	}
	if capacity < required || (limit > 0 && capacity > limit) {
		return nil, status.Errorf(codes.OutOfRange,
			"expanded capacity %d is outside requested range [%d,%s]", capacity, required, printableLimit(limit))
	}
	return &csi.ControllerExpandVolumeResponse{CapacityBytes: capacity, NodeExpansionRequired: true}, nil
}

func (d *Driver) expansionCapacity(capacityRange *csi.CapacityRange) (required, limit int64, err error) {
	if capacityRange == nil {
		return 0, 0, status.Error(codes.InvalidArgument, "capacity_range is required")
	}
	required = capacityRange.GetRequiredBytes()
	limit = capacityRange.GetLimitBytes()
	if required < 0 || limit < 0 {
		return 0, 0, status.Error(codes.InvalidArgument, "capacity range cannot be negative")
	}
	if required == 0 {
		required = limit
	}
	if required == 0 {
		return 0, 0, status.Error(codes.InvalidArgument, "capacity_range must set required_bytes or limit_bytes")
	}
	if limit > 0 && required > limit {
		return 0, 0, status.Error(codes.InvalidArgument, "required capacity exceeds limit")
	}
	if d.cfg.MaxVolumeSize > 0 && required > d.cfg.MaxVolumeSize {
		return 0, 0, status.Error(codes.OutOfRange, "requested capacity exceeds the configured maximum")
	}
	return required, limit, nil
}

// NodeExpandVolume grows the ext4 filesystem after ControllerExpandVolume.
// volume_path must be a mount of this volume's device, either directly or as a
// bind mount of the staged filesystem.
func (d *Driver) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	if err := d.requireMounter(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := require(req.GetVolumeId(), "volume_id"); err != nil {
		return nil, err
	}
	if err := require(req.GetVolumePath(), "volume_path"); err != nil {
		return nil, err
	}
	if capability := req.GetVolumeCapability(); capability != nil {
		if err := validateVolumeCapabilities([]*csi.VolumeCapability{capability}); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unsupported volume capability: %v", err)
		}
	}
	ref, err := d.volumeRef(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	required := req.GetCapacityRange().GetRequiredBytes()
	if required < 0 {
		return nil, status.Error(codes.InvalidArgument, "capacity range cannot be negative")
	}
	devicePath, err := VirtioDevicePath(ref.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive device path: %v", err)
	}
	actualDevice, err := d.mounter.WaitForDevice(ctx, devicePath)
	if err != nil {
		return nil, hostStatus("wait for volume device", err)
	}
	mounted, present, err := d.mounter.GetMount(ctx, req.GetVolumePath())
	if err != nil {
		return nil, hostStatus("inspect volume path", err)
	}
	if !present {
		return nil, status.Error(codes.NotFound, "volume_path is not mounted")
	}
	matches, err := d.mountBelongsToDevice(ctx, mounted, actualDevice, req.GetStagingTargetPath())
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, status.Error(codes.FailedPrecondition, "volume_path belongs to a different volume")
	}
	capacity, err := d.mounter.ExpandFilesystem(ctx, actualDevice, req.GetVolumePath(), required)
	if err != nil {
		return nil, hostStatus("expand filesystem", err)
	}
	return &csi.NodeExpandVolumeResponse{CapacityBytes: capacity}, nil
}

func (d *Driver) mountBelongsToDevice(ctx context.Context, mounted host.Mount, device, stagingPath string) (bool, error) {
	matches, err := d.mounter.SameSource(ctx, mounted, device)
	if err != nil {
		return false, hostStatus("compare volume path source", err)
	}
	if matches || stagingPath == "" {
		return matches, nil
	}
	staged, present, err := d.mounter.GetMount(ctx, stagingPath)
	if err != nil {
		return false, hostStatus("inspect staging target", err)
	}
	if !present {
		return false, nil
	}
	stagedMatches, err := d.mounter.SameSource(ctx, staged, device)
	if err != nil {
		return false, hostStatus("compare staged volume source", err)
	}
	if !stagedMatches {
		return false, nil
	}
	boundToStage, err := d.mounter.SameSource(ctx, mounted, stagingPath)
	if err != nil {
		return false, hostStatus("compare volume path with staging target", err)
	}
	return boundToStage, nil
}

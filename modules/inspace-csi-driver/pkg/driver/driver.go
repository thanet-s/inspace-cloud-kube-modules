// Package driver implements the CSI v1.12 protocol surface for InSpace block
// volumes. Provider and host effects are delegated to narrow interfaces.
package driver

import (
	"context"
	"errors"
	"fmt"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/cloud"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/host"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	DefaultPluginName          = "csi.inspace.cloud"
	DefaultPluginVersion       = "0.1.0"
	DefaultVolumeSize    int64 = 10 * 1024 * 1024 * 1024
	TopologyLocationKey        = "topology.inspace.cloud/location"
)

type Mode string

const (
	ModeController Mode = "controller"
	ModeNode       Mode = "node"
	// ModeAll exists for in-process protocol tests. Production manifests run
	// separate controller and node processes so API credentials never reach a
	// worker Pod.
	ModeAll Mode = "all"
)

type Config struct {
	Mode              Mode
	PluginName        string
	PluginVersion     string
	Location          string
	NodeID            string
	DefaultVolumeSize int64
	MaxVolumeSize     int64
	MaxVolumesPerNode int64
}

// Driver implements Identity, Controller, and Node services. Production
// processes register only the service selected by Config.Mode.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedControllerServer
	csi.UnimplementedNodeServer

	cfg     Config
	cloud   cloud.Interface
	mounter host.Mounter
}

var (
	_ csi.IdentityServer   = (*Driver)(nil)
	_ csi.ControllerServer = (*Driver)(nil)
	_ csi.NodeServer       = (*Driver)(nil)
)

func New(cfg Config, provider cloud.Interface, mounter host.Mounter) (*Driver, error) {
	if cfg.Location == "" {
		return nil, errors.New("location is required")
	}
	if cfg.PluginName == "" {
		cfg.PluginName = DefaultPluginName
	}
	if cfg.PluginVersion == "" {
		cfg.PluginVersion = DefaultPluginVersion
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeAll
	}
	if cfg.Mode != ModeController && cfg.Mode != ModeNode && cfg.Mode != ModeAll {
		return nil, fmt.Errorf("unsupported driver mode %q", cfg.Mode)
	}
	if cfg.DefaultVolumeSize == 0 {
		cfg.DefaultVolumeSize = DefaultVolumeSize
	}
	if cfg.DefaultVolumeSize < 0 || cfg.MaxVolumeSize < 0 || cfg.MaxVolumesPerNode < 0 {
		return nil, errors.New("size and volume limits cannot be negative")
	}
	if cfg.MaxVolumeSize > 0 && cfg.DefaultVolumeSize > cfg.MaxVolumeSize {
		return nil, errors.New("default volume size exceeds maximum volume size")
	}
	return &Driver{cfg: cfg, cloud: provider, mounter: mounter}, nil
}

func (d *Driver) Register(registrar grpc.ServiceRegistrar) {
	csi.RegisterIdentityServer(registrar, d)
	if d.controllerEnabled() {
		csi.RegisterControllerServer(registrar, d)
	}
	if d.nodeEnabled() {
		csi.RegisterNodeServer(registrar, d)
	}
}

func (d *Driver) controllerEnabled() bool {
	return d.cfg.Mode == ModeController || d.cfg.Mode == ModeAll
}

func (d *Driver) nodeEnabled() bool { return d.cfg.Mode == ModeNode || d.cfg.Mode == ModeAll }

func (d *Driver) requireCloud() error {
	if d.cloud == nil {
		return status.Error(codes.Unavailable, "InSpace cloud adapter is not configured")
	}
	return nil
}

func (d *Driver) requireMounter() error {
	if d.mounter == nil {
		return status.Error(codes.Unavailable, "host mounter adapter is not configured")
	}
	return nil
}

func (d *Driver) volumeRef(handle string) (VolumeRef, error) {
	ref, err := ParseVolumeHandle(handle)
	if err != nil {
		return VolumeRef{}, status.Errorf(codes.InvalidArgument, "invalid volume_id: %v", err)
	}
	if ref.Location != d.cfg.Location {
		return VolumeRef{}, status.Errorf(codes.InvalidArgument, "volume belongs to location %q, driver serves %q", ref.Location, d.cfg.Location)
	}
	return ref, nil
}

func cloudStatus(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, operation+": request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, operation+": deadline exceeded")
	case errors.Is(err, cloud.ErrNotFound):
		return status.Error(codes.NotFound, operation+": volume not found")
	case errors.Is(err, cloud.ErrVolumeAttachedElsewhere):
		return status.Error(codes.FailedPrecondition, operation+": volume is attached to another node")
	case errors.Is(err, cloud.ErrIncompatibleVolume):
		return status.Error(codes.AlreadyExists, operation+": same-named volume is incompatible")
	case errors.Is(err, cloud.ErrSnapshotsPresent):
		return status.Error(codes.FailedPrecondition, operation+": volume has snapshots; delete them explicitly first")
	case errors.Is(err, cloud.ErrInvalidNode):
		return status.Error(codes.NotFound, operation+": node does not resolve to an InSpace VM")
	case errors.Is(err, cloud.ErrUnavailable):
		return status.Error(codes.Unavailable, operation+": InSpace API is temporarily unavailable")
	case errors.Is(err, cloud.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, operation+": InSpace API authentication failed")
	case errors.Is(err, cloud.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, operation+": InSpace API denied the operation")
	case errors.Is(err, cloud.ErrConflict):
		return status.Error(codes.Aborted, operation+": InSpace API reported a concurrent conflict")
	default:
		return status.Errorf(codes.Internal, "%s failed: %v", operation, err)
	}
}

func hostStatus(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, operation+": request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, operation+": deadline exceeded")
	case errors.Is(err, host.ErrMountConflict):
		return status.Errorf(codes.FailedPrecondition, "%s: target has a conflicting mount", operation)
	}
	return status.Errorf(codes.Internal, "%s failed: %v", operation, err)
}

func require(value, field string) error {
	if value == "" {
		return status.Errorf(codes.InvalidArgument, "%s is required", field)
	}
	return nil
}

func topology(location string) *csi.Topology {
	return &csi.Topology{Segments: map[string]string{TopologyLocationKey: location}}
}

func incompatibility(name string, capacity, required, limit int64) error {
	return status.Errorf(codes.AlreadyExists,
		"volume %q has capacity %d, outside requested range [%d,%s]",
		name, capacity, required, printableLimit(limit))
}

func printableLimit(limit int64) string {
	if limit == 0 {
		return "unbounded"
	}
	return fmt.Sprintf("%d", limit)
}

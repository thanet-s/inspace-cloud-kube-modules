// Package cloud defines the deliberately small boundary between the CSI
// protocol implementation and an InSpace API client.
package cloud

import (
	"context"
	"errors"
)

var (
	// ErrNotFound is returned when a volume does not exist.
	ErrNotFound = errors.New("cloud volume not found")
	// ErrVolumeAttachedElsewhere is returned when a single-writer volume is
	// already attached to a different node.
	ErrVolumeAttachedElsewhere = errors.New("volume is attached to another node")
	// ErrIncompatibleVolume is returned when an idempotent create finds a
	// same-named volume which cannot satisfy the requested specification.
	ErrIncompatibleVolume = errors.New("same-named volume has incompatible properties")
	// ErrSnapshotsPresent protects snapshots from the InSpace delete-disk API,
	// which otherwise deletes a disk and every snapshot below it.
	ErrSnapshotsPresent = errors.New("volume has snapshots")
	// ErrInvalidNode means a CSI node ID could not be resolved to an InSpace VM.
	ErrInvalidNode = errors.New("invalid or unresolved node ID")
	// ErrUnavailable marks a temporary provider or dependency failure.
	ErrUnavailable      = errors.New("cloud dependency unavailable")
	ErrUnauthenticated  = errors.New("cloud authentication failed")
	ErrPermissionDenied = errors.New("cloud permission denied")
	ErrConflict         = errors.New("cloud operation conflict")
)

// VolumeSpec is the desired durable state used by EnsureVolume.
type VolumeSpec struct {
	Name          string
	Location      string
	CapacityBytes int64
}

// Volume is the provider representation needed by the CSI layer.
type Volume struct {
	ID            string
	Name          string
	Location      string
	CapacityBytes int64
}

// Interface is implemented by the shared InSpace SDK adapter and test fake.
//
// Every method must be safe to retry. EnsureVolume is idempotent by
// (Location, Name), DeleteVolume and DetachVolume may return ErrNotFound, and
// attaching a volume to its current node must succeed. DetachVolume with an
// empty nodeID means detach the volume from whichever single node holds it, as
// required by ControllerUnpublishVolume.
type Interface interface {
	Probe(context.Context) error
	EnsureVolume(context.Context, VolumeSpec) (Volume, error)
	GetVolume(ctx context.Context, location, volumeID string) (Volume, error)
	DeleteVolume(ctx context.Context, location, volumeID string) error
	AttachVolume(ctx context.Context, location, volumeID, nodeID string) error
	DetachVolume(ctx context.Context, location, volumeID, nodeID string) error
}

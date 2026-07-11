// Package host defines the node-side device and mount boundary.
package host

import (
	"context"
	"errors"
)

var ErrMountConflict = errors.New("target is mounted from a different source")

// Mounter abstracts all host mutation. The CSI protocol package never invokes
// mount, mkfs, udev, or filesystem syscalls directly.
type Mounter interface {
	Probe(context.Context) error
	// WaitForDevice waits for the stable by-id path and returns its canonical
	// device path. Returning the canonical path makes mount idempotency checks
	// reliable even when mountinfo reports /dev/vdb rather than the symlink.
	WaitForDevice(ctx context.Context, devicePath string) (string, error)
	GetMount(ctx context.Context, target string) (Mount, bool, error)
	// SameSource compares a mount with an expected block device or bind source.
	// Linux implementations must account for mountinfo resolving by-id links and
	// reporting a bind mount's backing device instead of its source directory.
	SameSource(ctx context.Context, mounted Mount, expectedSource string) (bool, error)
	FormatAndMount(ctx context.Context, devicePath, target, fsType string, mountFlags []string) error
	BindMount(ctx context.Context, source, target string, readOnly bool, mountFlags []string) error
	Unmount(ctx context.Context, target string) error
}

// Mount describes fake mounter state and is useful in smoke assertions.
type Mount struct {
	Source     string
	Target     string
	FSType     string
	ReadOnly   bool
	Bind       bool
	MountFlags []string
}

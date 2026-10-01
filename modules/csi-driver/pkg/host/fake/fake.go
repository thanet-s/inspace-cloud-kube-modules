// Package fake provides an in-memory Mounter which never changes the host.
package fake

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"sync"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host"
)

type Mounter struct {
	mu          sync.Mutex
	mounts      map[string]host.Mount
	devices     map[string]int
	deviceSizes map[string]int64
	expansions  map[string]int
	stats       map[string]host.VolumeStats
	statsErrors map[string]error
}

func New() *Mounter {
	return &Mounter{
		mounts:      make(map[string]host.Mount),
		devices:     make(map[string]int),
		deviceSizes: make(map[string]int64),
		expansions:  make(map[string]int),
		stats:       make(map[string]host.VolumeStats),
		statsErrors: make(map[string]error),
	}
}

func (m *Mounter) Probe(context.Context) error { return nil }

func (m *Mounter) WaitForDevice(_ context.Context, devicePath string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[devicePath]++
	return devicePath, nil
}

func (m *Mounter) GetMount(_ context.Context, target string) (host.Mount, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mount, ok := m.mounts[target]
	return mount, ok, nil
}

func (m *Mounter) SameSource(_ context.Context, mounted host.Mount, expectedSource string) (bool, error) {
	return mounted.Source == expectedSource, nil
}

func (m *Mounter) FormatAndMount(_ context.Context, devicePath, target, fsType string, mountFlags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := host.Mount{Source: devicePath, Target: target, FSType: fsType, MountFlags: slices.Clone(mountFlags)}
	if got, ok := m.mounts[target]; ok {
		if got.Source == want.Source && got.FSType == want.FSType && !got.Bind {
			return nil
		}
		return fmt.Errorf("%w: %s", host.ErrMountConflict, target)
	}
	m.mounts[target] = want
	return nil
}

func (m *Mounter) BindMount(_ context.Context, source, target string, readOnly bool, mountFlags []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mounts[source]; !ok {
		return fmt.Errorf("source is not mounted: %s", source)
	}
	want := host.Mount{
		Source: source, Target: target, ReadOnly: readOnly, Bind: true, MountFlags: slices.Clone(mountFlags),
	}
	if got, ok := m.mounts[target]; ok {
		if got.Source == source && got.Bind && got.ReadOnly == readOnly {
			return nil
		}
		return fmt.Errorf("%w: %s", host.ErrMountConflict, target)
	}
	m.mounts[target] = want
	return nil
}

func (m *Mounter) Unmount(_ context.Context, target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mounts, target)
	return nil
}

// ExpandFilesystem treats a device without an explicit SetDeviceSize as
// already grown to the requested size.
func (m *Mounter) ExpandFilesystem(_ context.Context, devicePath, mountPath string, minimumBytes int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mounts[mountPath]; !ok {
		return 0, fmt.Errorf("filesystem is not mounted: %s", mountPath)
	}
	size, known := m.deviceSizes[devicePath]
	if !known {
		size = minimumBytes
	}
	if size < minimumBytes {
		return 0, fmt.Errorf("%w: %s has %d bytes, want %d", host.ErrDeviceNotResized, devicePath, size, minimumBytes)
	}
	m.expansions[devicePath]++
	return size, nil
}

func (m *Mounter) SetDeviceSize(devicePath string, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deviceSizes[devicePath] = bytes
}

func (m *Mounter) FilesystemExpansions(devicePath string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.expansions[devicePath]
}

// SetMount records a mount without going through FormatAndMount.
func (m *Mounter) SetMount(mount host.Mount) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mounts[mount.Target] = mount
}

// SetVolumeStats makes path exist and report stats.
func (m *Mounter) SetVolumeStats(path string, stats host.VolumeStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats[path] = stats
	delete(m.statsErrors, path)
}

// SetVolumeStatsError makes VolumeStats fail for path with err.
func (m *Mounter) SetVolumeStatsError(path string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statsErrors[path] = err
}

// VolumeStats returns configured stats. A path without configured stats does
// not exist.
func (m *Mounter) VolumeStats(_ context.Context, path string) (host.VolumeStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.statsErrors[path]; ok {
		return host.VolumeStats{}, err
	}
	stats, ok := m.stats[path]
	if !ok {
		return host.VolumeStats{}, fmt.Errorf("stat %s: %w", path, fs.ErrNotExist)
	}
	return stats, nil
}

func (m *Mounter) Mount(target string) (host.Mount, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	got, ok := m.mounts[target]
	return got, ok
}

func (m *Mounter) MountCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.mounts)
}

var _ host.Mounter = (*Mounter)(nil)

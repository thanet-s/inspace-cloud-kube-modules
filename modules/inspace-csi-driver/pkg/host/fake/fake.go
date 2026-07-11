// Package fake provides an in-memory Mounter which never changes the host.
package fake

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/host"
)

type Mounter struct {
	mu      sync.Mutex
	mounts  map[string]host.Mount
	devices map[string]int
}

func New() *Mounter {
	return &Mounter{
		mounts:  make(map[string]host.Mount),
		devices: make(map[string]int),
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

// Package fake provides a concurrency-safe, in-memory cloud implementation.
// It never performs network I/O.
package fake

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

type record struct {
	volume     cloud.Volume
	attachedTo string
}

// Cloud is an in-memory implementation of cloud.Interface for tests and local
// protocol development.
type Cloud struct {
	mu      sync.Mutex
	volumes map[string]*record
	byName  map[string]string
}

func New() *Cloud {
	return &Cloud{
		volumes: make(map[string]*record),
		byName:  make(map[string]string),
	}
}

func (c *Cloud) Probe(context.Context) error { return nil }

func (c *Cloud) EnsureVolume(_ context.Context, spec cloud.VolumeSpec) (cloud.Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	nameKey := key(spec.Location, spec.Name)
	if id, ok := c.byName[nameKey]; ok {
		v := c.volumes[key(spec.Location, id)].volume
		return v, nil
	}

	id := deterministicUUID(spec.Location + "\x00" + spec.Name)
	v := cloud.Volume{
		ID:            id,
		Name:          spec.Name,
		Location:      spec.Location,
		CapacityBytes: spec.CapacityBytes,
	}
	c.volumes[key(spec.Location, id)] = &record{volume: v}
	c.byName[nameKey] = id
	return v, nil
}

func (c *Cloud) GetVolume(_ context.Context, location, volumeID string) (cloud.Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.volumes[key(location, volumeID)]
	if !ok {
		return cloud.Volume{}, cloud.ErrNotFound
	}
	return r.volume, nil
}

func (c *Cloud) DeleteVolume(_ context.Context, location, volumeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := key(location, volumeID)
	r, ok := c.volumes[k]
	if !ok {
		return cloud.ErrNotFound
	}
	if r.attachedTo != "" {
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, r.attachedTo)
	}
	delete(c.byName, key(location, r.volume.Name))
	delete(c.volumes, k)
	return nil
}

func (c *Cloud) AttachVolume(_ context.Context, location, volumeID, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.volumes[key(location, volumeID)]
	if !ok {
		return cloud.ErrNotFound
	}
	if r.attachedTo != "" && r.attachedTo != nodeID {
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, r.attachedTo)
	}
	r.attachedTo = nodeID
	return nil
}

func (c *Cloud) DetachVolume(_ context.Context, location, volumeID, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.volumes[key(location, volumeID)]
	if !ok {
		return cloud.ErrNotFound
	}
	if r.attachedTo == "" {
		return nil
	}
	if nodeID == "" {
		r.attachedTo = ""
		return nil
	}
	if r.attachedTo != nodeID {
		// CSI ControllerUnpublishVolume is idempotent for the requested
		// (volume,node) pair. A disk attached somewhere else is already
		// unpublished from this node and must not be detached from its owner.
		return nil
	}
	r.attachedTo = ""
	return nil
}

func (c *Cloud) VolumeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.volumes)
}

func (c *Cloud) AttachedNode(location, volumeID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.volumes[key(location, volumeID)]
	if !ok {
		return "", cloud.ErrNotFound
	}
	return r.attachedTo, nil
}

func key(location, value string) string { return location + "\x00" + value }

func deterministicUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	hex := fmt.Sprintf("%x", sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

var _ cloud.Interface = (*Cloud)(nil)

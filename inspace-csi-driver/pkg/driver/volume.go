package driver

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const virtioSerialLength = 20

var (
	locationPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type VolumeRef struct {
	Location string
	ID       string
}

func NewVolumeHandle(location, volumeID string) (string, error) {
	location = strings.ToLower(location)
	volumeID = strings.ToLower(volumeID)
	if !locationPattern.MatchString(location) {
		return "", fmt.Errorf("invalid location %q", location)
	}
	if !uuidPattern.MatchString(volumeID) {
		return "", fmt.Errorf("invalid volume UUID %q", volumeID)
	}
	return "inspace://" + location + "/" + volumeID, nil
}

func ParseVolumeHandle(handle string) (VolumeRef, error) {
	u, err := url.Parse(handle)
	if err != nil {
		return VolumeRef{}, err
	}
	if u.Scheme != "inspace" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return VolumeRef{}, fmt.Errorf("expected inspace://<location>/<volume-uuid>")
	}
	location := strings.ToLower(u.Host)
	id := strings.ToLower(strings.TrimPrefix(u.EscapedPath(), "/"))
	if strings.Contains(id, "/") || id == "" {
		return VolumeRef{}, fmt.Errorf("expected exactly one volume UUID path segment")
	}
	decoded, err := url.PathUnescape(id)
	if err != nil {
		return VolumeRef{}, fmt.Errorf("decode volume UUID: %w", err)
	}
	if !locationPattern.MatchString(location) || !uuidPattern.MatchString(decoded) {
		return VolumeRef{}, fmt.Errorf("invalid location or volume UUID")
	}
	return VolumeRef{Location: location, ID: decoded}, nil
}

// VirtioDevicePath returns the stable by-id path documented by InSpace. QEMU's
// virtio serial is the first 20 characters of the native disk UUID.
func VirtioDevicePath(volumeID string) (string, error) {
	id := strings.ToLower(volumeID)
	if !uuidPattern.MatchString(id) {
		return "", fmt.Errorf("invalid volume UUID %q", volumeID)
	}
	return "/dev/disk/by-id/virtio-" + id[:virtioSerialLength], nil
}

package driver

import (
	"fmt"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

func validateVolumeCapabilities(capabilities []*csi.VolumeCapability) error {
	if len(capabilities) == 0 {
		return fmt.Errorf("at least one volume capability is required")
	}
	for _, capability := range capabilities {
		if capability == nil || capability.GetAccessMode() == nil {
			return fmt.Errorf("volume capability and access mode are required")
		}
		if capability.GetAccessMode().GetMode() != csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER {
			return fmt.Errorf("only SINGLE_NODE_WRITER (Kubernetes ReadWriteOnce) is supported")
		}
		mount := capability.GetMount()
		if mount == nil {
			return fmt.Errorf("only mounted filesystem volumes are supported; raw block and multi-node modes are not supported")
		}
		if fsType := mount.GetFsType(); fsType != "" && fsType != "ext4" {
			return fmt.Errorf("only ext4 is supported, got %q", fsType)
		}
	}
	return nil
}

func fsType(capability *csi.VolumeCapability) string {
	if value := capability.GetMount().GetFsType(); value != "" {
		return value
	}
	return "ext4"
}

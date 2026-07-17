//go:build linux

package linux

import (
	"errors"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host"
)

func TestValidateFlags(t *testing.T) {
	flags, err := validateFlags([]string{"discard", "noatime", "discard"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 2 || flags[0] != "discard" || flags[1] != "noatime" {
		t.Fatalf("flags=%v", flags)
	}
	for _, flag := range []string{"bind", "ro", "loop", "discard,exec", "unknown"} {
		if _, err := validateFlags([]string{flag}, false); err == nil {
			t.Errorf("flag %q unexpectedly accepted", flag)
		}
	}
	if _, err := validateFlags([]string{"errors=remount-ro"}, true); err == nil {
		t.Fatal("ext4-only flag unexpectedly accepted for bind mount")
	}
}

func TestMountInfoUnescape(t *testing.T) {
	got := unescapeMountInfo(`/path\040with\040spaces\134name`)
	if want := "/path with spaces\\name"; got != want {
		t.Fatalf("unescape=%q, want %q", got, want)
	}
}

func TestValidateAbsolutePath(t *testing.T) {
	for _, valid := range []string{"/", "/var/lib/kubelet/plugins"} {
		if err := validateAbsolutePath(valid); err != nil {
			t.Errorf("valid path %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "relative", "/tmp/../etc", "/tmp//x"} {
		if err := validateAbsolutePath(invalid); err == nil {
			t.Errorf("invalid path %q accepted", invalid)
		}
	}
}

func TestValidateWholeDiskMountSafety(t *testing.T) {
	const device = "/dev/vdb"
	valid := `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":[null]}]}`
	if err := validateWholeDiskMountSafety([]byte(valid), device); err != nil {
		t.Fatalf("valid empty whole disk: %v", err)
	}
	validEmptyMountpoints := `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":[]}]}`
	if err := validateWholeDiskMountSafety([]byte(validEmptyMountpoints), device); err != nil {
		t.Fatalf("valid whole disk with empty mountpoint array: %v", err)
	}

	invalid := map[string]string{
		"mounted":             `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":["/"]}]}`,
		"partitioned":         `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":[null],"children":[{"path":"/dev/vdb1","type":"part","mountpoints":["/"]}]}]}`,
		"partition":           `{"blockdevices":[{"path":"/dev/vdb","type":"part","mountpoints":[null]}]}`,
		"wrong path":          `{"blockdevices":[{"path":"/dev/vda","type":"disk","mountpoints":[null]}]}`,
		"omitted mountpoints": `{"blockdevices":[{"path":"/dev/vdb","type":"disk"}]}`,
		"duplicate roots":     `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":[null]},{"path":"/dev/vdc","type":"disk","mountpoints":[null]}]}`,
		"trailing JSON":       `{"blockdevices":[{"path":"/dev/vdb","type":"disk","mountpoints":[null]}]} {}`,
	}
	for name, payload := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := validateWholeDiskMountSafety([]byte(payload), device); !errors.Is(err, host.ErrMountConflict) && name != "trailing JSON" {
				t.Fatalf("error = %v, want ErrMountConflict", err)
			} else if err == nil {
				t.Fatal("unsafe block-device topology unexpectedly accepted")
			}
		})
	}
}

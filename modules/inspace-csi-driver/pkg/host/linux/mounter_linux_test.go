//go:build linux

package linux

import "testing"

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

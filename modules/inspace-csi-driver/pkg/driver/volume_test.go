package driver

import "testing"

func TestVolumeHandleRoundTripAndDevicePath(t *testing.T) {
	t.Parallel()
	const (
		location = "bkk01"
		id       = "12345678-1234-1234-1234-123456789abc"
	)
	handle, err := NewVolumeHandle(location, id)
	if err != nil {
		t.Fatal(err)
	}
	if want := "inspace://bkk01/12345678-1234-1234-1234-123456789abc"; handle != want {
		t.Fatalf("handle = %q, want %q", handle, want)
	}
	ref, err := ParseVolumeHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Location != location || ref.ID != id {
		t.Fatalf("ref = %#v", ref)
	}
	path, err := VirtioDevicePath(id)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/dev/disk/by-id/virtio-12345678-1234-1234-1"; path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

func TestRejectsMalformedHandles(t *testing.T) {
	t.Parallel()
	for _, handle := range []string{
		"",
		"https://bkk01/12345678-1234-1234-1234-123456789abc",
		"inspace://BKK_01/12345678-1234-1234-1234-123456789abc",
		"inspace://bkk01/not-a-uuid",
		"inspace://bkk01/12345678-1234-1234-1234-123456789abc/extra",
		"inspace://bkk01/12345678-1234-1234-1234-123456789abc?q=x",
	} {
		if _, err := ParseVolumeHandle(handle); err == nil {
			t.Errorf("ParseVolumeHandle(%q) unexpectedly succeeded", handle)
		}
	}
}

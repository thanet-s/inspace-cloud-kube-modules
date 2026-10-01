//go:build linux

package linux

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

func TestVolumeStatsMathFromStatfs(t *testing.T) {
	original := statfs
	defer func() { statfs = original }()
	statfs = func(path string, st *syscall.Statfs_t) error {
		st.Bsize = 4096
		st.Blocks = 1000
		st.Bfree = 400 // includes root-reserved blocks
		st.Bavail = 300
		st.Files = 5000
		st.Ffree = 4200
		return nil
	}
	got, err := (&Mounter{}).VolumeStats(context.Background(), "/var/lib/kubelet/x")
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalBytes != 1000*4096 || got.AvailableBytes != 300*4096 || got.UsedBytes != 600*4096 {
		t.Fatalf("bytes = %+v", got)
	}
	if got.TotalInodes != 5000 || got.AvailableInodes != 4200 || got.UsedInodes != 800 {
		t.Fatalf("inodes = %+v", got)
	}
}

func TestVolumeStatsReportsMissingPath(t *testing.T) {
	_, err := (&Mounter{}).VolumeStats(context.Background(), filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestVolumeStatsReadsRealFilesystem(t *testing.T) {
	got, err := (&Mounter{}).VolumeStats(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalBytes <= 0 || got.UsedBytes < 0 || got.AvailableBytes > got.TotalBytes {
		t.Fatalf("implausible stats %+v", got)
	}
}

func TestVolumeStatsRejectsRelativePath(t *testing.T) {
	if _, err := (&Mounter{}).VolumeStats(context.Background(), "relative"); err == nil {
		t.Fatal("relative path accepted")
	}
}

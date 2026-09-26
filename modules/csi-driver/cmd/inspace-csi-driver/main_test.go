package main

import "testing"

func TestMaxVolumeSizeBytes(t *testing.T) {
	got, err := maxVolumeSizeBytes(2000)
	if err != nil || got != 2000*1024*1024*1024 {
		t.Fatalf("maxVolumeSizeBytes(2000) = %d, %v", got, err)
	}
	for _, invalid := range []int64{0, -1, 1 << 40} {
		if _, err := maxVolumeSizeBytes(invalid); err == nil {
			t.Errorf("maxVolumeSizeBytes(%d) accepted an invalid size", invalid)
		}
	}
}

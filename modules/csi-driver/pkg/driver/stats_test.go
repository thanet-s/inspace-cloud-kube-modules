package driver

import (
	"context"
	"errors"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host"
	hostfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host/fake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	statsHandle = "inspace://bkk01/11111111-1111-4111-8111-111111111111"
	statsPath   = "/var/lib/kubelet/pods/p/volumes/kubernetes.io~csi/pvc/mount"
)

func newStatsNode(t *testing.T) (*Driver, *hostfake.Mounter) {
	t.Helper()
	mounter := hostfake.New()
	node, err := New(Config{Mode: ModeNode, Location: "bkk01", NodeID: "node-1"}, nil, mounter)
	if err != nil {
		t.Fatal(err)
	}
	return node, mounter
}

func TestNodeAdvertisesVolumeStatsCapabilities(t *testing.T) {
	node, _ := newStatsNode(t)
	response, err := node.NodeGetCapabilities(context.Background(), &csi.NodeGetCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[csi.NodeServiceCapability_RPC_Type]bool{}
	for _, capability := range response.GetCapabilities() {
		seen[capability.GetRpc().GetType()] = true
	}
	for _, want := range []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
		csi.NodeServiceCapability_RPC_GET_VOLUME_STATS,
	} {
		if !seen[want] {
			t.Errorf("node did not advertise %s", want)
		}
	}
}

func TestNodeGetVolumeStatsReportsBytesAndInodes(t *testing.T) {
	node, mounter := newStatsNode(t)
	mounter.SetMount(host.Mount{Source: "/dev/vdb", Target: statsPath, FSType: "ext4"})
	mounter.SetVolumeStats(statsPath, host.VolumeStats{
		TotalBytes: 100, AvailableBytes: 70, UsedBytes: 25,
		TotalInodes: 1000, AvailableInodes: 900, UsedInodes: 100,
	})
	response, err := node.NodeGetVolumeStats(context.Background(), &csi.NodeGetVolumeStatsRequest{
		VolumeId: statsHandle, VolumePath: statsPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	usage := map[csi.VolumeUsage_Unit]*csi.VolumeUsage{}
	for _, entry := range response.GetUsage() {
		usage[entry.GetUnit()] = entry
	}
	if len(usage) != 2 {
		t.Fatalf("usage = %v, want BYTES and INODES", response.GetUsage())
	}
	if got := usage[csi.VolumeUsage_BYTES]; got.GetTotal() != 100 || got.GetAvailable() != 70 || got.GetUsed() != 25 {
		t.Fatalf("bytes usage = %v", got)
	}
	if got := usage[csi.VolumeUsage_INODES]; got.GetTotal() != 1000 || got.GetAvailable() != 900 || got.GetUsed() != 100 {
		t.Fatalf("inodes usage = %v", got)
	}
}

func TestNodeGetVolumeStatsRejectsBadRequests(t *testing.T) {
	node, mounter := newStatsNode(t)
	mounter.SetVolumeStats(statsPath+"-plain", host.VolumeStats{TotalBytes: 100})
	mounter.SetVolumeStatsError(statsPath+"-broken", errors.New("input/output error"))
	mounter.SetMount(host.Mount{Source: "/dev/vdb", Target: statsPath + "-broken", FSType: "ext4"})
	tests := []struct {
		name string
		req  *csi.NodeGetVolumeStatsRequest
		want codes.Code
	}{
		{"nil request", nil, codes.InvalidArgument},
		{"missing volume id", &csi.NodeGetVolumeStatsRequest{VolumePath: statsPath}, codes.InvalidArgument},
		{"missing volume path", &csi.NodeGetVolumeStatsRequest{VolumeId: statsHandle}, codes.InvalidArgument},
		{"malformed volume id", &csi.NodeGetVolumeStatsRequest{VolumeId: "nope", VolumePath: statsPath}, codes.InvalidArgument},
		{"path does not exist", &csi.NodeGetVolumeStatsRequest{VolumeId: statsHandle, VolumePath: statsPath}, codes.NotFound},
		{"path exists but is not a mount", &csi.NodeGetVolumeStatsRequest{VolumeId: statsHandle, VolumePath: statsPath + "-plain"}, codes.NotFound},
		{"statfs fails", &csi.NodeGetVolumeStatsRequest{VolumeId: statsHandle, VolumePath: statsPath + "-broken"}, codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := node.NodeGetVolumeStats(context.Background(), test.req)
			if got := status.Code(err); got != test.want {
				t.Fatalf("code = %v (%v), want %v", got, err, test.want)
			}
		})
	}
}

func TestNodeGetVolumeStatsNeedsMounter(t *testing.T) {
	controller, err := New(Config{Mode: ModeController, Location: "bkk01"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.NodeGetVolumeStats(context.Background(), &csi.NodeGetVolumeStatsRequest{VolumeId: statsHandle, VolumePath: "/x"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

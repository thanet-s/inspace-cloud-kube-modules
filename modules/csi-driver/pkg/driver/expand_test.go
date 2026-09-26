package driver

import (
	"context"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud/fake"
	hostfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/host/fake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const expandedCapacity int64 = 30 * 1024 * 1024 * 1024

type publishedVolume struct {
	handle      string
	device      string
	stagingPath string
	targetPath  string
}

func publishSmokeVolume(t *testing.T, h *smokeHarness, name string) publishedVolume {
	t.Helper()
	ctx := context.Background()
	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: name, CapacityRange: &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	published, err := h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId: handle, NodeId: "inspace://bkk01/node-1", VolumeCapability: rwoCapability(),
	})
	if err != nil {
		t.Fatal(err)
	}
	volume := publishedVolume{
		handle: handle, device: published.GetPublishContext()["devicePath"],
		stagingPath: "/staging/" + name, targetPath: "/pods/pod-1/volumes/" + name,
	}
	if _, err := h.node.NodeStageVolume(ctx, &csi.NodeStageVolumeRequest{
		VolumeId: handle, StagingTargetPath: volume.stagingPath,
		VolumeCapability: rwoCapability(), PublishContext: published.GetPublishContext(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.node.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: handle, StagingTargetPath: volume.stagingPath,
		TargetPath: volume.targetPath, VolumeCapability: rwoCapability(),
	}); err != nil {
		t.Fatal(err)
	}
	return volume
}

func TestExpansionCapabilitiesAreAdvertised(t *testing.T) {
	ctx := context.Background()
	controller, err := New(Config{Mode: ModeController, Location: "bkk01"}, cloudfake.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := controller.GetPluginCapabilities(ctx, &csi.GetPluginCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	online := false
	for _, capability := range plugin.GetCapabilities() {
		if capability.GetVolumeExpansion().GetType() == csi.PluginCapability_VolumeExpansion_ONLINE {
			online = true
		}
	}
	if !online {
		t.Fatal("controller mode did not advertise ONLINE volume expansion")
	}
	controllerCapabilities, err := controller.ControllerGetCapabilities(ctx, &csi.ControllerGetCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	controllerExpand := false
	for _, capability := range controllerCapabilities.GetCapabilities() {
		if capability.GetRpc().GetType() == csi.ControllerServiceCapability_RPC_EXPAND_VOLUME {
			controllerExpand = true
		}
	}
	if !controllerExpand {
		t.Fatal("controller did not advertise EXPAND_VOLUME")
	}

	node, err := New(Config{Mode: ModeNode, Location: "bkk01", NodeID: "node-1"}, nil, hostfake.New())
	if err != nil {
		t.Fatal(err)
	}
	nodeCapabilities, err := node.NodeGetCapabilities(ctx, &csi.NodeGetCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	nodeExpand := false
	for _, capability := range nodeCapabilities.GetCapabilities() {
		if capability.GetRpc().GetType() == csi.NodeServiceCapability_RPC_EXPAND_VOLUME {
			nodeExpand = true
		}
	}
	if !nodeExpand {
		t.Fatal("node did not advertise EXPAND_VOLUME")
	}
}

func TestOnlineExpansionGrowsDiskThenFilesystem(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	volume := publishSmokeVolume(t, h, "pvc-expand")

	expanded, err := h.controller.ControllerExpandVolume(ctx, &csi.ControllerExpandVolumeRequest{
		VolumeId: volume.handle, CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
		VolumeCapability: rwoCapability(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if expanded.GetCapacityBytes() != expandedCapacity || !expanded.GetNodeExpansionRequired() {
		t.Fatalf("controller expand = %v, want %d bytes with node expansion", expanded, expandedCapacity)
	}

	nodeExpanded, err := h.node.NodeExpandVolume(ctx, &csi.NodeExpandVolumeRequest{
		VolumeId: volume.handle, VolumePath: volume.targetPath, StagingTargetPath: volume.stagingPath,
		CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity}, VolumeCapability: rwoCapability(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if nodeExpanded.GetCapacityBytes() < expandedCapacity {
		t.Fatalf("node expand capacity = %d, want at least %d", nodeExpanded.GetCapacityBytes(), expandedCapacity)
	}
	if got := h.mounter.FilesystemExpansions(volume.device); got != 1 {
		t.Fatalf("filesystem expansions of %s = %d, want 1", volume.device, got)
	}
}

func TestControllerExpandRequiresAttachedVolume(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: "pvc-offline", CapacityRange: &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.controller.ControllerExpandVolume(ctx, &csi.ControllerExpandVolumeRequest{
		VolumeId: created.GetVolume().GetVolumeId(), CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("offline expand code = %v, err = %v; want FailedPrecondition", status.Code(err), err)
	}
}

func TestControllerExpandValidatesRequest(t *testing.T) {
	provider := cloudfake.New()
	d, err := New(Config{Mode: ModeController, Location: "bkk01", MaxVolumeSize: expandedCapacity}, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := d.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: "pvc-validate-expand", CapacityRange: &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	block := &csi.VolumeCapability{
		AccessType: &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}},
		AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
	}
	tests := map[string]struct {
		request *csi.ControllerExpandVolumeRequest
		code    codes.Code
	}{
		"missing volume ID": {
			request: &csi.ControllerExpandVolumeRequest{CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity}},
			code:    codes.InvalidArgument,
		},
		"missing capacity range": {
			request: &csi.ControllerExpandVolumeRequest{VolumeId: handle},
			code:    codes.InvalidArgument,
		},
		"required exceeds limit": {
			request: &csi.ControllerExpandVolumeRequest{VolumeId: handle, CapacityRange: &csi.CapacityRange{
				RequiredBytes: expandedCapacity, LimitBytes: smokeCapacity,
			}},
			code: codes.InvalidArgument,
		},
		"exceeds configured maximum": {
			request: &csi.ControllerExpandVolumeRequest{VolumeId: handle, CapacityRange: &csi.CapacityRange{
				RequiredBytes: expandedCapacity + 1,
			}},
			code: codes.OutOfRange,
		},
		"raw block capability": {
			request: &csi.ControllerExpandVolumeRequest{VolumeId: handle, VolumeCapability: block, CapacityRange: &csi.CapacityRange{
				RequiredBytes: expandedCapacity,
			}},
			code: codes.InvalidArgument,
		},
		"foreign location": {
			request: &csi.ControllerExpandVolumeRequest{
				VolumeId:      "inspace://sgp01/11111111-1111-4111-8111-111111111111",
				CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
			},
			code: codes.InvalidArgument,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := d.ControllerExpandVolume(ctx, test.request); status.Code(err) != test.code {
				t.Fatalf("code = %v, err = %v; want %v", status.Code(err), err, test.code)
			}
		})
	}
}

func TestNodeExpandRejectsVolumePathThatIsNotMounted(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	volume := publishSmokeVolume(t, h, "pvc-unmounted-expand")
	_, err := h.node.NodeExpandVolume(context.Background(), &csi.NodeExpandVolumeRequest{
		VolumeId: volume.handle, VolumePath: "/pods/other/volumes/missing",
		CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unmounted path code = %v, err = %v; want NotFound", status.Code(err), err)
	}
	if got := h.mounter.FilesystemExpansions(volume.device); got != 0 {
		t.Fatalf("unmounted path ran %d filesystem expansion(s)", got)
	}
}

func TestNodeExpandRejectsVolumePathOfAnotherDevice(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	first := publishSmokeVolume(t, h, "pvc-expand-first")
	second := publishSmokeVolume(t, h, "pvc-expand-second")
	_, err := h.node.NodeExpandVolume(context.Background(), &csi.NodeExpandVolumeRequest{
		VolumeId: first.handle, VolumePath: second.targetPath, StagingTargetPath: second.stagingPath,
		CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("foreign mount code = %v, err = %v; want FailedPrecondition", status.Code(err), err)
	}
	if h.mounter.FilesystemExpansions(first.device) != 0 || h.mounter.FilesystemExpansions(second.device) != 0 {
		t.Fatal("foreign mount ran a filesystem expansion")
	}
}

func TestNodeExpandWaitsForGuestToSeeGrownDevice(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	volume := publishSmokeVolume(t, h, "pvc-expand-lagging")
	h.mounter.SetDeviceSize(volume.device, smokeCapacity)
	_, err := h.node.NodeExpandVolume(context.Background(), &csi.NodeExpandVolumeRequest{
		VolumeId: volume.handle, VolumePath: volume.targetPath, StagingTargetPath: volume.stagingPath,
		CapacityRange: &csi.CapacityRange{RequiredBytes: expandedCapacity},
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("lagging device code = %v, err = %v; want Unavailable", status.Code(err), err)
	}
	if got := h.mounter.FilesystemExpansions(volume.device); got != 0 {
		t.Fatalf("lagging device ran %d filesystem expansion(s)", got)
	}
}

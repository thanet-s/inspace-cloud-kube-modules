package driver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/cloud/fake"
	hostfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/host/fake"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const smokeCapacity int64 = 20 * 1024 * 1024 * 1024

type smokeHarness struct {
	controller csi.ControllerClient
	node       csi.NodeClient
	identity   csi.IdentityClient
	cloud      *cloudfake.Cloud
	mounter    *hostfake.Mounter
	close      func()
}

func newSmokeHarness(t *testing.T) *smokeHarness {
	t.Helper()
	provider := cloudfake.New()
	mounter := hostfake.New()
	d, err := New(Config{Location: "bkk01", NodeID: "inspace://bkk01/node-1"}, provider, mounter)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	d.Register(server)
	go func() {
		if err := server.Serve(listener); err != nil {
			return
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		server.Stop()
		listener.Close()
		t.Fatal(err)
	}
	return &smokeHarness{
		controller: csi.NewControllerClient(conn),
		node:       csi.NewNodeClient(conn),
		identity:   csi.NewIdentityClient(conn),
		cloud:      provider,
		mounter:    mounter,
		close: func() {
			conn.Close()
			server.Stop()
			listener.Close()
		},
	}
}

func rwoCapability() *csi.VolumeCapability {
	return &csi.VolumeCapability{
		AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{FsType: "ext4"}},
		AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
	}
}

func TestCSIRWOLifecycleSmoke(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()

	info, err := h.identity.GetPluginInfo(ctx, &csi.GetPluginInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.GetName() != DefaultPluginName {
		t.Fatalf("plugin name = %q", info.GetName())
	}

	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name:               "pvc-smoke",
		CapacityRange:      &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	ref, err := ParseVolumeHandle(handle)
	if err != nil {
		t.Fatal(err)
	}

	published, err := h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId: handle, NodeId: "inspace://bkk01/node-1", VolumeCapability: rwoCapability(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.cloud.AttachedNode("bkk01", ref.ID); err != nil || got != "inspace://bkk01/node-1" {
		t.Fatalf("attached node = %q, err = %v", got, err)
	}

	stage := &csi.NodeStageVolumeRequest{
		VolumeId: handle, StagingTargetPath: "/staging/pvc-smoke",
		VolumeCapability: rwoCapability(), PublishContext: published.GetPublishContext(),
	}
	if _, err := h.node.NodeStageVolume(ctx, stage); err != nil {
		t.Fatal(err)
	}
	publish := &csi.NodePublishVolumeRequest{
		VolumeId: handle, StagingTargetPath: stage.StagingTargetPath,
		TargetPath: "/pods/pod-1/volumes/pvc-smoke", VolumeCapability: rwoCapability(),
	}
	if _, err := h.node.NodePublishVolume(ctx, publish); err != nil {
		t.Fatal(err)
	}
	if got := h.mounter.MountCount(); got != 2 {
		t.Fatalf("mount count = %d, want 2", got)
	}

	if _, err := h.node.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: handle, TargetPath: publish.TargetPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.node.NodeUnstageVolume(ctx, &csi.NodeUnstageVolumeRequest{VolumeId: handle, StagingTargetPath: stage.StagingTargetPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{VolumeId: handle, NodeId: "inspace://bkk01/node-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.DeleteVolume(ctx, &csi.DeleteVolumeRequest{VolumeId: handle}); err != nil {
		t.Fatal(err)
	}
	if h.cloud.VolumeCount() != 0 || h.mounter.MountCount() != 0 {
		t.Fatalf("resources leaked: volumes=%d mounts=%d", h.cloud.VolumeCount(), h.mounter.MountCount())
	}
}

func TestLifecycleRequestsAreIdempotent(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	createRequest := &csi.CreateVolumeRequest{
		Name: "pvc-idempotent", CapacityRange: &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	}
	first, err := h.controller.CreateVolume(ctx, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.controller.CreateVolume(ctx, createRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetVolume().GetVolumeId() != second.GetVolume().GetVolumeId() || h.cloud.VolumeCount() != 1 {
		t.Fatalf("idempotent create returned different volume or duplicate")
	}
	handle := first.GetVolume().GetVolumeId()
	attach := &csi.ControllerPublishVolumeRequest{VolumeId: handle, NodeId: "node-1", VolumeCapability: rwoCapability()}
	var publishContext map[string]string
	for range 2 {
		response, err := h.controller.ControllerPublishVolume(ctx, attach)
		if err != nil {
			t.Fatal(err)
		}
		publishContext = response.GetPublishContext()
	}
	stage := &csi.NodeStageVolumeRequest{VolumeId: handle, StagingTargetPath: "/stage/idempotent", VolumeCapability: rwoCapability(), PublishContext: publishContext}
	for range 2 {
		if _, err := h.node.NodeStageVolume(ctx, stage); err != nil {
			t.Fatal(err)
		}
	}
	publish := &csi.NodePublishVolumeRequest{VolumeId: handle, StagingTargetPath: stage.StagingTargetPath, TargetPath: "/target/idempotent", VolumeCapability: rwoCapability()}
	for range 2 {
		if _, err := h.node.NodePublishVolume(ctx, publish); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if _, err := h.node.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: handle, TargetPath: publish.TargetPath}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.node.NodeUnstageVolume(ctx, &csi.NodeUnstageVolumeRequest{VolumeId: handle, StagingTargetPath: stage.StagingTargetPath}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.controller.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{VolumeId: handle, NodeId: "node-1"}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if _, err := h.controller.DeleteVolume(ctx, &csi.DeleteVolumeRequest{VolumeId: handle}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRejectsMultiNodeAndNonExt4Capabilities(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	for name, capability := range map[string]*csi.VolumeCapability{
		"rwx": {
			AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{FsType: "ext4"}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER},
		},
		"xfs": {
			AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{FsType: "xfs"}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
		},
		"raw-block": {
			AccessType: &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{Name: "bad-" + name, VolumeCapabilities: []*csi.VolumeCapability{capability}})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument; err=%v", status.Code(err), err)
			}
		})
	}
}

func TestRWORejectsAttachToSecondNode(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: "pvc-single-node", VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	for _, node := range []string{"node-1", "node-1"} {
		if _, err := h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
			VolumeId: handle, NodeId: node, VolumeCapability: rwoCapability(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId: handle, NodeId: "node-2", VolumeCapability: rwoCapability(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second-node attach code = %v, want FailedPrecondition; err=%v", status.Code(err), err)
	}
}

func TestIdempotentCreateRequiresCompatibleCapacityAndTopology(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	request := &csi.CreateVolumeRequest{
		Name: "pvc-capacity", CapacityRange: &csi.CapacityRange{RequiredBytes: smokeCapacity},
		VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	}
	if _, err := h.controller.CreateVolume(ctx, request); err != nil {
		t.Fatal(err)
	}
	request.CapacityRange.RequiredBytes = smokeCapacity * 2
	if _, err := h.controller.CreateVolume(ctx, request); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("incompatible retry code = %v, want AlreadyExists; err=%v", status.Code(err), err)
	}
	request.Name = "pvc-other-location"
	request.CapacityRange.RequiredBytes = smokeCapacity
	request.AccessibilityRequirements = &csi.TopologyRequirement{Requisite: []*csi.Topology{{
		Segments: map[string]string{TopologyLocationKey: "sin01"},
	}}}
	if _, err := h.controller.CreateVolume(ctx, request); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("topology code = %v, want ResourceExhausted; err=%v", status.Code(err), err)
	}
}

func TestControllerUnpublishWithoutNodeDetachesSingleAttachment(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: "pvc-unpublish-all", VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	ref, err := ParseVolumeHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId: handle, NodeId: "node-1", VolumeCapability: rwoCapability(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{VolumeId: handle}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.cloud.AttachedNode("bkk01", ref.ID); err != nil || got != "" {
		t.Fatalf("attached node after all-node detach = %q, err=%v", got, err)
	}
}

func TestRejectsContentSourcesParametersMutableParametersAndMalformedTopology(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	request := func() *csi.CreateVolumeRequest {
		return &csi.CreateVolumeRequest{Name: "pvc-validation", VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()}}
	}

	withSource := request()
	withSource.VolumeContentSource = &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Volume{
		Volume: &csi.VolumeContentSource_VolumeSource{VolumeId: "source"},
	}}
	if _, err := h.controller.CreateVolume(ctx, withSource); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("content source code=%v, err=%v", status.Code(err), err)
	}
	withParameter := request()
	withParameter.Parameters = map[string]string{"unknown": "value"}
	if _, err := h.controller.CreateVolume(ctx, withParameter); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("parameter code=%v, err=%v", status.Code(err), err)
	}
	withMutable := request()
	withMutable.MutableParameters = map[string]string{"size": "20Gi"}
	if _, err := h.controller.CreateVolume(ctx, withMutable); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("create mutable parameters code=%v, err=%v", status.Code(err), err)
	}
	withTopology := request()
	withTopology.AccessibilityRequirements = &csi.TopologyRequirement{}
	if _, err := h.controller.CreateVolume(ctx, withTopology); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty topology code=%v, err=%v", status.Code(err), err)
	}

	created, err := h.controller.CreateVolume(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.controller.ValidateVolumeCapabilities(ctx, &csi.ValidateVolumeCapabilitiesRequest{
		VolumeId: created.GetVolume().GetVolumeId(), VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
		MutableParameters: map[string]string{"size": "20Gi"},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("mutable parameters code=%v, err=%v", status.Code(err), err)
	}
}

func TestNodeRejectsConflictingStageAndPublishMounts(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	created, err := h.controller.CreateVolume(ctx, &csi.CreateVolumeRequest{
		Name: "pvc-conflict", VolumeCapabilities: []*csi.VolumeCapability{rwoCapability()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := created.GetVolume().GetVolumeId()
	published, err := h.controller.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
		VolumeId: handle, NodeId: "node-1", VolumeCapability: rwoCapability(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.mounter.FormatAndMount(ctx, "/dev/wrong", "/stage/conflict", "ext4", nil); err != nil {
		t.Fatal(err)
	}
	stage := &csi.NodeStageVolumeRequest{
		VolumeId: handle, StagingTargetPath: "/stage/conflict", VolumeCapability: rwoCapability(),
		PublishContext: published.GetPublishContext(),
	}
	if _, err := h.node.NodeStageVolume(ctx, stage); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stage conflict code=%v, err=%v", status.Code(err), err)
	}
	if err := h.mounter.Unmount(ctx, stage.StagingTargetPath); err != nil {
		t.Fatal(err)
	}
	if _, err := h.node.NodeStageVolume(ctx, stage); err != nil {
		t.Fatal(err)
	}
	if err := h.mounter.FormatAndMount(ctx, "/dev/other", "/stage/other", "ext4", nil); err != nil {
		t.Fatal(err)
	}
	if err := h.mounter.BindMount(ctx, "/stage/other", "/target/conflict", false, nil); err != nil {
		t.Fatal(err)
	}
	_, err = h.node.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
		VolumeId: handle, StagingTargetPath: stage.StagingTargetPath, TargetPath: "/target/conflict",
		VolumeCapability: rwoCapability(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("publish conflict code=%v, err=%v", status.Code(err), err)
	}
}

func TestNodeStageAndPublishPreconditionCodes(t *testing.T) {
	h := newSmokeHarness(t)
	defer h.close()
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"stage-path": func() error {
			_, err := h.node.NodeStageVolume(ctx, &csi.NodeStageVolumeRequest{VolumeId: "x", VolumeCapability: rwoCapability()})
			return err
		},
		"publish-path": func() error {
			_, err := h.node.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{VolumeId: "x", TargetPath: "/target", VolumeCapability: rwoCapability()})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("code=%v err=%v", status.Code(err), err)
			}
		})
	}
}

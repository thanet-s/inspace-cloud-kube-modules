package driver

import (
	"context"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/cloud/fake"
	hostfake "github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/host/fake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestModeCapabilitiesAndDependencyAwareProbe(t *testing.T) {
	ctx := context.Background()
	controller, err := New(Config{Mode: ModeController, Location: "bkk01"}, cloudfake.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := controller.GetPluginCapabilities(ctx, &csi.GetPluginCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasControllerCapability(response.GetCapabilities()) {
		t.Fatal("controller mode did not advertise controller service")
	}
	probe, err := controller.Probe(ctx, &csi.ProbeRequest{})
	if err != nil || !probe.GetReady().GetValue() {
		t.Fatalf("controller probe=%v err=%v", probe, err)
	}

	node, err := New(Config{Mode: ModeNode, Location: "bkk01", NodeID: "node-1"}, nil, hostfake.New())
	if err != nil {
		t.Fatal(err)
	}
	response, err = node.GetPluginCapabilities(ctx, &csi.GetPluginCapabilitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if hasControllerCapability(response.GetCapabilities()) {
		t.Fatal("node mode advertised controller service")
	}
	probe, err = node.Probe(ctx, &csi.ProbeRequest{})
	if err != nil || !probe.GetReady().GetValue() {
		t.Fatalf("node probe=%v err=%v", probe, err)
	}

	missing, err := New(Config{Mode: ModeController, Location: "bkk01"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Probe(ctx, &csi.ProbeRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing dependency probe code=%v err=%v", status.Code(err), err)
	}
}

func hasControllerCapability(capabilities []*csi.PluginCapability) bool {
	for _, capability := range capabilities {
		if capability.GetService().GetType() == csi.PluginCapability_Service_CONTROLLER_SERVICE {
			return true
		}
	}
	return false
}

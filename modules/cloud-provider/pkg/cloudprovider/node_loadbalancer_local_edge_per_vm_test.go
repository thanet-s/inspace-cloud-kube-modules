package cloudprovider

import "testing"

func TestPublicNodeLocalEdgeDefaultsToPerService(t *testing.T) {
	f := newPublishedPublicNodeLocalFixture(t)
	if f.controller.publicNodeLocalPerVMModeEnabled() {
		t.Fatal("the default mode must be perService")
	}
	if _, ok := f.controller.publicNodeLocalEdgeFor(f.current(t)).(perServiceEdge); !ok {
		t.Fatalf("the default edge is %T, want perServiceEdge", f.controller.publicNodeLocalEdgeFor(f.current(t)))
	}
}

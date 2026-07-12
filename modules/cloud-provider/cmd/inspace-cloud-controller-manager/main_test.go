package main

import (
	"os"
	"strings"
	"testing"
)

func TestManifestWiresReservedPrivateAddressEnvironment(t *testing.T) {
	data, err := os.ReadFile("../../config/ccm/cloud-controller-manager.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	for _, required := range []string{
		"controlPlaneVIP: REPLACE_WITH_CONTROL_PLANE_VIP",
		"name: INSPACE_CONTROL_PLANE_VIP",
		"key: controlPlaneVIP",
		"privateLoadBalancerPoolStart: REPLACE_WITH_PRIVATE_LOAD_BALANCER_POOL_START",
		"privateLoadBalancerPoolStop: REPLACE_WITH_PRIVATE_LOAD_BALANCER_POOL_STOP",
		"name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_START",
		"key: privateLoadBalancerPoolStart",
		"name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP",
		"key: privateLoadBalancerPoolStop",
	} {
		if !strings.Contains(manifest, required) {
			t.Errorf("CCM manifest lacks %q", required)
		}
	}
}

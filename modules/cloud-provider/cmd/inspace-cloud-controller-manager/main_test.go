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
		"billingAccountID: \"REPLACE_WITH_BILLING_ACCOUNT_ID\"",
		"name: INSPACE_BILLING_ACCOUNT_ID",
		"key: billingAccountID",
		"optional: false",
	} {
		if !strings.Contains(manifest, required) {
			t.Errorf("CCM manifest lacks %q", required)
		}
	}
}

func TestParseRequiredPositiveInt64(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		want    int64
		wantErr bool
	}{
		{name: "missing", wantErr: true},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "not an integer", value: "account", wantErr: true},
		{name: "positive", value: " 42 ", want: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("INSPACE_BILLING_ACCOUNT_ID", test.value)
			got, err := parseRequiredPositiveInt64("INSPACE_BILLING_ACCOUNT_ID")
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("parseRequiredPositiveInt64() = %d, %v", got, err)
			}
		})
	}
}

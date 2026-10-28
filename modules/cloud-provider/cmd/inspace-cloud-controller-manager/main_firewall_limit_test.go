package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseMaxFirewallsPerVM(t *testing.T) {
	const name = "INSPACE_NODE_LOAD_BALANCER_MAX_FIREWALLS_PER_VM"
	for _, test := range []struct {
		value   string
		want    int32
		wantErr bool
	}{
		{value: "", want: 3},
		{value: "  ", want: 3},
		{value: "4", want: 4},
		{value: " 2 ", want: 2},
		{value: "0", want: 3},
		{value: "-5", want: 3},
		{value: "many", wantErr: true},
		{value: "2.5", wantErr: true},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv(name, test.value)
			got, err := parseMaxFirewallsPerVM()
			if (err != nil) != test.wantErr || (err == nil && got != test.want) {
				t.Fatalf("parseMaxFirewallsPerVM(%q) = %d, %v; want %d, error %t", test.value, got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestManifestWiresMaxFirewallsPerVM(t *testing.T) {
	data, err := os.ReadFile("../../config/ccm/cloud-controller-manager.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "name: INSPACE_NODE_LOAD_BALANCER_MAX_FIREWALLS_PER_VM\n              value: \"3\"") {
		t.Fatal("manifest does not wire INSPACE_NODE_LOAD_BALANCER_MAX_FIREWALLS_PER_VM=3")
	}
}

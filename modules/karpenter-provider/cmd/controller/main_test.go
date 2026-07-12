package main

import (
	"strings"
	"testing"
)

func setValidControllerEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("INSPACE_API_TOKEN", "test-token")
	t.Setenv("INSPACE_CLUSTER_NAME", "test-cluster")
	t.Setenv("INSPACE_DEFAULT_NODECLASS", "workers")
	t.Setenv("INSPACE_LOCATION", "bkk01")
	t.Setenv("INSPACE_NETWORK_UUID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("INSPACE_CONTROL_PLANE_VIP", "10.0.0.10")
	t.Setenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_START", "10.0.0.200")
	t.Setenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP", "10.0.0.219")
	t.Setenv("INSPACE_ALLOW_REMOTE_MUTATIONS", "true")
}

func TestLoadSettingsRequiresCanonicalPrivateLoadBalancerPool(t *testing.T) {
	setValidControllerEnvironment(t)
	cfg, err := loadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.privateLoadBalancerPool.Start != "10.0.0.200" || cfg.privateLoadBalancerPool.Stop != "10.0.0.219" {
		t.Fatalf("private pool = %#v", cfg.privateLoadBalancerPool)
	}
	if cfg.networkUUID != "11111111-1111-4111-8111-111111111111" || cfg.controlPlaneVIP != "10.0.0.10" {
		t.Fatalf("controller network contract = network %q VIP %q", cfg.networkUUID, cfg.controlPlaneVIP)
	}

	for name, values := range map[string][2]string{
		"missing":      {"", ""},
		"too small":    {"10.0.0.200", "10.0.0.214"},
		"reversed":     {"10.0.0.219", "10.0.0.200"},
		"pod CIDR":     {"10.42.0.10", "10.42.0.25"},
		"service CIDR": {"10.43.0.10", "10.43.0.25"},
		"too large":    {"10.0.1.0", "10.0.2.0"},
	} {
		t.Run(name, func(t *testing.T) {
			setValidControllerEnvironment(t)
			t.Setenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_START", values[0])
			t.Setenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP", values[1])
			_, err := loadSettings()
			if err == nil || !strings.Contains(err.Error(), "INSPACE_PRIVATE_LOAD_BALANCER_POOL_START/STOP") {
				t.Fatalf("loadSettings() error = %v", err)
			}
		})
	}
}

func TestLoadSettingsRequiresExactNetworkAndControlPlaneVIP(t *testing.T) {
	for _, test := range []struct {
		name  string
		env   string
		value string
	}{
		{name: "missing network", env: "INSPACE_NETWORK_UUID", value: ""},
		{name: "invalid network", env: "INSPACE_NETWORK_UUID", value: "not-a-uuid"},
		{name: "missing VIP", env: "INSPACE_CONTROL_PLANE_VIP", value: ""},
		{name: "noncanonical VIP", env: "INSPACE_CONTROL_PLANE_VIP", value: "10.0.0.010"},
		{name: "pod CIDR VIP", env: "INSPACE_CONTROL_PLANE_VIP", value: "10.42.0.10"},
		{name: "service CIDR VIP", env: "INSPACE_CONTROL_PLANE_VIP", value: "10.43.0.10"},
		{name: "VIP in private pool", env: "INSPACE_CONTROL_PLANE_VIP", value: "10.0.0.205"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setValidControllerEnvironment(t)
			t.Setenv(test.env, test.value)
			if _, err := loadSettings(); err == nil {
				t.Fatalf("loadSettings() accepted %s=%q", test.env, test.value)
			}
		})
	}
}

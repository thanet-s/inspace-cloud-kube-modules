package v1alpha1

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPrivateLoadBalancerPoolValidation(t *testing.T) {
	supervisor := netip.MustParseAddr("10.0.0.10")
	for name, test := range map[string]struct {
		pool      PrivateLoadBalancerPool
		wantError bool
	}{
		"valid":               {pool: PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"}},
		"minimum 16":          {pool: PrivateLoadBalancerPool{Start: "10.91.72.232", Stop: "10.91.72.247"}},
		"maximum 256":         {pool: PrivateLoadBalancerPool{Start: "10.0.1.0", Stop: "10.0.1.255"}},
		"missing":             {wantError: true},
		"single address":      {pool: PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.200"}, wantError: true},
		"fewer than 16":       {pool: PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.214"}, wantError: true},
		"public":              {pool: PrivateLoadBalancerPool{Start: "203.0.113.10", Stop: "203.0.113.20"}, wantError: true},
		"private IPv6":        {pool: PrivateLoadBalancerPool{Start: "fd00::10", Stop: "fd00::20"}, wantError: true},
		"noncanonical":        {pool: PrivateLoadBalancerPool{Start: "10.0.0.020", Stop: "10.0.0.021"}, wantError: true},
		"reversed":            {pool: PrivateLoadBalancerPool{Start: "10.0.0.220", Stop: "10.0.0.200"}, wantError: true},
		"more than 256":       {pool: PrivateLoadBalancerPool{Start: "10.0.1.0", Stop: "10.0.2.0"}, wantError: true},
		"pod CIDR":            {pool: PrivateLoadBalancerPool{Start: "10.42.1.10", Stop: "10.42.1.25"}, wantError: true},
		"crosses pod CIDR":    {pool: PrivateLoadBalancerPool{Start: "10.41.255.248", Stop: "10.42.0.7"}, wantError: true},
		"service CIDR":        {pool: PrivateLoadBalancerPool{Start: "10.43.1.10", Stop: "10.43.1.25"}, wantError: true},
		"supervisor included": {pool: PrivateLoadBalancerPool{Start: "10.0.0.1", Stop: "10.0.0.16"}, wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			err := test.pool.ValidateForSupervisor(supervisor)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateForSupervisor() error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestPrivateLoadBalancerPoolSizeBounds(t *testing.T) {
	if PrivateLoadBalancerPoolMinAddresses != 16 || MaxPrivateLoadBalancerPoolAddresses != 256 {
		t.Fatalf("Service pool bounds = %d..%d, want 16..256", PrivateLoadBalancerPoolMinAddresses, MaxPrivateLoadBalancerPoolAddresses)
	}
	if _, _, err := (PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.214"}).Range(); err == nil || !strings.Contains(err.Error(), "minimum is 16") {
		t.Fatalf("15-address Range() error = %v, want minimum bound", err)
	}
	if _, _, err := (PrivateLoadBalancerPool{Start: "10.0.1.0", Stop: "10.0.2.0"}).Range(); err == nil || !strings.Contains(err.Error(), "maximum is 256") {
		t.Fatalf("257-address Range() error = %v, want maximum bound", err)
	}
}

func TestPrivateLoadBalancerPoolContains(t *testing.T) {
	pool := PrivateLoadBalancerPool{Start: "10.0.0.200", Stop: "10.0.0.219"}
	for value, want := range map[string]bool{
		"10.0.0.199": false,
		"10.0.0.200": true,
		"10.0.0.210": true,
		"10.0.0.219": true,
		"10.0.0.220": false,
	} {
		got, err := pool.Contains(netip.MustParseAddr(value))
		if err != nil || got != want {
			t.Fatalf("Contains(%s) = %t, %v; want %t", value, got, err, want)
		}
	}
}

func TestParseControlPlaneVIPUsesFixedClusterExclusions(t *testing.T) {
	if vip, err := ParseControlPlaneVIP("10.0.0.10"); err != nil || vip.String() != "10.0.0.10" {
		t.Fatalf("ParseControlPlaneVIP(valid) = %s, %v", vip, err)
	}
	for _, value := range []string{"", "203.0.113.10", "10.0.0.010", "10.42.0.10", "10.43.0.10"} {
		if _, err := ParseControlPlaneVIP(value); err == nil {
			t.Fatalf("ParseControlPlaneVIP(%q) unexpectedly succeeded", value)
		}
	}
}

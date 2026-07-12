package v1alpha1

import (
	"fmt"
	"net/netip"
)

const (
	CiliumNativeRoutingPodCIDR          = "10.42.0.0/16"
	KubernetesServiceCIDR               = "10.43.0.0/16"
	PrivateLoadBalancerPoolMinAddresses = uint64(16)
	MaxPrivateLoadBalancerPoolAddresses = uint64(256)
)

// PrivateLoadBalancerPool is the inclusive 16-to-256-address private IPv4
// range reserved for Cilium LB IPAM Services. Karpenter must never allow a
// worker NIC address in this range.
type PrivateLoadBalancerPool struct {
	Start string `json:"start"`
	Stop  string `json:"stop"`
}

// Range returns the canonical ordered range after deterministic validation
// that does not require an InSpace API read.
func (p PrivateLoadBalancerPool) Range() (netip.Addr, netip.Addr, error) {
	start, err := parseCanonicalPrivateIPv4(p.Start, "start")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	stop, err := parseCanonicalPrivateIPv4(p.Stop, "stop")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	startValue := ipv4Value(start)
	stopValue := ipv4Value(stop)
	if startValue > stopValue {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("start %s must not be greater than stop %s", start, stop)
	}
	size := stopValue - startValue + 1
	if size < PrivateLoadBalancerPoolMinAddresses {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("range contains %d addresses; minimum is %d", size, PrivateLoadBalancerPoolMinAddresses)
	}
	if size > MaxPrivateLoadBalancerPoolAddresses {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("range contains %d addresses; maximum is %d", size, MaxPrivateLoadBalancerPoolAddresses)
	}
	for _, reserved := range []netip.Prefix{
		netip.MustParsePrefix(CiliumNativeRoutingPodCIDR),
		netip.MustParsePrefix(KubernetesServiceCIDR),
	} {
		if inclusiveRangeOverlapsPrefix(start, stop, reserved) {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("range %s-%s must not overlap reserved CIDR %s", start, stop, reserved)
		}
	}
	return start, stop, nil
}

// ValidateForSupervisor also reserves the RKE2 registration VIP outside the
// Service address range.
func (p PrivateLoadBalancerPool) ValidateForSupervisor(supervisorVIP netip.Addr) error {
	start, stop, err := p.Range()
	if err != nil {
		return err
	}
	if supervisorVIP.IsValid() && AddressInInclusiveRange(supervisorVIP, start, stop) {
		return fmt.Errorf("range %s-%s contains private RKE2 supervisor VIP %s", start, stop, supervisorVIP)
	}
	return nil
}

// ParseControlPlaneVIP returns the canonical private RKE2 supervisor VIP after
// excluding the fixed pod and Kubernetes Service networks. Controller-wide
// configuration and NodeClass URLs use this same parser so they cannot drift
// on what constitutes a valid cluster endpoint.
func ParseControlPlaneVIP(value string) (netip.Addr, error) {
	vip, err := parseCanonicalPrivateIPv4(value, "private RKE2 supervisor VIP")
	if err != nil {
		return netip.Addr{}, err
	}
	for _, reserved := range []struct {
		description string
		prefix      netip.Prefix
	}{
		{description: "Cilium native-routing pod CIDR", prefix: netip.MustParsePrefix(CiliumNativeRoutingPodCIDR)},
		{description: "Kubernetes Service CIDR", prefix: netip.MustParsePrefix(KubernetesServiceCIDR)},
	} {
		if reserved.prefix.Contains(vip) {
			return netip.Addr{}, fmt.Errorf("must not use an address in %s %s", reserved.description, reserved.prefix)
		}
	}
	return vip, nil
}

func (p PrivateLoadBalancerPool) Contains(address netip.Addr) (bool, error) {
	start, stop, err := p.Range()
	if err != nil {
		return false, err
	}
	return AddressInInclusiveRange(address, start, stop), nil
}

func AddressInInclusiveRange(address, start, stop netip.Addr) bool {
	if !address.Is4() || !start.Is4() || !stop.Is4() {
		return false
	}
	value := ipv4Value(address)
	return value >= ipv4Value(start) && value <= ipv4Value(stop)
}

func parseCanonicalPrivateIPv4(value, fieldName string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("%s %q must be a literal RFC1918 IPv4 address", fieldName, value)
	}
	if value != address.String() {
		return netip.Addr{}, fmt.Errorf("%s %q must use canonical IPv4 form %s", fieldName, value, address)
	}
	return address, nil
}

func inclusiveRangeOverlapsPrefix(start, stop netip.Addr, prefix netip.Prefix) bool {
	if !start.Is4() || !stop.Is4() || !prefix.Addr().Is4() {
		return false
	}
	prefixStart := prefix.Masked().Addr()
	prefixBits := prefix.Bits()
	prefixStartValue := ipv4Value(prefixStart)
	prefixEndValue := prefixStartValue + (uint64(1) << uint(32-prefixBits)) - 1
	return ipv4Value(start) <= prefixEndValue && prefixStartValue <= ipv4Value(stop)
}

func ipv4Value(address netip.Addr) uint64 {
	bytes := address.As4()
	return uint64(bytes[0])<<24 | uint64(bytes[1])<<16 | uint64(bytes[2])<<8 | uint64(bytes[3])
}

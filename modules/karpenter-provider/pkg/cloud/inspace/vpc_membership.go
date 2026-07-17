package inspace

import (
	"errors"
	"fmt"
	"strings"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// canonicalConfiguredVPCVMUUIDs validates the complete configured-VPC
// membership response before any member or omission can become cloud mutation
// authority. JSON null elements decode into empty strings, so UUID validation
// also rejects null membership rows. Keys are canonical lowercase UUIDs and
// duplicates are rejected case-insensitively.
func canonicalConfiguredVPCVMUUIDs(network *sdk.Network) (map[string]struct{}, error) {
	if network == nil {
		return nil, errors.New("configured VPC response is empty")
	}
	if network.VMUUIDs == nil {
		return nil, errors.New("configured VPC omitted VM membership")
	}
	members := make(map[string]struct{}, len(network.VMUUIDs))
	for index, member := range network.VMUUIDs {
		if !vmUUIDPattern.MatchString(member) {
			return nil, fmt.Errorf("configured VPC member %d has invalid VM UUID %q", index, member)
		}
		canonical := strings.ToLower(member)
		if _, duplicate := members[canonical]; duplicate {
			return nil, fmt.Errorf("configured VPC contains duplicate VM UUID %s", canonical)
		}
		members[canonical] = struct{}{}
	}
	return members, nil
}

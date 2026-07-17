package cloudprovider

import (
	"errors"
	"fmt"
	"strings"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/providerid"
)

// canonicalConfiguredVPCVMUUIDs validates the complete configured-VPC
// membership response before any member (or omission) can become cloud
// mutation authority. JSON null elements decode into empty strings, so UUID
// validation also rejects null membership rows. Keys are canonical lowercase
// UUIDs. Values preserve the API's source spelling for consumers that require
// an exact canonical wire identity.
func canonicalConfiguredVPCVMUUIDs(location string, network *inspace.Network) (map[string]string, error) {
	if network == nil {
		return nil, errors.New("configured VPC response is empty")
	}
	if network.VMUUIDs == nil {
		return nil, errors.New("configured VPC omitted VM membership")
	}
	members := make(map[string]string, len(network.VMUUIDs))
	for index, member := range network.VMUUIDs {
		if _, err := providerid.New(location, member); err != nil {
			return nil, fmt.Errorf("configured VPC member %d has invalid VM UUID %q: %w", index, member, err)
		}
		canonical := strings.ToLower(member)
		if _, duplicate := members[canonical]; duplicate {
			return nil, fmt.Errorf("configured VPC contains duplicate VM UUID %s", canonical)
		}
		members[canonical] = member
	}
	return members, nil
}

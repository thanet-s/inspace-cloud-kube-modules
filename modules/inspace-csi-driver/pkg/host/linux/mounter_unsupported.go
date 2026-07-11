//go:build !linux

// Package linux provides a compile-time compatible constructor on non-Linux
// development hosts. CSI node operations are supported only on Linux.
package linux

import (
	"errors"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/inspace-csi-driver/pkg/host"
)

func New() (host.Mounter, error) {
	return nil, errors.New("the production CSI node mounter requires Linux")
}

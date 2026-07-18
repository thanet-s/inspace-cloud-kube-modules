package inspace

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
)

// validateVMDeleteVolumeSafety permits deletion only when the canonical VM
// reports exactly one primary root disk and no attached non-primary block
// volumes. An omitted or ambiguous storage inventory cannot prove that VM
// deletion is safe because InSpace cascades attached volumes with the VM.
func validateVMDeleteVolumeSafety(vm sdk.VM) error {
	primaryCount := 0
	nonPrimaryCount := 0
	for _, volume := range vm.Storage {
		if volume.Primary {
			primaryCount++
			continue
		}
		nonPrimaryCount++
	}
	if nonPrimaryCount != 0 {
		return fmt.Errorf(
			"%w: VM %s reports %d attached non-primary block volume(s); detach every additional volume before deleting the VM",
			cloudapi.ErrAttachedNonPrimaryVolumes,
			vm.UUID,
			nonPrimaryCount,
		)
	}
	if len(vm.Storage) == 0 || primaryCount != 1 {
		return fmt.Errorf(
			"%w: VM %s reports %d storage entries and %d primary root disks; exactly one primary root disk is required before deletion",
			cloudapi.ErrVMStorageInventoryUncertain,
			vm.UUID,
			len(vm.Storage),
			primaryCount,
		)
	}
	return nil
}

// proveVMDeleteVolumeSafety performs the last exact cloud read immediately
// before DELETE dispatch. InSpace exposes no conditional-delete primitive, so
// this is the narrowest provider-side guard against an attachment racing the
// earlier ownership and configured-VPC proofs.
func (a *Adapter) proveVMDeleteVolumeSafety(ctx context.Context, location, vmUUID string) error {
	requestCtx, cancel := context.WithTimeout(ctx, a.networkAttachmentRequestTimeout)
	defer cancel()
	vm, err := a.api.GetVM(requestCtx, location, vmUUID)
	if err != nil {
		return fmt.Errorf("reading canonical VM storage immediately before DELETE: %w", err)
	}
	if vm == nil || !strings.EqualFold(vm.UUID, vmUUID) {
		observedUUID := ""
		if vm != nil {
			observedUUID = vm.UUID
		}
		return fmt.Errorf(
			"%w: canonical VM detail UUID %q does not match delete target %q",
			cloudapi.ErrOwnershipMismatch,
			observedUUID,
			vmUUID,
		)
	}
	if err := rejectDeletedVMForActiveUse(*vm); err != nil {
		return err
	}
	return validateVMDeleteVolumeSafety(*vm)
}

// vmDeleteWasNotDispatched distinguishes locally blocked attempts from
// ambiguous API outcomes. Callers return these errors directly instead of
// entering the five-minute absence proof reserved for a dispatched DELETE.
func vmDeleteWasNotDispatched(err error) bool {
	return errors.Is(err, errVMDeleteUndispatched)
}

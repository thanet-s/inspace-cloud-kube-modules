package inspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

// ExpandVolume grows an attached disk to at least capacityBytes, rounded up to
// whole GiB, and returns the resulting capacity.
//
// InSpace resizes a disk only through its VM storage relation, so expansion is
// online-only: a detached disk returns cloud.ErrVolumeNotAttached. The PATCH
// carries an absolute target size and the API rejects shrinking, so replaying
// it after an ambiguous response cannot grow the disk twice. That is why this
// path needs no durable mutation fence; exact disk readback is the completion
// authority. A complete non-retryable rejection returns its cause at once.
func (a *Adapter) ExpandVolume(ctx context.Context, location, volumeID string, capacityBytes int64) (int64, error) {
	sizeGiB, err := bytesToGiB(capacityBytes)
	if err != nil {
		return 0, err
	}
	disk, err := a.getOwnedDisk(ctx, location, volumeID)
	if err != nil {
		return 0, err
	}
	if disk.SizeGiB >= sizeGiB {
		return diskCapacity(location, disk)
	}
	// Never resize while an earlier attach, detach, or delete remains
	// ambiguous; its outcome decides which VM, if any, holds the disk.
	if _, err := a.settleExistingAttachmentFence(ctx, diskAttachmentIntent{
		Operation: "disk-attachment", Location: location, DiskUUID: strings.ToLower(volumeID), BillingAccountID: a.billing,
	}); err != nil {
		return 0, err
	}
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		return 0, err
	}
	if attachedVM == "" {
		return 0, fmt.Errorf("%w: disk %s must be attached to a node to expand", cloud.ErrVolumeNotAttached, volumeID)
	}
	targetVM, err := a.getOwnedVM(ctx, location, attachedVM)
	if err != nil {
		return 0, err
	}
	if err := requireExactVMAttachmentCollection(targetVM, volumeID); err != nil {
		return 0, err
	}
	if err := rejectPrimaryDiskReference(targetVM, volumeID); err != nil {
		return 0, err
	}
	if rows := vmDiskRows(targetVM, volumeID); rows != 1 {
		return 0, fmt.Errorf("InSpace exact VM %s reported %d attachment rows for disk %s", attachedVM, rows, volumeID)
	}
	// Exact disk ownership and attachment are the final reads before the
	// resize mutation.
	disk, err = a.getOwnedDisk(ctx, location, volumeID)
	if err != nil {
		return 0, err
	}
	if disk.SizeGiB >= sizeGiB {
		return diskCapacity(location, disk)
	}
	finalAttachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		return 0, err
	}
	if finalAttachedVM != attachedVM {
		return 0, fmt.Errorf("%w: disk %s moved from VM %q to VM %q before resize", cloud.ErrConflict, volumeID, attachedVM, finalAttachedVM)
	}
	if err := requireMutationDispatchReserve(ctx); err != nil {
		return 0, err
	}
	_, mutationErr := a.api.ResizeAttachedDisk(ctx, location, attachedVM, volumeID, sizeGiB)
	if errors.Is(mutationErr, sdk.ErrMutationBlocked) {
		return 0, mutationErr
	}
	if rejection := definitiveResizeRejection(mutationErr); rejection != nil {
		// A complete non-retryable answer is final for this request. One exact
		// read still accepts a resize that raced in, such as a 409 behind a
		// concurrent identical PATCH.
		disk, err := a.getOwnedDisk(ctx, location, volumeID)
		if err == nil && disk.SizeGiB >= sizeGiB {
			return diskCapacity(location, disk)
		}
		return 0, rejection
	}
	readbackCtx, cancel := a.mutationReadbackContext(ctx)
	defer cancel()
	resized, err := a.waitForDiskSize(readbackCtx, location, volumeID, sizeGiB)
	if err != nil {
		return 0, fmt.Errorf("%w: disk %s did not reach %d GiB: %v",
			cloud.ErrUnavailable, volumeID, sizeGiB, errors.Join(normalizeAPIError(mutationErr), err))
	}
	return diskCapacity(location, resized)
}

// definitiveResizeRejection classifies a complete, non-retryable 4xx answer to
// the resize PATCH. Timeouts, throttling, 5xx, and transport errors return nil:
// their outcome is ambiguous, so exact readback stays the completion authority.
func definitiveResizeRejection(err error) error {
	var apiErr *sdk.APIError
	if !errors.As(err, &apiErr) || apiErr.Retryable {
		return nil
	}
	switch status := apiErr.StatusCode; {
	case status < 400 || status >= 500, status == 408, status == 425, status == 429:
		return nil
	case status == 401 || status == 403 || status == 404 || status == 409:
		return normalizeAPIError(err)
	default:
		return fmt.Errorf("%w: %v", cloud.ErrRejected, err)
	}
}

// waitForDiskSize polls exact disk detail because the resize response and VM
// storage rows may precede or lag the canonical disk record.
func (a *Adapter) waitForDiskSize(ctx context.Context, location, volumeID string, sizeGiB int) (sdk.Disk, error) {
	for {
		disk, err := a.getOwnedDisk(ctx, location, volumeID)
		if err == nil && disk.SizeGiB >= sizeGiB {
			return disk, nil
		}
		if errors.Is(err, cloud.ErrPermissionDenied) || errors.Is(err, cloud.ErrNotFound) {
			return sdk.Disk{}, err
		}
		timer := time.NewTimer(a.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return sdk.Disk{}, errors.Join(ctx.Err(), err)
		case <-timer.C:
		}
	}
}

func diskCapacity(location string, disk sdk.Disk) (int64, error) {
	volume, err := diskVolume(location, disk)
	if err != nil {
		return 0, err
	}
	return volume.CapacityBytes, nil
}

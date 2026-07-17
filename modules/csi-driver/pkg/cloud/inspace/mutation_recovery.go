package inspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

type diskCreateIntent struct {
	Operation        string `json:"operation"`
	Location         string `json:"location"`
	Name             string `json:"name"`
	SizeGiB          int    `json:"sizeGiB"`
	BillingAccountID int64  `json:"billingAccountID"`
}

type diskAttachmentIntent struct {
	Operation        string `json:"operation"`
	Location         string `json:"location"`
	DiskUUID         string `json:"diskUUID"`
	BillingAccountID int64  `json:"billingAccountID"`
	DesiredVMUUID    string `json:"desiredVMUUID,omitempty"`
	PreviousVMUUID   string `json:"previousVMUUID,omitempty"`
}

const (
	detachAbsenceObservationKind     = "disk-detach-absence"
	diskDeleteAbsenceObservationKind = "disk-delete-absence"
)

// mutationObservation is persisted in the mutation Lease. Destructive absence
// is intentionally a three-step durable fact: a controller publishes three
// independently corroborated observations separated by the provider-convergence
// interval before a delete/detach Lease can complete. Visibility at any
// authoritative endpoint clears only this observation; the immutable Attempt
// that authorized the original mutation is never changed.
type mutationObservation struct {
	Kind            string `json:"kind"`
	Count           int    `json:"count"`
	FirstObservedAt string `json:"firstObservedAt"`
	LastObservedAt  string `json:"lastObservedAt,omitempty"`
}

func encodeMutationObservation(observation mutationObservation) (string, error) {
	if err := validateMutationObservation(observation); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		return "", fmt.Errorf("encode CSI mutation observation: %w", err)
	}
	return string(encoded), nil
}

func decodeMutationObservation(encoded string) (mutationObservation, error) {
	var observation mutationObservation
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		return mutationObservation{}, fmt.Errorf("CSI mutation fence observation is malformed: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return mutationObservation{}, errors.New("CSI mutation fence observation contains trailing data")
	}
	if err := validateMutationObservation(observation); err != nil {
		return mutationObservation{}, err
	}
	return observation, nil
}

func validateMutationObservation(observation mutationObservation) error {
	if observation.Kind != detachAbsenceObservationKind && observation.Kind != diskDeleteAbsenceObservationKind {
		return fmt.Errorf("CSI mutation fence observation kind %q is unsupported", observation.Kind)
	}
	if observation.Count < 1 || observation.Count > 3 {
		return fmt.Errorf("CSI mutation fence observation count %d is invalid", observation.Count)
	}
	firstObservedAt, err := time.Parse(time.RFC3339Nano, observation.FirstObservedAt)
	if err != nil || firstObservedAt.IsZero() {
		return errors.New("CSI mutation fence first-observation timestamp is invalid")
	}
	if observation.Count == 1 {
		if observation.LastObservedAt != "" {
			return errors.New("CSI mutation fence first observation unexpectedly contains a last-observation timestamp")
		}
		return nil
	}
	lastObservedAt, err := time.Parse(time.RFC3339Nano, observation.LastObservedAt)
	if err != nil || lastObservedAt.IsZero() || !lastObservedAt.After(firstObservedAt) {
		return errors.New("CSI mutation fence last-observation timestamp is invalid")
	}
	return nil
}

func validateMutationObservationSpacing(observation mutationObservation, interval time.Duration) error {
	if observation.Count < 2 {
		return nil
	}
	first, firstErr := time.Parse(time.RFC3339Nano, observation.FirstObservedAt)
	last, lastErr := time.Parse(time.RFC3339Nano, observation.LastObservedAt)
	if firstErr != nil || lastErr != nil || interval <= 0 {
		return errors.New("CSI mutation fence observation spacing is invalid")
	}
	minimum := first.Add(time.Duration(observation.Count-1) * interval)
	if last.Before(minimum) {
		return fmt.Errorf("CSI mutation fence observation count %d was not spaced by %s", observation.Count, interval)
	}
	return nil
}

func diskCreateFenceKey(location, name string) string {
	sum := sha256.Sum256([]byte(name))
	return "disk-create/" + strings.ToLower(location) + "/" + hex.EncodeToString(sum[:])
}

func diskAttachmentFenceKey(location, diskUUID string) string {
	return "disk-attachment/" + strings.ToLower(location) + "/" + strings.ToLower(diskUUID)
}

func (a *Adapter) mutationReadbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), a.readback)
}

func (a *Adapter) destructiveReadbackContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), a.destructive)
}

func (a *Adapter) beginDiskCreateFence(ctx context.Context, intent diskCreateIntent) (mutationFence, bool, error) {
	key := diskCreateFenceKey(intent.Location, intent.Name)
	if current, err := a.fences.Get(ctx, key); err != nil {
		return mutationFence{}, false, err
	} else if current != nil {
		stored, err := decodeMutationIntent[diskCreateIntent](*current)
		if err != nil {
			return mutationFence{}, false, err
		}
		if stored != intent {
			return mutationFence{}, false, fmt.Errorf("%w: unresolved disk-create fence has intent %#v, requested %#v", cloud.ErrIncompatibleVolume, stored, intent)
		}
		return *current, false, nil
	}
	candidate, err := newMutationFence(key, intent)
	if err != nil {
		return mutationFence{}, false, err
	}
	stored, acquired, err := a.fences.Create(ctx, candidate)
	if err != nil {
		return mutationFence{}, false, err
	}
	if stored == nil {
		return mutationFence{}, false, errors.New("CSI mutation fence store returned an empty create result")
	}
	actual, err := decodeMutationIntent[diskCreateIntent](*stored)
	if err != nil {
		return mutationFence{}, false, err
	}
	if stored.Key != key || actual != intent {
		return mutationFence{}, false, fmt.Errorf("%w: disk-create fence changed during acquisition", cloud.ErrIncompatibleVolume)
	}
	return *stored, acquired, nil
}

func (a *Adapter) reconcileDiskCreateFence(ctx context.Context, intent diskCreateIntent, fence mutationFence, mutationErr error) (cloud.Volume, error) {
	stored, err := decodeMutationIntent[diskCreateIntent](fence)
	if err != nil {
		return cloud.Volume{}, err
	}
	if stored != intent || fence.Key != diskCreateFenceKey(intent.Location, intent.Name) {
		return cloud.Volume{}, fmt.Errorf("%w: disk-create fence does not match the requested volume", cloud.ErrIncompatibleVolume)
	}
	var lastObservation error
	for {
		disks, listErr := a.api.ListDisks(ctx, intent.Location)
		if listErr == nil {
			disk, found, findErr := uniqueNamedDisk(disks, intent.Name)
			if findErr != nil {
				return cloud.Volume{}, findErr
			}
			if found {
				return a.finishFencedDisk(ctx, intent, fence, disk)
			}
			lastObservation = errors.New("same-named disk is not visible")
		} else {
			lastObservation = normalizeAPIError(listErr)
		}

		if err := waitMutationReadback(ctx, a.poll); err != nil {
			return cloud.Volume{}, fmt.Errorf(
				"%w: disk create outcome remains ambiguous behind durable fence %s; operator must inspect cloud state and remove only a fence whose POST did not commit: %v",
				cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key), errors.Join(mutationErr, lastObservation, err),
			)
		}
	}
}

func (a *Adapter) finishFencedDisk(ctx context.Context, intent diskCreateIntent, fence mutationFence, disk sdk.Disk) (cloud.Volume, error) {
	if err := validateDiskCreateReadback(disk, intent); err != nil {
		return cloud.Volume{}, err
	}
	ready, err := a.waitForDiskReady(ctx, intent, disk)
	if err != nil {
		return cloud.Volume{}, err
	}
	canonical, err := a.fences.SetReceipt(ctx, fence, strings.ToLower(ready.UUID))
	if err != nil {
		return cloud.Volume{}, fmt.Errorf("%w: persist canonical disk-create receipt after authoritative readback: %v", cloud.ErrUnavailable, err)
	}
	fence = *canonical
	volume, err := diskVolume(intent.Location, ready)
	if err != nil {
		return cloud.Volume{}, err
	}
	if err := a.fences.Delete(ctx, fence); err != nil {
		return cloud.Volume{}, fmt.Errorf("%w: complete disk-create fence after authoritative readback: %v", cloud.ErrUnavailable, err)
	}
	return volume, nil
}

func validateDiskCreateReadback(disk sdk.Disk, intent diskCreateIntent) error {
	if intent.BillingAccountID <= 0 {
		return fmt.Errorf("%w: disk-create intent has no positive billing account", cloud.ErrIncompatibleVolume)
	}
	if err := validateExactDisk(disk, disk.UUID, intent.BillingAccountID); err != nil {
		return fmt.Errorf("%w: disk create ownership readback: %v", cloud.ErrIncompatibleVolume, err)
	}
	if disk.DisplayName != intent.Name {
		return fmt.Errorf("%w: disk receipt name %q does not match %q", cloud.ErrIncompatibleVolume, disk.DisplayName, intent.Name)
	}
	if disk.SizeGiB != intent.SizeGiB {
		return fmt.Errorf("%w: disk %s has %d GiB, requested %d GiB", cloud.ErrIncompatibleVolume, disk.UUID, disk.SizeGiB, intent.SizeGiB)
	}
	if disk.SourceImageType != "" && !strings.EqualFold(disk.SourceImageType, "EMPTY") {
		return fmt.Errorf("%w: disk %s source type is %q", cloud.ErrIncompatibleVolume, disk.UUID, disk.SourceImageType)
	}
	return nil
}

func (a *Adapter) matchingDiskCreateFence(ctx context.Context, location, volumeID string, disk *sdk.Disk) (*mutationFence, error) {
	prefix := "disk-create/" + strings.ToLower(location) + "/"
	fences, err := a.fences.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var match *mutationFence
	for index := range fences {
		fence := fences[index]
		intent, err := decodeMutationIntent[diskCreateIntent](fence)
		if err != nil || intent.Operation != "create-disk" || !strings.EqualFold(intent.Location, location) {
			return nil, errors.Join(err, fmt.Errorf("%w: malformed disk-create fence %s", cloud.ErrConflict, mutationFenceLeaseName(fence.Key)))
		}
		matchesReceipt := fence.Receipt != "" && strings.EqualFold(fence.Receipt, volumeID)
		matchesName := disk != nil && disk.DisplayName != "" && disk.DisplayName == intent.Name
		if disk != nil && disk.DisplayName == "" && fence.Receipt == "" {
			return nil, fmt.Errorf(
				"%w: cannot exclude unresolved create fence %s while disk %s has no display name; operator must inspect or remove the Lease",
				cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key), volumeID,
			)
		}
		if !matchesReceipt && !matchesName {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("%w: multiple durable create fences match disk %s", cloud.ErrConflict, volumeID)
		}
		copy := fence
		match = &copy
		if fence.Receipt == "" {
			return nil, fmt.Errorf(
				"%w: create fence %s has no exact disk receipt and could still commit; operator must inspect or remove the Lease",
				cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key),
			)
		}
		if !strings.EqualFold(fence.Receipt, volumeID) {
			return nil, fmt.Errorf(
				"%w: create fence %s receipt %s conflicts with disk %s",
				cloud.ErrConflict, mutationFenceLeaseName(fence.Key), fence.Receipt, volumeID,
			)
		}
		if disk != nil {
			if err := validateDiskCreateReadback(*disk, intent); err != nil {
				return nil, err
			}
		}
	}
	return match, nil
}

func (a *Adapter) waitForDiskAbsent(ctx context.Context, location, volumeID string, fence mutationFence) (mutationFence, error) {
	currentFence := fence
	for {
		var observation mutationObservation
		if currentFence.Observation != "" {
			decoded, err := decodeMutationObservation(currentFence.Observation)
			if err != nil {
				return mutationFence{}, err
			}
			if decoded.Kind != diskDeleteAbsenceObservationKind {
				return mutationFence{}, errors.New("disk-delete mutation fence contains another operation's absence observation")
			}
			if err := validateMutationObservationSpacing(decoded, a.absencePoll); err != nil {
				return mutationFence{}, err
			}
			observation = decoded
		}
		var lastObservation error
		getAbsent := false
		disk, getErr := a.api.GetDisk(ctx, location, volumeID)
		switch {
		case sdk.IsNotFound(getErr):
			getAbsent = true
		case getErr != nil:
			lastObservation = normalizeAPIError(getErr)
		case disk == nil:
			lastObservation = errors.New("InSpace API returned an empty disk during deletion readback")
		default:
			if err := validateExactDisk(*disk, volumeID, a.billing); err != nil {
				return mutationFence{}, err
			}
			lastObservation = fmt.Errorf("disk %s remains visible by exact GET", volumeID)
		}

		listAbsent := false
		disks, listErr := a.api.ListDisks(ctx, location)
		if listErr != nil {
			lastObservation = errors.Join(lastObservation, normalizeAPIError(listErr))
		} else {
			matches := 0
			for _, current := range disks {
				if strings.EqualFold(current.UUID, volumeID) {
					if err := validateExactDisk(current, volumeID, a.billing); err != nil {
						return mutationFence{}, err
					}
					matches++
				}
			}
			if matches > 1 {
				return mutationFence{}, fmt.Errorf("%w: disk list contains UUID %s %d times", cloud.ErrConflict, volumeID, matches)
			}
			listAbsent = matches == 0
			if !listAbsent {
				lastObservation = fmt.Errorf("disk %s remains visible in ListDisks", volumeID)
			}
		}

		if !getAbsent || !listAbsent {
			if currentFence.Observation != "" {
				updated, completed, err := a.updateMutationObservation(ctx, currentFence, "")
				if err != nil {
					return mutationFence{}, err
				}
				if completed {
					return mutationFence{}, errors.New("disk-delete mutation fence disappeared while its disk was visible")
				}
				currentFence = updated
			}
			if err := waitMutationReadback(ctx, a.poll); err != nil {
				return mutationFence{}, errors.Join(lastObservation, err)
			}
			continue
		}

		now := time.Now().UTC()
		switch observation.Count {
		case 0:
			encoded, err := encodeMutationObservation(mutationObservation{
				Kind: diskDeleteAbsenceObservationKind, Count: 1, FirstObservedAt: now.Format(time.RFC3339Nano),
			})
			if err != nil {
				return mutationFence{}, err
			}
			updated, completed, err := a.updateMutationObservation(ctx, currentFence, encoded)
			if err != nil {
				return mutationFence{}, err
			}
			if completed {
				return mutationFence{}, nil
			}
			currentFence = updated
		case 1, 2:
			previousAt := observation.FirstObservedAt
			if observation.Count == 2 {
				previousAt = observation.LastObservedAt
			}
			lastObservedAt, err := time.Parse(time.RFC3339Nano, previousAt)
			if err != nil {
				return mutationFence{}, errors.New("disk-delete mutation fence has an invalid observation timestamp")
			}
			notBefore := lastObservedAt.Add(a.absencePoll)
			if now.Before(notBefore) {
				if err := waitMutationReadbackUntil(ctx, notBefore); err != nil {
					return mutationFence{}, err
				}
				continue
			}
			encoded, err := encodeMutationObservation(mutationObservation{
				Kind: diskDeleteAbsenceObservationKind, Count: observation.Count + 1,
				FirstObservedAt: observation.FirstObservedAt, LastObservedAt: now.Format(time.RFC3339Nano),
			})
			if err != nil {
				return mutationFence{}, err
			}
			updated, completed, err := a.updateMutationObservation(ctx, currentFence, encoded)
			if err != nil {
				return mutationFence{}, err
			}
			if completed {
				return mutationFence{}, nil
			}
			currentFence = updated
			if observation.Count == 2 {
				return currentFence, nil
			}
		case 3:
			// A restart after the third persisted observation performs one more
			// independent exact GET+list absence read before completion.
			return currentFence, nil
		default:
			return mutationFence{}, errors.New("disk-delete mutation fence has an invalid absence observation")
		}
		if err := waitMutationReadback(ctx, a.poll); err != nil {
			return mutationFence{}, errors.Join(lastObservation, err)
		}
	}
}

func (a *Adapter) settleExistingAttachmentFence(ctx context.Context, requested diskAttachmentIntent) (bool, error) {
	if requested.BillingAccountID != a.billing || requested.BillingAccountID <= 0 {
		return false, fmt.Errorf("%w: requested disk mutation billing account does not match the configured account", cloud.ErrConflict)
	}
	key := diskAttachmentFenceKey(requested.Location, requested.DiskUUID)
	fence, err := a.fences.Get(ctx, key)
	if err != nil || fence == nil {
		return false, err
	}
	intent, err := decodeMutationIntent[diskAttachmentIntent](*fence)
	if err != nil {
		return false, err
	}
	if intent.Location != requested.Location || intent.DiskUUID != requested.DiskUUID || intent.BillingAccountID != a.billing {
		return false, fmt.Errorf("%w: attachment fence identity does not match disk %s", cloud.ErrConflict, requested.DiskUUID)
	}
	if intent.Operation == "disk-delete" {
		return false, fmt.Errorf(
			"%w: disk deletion remains protected by durable fence %s",
			cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key),
		)
	}
	if intent.Operation != "disk-attachment" {
		return false, fmt.Errorf("%w: unknown disk mutation fence operation %q", cloud.ErrConflict, intent.Operation)
	}
	var readbackCtx context.Context
	var cancel context.CancelFunc
	if intent.DesiredVMUUID == "" {
		readbackCtx, cancel = a.destructiveReadbackContext(ctx)
	} else {
		readbackCtx, cancel = a.mutationReadbackContext(ctx)
	}
	defer cancel()
	resolvedFence, err := a.waitForFencedAttachment(readbackCtx, intent, *fence)
	if err != nil {
		return false, fmt.Errorf("%w: unresolved durable attachment fence %s; operator must inspect cloud state before removing it: %v", cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key), err)
	}
	if resolvedFence.Key != "" {
		if err := a.fences.Delete(readbackCtx, resolvedFence); err != nil {
			return false, fmt.Errorf("%w: complete attachment fence: %v", cloud.ErrUnavailable, err)
		}
	}
	return intent == requested, nil
}

func (a *Adapter) waitForFencedAttachment(ctx context.Context, intent diskAttachmentIntent, fence mutationFence) (mutationFence, error) {
	if intent.BillingAccountID != a.billing || intent.BillingAccountID <= 0 {
		return mutationFence{}, fmt.Errorf("%w: attachment fence billing account does not match the configured account", cloud.ErrConflict)
	}
	if intent.DesiredVMUUID != "" {
		if fence.Observation != "" {
			return mutationFence{}, errors.New("attach mutation fence contains a detach-absence observation")
		}
		if err := a.waitForAttachment(ctx, intent.Location, intent.DiskUUID, intent.DesiredVMUUID, intent.PreviousVMUUID); err != nil {
			return mutationFence{}, err
		}
		return fence, nil
	}
	if intent.PreviousVMUUID == "" || !uuidPattern.MatchString(strings.ToLower(intent.PreviousVMUUID)) {
		return mutationFence{}, errors.New("detach mutation fence has an invalid previous VM UUID")
	}
	return a.waitForDetached(ctx, intent, fence)
}

func (a *Adapter) waitForDetached(ctx context.Context, intent diskAttachmentIntent, fence mutationFence) (mutationFence, error) {
	currentFence := fence
	for {
		var observation mutationObservation
		if currentFence.Observation != "" {
			decoded, err := decodeMutationObservation(currentFence.Observation)
			if err != nil {
				return mutationFence{}, err
			}
			if decoded.Kind != detachAbsenceObservationKind {
				return mutationFence{}, errors.New("detach mutation fence contains another operation's absence observation")
			}
			if err := validateMutationObservationSpacing(decoded, a.absencePoll); err != nil {
				return mutationFence{}, err
			}
			observation = decoded
		}

		visibleVM, stateErr := a.observeDetachState(ctx, intent)
		if visibleVM != "" {
			if currentFence.Observation != "" {
				updated, completed, err := a.updateMutationObservation(ctx, currentFence, "")
				if err != nil {
					return mutationFence{}, err
				}
				if completed {
					return mutationFence{}, errors.New("detach mutation fence disappeared while its disk was visible")
				}
				currentFence = updated
			}
			if stateErr != nil {
				return mutationFence{}, stateErr
			}
			if !strings.EqualFold(visibleVM, intent.PreviousVMUUID) {
				return mutationFence{}, fmt.Errorf("%w: disk %s converged to VM %s instead of detached", cloud.ErrVolumeAttachedElsewhere, intent.DiskUUID, visibleVM)
			}
			if err := waitMutationReadback(ctx, a.poll); err != nil {
				return mutationFence{}, err
			}
			continue
		}
		if stateErr != nil {
			return mutationFence{}, stateErr
		}

		now := time.Now().UTC()
		switch observation.Count {
		case 0:
			encoded, err := encodeMutationObservation(mutationObservation{
				Kind: detachAbsenceObservationKind, Count: 1, FirstObservedAt: now.Format(time.RFC3339Nano),
			})
			if err != nil {
				return mutationFence{}, err
			}
			updated, completed, err := a.updateMutationObservation(ctx, currentFence, encoded)
			if err != nil {
				return mutationFence{}, err
			}
			if completed {
				return mutationFence{}, nil
			}
			currentFence = updated
		case 1, 2:
			previousAt := observation.FirstObservedAt
			if observation.Count == 2 {
				previousAt = observation.LastObservedAt
			}
			lastObservedAt, err := time.Parse(time.RFC3339Nano, previousAt)
			if err != nil {
				return mutationFence{}, errors.New("detach mutation fence has an invalid observation timestamp")
			}
			notBefore := lastObservedAt.Add(a.absencePoll)
			if now.Before(notBefore) {
				if err := waitMutationReadbackUntil(ctx, notBefore); err != nil {
					return mutationFence{}, err
				}
				continue
			}
			encoded, err := encodeMutationObservation(mutationObservation{
				Kind: detachAbsenceObservationKind, Count: observation.Count + 1,
				FirstObservedAt: observation.FirstObservedAt, LastObservedAt: now.Format(time.RFC3339Nano),
			})
			if err != nil {
				return mutationFence{}, err
			}
			updated, completed, err := a.updateMutationObservation(ctx, currentFence, encoded)
			if err != nil {
				return mutationFence{}, err
			}
			if completed {
				return mutationFence{}, nil
			}
			currentFence = updated
			if observation.Count == 2 {
				return currentFence, nil
			}
		case 3:
			// A controller may restart after persisting the third observation
			// but before completing the Lease. This iteration performed another
			// independent ListVMs+GetVM absence read, so completion is safe.
			return currentFence, nil
		default:
			return mutationFence{}, errors.New("detach mutation fence has an invalid absence observation")
		}
		if err := waitMutationReadback(ctx, a.poll); err != nil {
			return mutationFence{}, err
		}
	}
}

func (a *Adapter) observeDetachState(ctx context.Context, intent diskAttachmentIntent) (string, error) {
	vms, err := a.api.ListVMs(ctx, intent.Location)
	if err != nil {
		return "", normalizeAPIError(err)
	}
	listedVM := ""
	listedRows := 0
	var listStateErr error
	for _, vm := range vms {
		for _, storage := range vm.Storage {
			if !strings.EqualFold(storage.UUID, intent.DiskUUID) {
				continue
			}
			listedRows++
			vmUUID := strings.ToLower(vm.UUID)
			if !uuidPattern.MatchString(vmUUID) {
				listStateErr = errors.Join(listStateErr, fmt.Errorf("InSpace reported disk %s on a VM with invalid UUID %q", intent.DiskUUID, vm.UUID))
				if listedVM == "" {
					listedVM = "<invalid-vm>"
				}
				continue
			}
			if listedVM != "" && !strings.EqualFold(listedVM, vmUUID) {
				listStateErr = errors.Join(listStateErr, fmt.Errorf("InSpace reported disk %s attached to multiple VMs", intent.DiskUUID))
			}
			if listedVM == "" || listedVM == "<invalid-vm>" {
				listedVM = vmUUID
			}
		}
	}
	if listedRows > 1 {
		listStateErr = errors.Join(listStateErr, fmt.Errorf("InSpace reported disk %s in %d ListVMs attachment rows", intent.DiskUUID, listedRows))
	}

	vm, getErr := a.api.GetVM(ctx, intent.Location, intent.PreviousVMUUID)
	exactPresent := false
	var exactStateErr error
	switch {
	case sdk.IsNotFound(getErr):
		// A deleted previous VM corroborates that it cannot retain the disk.
	case getErr != nil:
		return "", normalizeAPIError(getErr)
	case vm == nil:
		return "", errors.New("InSpace API returned an empty VM during detach readback")
	case !strings.EqualFold(vm.UUID, intent.PreviousVMUUID):
		exactStateErr = fmt.Errorf("InSpace API returned VM %q for exact detach readback of %s", vm.UUID, intent.PreviousVMUUID)
	default:
		if err := a.validateExactVM(*vm, intent.PreviousVMUUID); err != nil {
			exactStateErr = err
			break
		}
		rows := 0
		for _, storage := range vm.Storage {
			if strings.EqualFold(storage.UUID, intent.DiskUUID) {
				rows++
			}
		}
		if rows > 1 {
			exactStateErr = fmt.Errorf("InSpace reported disk %s in %d exact attachment rows on VM %s", intent.DiskUUID, rows, intent.PreviousVMUUID)
		}
		exactPresent = rows > 0
	}

	if listedVM != "" {
		return listedVM, errors.Join(listStateErr, exactStateErr)
	}
	if exactPresent {
		return strings.ToLower(intent.PreviousVMUUID), errors.Join(listStateErr, exactStateErr)
	}
	return "", errors.Join(listStateErr, exactStateErr)
}

func (a *Adapter) updateMutationObservation(ctx context.Context, fence mutationFence, observation string) (mutationFence, bool, error) {
	updated, err := a.fences.SetObservation(ctx, fence, observation)
	if err == nil {
		if updated == nil {
			return mutationFence{}, false, errors.New("CSI mutation fence store returned an empty observation result")
		}
		return *updated, false, nil
	}
	if !errors.Is(err, errMutationFenceChanged) {
		return mutationFence{}, false, err
	}
	current, getErr := a.fences.Get(ctx, fence.Key)
	if getErr != nil {
		return mutationFence{}, false, errors.Join(err, getErr)
	}
	if current == nil {
		return mutationFence{}, true, nil
	}
	if !sameMutationFenceAuthority(*current, fence) {
		return mutationFence{}, false, fmt.Errorf("%w: CSI mutation authority changed during observation update", cloud.ErrConflict)
	}
	return *current, false, nil
}

func waitMutationReadbackUntil(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Adapter) prepareDiskDeleteFence(ctx context.Context, location, diskUUID string) (mutationFence, bool, error) {
	intent := diskAttachmentIntent{
		Operation: "disk-delete", Location: location, DiskUUID: strings.ToLower(diskUUID), BillingAccountID: a.billing,
	}
	key := diskAttachmentFenceKey(location, diskUUID)
	for range 3 {
		current, err := a.fences.Get(ctx, key)
		if err != nil {
			return mutationFence{}, false, err
		}
		if current != nil {
			stored, err := decodeMutationIntent[diskAttachmentIntent](*current)
			if err != nil {
				return mutationFence{}, false, err
			}
			if stored == intent {
				return *current, false, nil
			}
			if _, err := a.settleExistingAttachmentFence(ctx, intent); err != nil {
				return mutationFence{}, false, err
			}
			continue
		}
		candidate, err := newMutationFence(key, intent)
		if err != nil {
			return mutationFence{}, false, err
		}
		stored, acquired, err := a.fences.Create(ctx, candidate)
		if err != nil {
			return mutationFence{}, false, err
		}
		if stored == nil {
			return mutationFence{}, false, errors.New("CSI mutation fence store returned an empty disk-delete result")
		}
		actual, err := decodeMutationIntent[diskAttachmentIntent](*stored)
		if err != nil {
			return mutationFence{}, false, err
		}
		if actual == intent {
			return *stored, acquired, nil
		}
	}
	return mutationFence{}, false, fmt.Errorf("%w: disk-delete fence changed repeatedly during acquisition", cloud.ErrUnavailable)
}

func (a *Adapter) beginAttachmentFence(ctx context.Context, intent diskAttachmentIntent) (mutationFence, bool, error) {
	key := diskAttachmentFenceKey(intent.Location, intent.DiskUUID)
	candidate, err := newMutationFence(key, intent)
	if err != nil {
		return mutationFence{}, false, err
	}
	stored, acquired, err := a.fences.Create(ctx, candidate)
	if err != nil {
		return mutationFence{}, false, err
	}
	if stored == nil {
		return mutationFence{}, false, errors.New("CSI mutation fence store returned an empty attachment result")
	}
	actual, err := decodeMutationIntent[diskAttachmentIntent](*stored)
	if err != nil {
		return mutationFence{}, false, err
	}
	if stored.Key != key || actual != intent {
		return *stored, false, nil
	}
	return *stored, acquired, nil
}

func (a *Adapter) prepareAttachmentFence(ctx context.Context, intent diskAttachmentIntent) (mutationFence, bool, error) {
	for range 3 {
		alreadyDone, err := a.settleExistingAttachmentFence(ctx, intent)
		if err != nil {
			return mutationFence{}, false, err
		}
		if alreadyDone {
			return mutationFence{}, true, nil
		}
		fence, acquired, err := a.beginAttachmentFence(ctx, intent)
		if err != nil {
			return mutationFence{}, false, err
		}
		if acquired {
			return fence, false, nil
		}
		// Another controller created the same logical disk fence between our
		// GET and POST. Reconcile that exact intent; never issue a second cloud
		// mutation merely because the Lease race was lost.
	}
	return mutationFence{}, false, fmt.Errorf("%w: attachment fence changed repeatedly during acquisition", cloud.ErrUnavailable)
}

func (a *Adapter) finishAttachmentMutation(ctx context.Context, intent diskAttachmentIntent, fence mutationFence, mutationErr error) error {
	if errors.Is(mutationErr, sdk.ErrMutationBlocked) {
		if err := a.fences.Delete(context.WithoutCancel(ctx), fence); err != nil {
			return errors.Join(mutationErr, fmt.Errorf("clear locally blocked disk attachment fence: %w", err))
		}
		return mutationErr
	}
	var readbackCtx context.Context
	var cancel context.CancelFunc
	if intent.DesiredVMUUID == "" {
		readbackCtx, cancel = a.destructiveReadbackContext(ctx)
	} else {
		readbackCtx, cancel = a.mutationReadbackContext(ctx)
	}
	defer cancel()
	resolvedFence, err := a.waitForFencedAttachment(readbackCtx, intent, fence)
	if err != nil {
		return fmt.Errorf(
			"%w: disk attachment outcome remains ambiguous behind durable fence %s; operator must inspect cloud state before removing it: %v",
			cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key), errors.Join(mutationErr, err),
		)
	}
	if resolvedFence.Key != "" {
		if err := a.fences.Delete(readbackCtx, resolvedFence); err != nil {
			return fmt.Errorf("%w: complete disk attachment fence: %v", cloud.ErrUnavailable, err)
		}
	}
	return nil
}

func waitMutationReadback(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

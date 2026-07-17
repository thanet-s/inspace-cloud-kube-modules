// Package inspace adapts the shared InSpace SDK to the CSI cloud boundary.
package inspace

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	gib                               = int64(1024 * 1024 * 1024)
	defaultMutationReadbackTimeout    = 30 * time.Second
	defaultDestructiveAbsenceInterval = 30 * time.Second
	defaultDestructiveReadbackTimeout = 2 * time.Minute
	minimumMutationDispatchReserve    = 8 * time.Minute
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// canonicalNetworkVMMembers validates one complete network membership
// snapshot. A nil slice is omitted authority rather than an empty VPC, and
// duplicates are ambiguous even when only an unrelated VM is duplicated.
func canonicalNetworkVMMembers(vmUUIDs []string) (map[string]struct{}, error) {
	if vmUUIDs == nil {
		return nil, errors.New("network VM membership is omitted")
	}
	members := make(map[string]struct{}, len(vmUUIDs))
	for _, raw := range vmUUIDs {
		vmUUID := strings.ToLower(strings.TrimSpace(raw))
		if !uuidPattern.MatchString(vmUUID) {
			return nil, fmt.Errorf("network contains invalid VM UUID %q", raw)
		}
		if _, duplicate := members[vmUUID]; duplicate {
			return nil, fmt.Errorf("network contains VM %s more than once", vmUUID)
		}
		members[vmUUID] = struct{}{}
	}
	return members, nil
}

// API is the location-aware subset of the shared SDK used by CSI. Keeping it
// narrow makes idempotency and attachment behavior testable without HTTP.
type API interface {
	CreateDisk(context.Context, string, sdk.CreateDiskRequest) (*sdk.Disk, error)
	GetDisk(context.Context, string, string) (*sdk.Disk, error)
	ListDisks(context.Context, string) ([]sdk.Disk, error)
	DeleteDisk(context.Context, string, string) error
	ListVMs(context.Context, string) ([]sdk.VM, error)
	GetVM(context.Context, string, string) (*sdk.VM, error)
	GetNetwork(context.Context, string, string) (*sdk.Network, error)
	AttachDisk(context.Context, string, string, string) (*sdk.VMStorage, error)
	DetachDisk(context.Context, string, string, string) error
}

// NodeResolver returns the Kubernetes Node's spec.providerID. The adapter
// invokes it only when CSI sends a node name instead of an InSpace provider ID.
type NodeResolver interface {
	ProviderIDForNode(context.Context, string) (string, error)
}

type Config struct {
	Location                   string
	NetworkUUID                string
	BillingAccountID           int64
	PollInterval               time.Duration
	MutationReadbackTimeout    time.Duration
	DestructiveAbsenceInterval time.Duration
	DestructiveReadbackTimeout time.Duration
}

type Adapter struct {
	api         API
	nodes       NodeResolver
	fences      mutationFenceStore
	location    string
	network     string
	billing     int64
	poll        time.Duration
	readback    time.Duration
	absencePoll time.Duration
	destructive time.Duration
}

func New(api API, nodes NodeResolver, cfg Config) (*Adapter, error) {
	if api == nil {
		return nil, errors.New("InSpace API client is required")
	}
	if strings.TrimSpace(cfg.Location) == "" {
		return nil, errors.New("location is required")
	}
	if cfg.BillingAccountID <= 0 {
		return nil, errors.New("billing account ID must be positive")
	}
	cfg.NetworkUUID = strings.ToLower(strings.TrimSpace(cfg.NetworkUUID))
	if cfg.NetworkUUID != "" && !uuidPattern.MatchString(cfg.NetworkUUID) {
		return nil, errors.New("network UUID is invalid")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.MutationReadbackTimeout <= 0 {
		cfg.MutationReadbackTimeout = defaultMutationReadbackTimeout
	}
	if cfg.DestructiveAbsenceInterval <= 0 {
		cfg.DestructiveAbsenceInterval = defaultDestructiveAbsenceInterval
	}
	if cfg.DestructiveReadbackTimeout <= 0 {
		cfg.DestructiveReadbackTimeout = defaultDestructiveReadbackTimeout
	}
	if cfg.DestructiveReadbackTimeout <= 3*cfg.DestructiveAbsenceInterval {
		return nil, errors.New("destructive readback timeout must exceed three destructive absence intervals")
	}
	fences, ok := nodes.(mutationFenceStore)
	if !ok {
		// Production controller mode always supplies KubernetesNodeResolver. The
		// memory implementation keeps standalone unit/live tests deterministic.
		fences = newMemoryMutationFenceStore()
	}
	return &Adapter{
		api: api, nodes: nodes, fences: fences, location: cfg.Location, network: cfg.NetworkUUID,
		billing: cfg.BillingAccountID, poll: cfg.PollInterval,
		readback: cfg.MutationReadbackTimeout, absencePoll: cfg.DestructiveAbsenceInterval,
		destructive: cfg.DestructiveReadbackTimeout,
	}, nil
}

func (a *Adapter) Probe(ctx context.Context) error {
	_, err := a.api.ListDisks(ctx, a.location)
	return normalizeAPIError(err)
}

func (a *Adapter) EnsureVolume(ctx context.Context, spec cloud.VolumeSpec) (cloud.Volume, error) {
	sizeGiB, err := bytesToGiB(spec.CapacityBytes)
	if err != nil {
		return cloud.Volume{}, err
	}
	intent := diskCreateIntent{
		Operation: "create-disk", Location: spec.Location, Name: spec.Name,
		SizeGiB: sizeGiB, BillingAccountID: a.billing,
	}
	disks, err := a.api.ListDisks(ctx, spec.Location)
	if err != nil {
		return cloud.Volume{}, normalizeAPIError(err)
	}
	if existing, found, err := uniqueNamedDisk(disks, spec.Name); err != nil {
		return cloud.Volume{}, err
	} else if found {
		if err := validateDiskCreateReadback(existing, intent); err != nil {
			return cloud.Volume{}, err
		}
		ready, err := a.waitForDiskReady(ctx, intent, existing)
		if err != nil {
			return cloud.Volume{}, err
		}
		// A previous response may have been lost after the disk committed. Clear
		// only an exact matching fence after the authoritative disk is Ready.
		if fence, fenceErr := a.fences.Get(ctx, diskCreateFenceKey(intent.Location, intent.Name)); fenceErr != nil {
			return cloud.Volume{}, fenceErr
		} else if fence != nil {
			stored, decodeErr := decodeMutationIntent[diskCreateIntent](*fence)
			if decodeErr != nil || stored != intent {
				return cloud.Volume{}, errors.Join(decodeErr, fmt.Errorf("%w: same-named disk does not match its durable create fence", cloud.ErrIncompatibleVolume))
			}
			// Receipt values from older versions may have come directly from an
			// untrusted POST response. Replace them only after the unique
			// deterministic-name disk has passed authoritative ownership,
			// shape, source, and Ready-state validation.
			canonical, receiptErr := a.fences.SetReceipt(ctx, *fence, strings.ToLower(ready.UUID))
			if receiptErr != nil {
				return cloud.Volume{}, fmt.Errorf("%w: persist canonical disk-create receipt: %v", cloud.ErrUnavailable, receiptErr)
			}
			if deleteErr := a.fences.Delete(ctx, *canonical); deleteErr != nil {
				return cloud.Volume{}, fmt.Errorf("%w: complete disk-create fence: %v", cloud.ErrUnavailable, deleteErr)
			}
		}
		return diskVolume(spec.Location, ready)
	}

	fence, acquired, err := a.beginDiskCreateFence(ctx, intent)
	if err != nil {
		return cloud.Volume{}, err
	}
	if !acquired {
		readbackCtx, cancel := a.mutationReadbackContext(ctx)
		defer cancel()
		return a.reconcileDiskCreateFence(readbackCtx, intent, fence, errors.New("a previous disk-create attempt remains unresolved"))
	}
	// The Lease CAS can take long enough for an independently created disk to
	// become visible. Re-read the unfiltered location inventory after winning
	// the durable issue and before the paid POST. Only exact deterministic-name
	// absence authorizes CreateDisk; an exact owned match is adopted read-only,
	// while every foreign, duplicate, or failed read blocks the POST and clears
	// only this invocation's proven-undispatched fence.
	postFenceDisks, postFenceErr := a.api.ListDisks(ctx, spec.Location)
	if postFenceErr != nil {
		// This invocation acquired the fence and has not called CreateDisk yet.
		// A failed post-CAS GET is therefore proven pre-dispatch, not an
		// ambiguous mutation outcome. Retaining the Lease here would permanently
		// suppress every future create after one transient read failure.
		authorityErr := fmt.Errorf(
			"%w: post-fence disk-create authority is unavailable behind durable fence %s: %v",
			cloud.ErrUnavailable, mutationFenceLeaseName(fence.Key), normalizeAPIError(postFenceErr),
		)
		return cloud.Volume{}, a.clearUndispatchedDiskCreateFence(ctx, fence, authorityErr)
	}
	if existing, found, findErr := uniqueNamedDisk(postFenceDisks, spec.Name); findErr != nil {
		return cloud.Volume{}, a.clearUndispatchedDiskCreateFence(ctx, fence, findErr)
	} else if found {
		readbackCtx, cancel := a.mutationReadbackContext(ctx)
		defer cancel()
		return a.finishUndispatchedFencedDisk(readbackCtx, intent, fence, existing)
	}

	if reserveErr := requireMutationDispatchReserve(ctx); reserveErr != nil {
		return cloud.Volume{}, a.clearUndispatchedDiskCreateFence(ctx, fence, reserveErr)
	}
	created, createErr := a.api.CreateDisk(ctx, spec.Location, sdk.CreateDiskRequest{
		DisplayName:      spec.Name,
		SizeGiB:          sizeGiB,
		BillingAccountID: a.billing,
		SourceImageType:  "EMPTY",
	})
	readbackCtx, cancel := a.mutationReadbackContext(ctx)
	defer cancel()
	if errors.Is(createErr, sdk.ErrMutationBlocked) {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return cloud.Volume{}, errors.Join(createErr, fmt.Errorf("clear locally blocked disk-create fence: %w", deleteErr))
		}
		return cloud.Volume{}, createErr
	}
	// The response body is diagnostic only. A syntactically valid UUID can be
	// stale, foreign, or mismatched with the resource that actually committed.
	// Canonical identity is promoted only from deterministic-name inventory
	// readback in reconcileDiskCreateFence.
	if createErr == nil && created == nil {
		createErr = errors.New("InSpace API returned an empty create-disk response")
	}
	return a.reconcileDiskCreateFence(readbackCtx, intent, fence, createErr)
}

func (a *Adapter) GetVolume(ctx context.Context, location, volumeID string) (cloud.Volume, error) {
	disk, err := a.getOwnedDisk(ctx, location, volumeID)
	if err != nil {
		return cloud.Volume{}, err
	}
	return diskVolume(location, disk)
}

func (a *Adapter) DeleteVolume(ctx context.Context, location, volumeID string) error {
	deleteFence, issueDelete, err := a.prepareDiskDeleteFence(ctx, location, volumeID)
	if err != nil {
		return err
	}
	disk, err := a.api.GetDisk(ctx, location, volumeID)
	missing := sdk.IsNotFound(err)
	deletedTombstone := false
	if err != nil && !missing {
		if issueDelete {
			if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
				return errors.Join(normalizeAPIError(err), fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
			}
		}
		return normalizeAPIError(err)
	}
	if !missing && disk == nil {
		if issueDelete {
			if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
				return errors.Join(errors.New("InSpace API returned an empty disk response"), deleteErr)
			}
		}
		return errors.New("InSpace API returned an empty disk response")
	}
	if !missing {
		if ownershipErr := validateExactDisk(*disk, volumeID, a.billing); ownershipErr != nil {
			if issueDelete {
				if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
					return errors.Join(ownershipErr, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
				}
			}
			return ownershipErr
		}
		deletedTombstone = diskDeletedTombstone(*disk)
		if issueDelete && !deletedTombstone {
			if relationErr := requireExactDiskSnapshotCollection(*disk, volumeID); relationErr != nil {
				if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
					return errors.Join(relationErr, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
				}
				return relationErr
			}
		}
	}
	createFence, err := a.matchingDiskCreateFence(ctx, location, volumeID, disk)
	if err != nil {
		if issueDelete {
			if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
				return errors.Join(err, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
			}
		}
		return err
	}
	readbackCtx, cancel := a.destructiveReadbackContext(ctx)
	defer cancel()
	if missing || deletedTombstone || !issueDelete {
		resolvedFence, err := a.waitForDiskAbsent(readbackCtx, location, volumeID, deleteFence)
		if err != nil {
			return fmt.Errorf(
				"%w: disk deletion remains ambiguous behind durable fence %s; operator must inspect cloud state before removing it: %v",
				cloud.ErrUnavailable, mutationFenceLeaseName(deleteFence.Key), err,
			)
		}
		deleteFence = resolvedFence
		if createFence != nil {
			if err := a.fences.Delete(readbackCtx, *createFence); err != nil {
				return fmt.Errorf("%w: complete matching disk-create fence after deletion: %v", cloud.ErrUnavailable, err)
			}
		}
		if err := a.fences.Delete(readbackCtx, deleteFence); err != nil {
			return fmt.Errorf("%w: complete disk-delete fence after absence proof: %v", cloud.ErrUnavailable, err)
		}
		if missing {
			return cloud.ErrNotFound
		}
		return nil
	}
	if len(disk.Snapshots) != 0 {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: disk %s has %d snapshot(s)", cloud.ErrSnapshotsPresent, volumeID, len(disk.Snapshots)), deleteErr)
		}
		return fmt.Errorf("%w: disk %s has %d snapshot(s)", cloud.ErrSnapshotsPresent, volumeID, len(disk.Snapshots))
	}
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
		}
		return err
	}
	if attachedVM != "" {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM), deleteErr)
		}
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM)
	}
	// Re-read the exact disk as the final API operation before deletion. List
	// and earlier detail responses are discovery only and cannot authorize a
	// paid destructive mutation.
	freshDisk, err := a.getOwnedDisk(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
		}
		return err
	}
	if relationErr := requireExactDiskSnapshotCollection(freshDisk, volumeID); relationErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(relationErr, fmt.Errorf("clear unissued disk-delete fence: %w", deleteErr))
		}
		return relationErr
	}
	if len(freshDisk.Snapshots) != 0 {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: disk %s has %d snapshot(s)", cloud.ErrSnapshotsPresent, volumeID, len(freshDisk.Snapshots)), deleteErr)
		}
		return fmt.Errorf("%w: disk %s has %d snapshot(s)", cloud.ErrSnapshotsPresent, volumeID, len(freshDisk.Snapshots))
	}
	// Attachment state can change while the durable delete fence and canonical
	// disk reads are being processed. Re-run the location-wide exact attachment
	// proof as the final authority before DeleteDisk.
	attachedVM, err = a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-delete fence after final attachment read: %w", deleteErr))
		}
		return err
	}
	if attachedVM != "" {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM), deleteErr)
		}
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM)
	}
	if reserveErr := requireMutationDispatchReserve(ctx); reserveErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(reserveErr, fmt.Errorf("clear undispatched disk-delete fence: %w", deleteErr))
		}
		return reserveErr
	}
	// The earlier destructive context supports pre-existing-fence and tombstone
	// recovery. A newly dispatched DELETE gets a fresh full recovery window
	// after the provider call returns; otherwise a five-minute HTTP request
	// could consume the entire two-minute absence-proof context before readback
	// even begins.
	cancel()
	mutationErr := a.api.DeleteDisk(ctx, location, volumeID)
	if errors.Is(mutationErr, sdk.ErrMutationBlocked) {
		if deleteErr := a.deleteMutationFenceDetached(ctx, deleteFence); deleteErr != nil {
			return errors.Join(mutationErr, fmt.Errorf("clear locally blocked disk-delete fence: %w", deleteErr))
		}
		return mutationErr
	}
	postMutationCtx, postMutationCancel := a.destructiveReadbackContext(ctx)
	defer postMutationCancel()
	resolvedFence, err := a.waitForDiskAbsent(postMutationCtx, location, volumeID, deleteFence)
	if err != nil {
		return fmt.Errorf(
			"%w: disk deletion remains ambiguous behind durable fence %s; operator must inspect cloud state before removing it: %v",
			cloud.ErrUnavailable, mutationFenceLeaseName(deleteFence.Key), errors.Join(mutationErr, err),
		)
	}
	deleteFence = resolvedFence
	if createFence != nil {
		if err := a.fences.Delete(postMutationCtx, *createFence); err != nil {
			return fmt.Errorf("%w: complete matching disk-create fence after deletion: %v", cloud.ErrUnavailable, err)
		}
	}
	if err := a.fences.Delete(postMutationCtx, deleteFence); err != nil {
		return fmt.Errorf("%w: complete disk-delete fence after absence proof: %v", cloud.ErrUnavailable, err)
	}
	return nil
}

func (a *Adapter) AttachVolume(ctx context.Context, location, volumeID, nodeID string) error {
	vmUUID, err := a.resolveVM(ctx, location, nodeID)
	if err != nil {
		return err
	}
	if _, err := a.GetVolume(ctx, location, volumeID); err != nil {
		return err
	}
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: location,
		DiskUUID: strings.ToLower(volumeID), BillingAccountID: a.billing, DesiredVMUUID: vmUUID,
	}
	fence, alreadyDone, err := a.prepareAttachmentFence(ctx, intent)
	if err != nil {
		return err
	}
	if alreadyDone {
		return nil
	}
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-attach fence: %w", deleteErr))
		}
		return err
	}
	switch {
	case attachedVM == vmUUID:
		return a.deleteMutationFenceDetached(ctx, fence)
	case attachedVM != "":
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM), deleteErr)
		}
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM)
	}
	targetVM, err := a.getOwnedVM(ctx, location, vmUUID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-attach fence: %w", deleteErr))
		}
		return err
	}
	if relationErr := requireExactVMAttachmentCollection(targetVM, volumeID); relationErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(relationErr, fmt.Errorf("clear unissued disk-attach fence: %w", deleteErr))
		}
		return relationErr
	}
	if rows := vmDiskRows(targetVM, volumeID); rows != 0 {
		if rows == 1 {
			// Canonical detail is newer than the stale list discovery. The
			// desired state already exists, so no attach POST is necessary.
			return a.deleteMutationFenceDetached(ctx, fence)
		}
		err := fmt.Errorf("InSpace exact VM %s reported %d attachment rows for disk %s", vmUUID, rows, volumeID)
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, deleteErr)
		}
		return err
	}
	// Exact disk ownership is the final read before the attachment mutation.
	if _, err := a.getOwnedDisk(ctx, location, volumeID); err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-attach fence: %w", deleteErr))
		}
		return err
	}
	finalAttachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-attach fence after final attachment read: %w", deleteErr))
		}
		return err
	}
	if finalAttachedVM == vmUUID {
		return a.deleteMutationFenceDetached(ctx, fence)
	}
	if finalAttachedVM != "" {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, finalAttachedVM), deleteErr)
		}
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, finalAttachedVM)
	}
	if reserveErr := requireMutationDispatchReserve(ctx); reserveErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(reserveErr, fmt.Errorf("clear undispatched disk-attach fence: %w", deleteErr))
		}
		return reserveErr
	}
	storage, mutationErr := a.api.AttachDisk(ctx, location, vmUUID, volumeID)
	if mutationErr == nil && (storage == nil || !strings.EqualFold(storage.UUID, volumeID)) {
		mutationErr = errors.New("InSpace API returned an invalid attach-disk response")
	}
	return a.finishAttachmentMutation(ctx, intent, fence, mutationErr)
}

func (a *Adapter) DetachVolume(ctx context.Context, location, volumeID, nodeID string) error {
	// Even an apparently detached volume must prove exact account ownership.
	// Otherwise an omitted billing field could turn a foreign disk into an
	// idempotent success and a later retry could mutate it.
	if _, err := a.getOwnedDisk(ctx, location, volumeID); err != nil {
		return err
	}
	// Resolve any prior attach/detach POST before accepting a fresh unpublish.
	// In particular, an empty VM readback must not return success while an
	// ambiguous attach can still commit later.
	if _, err := a.settleExistingAttachmentFence(ctx, diskAttachmentIntent{
		Operation: "disk-attachment", Location: location, DiskUUID: strings.ToLower(volumeID), BillingAccountID: a.billing,
	}); err != nil {
		return err
	}
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		return err
	}
	if attachedVM == "" {
		return nil
	}
	if nodeID != "" {
		requestedVM, err := a.resolveVM(ctx, location, nodeID)
		if err != nil {
			if errors.Is(err, cloud.ErrInvalidNode) {
				// An old VolumeAttachment may outlive its Kubernetes Node. If
				// the name no longer resolves, it cannot identify the current
				// attachment safely; treat this requested pair as unpublished.
				return nil
			}
			return err
		}
		if requestedVM != attachedVM {
			// The requested node is already unpublished. Never detach a disk
			// from a different node because a stale VolumeAttachment was deleted.
			return nil
		}
	}
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: location,
		DiskUUID: strings.ToLower(volumeID), BillingAccountID: a.billing, PreviousVMUUID: attachedVM,
	}
	fence, alreadyDone, err := a.prepareAttachmentFence(ctx, intent)
	if err != nil {
		return err
	}
	if alreadyDone {
		return nil
	}
	// Recheck after the durable fence is ours. If external state changed, no
	// cloud mutation has been issued, so clearing this fence is safe.
	current, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-detach fence: %w", deleteErr))
		}
		return err
	}
	if current == "" {
		return a.deleteMutationFenceDetached(ctx, fence)
	}
	if current != attachedVM {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: disk %s moved from VM %s to VM %s", cloud.ErrVolumeAttachedElsewhere, volumeID, attachedVM, current), deleteErr)
		}
		return fmt.Errorf("%w: disk %s moved from VM %s to VM %s", cloud.ErrVolumeAttachedElsewhere, volumeID, attachedVM, current)
	}
	targetVM, err := a.getOwnedVM(ctx, location, attachedVM)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-detach fence: %w", deleteErr))
		}
		return err
	}
	if relationErr := requireExactVMAttachmentCollection(targetVM, volumeID); relationErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(relationErr, fmt.Errorf("clear unissued disk-detach fence: %w", deleteErr))
		}
		return relationErr
	}
	if rows := vmDiskRows(targetVM, volumeID); rows != 1 {
		if rows == 0 {
			// Canonical detail is newer than stale discovery: the disk is
			// already detached, so complete the unissued fence.
			return a.deleteMutationFenceDetached(ctx, fence)
		}
		err := fmt.Errorf("InSpace exact VM %s reported %d attachment rows for disk %s", attachedVM, rows, volumeID)
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, deleteErr)
		}
		return err
	}
	// Exact disk ownership is the final read before the detach mutation.
	if _, err := a.getOwnedDisk(ctx, location, volumeID); err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-detach fence: %w", deleteErr))
		}
		return err
	}
	finalAttachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(err, fmt.Errorf("clear unissued disk-detach fence after final attachment read: %w", deleteErr))
		}
		return err
	}
	if finalAttachedVM == "" {
		return a.deleteMutationFenceDetached(ctx, fence)
	}
	if finalAttachedVM != attachedVM {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(fmt.Errorf("%w: disk %s moved from VM %s to VM %s", cloud.ErrVolumeAttachedElsewhere, volumeID, attachedVM, finalAttachedVM), deleteErr)
		}
		return fmt.Errorf("%w: disk %s moved from VM %s to VM %s", cloud.ErrVolumeAttachedElsewhere, volumeID, attachedVM, finalAttachedVM)
	}
	if reserveErr := requireMutationDispatchReserve(ctx); reserveErr != nil {
		if deleteErr := a.deleteMutationFenceDetached(ctx, fence); deleteErr != nil {
			return errors.Join(reserveErr, fmt.Errorf("clear undispatched disk-detach fence: %w", deleteErr))
		}
		return reserveErr
	}
	mutationErr := a.api.DetachDisk(ctx, location, attachedVM, volumeID)
	return a.finishAttachmentMutation(ctx, intent, fence, mutationErr)
}

// waitForAttachment makes ControllerPublish/Unpublish completion match CSI
// semantics even when the InSpace mutation response precedes VM storage-state
// convergence. transitional is the only intermediate state accepted while
// polling; a different VM attachment fails closed.
func (a *Adapter) waitForAttachment(ctx context.Context, location, volumeID, desired, transitional string) error {
	for {
		current, err := a.attachedVM(ctx, location, volumeID)
		if err != nil {
			return err
		}
		if current == desired {
			return nil
		}
		if current != transitional {
			return fmt.Errorf("%w: disk %s converged to VM %s instead of %s", cloud.ErrVolumeAttachedElsewhere, volumeID, current, desired)
		}
		timer := time.NewTimer(a.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Adapter) attachedVM(ctx context.Context, location, diskUUID string) (string, error) {
	if a.network == "" {
		return "", fmt.Errorf("%w: configured VPC UUID is required for CSI attachment discovery", cloud.ErrInvalidNode)
	}
	vms, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return "", normalizeAPIError(err)
	}
	network, err := a.api.GetNetwork(ctx, location, a.network)
	if err != nil {
		return "", normalizeAPIError(err)
	}
	if network == nil {
		return "", errors.New("InSpace API returned an empty network response while checking disk attachment")
	}
	if !strings.EqualFold(strings.TrimSpace(network.UUID), a.network) {
		return "", fmt.Errorf("InSpace exact network read returned UUID %q for %q", network.UUID, a.network)
	}
	members, err := canonicalNetworkVMMembers(network.VMUUIDs)
	if err != nil {
		return "", fmt.Errorf("InSpace network %s has invalid VM membership while checking disk attachment: %w", a.network, err)
	}
	inspect := make(map[string]struct{}, len(vms)+len(network.VMUUIDs))
	for vmUUID := range members {
		inspect[vmUUID] = struct{}{}
	}
	listed := make(map[string]struct{}, len(vms))
	for _, summary := range vms {
		vmUUID := strings.ToLower(strings.TrimSpace(summary.UUID))
		if !uuidPattern.MatchString(vmUUID) {
			return "", fmt.Errorf("InSpace listed a VM with invalid UUID %q while checking disk %s", summary.UUID, diskUUID)
		}
		if _, duplicate := listed[vmUUID]; duplicate {
			return "", fmt.Errorf("InSpace listed VM %s more than once while checking disk %s", vmUUID, diskUUID)
		}
		listed[vmUUID] = struct{}{}
		inspect[vmUUID] = struct{}{}
	}
	attached := ""
	attachmentRows := 0
	candidateUUIDs := make([]string, 0, len(inspect))
	for vmUUID := range inspect {
		candidateUUIDs = append(candidateUUIDs, vmUUID)
	}
	sort.Strings(candidateUUIDs)
	for _, vmUUID := range candidateUUIDs {
		// Exact-read the union of unfiltered VM inventory and configured-VPC
		// membership. This prevents a disk attached outside the configured VPC
		// from being misclassified as unattached and deleted or attached twice.
		vm, err := a.api.GetVM(ctx, location, vmUUID)
		if err != nil {
			return "", fmt.Errorf("read exact VM %s while checking disk %s: %w", vmUUID, diskUUID, normalizeAPIError(err))
		}
		if vm == nil || !strings.EqualFold(strings.TrimSpace(vm.UUID), vmUUID) {
			return "", fmt.Errorf("InSpace exact VM read changed identity for %s while checking disk %s", vmUUID, diskUUID)
		}
		if relationErr := requireExactVMAttachmentCollection(*vm, diskUUID); relationErr != nil {
			return "", relationErr
		}
		rows := vmDiskRows(*vm, diskUUID)
		if rows > 1 {
			return "", fmt.Errorf("InSpace exact VM %s reported %d attachment rows for disk %s", vmUUID, rows, diskUUID)
		}
		_, onConfiguredVPC := members[vmUUID]
		if onConfiguredVPC {
			if err := a.validateExactVM(*vm, vmUUID); err != nil {
				return "", fmt.Errorf("validate configured-VPC VM %s while checking disk %s: %w", vmUUID, diskUUID, err)
			}
		} else if rows > 0 {
			return "", fmt.Errorf("%w: disk %s is attached to VM %s outside configured VPC %s", cloud.ErrVolumeAttachedElsewhere, diskUUID, vmUUID, a.network)
		}
		if rows == 1 {
			if attached != "" && attached != vmUUID {
				return "", fmt.Errorf("InSpace reported disk %s attached to multiple VMs", diskUUID)
			}
			attached = vmUUID
			attachmentRows++
		}
	}
	if attachmentRows > 1 {
		return "", fmt.Errorf("InSpace reported disk %s in %d attachment rows on VM %s", diskUUID, attachmentRows, attached)
	}
	return attached, nil
}

func vmDiskRows(vm sdk.VM, diskUUID string) int {
	rows := 0
	for _, storage := range vm.Storage {
		if strings.EqualFold(storage.UUID, diskUUID) {
			rows++
		}
	}
	return rows
}

func requireExactDiskSnapshotCollection(disk sdk.Disk, diskUUID string) error {
	if disk.Snapshots == nil {
		return fmt.Errorf("InSpace exact disk %s omitted snapshots; refusing to treat the relationship as empty", diskUUID)
	}
	return nil
}

func requireExactVMAttachmentCollection(vm sdk.VM, diskUUID string) error {
	if vm.Storage == nil {
		return fmt.Errorf(
			"InSpace exact VM %s omitted storage while checking disk %s; refusing to treat the relationship as empty",
			vm.UUID,
			diskUUID,
		)
	}
	return nil
}

func (a *Adapter) waitForDiskReady(ctx context.Context, intent diskCreateIntent, disk sdk.Disk) (sdk.Disk, error) {
	expectedUUID := strings.ToLower(strings.TrimSpace(disk.UUID))
	for {
		if err := validateExactDisk(disk, expectedUUID, intent.BillingAccountID); err != nil {
			return sdk.Disk{}, fmt.Errorf("%w: disk create readiness identity changed: %v", cloud.ErrIncompatibleVolume, err)
		}
		if err := validateDiskCreateReadback(disk, intent); err != nil {
			return sdk.Disk{}, err
		}
		switch strings.ToLower(strings.TrimSpace(disk.Status)) {
		case "active":
			return disk, nil
		case "error", "failed", "deleted":
			return sdk.Disk{}, fmt.Errorf("InSpace disk %s entered terminal status %q", disk.UUID, disk.Status)
		}
		timer := time.NewTimer(a.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return sdk.Disk{}, ctx.Err()
		case <-timer.C:
		}
		current, err := a.api.GetDisk(ctx, intent.Location, disk.UUID)
		if err != nil {
			return sdk.Disk{}, normalizeAPIError(err)
		}
		if current == nil {
			return sdk.Disk{}, errors.New("InSpace API returned an empty disk response")
		}
		disk = *current
	}
}

// getOwnedDisk is the only authoritative disk detail read used by ordinary
// get and mutation paths. Both UUID and billing account must be echoed exactly;
// omission is uncertainty and therefore fails closed.
func (a *Adapter) getOwnedDisk(ctx context.Context, location, diskUUID string) (sdk.Disk, error) {
	disk, err := a.api.GetDisk(ctx, location, diskUUID)
	if err != nil {
		return sdk.Disk{}, normalizeAPIError(err)
	}
	if disk == nil {
		return sdk.Disk{}, errors.New("InSpace API returned an empty disk response")
	}
	if err := validateExactDisk(*disk, diskUUID, a.billing); err != nil {
		return sdk.Disk{}, err
	}
	if diskDeletedTombstone(*disk) {
		return sdk.Disk{}, cloud.ErrNotFound
	}
	return *disk, nil
}

func diskDeletedTombstone(disk sdk.Disk) bool {
	return strings.EqualFold(strings.TrimSpace(disk.Status), "deleted")
}

func validateExactDisk(disk sdk.Disk, expectedUUID string, billingAccountID int64) error {
	expectedUUID = strings.ToLower(strings.TrimSpace(expectedUUID))
	actualUUID := strings.ToLower(strings.TrimSpace(disk.UUID))
	if billingAccountID <= 0 {
		return fmt.Errorf("%w: configured billing account ID is not positive", cloud.ErrPermissionDenied)
	}
	if !uuidPattern.MatchString(expectedUUID) || !uuidPattern.MatchString(actualUUID) || actualUUID != expectedUUID {
		return fmt.Errorf("%w: exact disk read returned UUID %q for %q", cloud.ErrPermissionDenied, disk.UUID, expectedUUID)
	}
	if disk.BillingAccountID != billingAccountID {
		return fmt.Errorf("%w: disk %s billing account is %d, expected %d", cloud.ErrPermissionDenied, actualUUID, disk.BillingAccountID, billingAccountID)
	}
	return nil
}

// getOwnedVM requires three independent canonical ownership signals before a
// VM may participate in an attachment mutation: one unfiltered ListVMs row,
// exact detail with positive billing identity and no contradictory VPC value,
// and exactly one membership in the configured VPC. Sparse or lagging
// discovery is never mutation authority.
func (a *Adapter) getOwnedVM(ctx context.Context, location, vmUUID string) (sdk.VM, error) {
	vm, err := a.getVPCVM(ctx, location, vmUUID)
	if err != nil {
		return sdk.VM{}, err
	}
	vms, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return sdk.VM{}, normalizeAPIError(err)
	}
	listRows := 0
	for _, summary := range vms {
		if strings.EqualFold(strings.TrimSpace(summary.UUID), vmUUID) {
			listRows++
		}
	}
	if listRows != 1 {
		return sdk.VM{}, fmt.Errorf("%w: VM %s has %d unfiltered inventory rows, want one", cloud.ErrInvalidNode, vmUUID, listRows)
	}
	return vm, nil
}

// getVPCVM proves exact VM and configured-VPC identity without using the
// eventually consistent location inventory as mutation authority. This is
// sufficient for read-only idempotent convergence; every path that can issue
// an attachment mutation additionally calls getOwnedVM immediately before it.
func (a *Adapter) getVPCVM(ctx context.Context, location, vmUUID string) (sdk.VM, error) {
	if a.network == "" {
		return sdk.VM{}, fmt.Errorf("%w: configured VPC UUID is required for CSI VM mutations", cloud.ErrInvalidNode)
	}
	vm, err := a.api.GetVM(ctx, location, vmUUID)
	if err != nil {
		return sdk.VM{}, normalizeAPIError(err)
	}
	if vm == nil {
		return sdk.VM{}, errors.New("InSpace API returned an empty VM response")
	}
	if err := a.validateExactVM(*vm, vmUUID); err != nil {
		return sdk.VM{}, err
	}
	network, err := a.api.GetNetwork(ctx, location, a.network)
	if err != nil {
		return sdk.VM{}, normalizeAPIError(err)
	}
	if network == nil || !strings.EqualFold(strings.TrimSpace(network.UUID), a.network) {
		return sdk.VM{}, fmt.Errorf("%w: configured VPC %s lacks exact membership authority", cloud.ErrInvalidNode, a.network)
	}
	members, err := canonicalNetworkVMMembers(network.VMUUIDs)
	if err != nil {
		return sdk.VM{}, fmt.Errorf("%w: configured VPC %s has invalid VM membership: %v", cloud.ErrInvalidNode, a.network, err)
	}
	canonicalVMUUID := strings.ToLower(strings.TrimSpace(vmUUID))
	if _, member := members[canonicalVMUUID]; !member {
		return sdk.VM{}, fmt.Errorf("%w: VM %s has 0 configured-VPC memberships, want one", cloud.ErrInvalidNode, vmUUID)
	}
	return *vm, nil
}

func (a *Adapter) validateExactVM(vm sdk.VM, expectedUUID string) error {
	expectedUUID = strings.ToLower(strings.TrimSpace(expectedUUID))
	actualUUID := strings.ToLower(strings.TrimSpace(vm.UUID))
	if !uuidPattern.MatchString(expectedUUID) || !uuidPattern.MatchString(actualUUID) || actualUUID != expectedUUID {
		return fmt.Errorf("%w: exact VM read returned UUID %q for %q", cloud.ErrInvalidNode, vm.UUID, expectedUUID)
	}
	if strings.EqualFold(strings.TrimSpace(vm.Status), "deleted") {
		return fmt.Errorf("%w: exact VM %s is a deleted tombstone", cloud.ErrInvalidNode, actualUUID)
	}
	if vm.BillingAccountID != a.billing {
		return fmt.Errorf("%w: VM %s billing account is %d, expected %d", cloud.ErrPermissionDenied, actualUUID, vm.BillingAccountID, a.billing)
	}
	// InSpace VM detail/list responses currently omit network_uuid. Treat an
	// omitted value as sparse discovery rather than contrary evidence: callers
	// must independently prove exactly one membership in the configured VPC via
	// GetNetwork before this detail can authorize a VM mutation. A present value
	// is still useful corroboration and must agree exactly.
	if vmNetwork := strings.TrimSpace(vm.NetworkUUID); a.network != "" && vmNetwork != "" && !strings.EqualFold(vmNetwork, a.network) {
		return fmt.Errorf("%w: VM %s network is %q, expected %q", cloud.ErrInvalidNode, actualUUID, vm.NetworkUUID, a.network)
	}
	return nil
}

func (a *Adapter) resolveVM(ctx context.Context, location, nodeID string) (string, error) {
	providerID := strings.TrimSpace(nodeID)
	if providerID == "" {
		return "", fmt.Errorf("%w: empty node ID", cloud.ErrInvalidNode)
	}
	if !strings.HasPrefix(strings.ToLower(providerID), "inspace://") {
		if a.nodes == nil {
			return "", fmt.Errorf("%w: Kubernetes node %q cannot be resolved without a Node resolver", cloud.ErrInvalidNode, providerID)
		}
		resolved, err := a.nodes.ProviderIDForNode(ctx, providerID)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			if errors.Is(err, cloud.ErrUnavailable) {
				return "", err
			}
			return "", fmt.Errorf("%w: resolve Kubernetes node %q: %v", cloud.ErrInvalidNode, providerID, err)
		}
		providerID = resolved
	}
	providerLocation, vmUUID, err := parseProviderID(providerID)
	if err != nil {
		return "", fmt.Errorf("%w: %v", cloud.ErrInvalidNode, err)
	}
	if providerLocation != location {
		return "", fmt.Errorf("%w: provider location %q does not match %q", cloud.ErrInvalidNode, providerLocation, location)
	}
	if _, err := a.getVPCVM(ctx, location, vmUUID); err != nil {
		if errors.Is(err, cloud.ErrNotFound) {
			return "", fmt.Errorf("%w: VM %s not found", cloud.ErrInvalidNode, vmUUID)
		}
		return "", err
	}
	return vmUUID, nil
}

func parseProviderID(value string) (string, string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "inspace" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("expected inspace://<location>/<vm-uuid>")
	}
	location := strings.ToLower(u.Host)
	vmUUID := strings.ToLower(strings.TrimPrefix(u.EscapedPath(), "/"))
	if strings.Contains(vmUUID, "/") || !uuidPattern.MatchString(vmUUID) {
		return "", "", errors.New("provider ID contains an invalid VM UUID")
	}
	return location, vmUUID, nil
}

func uniqueNamedDisk(disks []sdk.Disk, name string) (sdk.Disk, bool, error) {
	var match sdk.Disk
	count := 0
	for _, disk := range disks {
		if disk.DisplayName == name {
			match = disk
			count++
		}
	}
	if count > 1 {
		return sdk.Disk{}, false, fmt.Errorf("%w: %d disks are named %q", cloud.ErrIncompatibleVolume, count, name)
	}
	return match, count == 1, nil
}

func diskVolume(location string, disk sdk.Disk) (cloud.Volume, error) {
	if !uuidPattern.MatchString(strings.ToLower(disk.UUID)) || disk.SizeGiB <= 0 {
		return cloud.Volume{}, errors.New("InSpace API returned an invalid disk")
	}
	if int64(disk.SizeGiB) > math.MaxInt64/gib {
		return cloud.Volume{}, errors.New("InSpace disk size overflows bytes")
	}
	return cloud.Volume{
		ID: strings.ToLower(disk.UUID), Name: disk.DisplayName, Location: location,
		CapacityBytes: int64(disk.SizeGiB) * gib,
	}, nil
}

func bytesToGiB(bytes int64) (int, error) {
	if bytes <= 0 {
		return 0, errors.New("volume capacity must be positive")
	}
	value := 1 + (bytes-1)/gib
	if value > int64(math.MaxInt) {
		return 0, errors.New("volume capacity is too large")
	}
	return int(value), nil
}

func normalizeAPIError(err error) error {
	if err == nil {
		return nil
	}
	if sdk.IsNotFound(err) {
		return cloud.ErrNotFound
	}
	var apiErr *sdk.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case 401:
			return fmt.Errorf("%w: %v", cloud.ErrUnauthenticated, err)
		case 403:
			return fmt.Errorf("%w: %v", cloud.ErrPermissionDenied, err)
		case 409:
			return fmt.Errorf("%w: %v", cloud.ErrConflict, err)
		}
		if apiErr.Retryable {
			return fmt.Errorf("%w: %v", cloud.ErrUnavailable, err)
		}
	}
	return err
}

var _ cloud.Interface = (*Adapter)(nil)

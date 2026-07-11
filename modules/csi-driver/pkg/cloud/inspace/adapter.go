// Package inspace adapts the shared InSpace SDK to the CSI cloud boundary.
package inspace

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const gib = int64(1024 * 1024 * 1024)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// API is the location-aware subset of the shared SDK used by CSI. Keeping it
// narrow makes idempotency and attachment behavior testable without HTTP.
type API interface {
	CreateDisk(context.Context, string, sdk.CreateDiskRequest) (*sdk.Disk, error)
	GetDisk(context.Context, string, string) (*sdk.Disk, error)
	ListDisks(context.Context, string) ([]sdk.Disk, error)
	DeleteDisk(context.Context, string, string) error
	ListVMs(context.Context, string) ([]sdk.VM, error)
	GetVM(context.Context, string, string) (*sdk.VM, error)
	AttachDisk(context.Context, string, string, string) (*sdk.VMStorage, error)
	DetachDisk(context.Context, string, string, string) error
}

// NodeResolver returns the Kubernetes Node's spec.providerID. The adapter
// invokes it only when CSI sends a node name instead of an InSpace provider ID.
type NodeResolver interface {
	ProviderIDForNode(context.Context, string) (string, error)
}

type Config struct {
	Location         string
	BillingAccountID int64
	PollInterval     time.Duration
}

type Adapter struct {
	api      API
	nodes    NodeResolver
	location string
	billing  int64
	poll     time.Duration
}

func New(api API, nodes NodeResolver, cfg Config) (*Adapter, error) {
	if api == nil {
		return nil, errors.New("InSpace API client is required")
	}
	if strings.TrimSpace(cfg.Location) == "" {
		return nil, errors.New("location is required")
	}
	if cfg.BillingAccountID < 0 {
		return nil, errors.New("billing account ID cannot be negative")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Adapter{api: api, nodes: nodes, location: cfg.Location, billing: cfg.BillingAccountID, poll: cfg.PollInterval}, nil
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
	disks, err := a.api.ListDisks(ctx, spec.Location)
	if err != nil {
		return cloud.Volume{}, normalizeAPIError(err)
	}
	if existing, found, err := uniqueNamedDisk(disks, spec.Name); err != nil {
		return cloud.Volume{}, err
	} else if found {
		ready, err := a.waitForDiskReady(ctx, spec.Location, existing)
		if err != nil {
			return cloud.Volume{}, err
		}
		return diskVolume(spec.Location, ready)
	}

	created, createErr := a.api.CreateDisk(ctx, spec.Location, sdk.CreateDiskRequest{
		DisplayName:      spec.Name,
		SizeGiB:          sizeGiB,
		BillingAccountID: a.billing,
		SourceImageType:  "EMPTY",
	})
	if createErr == nil {
		if created == nil {
			return cloud.Volume{}, errors.New("InSpace API returned an empty create-disk response")
		}
		ready, err := a.waitForDiskReady(ctx, spec.Location, *created)
		if err != nil {
			return cloud.Volume{}, err
		}
		return diskVolume(spec.Location, ready)
	}
	// The API has no idempotency-key contract. A timeout may happen after the
	// disk was committed, so reconcile by stable CSI name instead of blindly
	// issuing another POST.
	disks, listErr := a.api.ListDisks(ctx, spec.Location)
	if listErr == nil {
		if existing, found, findErr := uniqueNamedDisk(disks, spec.Name); findErr != nil {
			return cloud.Volume{}, findErr
		} else if found {
			ready, err := a.waitForDiskReady(ctx, spec.Location, existing)
			if err != nil {
				return cloud.Volume{}, err
			}
			return diskVolume(spec.Location, ready)
		}
	}
	return cloud.Volume{}, normalizeAPIError(createErr)
}

func (a *Adapter) GetVolume(ctx context.Context, location, volumeID string) (cloud.Volume, error) {
	disk, err := a.api.GetDisk(ctx, location, volumeID)
	if err != nil {
		return cloud.Volume{}, normalizeAPIError(err)
	}
	if disk == nil {
		return cloud.Volume{}, errors.New("InSpace API returned an empty disk response")
	}
	return diskVolume(location, *disk)
}

func (a *Adapter) DeleteVolume(ctx context.Context, location, volumeID string) error {
	disk, err := a.api.GetDisk(ctx, location, volumeID)
	if sdk.IsNotFound(err) {
		return cloud.ErrNotFound
	}
	if err != nil {
		return normalizeAPIError(err)
	}
	if disk == nil {
		return errors.New("InSpace API returned an empty disk response")
	}
	if len(disk.Snapshots) != 0 {
		return fmt.Errorf("%w: disk %s has %d snapshot(s)", cloud.ErrSnapshotsPresent, volumeID, len(disk.Snapshots))
	}
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		return err
	}
	if attachedVM != "" {
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM)
	}
	if err := a.api.DeleteDisk(ctx, location, volumeID); err != nil {
		return normalizeAPIError(err)
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
	attachedVM, err := a.attachedVM(ctx, location, volumeID)
	if err != nil {
		return err
	}
	switch {
	case attachedVM == vmUUID:
		return nil
	case attachedVM != "":
		return fmt.Errorf("%w: %s", cloud.ErrVolumeAttachedElsewhere, attachedVM)
	}
	if _, err := a.api.AttachDisk(ctx, location, vmUUID, volumeID); err != nil {
		// Reconcile an ambiguous POST response before reporting failure.
		if current, scanErr := a.attachedVM(ctx, location, volumeID); scanErr == nil && current == vmUUID {
			return nil
		}
		return normalizeAPIError(err)
	}
	return a.waitForAttachment(ctx, location, volumeID, vmUUID, "")
}

func (a *Adapter) DetachVolume(ctx context.Context, location, volumeID, nodeID string) error {
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
	if err := a.api.DetachDisk(ctx, location, attachedVM, volumeID); err != nil {
		if current, scanErr := a.attachedVM(ctx, location, volumeID); scanErr == nil && current == "" {
			return nil
		}
		return normalizeAPIError(err)
	}
	return a.waitForAttachment(ctx, location, volumeID, "", attachedVM)
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
	vms, err := a.api.ListVMs(ctx, location)
	if err != nil {
		return "", normalizeAPIError(err)
	}
	attached := ""
	for _, vm := range vms {
		for _, storage := range vm.Storage {
			if strings.EqualFold(storage.UUID, diskUUID) {
				if attached != "" && !strings.EqualFold(attached, vm.UUID) {
					return "", fmt.Errorf("InSpace reported disk %s attached to multiple VMs", diskUUID)
				}
				attached = strings.ToLower(vm.UUID)
			}
		}
	}
	return attached, nil
}

func (a *Adapter) waitForDiskReady(ctx context.Context, location string, disk sdk.Disk) (sdk.Disk, error) {
	for {
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
		current, err := a.api.GetDisk(ctx, location, disk.UUID)
		if err != nil {
			return sdk.Disk{}, normalizeAPIError(err)
		}
		if current == nil {
			return sdk.Disk{}, errors.New("InSpace API returned an empty disk response")
		}
		disk = *current
	}
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
	if _, err := a.api.GetVM(ctx, location, vmUUID); err != nil {
		if sdk.IsNotFound(err) {
			return "", fmt.Errorf("%w: VM %s not found", cloud.ErrInvalidNode, vmUUID)
		}
		return "", normalizeAPIError(err)
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

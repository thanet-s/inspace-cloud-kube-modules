package inspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

func validCSITestDisk() sdk.Disk {
	return sdk.Disk{
		UUID:             testDiskID,
		DisplayName:      "pvc-safe",
		Status:           "Active",
		SizeGiB:          10,
		BillingAccountID: 42,
		SourceImageType:  "EMPTY",
		Snapshots:        []sdk.DiskSnapshot{},
	}
}

func nonCSIDiskVariants() map[string]func(*sdk.Disk) {
	return map[string]func(*sdk.Disk){
		"OS base": func(disk *sdk.Disk) {
			disk.SourceImageType = "OS_BASE"
			disk.SourceImage = "ubuntu_24.04"
		},
		"unnamed": func(disk *sdk.Disk) {
			disk.DisplayName = ""
		},
		"image backed": func(disk *sdk.Disk) {
			disk.SourceImageType = "SNAPSHOT"
			disk.SourceImage = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"read-only bootable": func(disk *sdk.Disk) {
			disk.ReadOnlyBootable = true
		},
		"source identity omitted": func(disk *sdk.Disk) {
			disk.SourceImageType = ""
		},
		"unexpected EMPTY source image": func(disk *sdk.Disk) {
			disk.SourceImage = "unexpected-image"
		},
	}
}

func TestNamedEmptyNonPrimaryVolumeMutationLifecycle(t *testing.T) {
	api := &fakeAPI{
		disks: []sdk.Disk{validCSITestDisk()},
		vms: []sdk.VM{{
			UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{},
		}},
		networkVMUUIDs: []string{testVM1},
	}
	adapter := newAdapter(t, api, nodeResolver{
		"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
	})

	volume, err := adapter.GetVolume(context.Background(), testLocation, testDiskID)
	if err != nil {
		t.Fatalf("read valid CSI disk: %v", err)
	}
	if volume.ID != testDiskID {
		t.Fatalf("read valid CSI disk ID = %q, want %q", volume.ID, testDiskID)
	}
	if err := adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatalf("attach valid CSI disk: %v", err)
	}
	if err := adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1"); err != nil {
		t.Fatalf("detach valid CSI disk: %v", err)
	}
	if err := adapter.DeleteVolume(context.Background(), testLocation, testDiskID); err != nil {
		t.Fatalf("delete valid CSI disk: %v", err)
	}
	if api.attachCalls != 1 || api.detachCalls != 1 || api.deleteCalls != 1 {
		t.Fatalf(
			"valid CSI disk mutation calls attach=%d detach=%d delete=%d, want 1/1/1",
			api.attachCalls,
			api.detachCalls,
			api.deleteCalls,
		)
	}
}

func TestNonCSIDiskShapesFailBeforeEveryCloudMutation(t *testing.T) {
	operations := map[string]func(*Adapter) error{
		"read": func(adapter *Adapter) error {
			_, err := adapter.GetVolume(context.Background(), testLocation, testDiskID)
			return err
		},
		"attach": func(adapter *Adapter) error {
			return adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"detach": func(adapter *Adapter) error {
			return adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"delete": func(adapter *Adapter) error {
			return adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
		},
	}

	for variantName, mutate := range nonCSIDiskVariants() {
		for operationName, operation := range operations {
			t.Run(variantName+"/"+operationName, func(t *testing.T) {
				disk := validCSITestDisk()
				mutate(&disk)
				vm := sdk.VM{
					UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork, Storage: []sdk.VMStorage{},
				}
				if operationName == "detach" {
					vm.Storage = []sdk.VMStorage{{UUID: testDiskID, Primary: false}}
				}
				api := &fakeAPI{
					disks: []sdk.Disk{disk}, vms: []sdk.VM{vm},
					networkVMUUIDs: []string{testVM1}, preserveDiskSource: true,
				}
				adapter := newAdapter(t, api, nodeResolver{
					"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
				})

				err := operation(adapter)
				if !errors.Is(err, cloud.ErrPermissionDenied) {
					t.Fatalf("%s %s error = %v, want ErrPermissionDenied", variantName, operationName, err)
				}
				if calls := api.mutationCalls(); calls != 0 {
					t.Fatalf("%s %s issued %d cloud mutation(s)", variantName, operationName, calls)
				}
			})
		}
	}
}

func TestFinalExactDiskReadRejectsNonCSIShapeBeforeMutation(t *testing.T) {
	operations := map[string]func(*Adapter) error{
		"attach": func(adapter *Adapter) error {
			return adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"detach": func(adapter *Adapter) error {
			return adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"delete": func(adapter *Adapter) error {
			return adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
		},
	}

	for variantName, mutate := range nonCSIDiskVariants() {
		for operationName, operation := range operations {
			t.Run(variantName+"/"+operationName, func(t *testing.T) {
				invalid := validCSITestDisk()
				mutate(&invalid)
				vm := sdk.VM{
					UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork,
					Storage: []sdk.VMStorage{},
				}
				if operationName == "detach" {
					vm.Storage = []sdk.VMStorage{{UUID: testDiskID, Primary: false}}
				}
				base := &fakeAPI{
					disks: []sdk.Disk{validCSITestDisk()}, vms: []sdk.VM{vm},
					networkVMUUIDs: []string{testVM1}, preserveDiskSource: true,
				}
				api := &detailSequenceAPI{
					fakeAPI: base,
					// The first exact read authorizes discovery. The second is
					// the final exact read immediately before the mutation.
					diskOverride: map[int]sdk.Disk{2: invalid},
				}
				store := newMemoryMutationFenceStore()
				resolver := &fencedNodeResolver{
					nodeResolver: nodeResolver{
						"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
					},
					memoryMutationFenceStore: store,
				}
				adapter := newFencedNetworkAdapter(t, api, resolver, time.Second)

				err := operation(adapter)
				if !errors.Is(err, cloud.ErrPermissionDenied) {
					t.Fatalf("%s %s final read error = %v, want ErrPermissionDenied", variantName, operationName, err)
				}
				if calls := base.mutationCalls(); calls != 0 {
					t.Fatalf("%s %s final read issued %d cloud mutation(s)", variantName, operationName, calls)
				}
				if fences, listErr := store.List(context.Background(), ""); listErr != nil || len(fences) != 0 {
					t.Fatalf("%s %s retained unissued fences=%#v err=%v", variantName, operationName, fences, listErr)
				}
			})
		}
	}
}

func TestDiskCreateRecoveryReadbackRejectsNonCSIShape(t *testing.T) {
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "pvc-safe",
		SizeGiB: 10, BillingAccountID: 42,
	}
	fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}

	for variantName, mutate := range nonCSIDiskVariants() {
		t.Run(variantName, func(t *testing.T) {
			disk := validCSITestDisk()
			mutate(&disk)
			api := &fakeAPI{preserveDiskSource: true}
			adapter := newFencedAdapter(t, api, nil, time.Second)

			if _, err := adapter.finishFencedDisk(context.Background(), intent, fence, disk); !errors.Is(err, cloud.ErrIncompatibleVolume) {
				t.Fatalf("create recovery readback error = %v, want ErrIncompatibleVolume", err)
			}
			if calls := api.mutationCalls(); calls != 0 {
				t.Fatalf("create recovery readback issued %d cloud mutation(s)", calls)
			}
		})
	}
}

func TestPrimaryDiskReferenceFailsBeforeEveryCloudMutation(t *testing.T) {
	operations := map[string]func(*Adapter) error{
		"idempotent same-node attach": func(adapter *Adapter) error {
			return adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"detach": func(adapter *Adapter) error {
			return adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
		},
		"delete": func(adapter *Adapter) error {
			return adapter.DeleteVolume(context.Background(), testLocation, testDiskID)
		},
	}
	for operationName, operation := range operations {
		t.Run(operationName, func(t *testing.T) {
			api := &fakeAPI{
				disks: []sdk.Disk{validCSITestDisk()},
				vms: []sdk.VM{{
					UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork,
					Storage: []sdk.VMStorage{{UUID: testDiskID, SizeGiB: 10, Primary: true}},
				}},
				networkVMUUIDs: []string{testVM1},
			}
			adapter := newAdapter(t, api, nodeResolver{
				"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
			})

			err := operation(adapter)
			if !errors.Is(err, cloud.ErrPermissionDenied) {
				t.Fatalf("%s error = %v, want ErrPermissionDenied", operationName, err)
			}
			if calls := api.mutationCalls(); calls != 0 {
				t.Fatalf("%s issued %d cloud mutation(s)", operationName, calls)
			}
		})
	}
}

func TestExistingAttachmentFenceCannotBypassNonCSIDiskReadback(t *testing.T) {
	for variantName, mutate := range nonCSIDiskVariants() {
		for _, operation := range []string{"attach", "detach"} {
			t.Run(variantName+"/"+operation, func(t *testing.T) {
				disk := validCSITestDisk()
				mutate(&disk)
				vm := sdk.VM{
					UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork,
					Storage: []sdk.VMStorage{},
				}
				intent := diskAttachmentIntent{
					Operation: "disk-attachment", Location: testLocation,
					DiskUUID: testDiskID, BillingAccountID: 42,
				}
				if operation == "attach" {
					intent.DesiredVMUUID = testVM1
				} else {
					intent.PreviousVMUUID = testVM1
					vm.Storage = []sdk.VMStorage{{UUID: testDiskID, Primary: false}}
				}

				api := &fakeAPI{
					disks: []sdk.Disk{disk}, vms: []sdk.VM{vm},
					networkVMUUIDs: []string{testVM1}, preserveDiskSource: true,
				}
				store := newMemoryMutationFenceStore()
				resolver := &fencedNodeResolver{
					nodeResolver: nodeResolver{
						"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
					},
					memoryMutationFenceStore: store,
				}
				fence, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
				if err != nil {
					t.Fatal(err)
				}
				if stored, acquired, err := store.Create(context.Background(), fence); err != nil || !acquired || stored == nil {
					t.Fatalf("seed attachment fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
				}
				adapter := newFencedNetworkAdapter(t, api, resolver, time.Second)

				if operation == "attach" {
					err = adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
				} else {
					err = adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
				}
				if !errors.Is(err, cloud.ErrPermissionDenied) {
					t.Fatalf("%s %s recovery entry error = %v, want ErrPermissionDenied", variantName, operation, err)
				}
				if calls := api.mutationCalls(); calls != 0 {
					t.Fatalf("%s %s recovery entry issued %d cloud mutation(s)", variantName, operation, calls)
				}
				if remaining, getErr := store.Get(context.Background(), fence.Key); getErr != nil || remaining == nil {
					t.Fatalf("%s %s recovery entry removed safety fence: fence=%#v err=%v", variantName, operation, remaining, getErr)
				}
			})
		}
	}
}

func TestPrimaryDiskAttachmentFencesRemainFailClosed(t *testing.T) {
	for _, operation := range []string{"attach", "detach"} {
		t.Run(operation, func(t *testing.T) {
			api := &fakeAPI{
				disks: []sdk.Disk{validCSITestDisk()},
				vms: []sdk.VM{{
					UUID: testVM1, BillingAccountID: 42, NetworkUUID: testNetwork,
					Storage: []sdk.VMStorage{{UUID: testDiskID, SizeGiB: 10, Primary: true}},
				}},
				networkVMUUIDs: []string{testVM1},
			}
			store := newMemoryMutationFenceStore()
			resolver := &fencedNodeResolver{
				nodeResolver: nodeResolver{
					"worker-1": fmt.Sprintf("inspace://%s/%s", testLocation, testVM1),
				},
				memoryMutationFenceStore: store,
			}
			intent := diskAttachmentIntent{
				Operation: "disk-attachment", Location: testLocation,
				DiskUUID: testDiskID, BillingAccountID: 42,
			}
			if operation == "attach" {
				intent.DesiredVMUUID = testVM1
			} else {
				intent.PreviousVMUUID = testVM1
			}
			fence, err := newMutationFence(diskAttachmentFenceKey(testLocation, testDiskID), intent)
			if err != nil {
				t.Fatal(err)
			}
			if stored, acquired, err := store.Create(context.Background(), fence); err != nil || !acquired || stored == nil {
				t.Fatalf("seed attachment fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
			}
			adapter := newFencedNetworkAdapter(t, api, resolver, 20*time.Millisecond)

			if operation == "attach" {
				err = adapter.AttachVolume(context.Background(), testLocation, testDiskID, "worker-1")
			} else {
				err = adapter.DetachVolume(context.Background(), testLocation, testDiskID, "worker-1")
			}
			if !errors.Is(err, cloud.ErrUnavailable) || !strings.Contains(err.Error(), cloud.ErrPermissionDenied.Error()) {
				t.Fatalf("%s recovery error = %v, want unresolved ErrUnavailable containing ErrPermissionDenied", operation, err)
			}
			if calls := api.mutationCalls(); calls != 0 {
				t.Fatalf("%s recovery issued %d cloud mutation(s)", operation, calls)
			}
			if remaining, getErr := store.Get(context.Background(), fence.Key); getErr != nil || remaining == nil {
				t.Fatalf("%s recovery removed unresolved safety fence: fence=%#v err=%v", operation, remaining, getErr)
			} else if _, readbackErr := adapter.waitForFencedAttachment(context.Background(), intent, *remaining); !errors.Is(readbackErr, cloud.ErrPermissionDenied) {
				t.Fatalf("%s direct recovery readback error = %v, want ErrPermissionDenied", operation, readbackErr)
			}
		})
	}
}

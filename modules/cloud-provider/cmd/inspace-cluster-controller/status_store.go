package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

func newFileStatusCompareAndSwap(path string) bootstrap.StatusCompareAndSwapFunc {
	return func(
		ctx context.Context,
		expectedCluster *v1alpha1.InSpaceCluster,
		expected, desired v1alpha1.InSpaceClusterStatus,
	) (v1alpha1.InSpaceClusterStatus, error) {
		lock, err := acquireStatusFileLock(ctx, path+".status.lock")
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, err
		}
		defer func() {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
		}()

		data, err := os.ReadFile(path)
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("read cluster config for status CAS: %w", err)
		}
		var current v1alpha1.InSpaceCluster
		if err := yaml.UnmarshalStrict(data, &current); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("decode cluster config for status CAS: %w", err)
		}
		if current.APIVersion != expectedCluster.APIVersion || current.Kind != expectedCluster.Kind ||
			!sameEncodedValue(current.Metadata, expectedCluster.Metadata) || !sameEncodedValue(current.Spec, expectedCluster.Spec) {
			return v1alpha1.InSpaceClusterStatus{}, errors.New("cluster config identity or spec changed during status CAS")
		}
		if !reflect.DeepEqual(current.Status, expected) {
			return v1alpha1.InSpaceClusterStatus{}, errors.New("cluster status compare-and-swap conflict")
		}
		current.Status = desired
		encoded, err := yaml.Marshal(current)
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("encode cluster config status: %w", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("stat cluster config for status CAS: %w", err)
		}
		directory := filepath.Dir(path)
		temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".status-*")
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("create cluster status temporary file: %w", err)
		}
		temporaryPath := temporary.Name()
		removeTemporary := true
		defer func() {
			_ = temporary.Close()
			if removeTemporary {
				_ = os.Remove(temporaryPath)
			}
		}()
		if err := temporary.Chmod(info.Mode().Perm()); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("set cluster status temporary-file mode: %w", err)
		}
		if _, err := temporary.Write(encoded); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("write cluster status temporary file: %w", err)
		}
		if err := temporary.Sync(); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("sync cluster status temporary file: %w", err)
		}
		if err := temporary.Close(); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("close cluster status temporary file: %w", err)
		}
		if err := os.Rename(temporaryPath, path); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("atomically replace cluster config status: %w", err)
		}
		removeTemporary = false
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("open cluster status directory for sync: %w", err)
		}
		if err := directoryHandle.Sync(); err != nil {
			_ = directoryHandle.Close()
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("sync cluster status directory: %w", err)
		}
		if err := directoryHandle.Close(); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("close cluster status directory: %w", err)
		}

		readbackData, err := os.ReadFile(path)
		if err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("read back cluster status: %w", err)
		}
		var readback v1alpha1.InSpaceCluster
		if err := yaml.UnmarshalStrict(readbackData, &readback); err != nil {
			return v1alpha1.InSpaceClusterStatus{}, fmt.Errorf("decode cluster status readback: %w", err)
		}
		if !reflect.DeepEqual(readback.Status, desired) {
			return v1alpha1.InSpaceClusterStatus{}, errors.New("cluster status readback differs from persisted CAS value")
		}
		return readback.Status, nil
	}
}

// sameEncodedValue compares the persisted meaning of two config values. The
// file is rewritten with omitempty after every CAS, so an explicit empty list
// or map ("disable: []", "labels: {}") read at startup and the omitted field
// read back later are the same configuration; reflect.DeepEqual would treat
// the empty non-nil and nil forms as a spec change. Every other difference,
// including element order, still fails the comparison.
func sameEncodedValue(left, right any) bool {
	leftData, leftErr := json.Marshal(left)
	rightData, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func acquireStatusFileLock(ctx context.Context, path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cluster status lock: %w", err)
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock cluster status: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lock.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

package inspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	mutationFenceManagedLabel          = "storage.inspace.cloud/mutation-fence"
	mutationFenceKeyAnnotation         = "storage.inspace.cloud/fence-key"
	mutationFenceIntentAnnotation      = "storage.inspace.cloud/fence-intent"
	mutationFenceAttemptAnnotation     = "storage.inspace.cloud/fence-attempt"
	mutationFenceReceiptAnnotation     = "storage.inspace.cloud/fence-receipt"
	mutationFenceObservationAnnotation = "storage.inspace.cloud/fence-observation"
)

type kubernetesLease struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Metadata   struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace,omitempty"`
		UID             string            `json:"uid,omitempty"`
		ResourceVersion string            `json:"resourceVersion,omitempty"`
		Labels          map[string]string `json:"labels,omitempty"`
		Annotations     map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Spec struct {
		HolderIdentity       string `json:"holderIdentity,omitempty"`
		LeaseDurationSeconds int32  `json:"leaseDurationSeconds,omitempty"`
	} `json:"spec,omitempty"`
}

type kubernetesLeaseList struct {
	Items []kubernetesLease `json:"items"`
}

func mutationFenceLeaseName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "inspace-csi-" + hex.EncodeToString(sum[:20])
}

func (r *KubernetesNodeResolver) Get(ctx context.Context, key string) (*mutationFence, error) {
	if key == "" {
		return nil, errors.New("CSI mutation fence key is required")
	}
	lease, status, err := r.getMutationLease(ctx, mutationFenceLeaseName(key))
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, kubernetesFenceStatusError("get", status)
	}
	fence, err := mutationFenceFromLease(lease)
	if err != nil {
		return nil, err
	}
	if fence.Key != key {
		return nil, errors.New("CSI mutation Lease hash collision or foreign fence identity")
	}
	return &fence, nil
}

func (r *KubernetesNodeResolver) List(ctx context.Context, prefix string) ([]mutationFence, error) {
	query := url.Values{"labelSelector": {mutationFenceManagedLabel + "=true"}}
	status, data, err := r.mutationLeaseRequest(ctx, http.MethodGet, r.mutationLeaseCollectionPath()+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, kubernetesFenceStatusError("list", status)
	}
	var list kubernetesLeaseList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%w: decode Kubernetes mutation Lease list: %v", cloud.ErrUnavailable, err)
	}
	result := make([]mutationFence, 0, len(list.Items))
	seen := make(map[string]struct{}, len(list.Items))
	for _, lease := range list.Items {
		fence, err := mutationFenceFromLease(lease)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[fence.Key]; duplicate {
			return nil, fmt.Errorf("CSI mutation Lease list contains duplicate key %q", fence.Key)
		}
		seen[fence.Key] = struct{}{}
		if strings.HasPrefix(fence.Key, prefix) {
			result = append(result, fence)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func (r *KubernetesNodeResolver) Create(ctx context.Context, candidate mutationFence) (*mutationFence, bool, error) {
	if err := validateMutationFence(candidate); err != nil {
		return nil, false, err
	}
	lease := mutationFenceLease(candidate, r.namespace)
	status, data, requestErr := r.mutationLeaseRequest(ctx, http.MethodPost, r.mutationLeaseCollectionPath(), lease)
	if requestErr == nil && status >= 200 && status < 300 {
		stored, err := decodeMutationLease(data)
		if err != nil {
			return nil, false, err
		}
		fence, err := mutationFenceFromLease(stored)
		if err != nil {
			return nil, false, err
		}
		if fence != candidate {
			return nil, false, errors.New("Kubernetes API changed the CSI mutation fence during creation")
		}
		return &fence, true, nil
	}
	if requestErr == nil && status != http.StatusConflict && !ambiguousKubernetesMutationStatus(status) {
		return nil, false, kubernetesFenceStatusError("create", status)
	}

	// A Lease POST is itself safe to recover by exact object name and random
	// attempt token. This readback never authorizes a cloud POST unless it proves
	// that this caller's exact candidate won the Kubernetes create race.
	readbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	current, getErr := r.Get(readbackCtx, candidate.Key)
	if getErr != nil {
		return nil, false, errors.Join(requestErr, kubernetesFenceStatusError("create", status), getErr)
	}
	if current == nil {
		return nil, false, errors.Join(requestErr, kubernetesFenceStatusError("create", status), errors.New("CSI mutation Lease create outcome is not visible"))
	}
	if current.Intent == candidate.Intent && current.Attempt == candidate.Attempt && current.Receipt == candidate.Receipt {
		return current, true, nil
	}
	return current, false, nil
}

func (r *KubernetesNodeResolver) SetReceipt(ctx context.Context, fence mutationFence, receipt string) (*mutationFence, error) {
	if err := validateMutationFence(fence); err != nil {
		return nil, err
	}
	if !uuidPattern.MatchString(strings.ToLower(receipt)) {
		return nil, errors.New("CSI mutation receipt is not a valid UUID")
	}
	name := mutationFenceLeaseName(fence.Key)
	lease, status, err := r.getMutationLease(ctx, name)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, errors.New("CSI mutation Lease disappeared before receipt persistence")
	}
	if status < 200 || status >= 300 {
		return nil, kubernetesFenceStatusError("get before receipt update", status)
	}
	current, err := mutationFenceFromLease(lease)
	if err != nil {
		return nil, err
	}
	if !sameMutationFenceState(current, fence) {
		return nil, errors.New("CSI mutation Lease changed before receipt persistence")
	}
	if current.Receipt != "" {
		if strings.EqualFold(current.Receipt, receipt) {
			return &current, nil
		}
	}
	lease.Metadata.Annotations[mutationFenceReceiptAnnotation] = strings.ToLower(receipt)
	status, data, requestErr := r.mutationLeaseRequest(ctx, http.MethodPut, r.mutationLeasePath(name), lease)
	if requestErr == nil && status >= 200 && status < 300 {
		storedLease, err := decodeMutationLease(data)
		if err != nil {
			return nil, err
		}
		stored, err := mutationFenceFromLease(storedLease)
		if err != nil {
			return nil, err
		}
		if stored.Key != fence.Key || stored.Intent != fence.Intent || stored.Attempt != fence.Attempt ||
			stored.Observation != fence.Observation || !strings.EqualFold(stored.Receipt, receipt) {
			return nil, errors.New("Kubernetes API returned a mismatched CSI mutation receipt")
		}
		return &stored, nil
	}
	if requestErr == nil && !ambiguousKubernetesMutationStatus(status) && status != http.StatusConflict {
		return nil, kubernetesFenceStatusError("persist receipt", status)
	}
	readbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	readback, getErr := r.Get(readbackCtx, fence.Key)
	if getErr == nil && readback != nil && readback.Intent == fence.Intent && readback.Attempt == fence.Attempt &&
		readback.Observation == fence.Observation && strings.EqualFold(readback.Receipt, receipt) {
		return readback, nil
	}
	return nil, errors.Join(requestErr, kubernetesFenceStatusError("persist receipt", status), getErr)
}

func (r *KubernetesNodeResolver) SetObservation(ctx context.Context, fence mutationFence, observation string) (*mutationFence, error) {
	if err := validateMutationFence(fence); err != nil {
		return nil, err
	}
	if observation != "" {
		if _, err := decodeMutationObservation(observation); err != nil {
			return nil, err
		}
	}
	name := mutationFenceLeaseName(fence.Key)
	lease, status, err := r.getMutationLease(ctx, name)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("%w: CSI mutation Lease disappeared before observation persistence", errMutationFenceChanged)
	}
	if status < 200 || status >= 300 {
		return nil, kubernetesFenceStatusError("get before observation update", status)
	}
	current, err := mutationFenceFromLease(lease)
	if err != nil {
		return nil, err
	}
	if current.Observation == observation && sameMutationFenceAuthority(current, fence) {
		return &current, nil
	}
	if !sameMutationFenceState(current, fence) {
		return nil, fmt.Errorf("%w before observation persistence", errMutationFenceChanged)
	}
	if observation == "" {
		delete(lease.Metadata.Annotations, mutationFenceObservationAnnotation)
	} else {
		lease.Metadata.Annotations[mutationFenceObservationAnnotation] = observation
	}
	status, data, requestErr := r.mutationLeaseRequest(ctx, http.MethodPut, r.mutationLeasePath(name), lease)
	if requestErr == nil && status >= 200 && status < 300 {
		storedLease, err := decodeMutationLease(data)
		if err != nil {
			return nil, err
		}
		stored, err := mutationFenceFromLease(storedLease)
		if err != nil {
			return nil, err
		}
		if !sameMutationFenceAuthority(stored, fence) || stored.Observation != observation {
			return nil, errors.New("Kubernetes API returned a mismatched CSI mutation observation")
		}
		return &stored, nil
	}
	if requestErr == nil && !ambiguousKubernetesMutationStatus(status) && status != http.StatusConflict {
		return nil, kubernetesFenceStatusError("persist observation", status)
	}
	readbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	readback, getErr := r.Get(readbackCtx, fence.Key)
	if getErr == nil && readback != nil {
		if sameMutationFenceAuthority(*readback, fence) && readback.Observation == observation {
			return readback, nil
		}
		if sameMutationFenceAuthority(*readback, fence) {
			return nil, fmt.Errorf("%w during observation persistence", errMutationFenceChanged)
		}
	}
	return nil, errors.Join(requestErr, kubernetesFenceStatusError("persist observation", status), getErr)
}

func (r *KubernetesNodeResolver) Delete(ctx context.Context, fence mutationFence) error {
	if err := validateMutationFence(fence); err != nil {
		return err
	}
	name := mutationFenceLeaseName(fence.Key)
	lease, status, err := r.getMutationLease(ctx, name)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return kubernetesFenceStatusError("get before completion", status)
	}
	current, err := mutationFenceFromLease(lease)
	if err != nil {
		return err
	}
	if !sameMutationFenceState(current, fence) {
		return errors.New("CSI mutation Lease changed before completion")
	}
	request := struct {
		APIVersion    string `json:"apiVersion"`
		Kind          string `json:"kind"`
		Preconditions struct {
			UID             string `json:"uid,omitempty"`
			ResourceVersion string `json:"resourceVersion,omitempty"`
		} `json:"preconditions"`
	}{APIVersion: "v1", Kind: "DeleteOptions"}
	request.Preconditions.UID = lease.Metadata.UID
	request.Preconditions.ResourceVersion = lease.Metadata.ResourceVersion
	deleteStatus, _, deleteErr := r.mutationLeaseRequest(ctx, http.MethodDelete, r.mutationLeasePath(name), request)
	if deleteErr == nil && deleteStatus != http.StatusNotFound && (deleteStatus < 200 || deleteStatus >= 300) && !ambiguousKubernetesMutationStatus(deleteStatus) {
		return kubernetesFenceStatusError("complete", deleteStatus)
	}
	readbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	remaining, getErr := r.Get(readbackCtx, fence.Key)
	if getErr == nil && remaining == nil {
		return nil
	}
	return errors.Join(deleteErr, kubernetesFenceStatusError("complete", deleteStatus), getErr, errors.New("CSI mutation Lease completion is not yet visible"))
}

func mutationFenceLease(fence mutationFence, namespace string) kubernetesLease {
	lease := kubernetesLease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}
	lease.Metadata.Name = mutationFenceLeaseName(fence.Key)
	lease.Metadata.Namespace = namespace
	lease.Metadata.Labels = map[string]string{mutationFenceManagedLabel: "true"}
	lease.Metadata.Annotations = map[string]string{
		mutationFenceKeyAnnotation:     fence.Key,
		mutationFenceIntentAnnotation:  fence.Intent,
		mutationFenceAttemptAnnotation: fence.Attempt,
	}
	if fence.Receipt != "" {
		lease.Metadata.Annotations[mutationFenceReceiptAnnotation] = fence.Receipt
	}
	if fence.Observation != "" {
		lease.Metadata.Annotations[mutationFenceObservationAnnotation] = fence.Observation
	}
	lease.Spec.HolderIdentity = fence.Attempt
	lease.Spec.LeaseDurationSeconds = 0
	return lease
}

func mutationFenceFromLease(lease kubernetesLease) (mutationFence, error) {
	if lease.Metadata.Labels[mutationFenceManagedLabel] != "true" {
		return mutationFence{}, errors.New("refusing foreign Kubernetes Lease at CSI mutation fence name")
	}
	fence := mutationFence{
		Key:         lease.Metadata.Annotations[mutationFenceKeyAnnotation],
		Intent:      lease.Metadata.Annotations[mutationFenceIntentAnnotation],
		Attempt:     lease.Metadata.Annotations[mutationFenceAttemptAnnotation],
		Receipt:     strings.ToLower(lease.Metadata.Annotations[mutationFenceReceiptAnnotation]),
		Observation: lease.Metadata.Annotations[mutationFenceObservationAnnotation],
	}
	if err := validateMutationFence(fence); err != nil {
		return mutationFence{}, err
	}
	if lease.Spec.HolderIdentity != "" && lease.Spec.HolderIdentity != fence.Attempt {
		return mutationFence{}, errors.New("CSI mutation Lease holder identity does not match its attempt token")
	}
	return fence, nil
}

func validateMutationFence(fence mutationFence) error {
	if fence.Key == "" || fence.Intent == "" || fence.Attempt == "" {
		return errors.New("CSI mutation fence is incomplete")
	}
	if len(fence.Attempt) != 32 {
		return errors.New("CSI mutation fence attempt token is invalid")
	}
	if _, err := hex.DecodeString(fence.Attempt); err != nil {
		return errors.New("CSI mutation fence attempt token is invalid")
	}
	if fence.Receipt != "" && !uuidPattern.MatchString(strings.ToLower(fence.Receipt)) {
		return errors.New("CSI mutation fence receipt is invalid")
	}
	if fence.Observation != "" {
		if _, err := decodeMutationObservation(fence.Observation); err != nil {
			return err
		}
	}
	return nil
}

func decodeMutationLease(data []byte) (kubernetesLease, error) {
	var lease kubernetesLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return kubernetesLease{}, fmt.Errorf("%w: decode Kubernetes mutation Lease: %v", cloud.ErrUnavailable, err)
	}
	return lease, nil
}

func (r *KubernetesNodeResolver) getMutationLease(ctx context.Context, name string) (kubernetesLease, int, error) {
	status, data, err := r.mutationLeaseRequest(ctx, http.MethodGet, r.mutationLeasePath(name), nil)
	if err != nil {
		return kubernetesLease{}, 0, err
	}
	if status == http.StatusNotFound {
		return kubernetesLease{}, status, nil
	}
	if status < 200 || status >= 300 {
		return kubernetesLease{}, status, nil
	}
	lease, err := decodeMutationLease(data)
	return lease, status, err
}

func (r *KubernetesNodeResolver) mutationLeaseCollectionPath() string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(r.namespace) + "/leases"
}

func (r *KubernetesNodeResolver) mutationLeasePath(name string) string {
	return r.mutationLeaseCollectionPath() + "/" + url.PathEscape(name)
}

func (r *KubernetesNodeResolver) mutationLeaseRequest(ctx context.Context, method, path string, body any) (int, []byte, error) {
	token, err := os.ReadFile(r.tokenPath)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: read Kubernetes ServiceAccount token: %v", cloud.ErrUnavailable, err)
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	u := *r.baseURL
	requestURI, err := url.ParseRequestURI(path)
	if err != nil {
		return 0, nil, fmt.Errorf("build Kubernetes mutation Lease URL: %w", err)
	}
	u.Path = strings.TrimRight(r.baseURL.Path, "/") + requestURI.Path
	u.RawQuery = requestURI.RawQuery
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: Kubernetes mutation Lease request: %v", cloud.ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%w: read Kubernetes mutation Lease response: %v", cloud.ErrUnavailable, err)
	}
	return resp.StatusCode, data, nil
}

func ambiguousKubernetesMutationStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 || status == 0
}

func kubernetesFenceStatusError(operation string, status int) error {
	if status == 0 || status == http.StatusNotFound || status >= 200 && status < 300 {
		return nil
	}
	if ambiguousKubernetesMutationStatus(status) {
		return fmt.Errorf("%w: Kubernetes mutation Lease %s returned HTTP %d", cloud.ErrUnavailable, operation, status)
	}
	return fmt.Errorf("Kubernetes mutation Lease %s returned HTTP %d", operation, status)
}

var _ mutationFenceStore = (*KubernetesNodeResolver)(nil)

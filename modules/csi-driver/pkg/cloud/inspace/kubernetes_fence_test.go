package inspace

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mutationLeaseAPIServer struct {
	mu                        sync.Mutex
	lease                     *kubernetesLease
	commitFirstCreate500      bool
	commitFirstObservation500 bool
}

func (s *mutationLeaseAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	const collection = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == collection:
		if s.lease != nil {
			http.Error(w, "already exists", http.StatusConflict)
			return
		}
		var lease kubernetesLease
		if err := json.NewDecoder(r.Body).Decode(&lease); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lease.Metadata.UID = "lease-uid"
		lease.Metadata.ResourceVersion = "1"
		s.lease = &lease
		if s.commitFirstCreate500 {
			s.commitFirstCreate500 = false
			http.Error(w, "response lost after commit", http.StatusInternalServerError)
			return
		}
		writeLeaseJSON(w, http.StatusCreated, lease)
	case r.Method == http.MethodGet && r.URL.Path == collection:
		list := kubernetesLeaseList{}
		if s.lease != nil {
			list.Items = []kubernetesLease{*s.lease}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case r.Method == http.MethodGet && r.URL.Path != collection:
		if s.lease == nil || r.URL.Path != collection+"/"+s.lease.Metadata.Name {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeLeaseJSON(w, http.StatusOK, *s.lease)
	case r.Method == http.MethodPut && s.lease != nil && r.URL.Path == collection+"/"+s.lease.Metadata.Name:
		var lease kubernetesLease
		if err := json.NewDecoder(r.Body).Decode(&lease); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if lease.Metadata.ResourceVersion != s.lease.Metadata.ResourceVersion {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		lease.Metadata.UID = s.lease.Metadata.UID
		lease.Metadata.ResourceVersion = "2"
		s.lease = &lease
		if s.commitFirstObservation500 && lease.Metadata.Annotations[mutationFenceObservationAnnotation] != "" {
			s.commitFirstObservation500 = false
			http.Error(w, "observation response lost after commit", http.StatusInternalServerError)
			return
		}
		writeLeaseJSON(w, http.StatusOK, lease)
	case r.Method == http.MethodDelete && s.lease != nil && r.URL.Path == collection+"/"+s.lease.Metadata.Name:
		s.lease = nil
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func writeLeaseJSON(w http.ResponseWriter, status int, lease kubernetesLease) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(lease)
}

func TestKubernetesMutationFenceRecoversCommittedHTTP500AndPersistsReceipt(t *testing.T) {
	api := &mutationLeaseAPIServer{commitFirstCreate500: true}
	server := httptest.NewTLSServer(api)
	defer server.Close()
	temp := t.TempDir()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(temp, "ca.crt")
	tokenFile := filepath.Join(temp, "token")
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewKubernetesNodeResolver(KubernetesResolverConfig{
		BaseURL: server.URL, CAFile: caFile, TokenFile: tokenFile,
		Namespace: "kube-system", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	intent := diskCreateIntent{
		Operation: "create-disk", Location: testLocation, Name: "pvc-durable",
		SizeGiB: 1, BillingAccountID: 42,
	}
	fence, err := newMutationFence(diskCreateFenceKey(intent.Location, intent.Name), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := resolver.Create(context.Background(), fence)
	if err != nil || !acquired || stored == nil || stored.Attempt != fence.Attempt {
		t.Fatalf("committed HTTP 500 Lease create: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	stored, err = resolver.SetReceipt(context.Background(), *stored, testDiskID)
	if err != nil || stored.Receipt != testDiskID {
		t.Fatalf("persist receipt: stored=%#v err=%v", stored, err)
	}
	if fences, err := resolver.List(context.Background(), "disk-create/"); err != nil || len(fences) != 1 || fences[0].Receipt != testDiskID {
		t.Fatalf("listed durable fences = %#v, err=%v", fences, err)
	}

	competitor, err := newMutationFence(fence.Key, intent)
	if err != nil {
		t.Fatal(err)
	}
	winner, competitorAcquired, err := resolver.Create(context.Background(), competitor)
	if err != nil || competitorAcquired || winner == nil || winner.Attempt != fence.Attempt || winner.Receipt != testDiskID {
		t.Fatalf("competing Lease create: winner=%#v acquired=%t err=%v", winner, competitorAcquired, err)
	}
	if err := resolver.Delete(context.Background(), competitor); err == nil {
		t.Fatal("competitor deleted another attempt's durable fence")
	}
	if err := resolver.Delete(context.Background(), *stored); err != nil {
		t.Fatal(err)
	}
	if remaining, err := resolver.Get(context.Background(), fence.Key); err != nil || remaining != nil {
		t.Fatalf("completed Lease = %#v, err=%v", remaining, err)
	}
}

func TestKubernetesMutationFenceObservationUsesCompareAndSwap(t *testing.T) {
	api := &mutationLeaseAPIServer{commitFirstObservation500: true}
	resolver, cleanup := newTestMutationLeaseResolver(t, api)
	defer cleanup()
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: testLocation,
		DiskUUID: testDiskID, BillingAccountID: 42, PreviousVMUUID: testVM1,
	}
	fence, err := newMutationFence(diskAttachmentFenceKey(intent.Location, intent.DiskUUID), intent)
	if err != nil {
		t.Fatal(err)
	}
	stored, acquired, err := resolver.Create(context.Background(), fence)
	if err != nil || !acquired || stored == nil {
		t.Fatalf("create detach fence: stored=%#v acquired=%t err=%v", stored, acquired, err)
	}
	firstTime := time.Now().UTC().Add(-time.Second)
	first, err := encodeMutationObservation(mutationObservation{
		Kind: detachAbsenceObservationKind, Count: 1, FirstObservedAt: firstTime.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	withFirst, err := resolver.SetObservation(context.Background(), *stored, first)
	if err != nil || withFirst == nil || withFirst.Observation != first {
		t.Fatalf("persist first observation: stored=%#v err=%v", withFirst, err)
	}
	second, err := encodeMutationObservation(mutationObservation{
		Kind: detachAbsenceObservationKind, Count: 2,
		FirstObservedAt: firstTime.Format(time.RFC3339Nano), LastObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.SetObservation(context.Background(), *stored, second); !errors.Is(err, errMutationFenceChanged) {
		t.Fatalf("stale observation CAS error = %v, want errMutationFenceChanged", err)
	}
	current, err := resolver.Get(context.Background(), fence.Key)
	if err != nil || current == nil || current.Observation != first {
		t.Fatalf("stale CAS changed observation: current=%#v err=%v", current, err)
	}
	withSecond, err := resolver.SetObservation(context.Background(), *withFirst, second)
	if err != nil || withSecond == nil || withSecond.Observation != second {
		t.Fatalf("persist second observation: stored=%#v err=%v", withSecond, err)
	}
	if err := resolver.Delete(context.Background(), *withFirst); err == nil {
		t.Fatal("stale first observation completed a second-observation Lease")
	}
	if err := resolver.Delete(context.Background(), *withSecond); err != nil {
		t.Fatal(err)
	}
}

func TestMutationFenceObservationDecodingIsBackwardCompatibleAndFailClosed(t *testing.T) {
	intent := diskAttachmentIntent{
		Operation: "disk-attachment", Location: testLocation,
		DiskUUID: testDiskID, BillingAccountID: 42, PreviousVMUUID: testVM1,
	}
	fence, err := newMutationFence(diskAttachmentFenceKey(intent.Location, intent.DiskUUID), intent)
	if err != nil {
		t.Fatal(err)
	}
	legacy := mutationFenceLease(fence, "kube-system")
	decoded, err := mutationFenceFromLease(legacy)
	if err != nil || decoded != fence || decoded.Observation != "" {
		t.Fatalf("legacy annotation-less Lease decoded=%#v err=%v", decoded, err)
	}

	legacy.Metadata.Annotations[mutationFenceObservationAnnotation] = `{"kind":"disk-detach-absence","count":2,"firstObservedAt":"2026-07-17T00:00:00Z"}`
	if _, err := mutationFenceFromLease(legacy); err == nil || !strings.Contains(err.Error(), "last-observation timestamp") {
		t.Fatalf("malformed observation decode error = %v", err)
	}
}

func newTestMutationLeaseResolver(t *testing.T, api *mutationLeaseAPIServer) (*KubernetesNodeResolver, func()) {
	t.Helper()
	server := httptest.NewTLSServer(api)
	temp := t.TempDir()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(temp, "ca.crt")
	tokenFile := filepath.Join(temp, "token")
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	resolver, err := NewKubernetesNodeResolver(KubernetesResolverConfig{
		BaseURL: server.URL, CAFile: caFile, TokenFile: tokenFile,
		Namespace: "kube-system", Timeout: time.Second,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return resolver, server.Close
}

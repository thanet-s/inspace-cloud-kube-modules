package inspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	authorityNodeName  = "cluster-a-karp-general-abcde"
	authorityClaimName = "general-abcde"
	authorityClaimUID  = "55555555-5555-4555-8555-555555555555"
)

type missingNodeAuthorityAPIServer struct {
	exactNodeBody []byte
	claimBody     []byte
	claimListBody []byte
	nodeListBody  []byte
	calls         map[string]int
}

func (s *missingNodeAuthorityAPIServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	key := request.URL.Path
	if request.URL.RawQuery != "" {
		key += "?" + request.URL.RawQuery
	}
	s.calls[key]++
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/nodes/"+authorityNodeName:
		if s.exactNodeBody == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeMissingNodeAuthorityJSON(w, s.exactNodeBody)
	case request.Method == http.MethodGet && request.URL.Path == "/apis/karpenter.sh/v1/nodeclaims/"+authorityClaimName:
		writeMissingNodeAuthorityJSON(w, s.claimBody)
	case request.Method == http.MethodGet && request.URL.Path == "/apis/karpenter.sh/v1/nodeclaims":
		if request.URL.Query().Get("limit") != fmt.Sprint(missingNodeClaimAuthorityPageSize) {
			http.Error(w, "missing bounded limit", http.StatusBadRequest)
			return
		}
		writeMissingNodeAuthorityJSON(w, s.claimListBody)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/nodes":
		if request.URL.Query().Get("limit") != fmt.Sprint(missingNodeAuthorityNodePageSize) {
			http.Error(w, "missing bounded limit", http.StatusBadRequest)
			return
		}
		writeMissingNodeAuthorityJSON(w, s.nodeListBody)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func writeMissingNodeAuthorityJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type missingNodeAuthorityFixture struct {
	request   missingNodeDetachRequest
	ownership missingNodeOwnershipRecord
	fence     missingNodeCreateFence
	claim     missingNodeClaim
	claims    []missingNodeClaim
	nodes     []missingNodeKubernetesNode
}

func newMissingNodeAuthorityFixture(t *testing.T) missingNodeAuthorityFixture {
	t.Helper()
	uidHash := sha256.Sum256([]byte(authorityClaimUID))
	fullUIDHash := hex.EncodeToString(uidHash[:])
	ownership := missingNodeOwnershipRecord{
		Schema: inspaceOwnershipV3, Cluster: "cluster-a", NodeClaim: authorityClaimName,
		VMName: authorityNodeName, KeyHash: fullUIDHash[:32],
		HostClass: "amd-epyc", InstanceType: "general-2c-4g",
		HostPoolUUID: testVM2,
		VCPU:         2, MemoryGiB: 4, RootDiskGiB: 100,
		SpecHash: strings.Repeat("b", 32), BootstrapHash: strings.Repeat("c", 32),
		FirewallUUID: testVM2, FirewallProfile: "private-worker",
		NetworkUUID: testNetwork, ControlPlaneVIP: "10.91.72.10",
		PrivateLoadBalancerPoolStart: "10.91.72.128",
		PrivateLoadBalancerPoolStop:  "10.91.72.191",
		OSName:                       "ubuntu", OSVersion: "24.04",
		BillingAccountID: 42, FloatingIPName: "karpenter-general-abcde-a1b2c3d4",
	}
	description, err := json.Marshal(ownership)
	if err != nil {
		t.Fatal(err)
	}
	request := missingNodeDetachRequest{
		NodeName: authorityNodeName, Location: testLocation,
		VMUUID: testVM1, VMName: authorityNodeName, VMHostname: authorityNodeName,
		VMDescription: string(description), DiskUUID: testDiskID,
		NetworkUUID: testNetwork, BillingAccountID: 42,
	}
	now := "2026-07-18T12:00:00Z"
	fence := missingNodeCreateFence{
		Schema: inspaceCreateFenceV3,
		Binding: missingNodeCreateFenceBinding{
			NodeClaimUID: authorityClaimUID, IdempotencyKeyHash: fullUIDHash,
			RequestHash: strings.Repeat("d", 64),
			SpecHash:    ownership.SpecHash, BootstrapHash: ownership.BootstrapHash,
		},
		Cleanup: missingNodeCleanupIdentity{
			ClusterName: ownership.Cluster, Location: testLocation, NetworkUUID: testNetwork,
			NodePoolName: ownership.NodePool, ControlPlaneVIP: ownership.ControlPlaneVIP,
			PrivateLoadBalancerPoolStart: ownership.PrivateLoadBalancerPoolStart,
			PrivateLoadBalancerPoolStop:  ownership.PrivateLoadBalancerPoolStop,
			FirewallUUID:                 ownership.FirewallUUID, FirewallProfile: ownership.FirewallProfile,
			NodeClaimName: authorityClaimName, VMName: authorityNodeName,
			BillingAccountID: 42, OwnershipKeyHash: ownership.KeyHash,
		},
		Token: strings.Repeat("e", 32), Phase: inspaceCreateFenceMaterialized,
		Intent: "post", IssueID: strings.Repeat("f", 32),
		StartedAt: now, IssuedAt: stringPointer(now), LaunchObservedAt: stringPointer(now),
		CreatedVMUUID: testVM1, ObservedAt: stringPointer(now), ObservedVMUUID: testVM1,
		FloatingIPName: ownership.FloatingIPName, PublicIPv4: "103.117.150.45",
		BaseFirewallAssignment: &missingNodeFirewallAssignment{
			VMUUID: testVM1, FirewallUUID: ownership.FirewallUUID,
			Phase: inspaceFirewallAssignmentObserved, IssueID: strings.Repeat("1", 32),
			IntentAt: now, IssuedAt: stringPointer(now), ObservedAt: stringPointer(now),
		},
	}
	encodedFence, err := json.Marshal(fence)
	if err != nil {
		t.Fatal(err)
	}
	claim := missingNodeClaim{
		APIVersion: karpenterNodeClaimAPIVersion,
		Kind:       karpenterNodeClaimKind,
		Metadata: missingNodeObjectMeta{
			Name: authorityClaimName, UID: authorityClaimUID, ResourceVersion: "101",
			DeletionTimestamp: "2026-07-18T12:30:00Z",
			Finalizers:        []string{karpenterTerminationFinalizer, inspaceCreateProtectionFinalizer},
			Annotations: map[string]string{
				inspaceNodeNameAnnotation:    authorityNodeName,
				inspaceCreateFenceAnnotation: string(encodedFence),
			},
		},
		Status: missingNodeClaimStatus{
			NodeName:   authorityNodeName,
			ProviderID: "inspace://" + testLocation + "/" + testVM1,
			Conditions: []missingNodeCondition{{Type: karpenterRegisteredCondition, Status: "True"}},
		},
	}
	return missingNodeAuthorityFixture{
		request: request, ownership: ownership, fence: fence, claim: claim,
		claims: []missingNodeClaim{claim},
	}
}

func (f *missingNodeAuthorityFixture) render(t *testing.T) *missingNodeAuthorityAPIServer {
	t.Helper()
	description, err := json.Marshal(f.ownership)
	if err != nil {
		t.Fatal(err)
	}
	f.request.VMDescription = string(description)
	encodedFence, err := json.Marshal(f.fence)
	if err != nil {
		t.Fatal(err)
	}
	if f.claim.Metadata.Annotations == nil {
		f.claim.Metadata.Annotations = map[string]string{}
	}
	f.claim.Metadata.Annotations[inspaceCreateFenceAnnotation] = string(encodedFence)
	for index := range f.claims {
		if f.claims[index].Metadata.Name == f.claim.Metadata.Name &&
			f.claims[index].Metadata.UID == f.claim.Metadata.UID {
			f.claims[index] = f.claim
		}
	}
	claimBody, err := json.Marshal(f.claim)
	if err != nil {
		t.Fatal(err)
	}
	claimListBody, err := json.Marshal(missingNodeClaimList{
		APIVersion: karpenterNodeClaimAPIVersion, Kind: karpenterNodeClaimListKind,
		Metadata: missingNodeListMeta{ResourceVersion: "201"}, Items: f.claims,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeListBody, err := json.Marshal(missingNodeKubernetesNodeList{
		APIVersion: "v1", Kind: "NodeList",
		Metadata: missingNodeListMeta{ResourceVersion: "301"}, Items: f.nodes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &missingNodeAuthorityAPIServer{
		claimBody: claimBody, claimListBody: claimListBody, nodeListBody: nodeListBody,
	}
}

func newMissingNodeAuthorityResolver(
	t *testing.T,
	api http.Handler,
) (*KubernetesNodeResolver, func()) {
	t.Helper()
	server := httptest.NewTLSServer(api)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return &KubernetesNodeResolver{
		baseURL: baseURL, client: server.Client(), tokenPath: tokenFile, namespace: "kube-system",
	}, server.Close
}

func TestKubernetesMissingNodeDetachAuthorityAcceptsExactDeletingClaim(t *testing.T) {
	fixture := newMissingNodeAuthorityFixture(t)
	api := fixture.render(t)
	resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
	defer closeServer()

	if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if got := api.calls["/api/v1/nodes/"+authorityNodeName]; got != 2 {
		t.Fatalf("exact Node absence GET calls = %d, want 2", got)
	}
	if got := api.calls["/apis/karpenter.sh/v1/nodeclaims/"+authorityClaimName]; got != 2 {
		t.Fatalf("exact NodeClaim GET calls = %d, want 2", got)
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsBetweenReadRaces(t *testing.T) {
	t.Run("Node reappears before final proof", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		api := fixture.render(t)
		nodeGets := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet &&
				request.URL.Path == "/api/v1/nodes/"+authorityNodeName {
				nodeGets++
				if nodeGets == 2 {
					writeMissingNodeAuthorityJSON(
						w,
						[]byte(`{"spec":{"providerID":"inspace://bkk01/22222222-2222-4222-8222-222222222222"}}`),
					)
					return
				}
			}
			api.ServeHTTP(w, request)
		})
		resolver, closeServer := newMissingNodeAuthorityResolver(t, handler)
		defer closeServer()

		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
		if nodeGets != 2 {
			t.Fatalf("exact Node GET calls = %d, want 2", nodeGets)
		}
	})

	t.Run("NodeClaim stops deleting before final proof", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		api := fixture.render(t)
		claimGets := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet &&
				request.URL.Path == "/apis/karpenter.sh/v1/nodeclaims/"+authorityClaimName {
				claimGets++
				if claimGets == 2 {
					changed := fixture.claim
					changed.Metadata.DeletionTimestamp = ""
					body, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					writeMissingNodeAuthorityJSON(w, body)
					return
				}
			}
			api.ServeHTTP(w, request)
		})
		resolver, closeServer := newMissingNodeAuthorityResolver(t, handler)
		defer closeServer()

		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
		if claimGets != 2 {
			t.Fatalf("exact NodeClaim GET calls = %d, want 2", claimGets)
		}
	})
}

func TestKubernetesMissingNodeDetachAuthorityPaginatesBoundedInventories(t *testing.T) {
	fixture := newMissingNodeAuthorityFixture(t)
	api := fixture.render(t)
	firstPage, err := json.Marshal(missingNodeClaimList{
		APIVersion: karpenterNodeClaimAPIVersion,
		Kind:       karpenterNodeClaimListKind,
		Metadata: missingNodeListMeta{
			ResourceVersion: "201",
			Continue:        "next-page",
		},
		Items: []missingNodeClaim{},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondPage, err := json.Marshal(missingNodeClaimList{
		APIVersion: karpenterNodeClaimAPIVersion,
		Kind:       karpenterNodeClaimListKind,
		Metadata:   missingNodeListMeta{ResourceVersion: "201"},
		Items:      []missingNodeClaim{fixture.claim},
	})
	if err != nil {
		t.Fatal(err)
	}
	listCalls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet &&
			request.URL.Path == "/apis/karpenter.sh/v1/nodeclaims" {
			listCalls++
			if request.URL.Query().Get("limit") != fmt.Sprint(missingNodeClaimAuthorityPageSize) {
				http.Error(w, "wrong page limit", http.StatusBadRequest)
				return
			}
			switch request.URL.Query().Get("continue") {
			case "":
				writeMissingNodeAuthorityJSON(w, firstPage)
			case "next-page":
				writeMissingNodeAuthorityJSON(w, secondPage)
			default:
				http.Error(w, "unexpected continuation token", http.StatusBadRequest)
			}
			return
		}
		api.ServeHTTP(w, request)
	})
	resolver, closeServer := newMissingNodeAuthorityResolver(t, handler)
	defer closeServer()

	if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	if listCalls != 2 {
		t.Fatalf("NodeClaim LIST calls = %d, want 2", listCalls)
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsPaginationDrift(t *testing.T) {
	fixture := newMissingNodeAuthorityFixture(t)
	api := fixture.render(t)
	firstPage, err := json.Marshal(missingNodeClaimList{
		APIVersion: karpenterNodeClaimAPIVersion,
		Kind:       karpenterNodeClaimListKind,
		Metadata: missingNodeListMeta{
			ResourceVersion: "201",
			Continue:        "next-page",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondPage, err := json.Marshal(missingNodeClaimList{
		APIVersion: karpenterNodeClaimAPIVersion,
		Kind:       karpenterNodeClaimListKind,
		Metadata:   missingNodeListMeta{ResourceVersion: "202"},
		Items:      []missingNodeClaim{fixture.claim},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet &&
			request.URL.Path == "/apis/karpenter.sh/v1/nodeclaims" {
			if request.URL.Query().Get("continue") == "" {
				writeMissingNodeAuthorityJSON(w, firstPage)
			} else {
				writeMissingNodeAuthorityJSON(w, secondPage)
			}
			return
		}
		api.ServeHTTP(w, request)
	})
	resolver, closeServer := newMissingNodeAuthorityResolver(t, handler)
	defer closeServer()

	if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

func TestKubernetesMissingNodeDetachAuthorityAllowsBoundedLargeInventoryPage(t *testing.T) {
	fixture := newMissingNodeAuthorityFixture(t)
	api := fixture.render(t)
	paddingSize := maxKubernetesAPIResponseBytes + 1024
	body := strings.TrimSuffix(string(api.claimListBody), "}") +
		`,"padding":"` + strings.Repeat("x", paddingSize) + `"}`
	if int64(len(body)) >= maxMissingNodeAuthorityResponseBytes {
		t.Fatalf("test page size %d exceeds missing-node authority limit", len(body))
	}
	api.claimListBody = []byte(body)
	resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
	defer closeServer()

	if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsIdentityDrift(t *testing.T) {
	tests := map[string]func(*missingNodeAuthorityFixture){
		"claim not deleting": func(f *missingNodeAuthorityFixture) {
			f.claim.Metadata.DeletionTimestamp = ""
		},
		"termination finalizer absent": func(f *missingNodeAuthorityFixture) {
			f.claim.Metadata.Finalizers = []string{inspaceCreateProtectionFinalizer}
		},
		"create protection absent": func(f *missingNodeAuthorityFixture) {
			f.claim.Metadata.Finalizers = []string{karpenterTerminationFinalizer}
		},
		"node-name annotation differs": func(f *missingNodeAuthorityFixture) {
			f.claim.Metadata.Annotations[inspaceNodeNameAnnotation] = "other-node"
		},
		"status nodeName differs": func(f *missingNodeAuthorityFixture) {
			f.claim.Status.NodeName = "other-node"
		},
		"provider ID differs": func(f *missingNodeAuthorityFixture) {
			f.claim.Status.ProviderID = "inspace://" + testLocation + "/" + testVM2
		},
		"Registered is not true": func(f *missingNodeAuthorityFixture) {
			f.claim.Status.Conditions[0].Status = "False"
		},
		"InstanceTerminating exists": func(f *missingNodeAuthorityFixture) {
			f.claim.Status.Conditions = append(
				f.claim.Status.Conditions,
				missingNodeCondition{Type: karpenterTerminatingCondition, Status: "True"},
			)
		},
		"legacy create fence": func(f *missingNodeAuthorityFixture) {
			f.fence.Schema = "karpenter.inspace.cloud/create-fence-v2"
		},
		"created VM differs": func(f *missingNodeAuthorityFixture) {
			f.fence.CreatedVMUUID = testVM2
		},
		"observed VM differs": func(f *missingNodeAuthorityFixture) {
			f.fence.ObservedVMUUID = testVM2
		},
		"rollback selected": func(f *missingNodeAuthorityFixture) {
			f.fence.RollbackAt = stringPointer("2026-07-18T13:00:00Z")
		},
		"base firewall not observed": func(f *missingNodeAuthorityFixture) {
			f.fence.BaseFirewallAssignment.Phase = "issued"
		},
		"cleanup network differs": func(f *missingNodeAuthorityFixture) {
			f.fence.Cleanup.NetworkUUID = testVM2
		},
		"cleanup key hash differs": func(f *missingNodeAuthorityFixture) {
			f.fence.Cleanup.OwnershipKeyHash = strings.Repeat("9", 32)
		},
		"ownership key not UID-bound": func(f *missingNodeAuthorityFixture) {
			f.ownership.KeyHash = strings.Repeat("9", 32)
			f.fence.Cleanup.OwnershipKeyHash = strings.Repeat("9", 32)
		},
		"ownership host pool UUID absent": func(f *missingNodeAuthorityFixture) {
			f.ownership.HostPoolUUID = ""
		},
		"ownership embeds mutable public IPv4": func(f *missingNodeAuthorityFixture) {
			f.ownership.PublicIPv4 = "103.117.150.45"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newMissingNodeAuthorityFixture(t)
			mutate(&fixture)
			api := fixture.render(t)
			resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
			defer closeServer()

			err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request)
			if !errorsIsUnavailable(err) {
				t.Fatalf("AuthorizeMissingNodeDetach error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsReincarnatedInventory(t *testing.T) {
	t.Run("another NodeClaim advertises provider ID", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		duplicate := fixture.claim
		duplicate.Metadata.Name = "general-other"
		duplicate.Metadata.UID = "66666666-6666-4666-8666-666666666666"
		fixture.claims = append(fixture.claims, duplicate)
		api := fixture.render(t)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("another NodeClaim advertises non-canonical equivalent provider ID", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		duplicate := fixture.claim
		duplicate.Metadata.Name = "general-other"
		duplicate.Metadata.UID = "66666666-6666-4666-8666-666666666666"
		duplicate.Status.ProviderID = strings.ToUpper("inspace://" + testLocation + "/" + testVM1)
		fixture.claims = append(fixture.claims, duplicate)
		api := fixture.render(t)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("another NodeClaim has malformed InSpace provider ID", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		duplicate := fixture.claim
		duplicate.Metadata.Name = "general-other"
		duplicate.Metadata.UID = "66666666-6666-4666-8666-666666666666"
		duplicate.Status.ProviderID = "inspace:/" + testLocation + "/" + testVM1
		fixture.claims = append(fixture.claims, duplicate)
		api := fixture.render(t)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("another Node advertises provider ID", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		node := missingNodeKubernetesNode{}
		node.Metadata.Name = "replacement-worker"
		node.Metadata.UID = "77777777-7777-4777-8777-777777777777"
		node.Spec.ProviderID = "inspace://" + testLocation + "/" + testVM1
		fixture.nodes = []missingNodeKubernetesNode{node}
		api := fixture.render(t)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("another Node advertises non-canonical equivalent provider ID", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		node := missingNodeKubernetesNode{}
		node.Metadata.Name = "replacement-worker"
		node.Metadata.UID = "77777777-7777-4777-8777-777777777777"
		node.Spec.ProviderID = " " + strings.ToUpper("inspace://"+testLocation+"/"+testVM1)
		fixture.nodes = []missingNodeKubernetesNode{node}
		api := fixture.render(t)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("old Node name reappears", func(t *testing.T) {
		fixture := newMissingNodeAuthorityFixture(t)
		api := fixture.render(t)
		api.exactNodeBody = []byte(`{"spec":{"providerID":"inspace://bkk01/22222222-2222-4222-8222-222222222222"}}`)
		resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
		defer closeServer()
		if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
}

func TestKubernetesMissingNodeDetachAuthorityRejectsDuplicateAndTrailingJSON(t *testing.T) {
	tests := map[string]func(*missingNodeAuthorityAPIServer){
		"duplicate exact claim field": func(api *missingNodeAuthorityAPIServer) {
			api.claimBody = []byte(strings.Replace(
				string(api.claimBody),
				`"apiVersion":"karpenter.sh/v1"`,
				`"apiVersion":"karpenter.sh/v1","apiVersion":"karpenter.sh/v1"`,
				1,
			))
		},
		"trailing exact claim object": func(api *missingNodeAuthorityAPIServer) {
			api.claimBody = append(api.claimBody, []byte(`{}`)...)
		},
		"duplicate NodeClaim list field": func(api *missingNodeAuthorityAPIServer) {
			api.claimListBody = []byte(strings.Replace(
				string(api.claimListBody),
				`"kind":"NodeClaimList"`,
				`"kind":"NodeClaimList","kind":"NodeClaimList"`,
				1,
			))
		},
		"trailing Node list object": func(api *missingNodeAuthorityAPIServer) {
			api.nodeListBody = append(api.nodeListBody, []byte(`{}`)...)
		},
		"duplicate create-fence field": func(api *missingNodeAuthorityAPIServer) {
			var claim map[string]any
			if err := json.Unmarshal(api.claimBody, &claim); err != nil {
				t.Fatal(err)
			}
			metadata := claim["metadata"].(map[string]any)
			annotations := metadata["annotations"].(map[string]any)
			fence := annotations[inspaceCreateFenceAnnotation].(string)
			annotations[inspaceCreateFenceAnnotation] = strings.Replace(
				fence,
				`"schema":"karpenter.inspace.cloud/create-fence-v3"`,
				`"schema":"karpenter.inspace.cloud/create-fence-v3","schema":"karpenter.inspace.cloud/create-fence-v3"`,
				1,
			)
			api.claimBody, _ = json.Marshal(claim)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newMissingNodeAuthorityFixture(t)
			api := fixture.render(t)
			mutate(api)
			resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
			defer closeServer()
			if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsNoncanonicalCaseAliases(t *testing.T) {
	tests := map[string]func(*missingNodeAuthorityFixture, *missingNodeAuthorityAPIServer){
		"VM ownership billingAccountID alias": func(fixture *missingNodeAuthorityFixture, _ *missingNodeAuthorityAPIServer) {
			fixture.request.VMDescription = strings.Replace(
				fixture.request.VMDescription,
				`"billingAccountID":`,
				`"BillingAccountID":`,
				1,
			)
		},
		"VM ownership Unicode schema alias": func(fixture *missingNodeAuthorityFixture, _ *missingNodeAuthorityAPIServer) {
			fixture.request.VMDescription = strings.Replace(
				fixture.request.VMDescription,
				`"schema":`,
				`"ſchema":`,
				1,
			)
		},
		"NodeClaim providerID alias": func(_ *missingNodeAuthorityFixture, api *missingNodeAuthorityAPIServer) {
			api.claimBody = []byte(strings.Replace(
				string(api.claimBody),
				`"providerID":`,
				`"ProviderID":`,
				1,
			))
		},
		"NodeClaim UID alias": func(_ *missingNodeAuthorityFixture, api *missingNodeAuthorityAPIServer) {
			api.claimBody = []byte(strings.Replace(
				string(api.claimBody),
				`"uid":`,
				`"UID":`,
				1,
			))
		},
		"create-fence binding alias": func(_ *missingNodeAuthorityFixture, api *missingNodeAuthorityAPIServer) {
			var claim map[string]any
			if err := json.Unmarshal(api.claimBody, &claim); err != nil {
				t.Fatal(err)
			}
			metadata := claim["metadata"].(map[string]any)
			annotations := metadata["annotations"].(map[string]any)
			fence := annotations[inspaceCreateFenceAnnotation].(string)
			annotations[inspaceCreateFenceAnnotation] = strings.Replace(
				fence,
				`"nodeClaimUID":`,
				`"NodeClaimUID":`,
				1,
			)
			api.claimBody, _ = json.Marshal(claim)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newMissingNodeAuthorityFixture(t)
			api := fixture.render(t)
			mutate(&fixture, api)
			resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
			defer closeServer()
			if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestKubernetesMissingNodeDetachAuthorityRejectsInvalidRequestBeforeAPI(t *testing.T) {
	fixture := newMissingNodeAuthorityFixture(t)
	fixture.request.DiskUUID = ""
	api := fixture.render(t)
	resolver, closeServer := newMissingNodeAuthorityResolver(t, api)
	defer closeServer()
	if err := resolver.AuthorizeMissingNodeDetach(context.Background(), fixture.request); !errorsIsUnavailable(err) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("invalid request reached Kubernetes API: %#v", api.calls)
	}
}

func errorsIsUnavailable(err error) bool {
	return errors.Is(err, cloud.ErrUnavailable)
}

func stringPointer(value string) *string {
	return &value
}

package inspace_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

const sparseFloatingIPUUID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"

func sparseFloatingIPLiteral(
	address, uuid, name string,
	billingAccountID int64,
	assignmentFields string,
) string {
	return fmt.Sprintf(
		`{"uuid":%q,"id":73,"address":%q,"user_id":268,"billing_account_id":%d,`+
			`"type":"public","name":%q,"enabled":true,"is_deleted":false,"is_ipv6":false,`+
			`"created_at":"2026-07-17T08:00:00Z","updated_at":"2026-07-17T08:00:00Z"%s}`,
		uuid,
		address,
		billingAccountID,
		name,
		assignmentFields,
	)
}

func newFloatingIPContractClient(t *testing.T, handler http.HandlerFunc) *inspace.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestFloatingIPCreateAcceptsOnlyObservedSuccessStatuses(t *testing.T) {
	explicitUnassigned := sparseFloatingIPLiteral(
		floatingIP,
		sparseFloatingIPUUID,
		"owned",
		42,
		`,"assigned_to":null`,
	)
	for _, test := range []struct {
		status  int
		wantErr bool
	}{
		{status: http.StatusOK},
		{status: http.StatusCreated},
		{status: http.StatusAccepted, wantErr: true},
		{status: http.StatusPartialContent, wantErr: true},
		{status: http.StatusNoContent, wantErr: true},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/bkk01/network/ip_addresses" {
					t.Errorf("request = %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, explicitUnassigned)
			})
			created, err := client.CreateFloatingIP(context.Background(), "bkk01", inspace.CreateFloatingIPRequest{
				Name:             "owned",
				BillingAccountID: 42,
			})
			if test.wantErr {
				if err == nil {
					t.Fatalf("CreateFloatingIP() = %#v, nil; want status rejection", created)
				}
				return
			}
			if err != nil || created == nil || created.Address != floatingIP {
				t.Fatalf("CreateFloatingIP() = %#v, %v", created, err)
			}
		})
	}
}

func TestFloatingIPCreateRejectsPartialOrAssignedSuccessBodies(t *testing.T) {
	fullAssigned := sparseFloatingIPLiteral(
		floatingIP,
		sparseFloatingIPUUID,
		"owned",
		42,
		`,"assigned_to":"`+vmUUID+`","assigned_to_resource_type":"virtual_machine","assigned_to_private_ip":"10.91.72.10"`,
	)
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "partial explicit-unassigned body",
			body: `{"address":"` + floatingIP + `","assigned_to":null}`,
			want: "omits a required stable identity field",
		},
		{
			name: "unexpected assignment",
			body: fullAssigned,
			want: "unexpectedly reports assignment",
		},
	}
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		for _, test := range tests {
			t.Run(http.StatusText(status)+"/"+test.name, func(t *testing.T) {
				var requests atomic.Int32
				client := newFloatingIPContractClient(t, func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.WriteHeader(status)
					_, _ = io.WriteString(w, test.body)
				})
				if _, err := client.CreateFloatingIP(context.Background(), "bkk01", inspace.CreateFloatingIPRequest{
					Name:             "owned",
					BillingAccountID: 42,
				}); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("CreateFloatingIP() error = %v, want containing %q", err, test.want)
				}
				if requests.Load() != 1 {
					t.Fatalf("request count = %d, want exactly one POST and no readback", requests.Load())
				}
			})
		}
	}
}

func TestFloatingIPListCorroboratesLiveSparseUnassignedRow(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	var listReads atomic.Int32
	var exactReads atomic.Int32
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/network/ip_addresses":
			listReads.Add(1)
			_, _ = io.WriteString(w, "["+sparse+"]")
		case "/v1/bkk01/network/ip_addresses/" + floatingIP:
			exactReads.Add(1)
			_, _ = io.WriteString(w, sparse)
		default:
			http.NotFound(w, r)
		}
	})

	addresses, err := client.ListFloatingIPs(context.Background(), "bkk01", &inspace.FloatingIPFilters{
		BillingAccountID: 42,
	})
	if err != nil {
		t.Fatalf("ListFloatingIPs() error = %v", err)
	}
	if len(addresses) != 1 ||
		addresses[0].UUID != sparseFloatingIPUUID ||
		addresses[0].Address != floatingIP ||
		addresses[0].AssignedTo != "" ||
		addresses[0].AssignedToResourceType != "" {
		t.Fatalf("ListFloatingIPs() = %#v", addresses)
	}
	if listReads.Load() != 1 || exactReads.Load() != 1 {
		t.Fatalf("read counts list/exact = %d/%d, want 1/1", listReads.Load(), exactReads.Load())
	}
}

func TestFloatingIPExactReadCorroboratesLiveSparseUnassignedRow(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	var listQuery string
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/network/ip_addresses/" + floatingIP:
			_, _ = io.WriteString(w, sparse)
		case "/v1/bkk01/network/ip_addresses":
			listQuery = r.URL.RawQuery
			_, _ = io.WriteString(w, "["+sparse+"]")
		default:
			http.NotFound(w, r)
		}
	})

	address, err := client.GetFloatingIP(context.Background(), "bkk01", floatingIP)
	if err != nil {
		t.Fatalf("GetFloatingIP() error = %v", err)
	}
	if address.UUID != sparseFloatingIPUUID || address.AssignedTo != "" {
		t.Fatalf("GetFloatingIP() = %#v", address)
	}
	if listQuery != "billing_account_id=42" {
		t.Fatalf("corroborating list query = %q, want billing_account_id=42", listQuery)
	}
}

func TestSparseFloatingIPReadDoesNotHideExplicitAssignment(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	assigned := sparseFloatingIPLiteral(
		floatingIP,
		sparseFloatingIPUUID,
		name,
		42,
		`,"assigned_to":"`+vmUUID+`","assigned_to_resource_type":"virtual_machine","assigned_to_private_ip":"10.91.72.10"`,
	)
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/network/ip_addresses":
			_, _ = io.WriteString(w, "["+sparse+"]")
		case "/v1/bkk01/network/ip_addresses/" + floatingIP:
			_, _ = io.WriteString(w, assigned)
		default:
			http.NotFound(w, r)
		}
	})

	addresses, err := client.ListFloatingIPs(context.Background(), "bkk01", nil)
	if err != nil {
		t.Fatalf("ListFloatingIPs() error = %v", err)
	}
	if len(addresses) != 1 ||
		!strings.EqualFold(addresses[0].AssignedTo, vmUUID) ||
		addresses[0].AssignedToResourceType != "virtual_machine" {
		t.Fatalf("ListFloatingIPs() = %#v, want exact-read assignment", addresses)
	}
}

func TestSparseFloatingIPReadFailsClosedWithoutCoherentAuthority(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	tests := []struct {
		name      string
		exactBody string
		status    int
		want      string
	}{
		{
			name:      "stable name mismatch",
			exactBody: sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, "foreign", 42, ""),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable account mismatch",
			exactBody: sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 99, ""),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable UUID mismatch",
			exactBody: sparseFloatingIPLiteral(floatingIP, "88888888-9999-4aaa-8bbb-cccccccccccc", name, 42, ""),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable numeric ID mismatch",
			exactBody: strings.Replace(sparse, `"id":73`, `"id":74`, 1),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable user mismatch",
			exactBody: strings.Replace(sparse, `"user_id":268`, `"user_id":269`, 1),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable address mismatch",
			exactBody: strings.Replace(sparse, floatingIP, "203.0.113.26", 1),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable enabled mismatch",
			exactBody: strings.Replace(sparse, `"enabled":true`, `"enabled":false`, 1),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "stable timestamp mismatch",
			exactBody: strings.Replace(sparse, `"updated_at":"2026-07-17T08:00:00Z"`, `"updated_at":"2026-07-17T08:00:01Z"`, 1),
			status:    http.StatusOK,
			want:      "identity mismatch",
		},
		{
			name:      "corroborating stable field omitted",
			exactBody: strings.Replace(sparse, `,"is_deleted":false`, "", 1),
			status:    http.StatusOK,
			want:      "omits a required stable identity field",
		},
		{
			name:      "partial sparse relationship",
			exactBody: sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, `,"assigned_to_resource_type":null`),
			status:    http.StatusOK,
			want:      "omitted-assignment",
		},
		{
			name:   "exact read absent",
			status: http.StatusNotFound,
			want:   "reading exact floating IP",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/bkk01/network/ip_addresses":
					_, _ = io.WriteString(w, "["+sparse+"]")
				case "/v1/bkk01/network/ip_addresses/" + floatingIP:
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.exactBody)
				default:
					http.NotFound(w, r)
				}
			})
			if _, err := client.ListFloatingIPs(context.Background(), "bkk01", nil); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("ListFloatingIPs() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestSparseFloatingIPReadRequiresCompleteStableIdentity(t *testing.T) {
	incomplete := `{"uuid":"` + sparseFloatingIPUUID + `","address":"` + floatingIP +
		`","billing_account_id":42,"type":"public","created_at":"2026-07-17T08:00:00Z","updated_at":"2026-07-17T08:00:00Z"}`
	var exactReads atomic.Int32
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/network/ip_addresses":
			_, _ = io.WriteString(w, "["+incomplete+"]")
		case "/v1/bkk01/network/ip_addresses/" + floatingIP:
			exactReads.Add(1)
			_, _ = io.WriteString(w, incomplete)
		default:
			http.NotFound(w, r)
		}
	})

	if _, err := client.ListFloatingIPs(context.Background(), "bkk01", nil); err == nil ||
		!strings.Contains(err.Error(), "omits a required stable identity field") {
		t.Fatalf("ListFloatingIPs() error = %v, want incomplete identity rejection", err)
	}
	if exactReads.Load() != 0 {
		t.Fatalf("exact reads = %d, want no corroboration request for incomplete list identity", exactReads.Load())
	}
}

func TestFloatingIPFiltersRemainAuthoritativeAfterSparseCorroboration(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	tests := []struct {
		name    string
		filters *inspace.FloatingIPFilters
		want    string
	}{
		{
			name:    "billing account mismatch",
			filters: &inspace.FloatingIPFilters{BillingAccountID: 99},
			want:    "want filtered account 99",
		},
		{
			name:    "VM filter cannot return corroborated unassigned row",
			filters: &inspace.FloatingIPFilters{VMUUID: vmUUID},
			want:    "does not belong to filtered VM",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/bkk01/network/ip_addresses":
					_, _ = io.WriteString(w, "["+sparse+"]")
				case "/v1/bkk01/network/ip_addresses/" + floatingIP:
					_, _ = io.WriteString(w, sparse)
				default:
					http.NotFound(w, r)
				}
			})
			if _, err := client.ListFloatingIPs(context.Background(), "bkk01", test.filters); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("ListFloatingIPs() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestExactSparseFloatingIPReadRequiresMatchingCollectionRow(t *testing.T) {
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, "cluster-edge-ip", 42, "")
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/network/ip_addresses/" + floatingIP:
			_, _ = io.WriteString(w, sparse)
		case "/v1/bkk01/network/ip_addresses":
			_, _ = io.WriteString(w, "[]")
		default:
			http.NotFound(w, r)
		}
	})

	if _, err := client.GetFloatingIP(context.Background(), "bkk01", floatingIP); err == nil ||
		!strings.Contains(err.Error(), "absent from corroborating collection") {
		t.Fatalf("GetFloatingIP() error = %v, want missing corroboration rejection", err)
	}
}

func TestSparseFloatingIPTombstoneIsAuthoritativeWithoutAssignmentInference(t *testing.T) {
	active := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, "cluster-edge-ip", 42, "")
	tombstone := strings.Replace(active, `"is_deleted":false`, `"is_deleted":true`, 1)
	tests := []struct {
		name string
		call func(context.Context, *inspace.Client) (*inspace.FloatingIP, error)
	}{
		{
			name: "list",
			call: func(ctx context.Context, client *inspace.Client) (*inspace.FloatingIP, error) {
				addresses, err := client.ListFloatingIPs(ctx, "bkk01", nil)
				if err != nil || len(addresses) != 1 {
					return nil, err
				}
				return &addresses[0], nil
			},
		},
		{
			name: "exact",
			call: func(ctx context.Context, client *inspace.Client) (*inspace.FloatingIP, error) {
				return client.GetFloatingIP(ctx, "bkk01", floatingIP)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var reads atomic.Int32
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
				reads.Add(1)
				switch r.URL.Path {
				case "/v1/bkk01/network/ip_addresses":
					_, _ = io.WriteString(w, "["+tombstone+"]")
				case "/v1/bkk01/network/ip_addresses/" + floatingIP:
					_, _ = io.WriteString(w, tombstone)
				default:
					http.NotFound(w, r)
				}
			})
			address, err := test.call(context.Background(), client)
			if err != nil {
				t.Fatalf("%s sparse tombstone error = %v", test.name, err)
			}
			if address == nil || !address.IsDeleted || address.AssignedTo != "" {
				t.Fatalf("%s sparse tombstone = %#v", test.name, address)
			}
			if reads.Load() != 1 {
				t.Fatalf("%s read count = %d, want one authoritative tombstone read", test.name, reads.Load())
			}
		})
	}
}

func TestFloatingIPResponseFieldsRequireCanonicalCase(t *testing.T) {
	for _, test := range []struct {
		name  string
		body  string
		field string
	}{
		{
			name: "assignment field",
			body: sparseFloatingIPLiteral(
				floatingIP,
				sparseFloatingIPUUID,
				"cluster-edge-ip",
				42,
				`,"ASSIGNED_TO":null`,
			),
			field: "ASSIGNED_TO",
		},
		{
			name:  "stable identity field",
			body:  `{"UUID":"` + sparseFloatingIPUUID + `","address":"` + floatingIP + `","assigned_to":null}`,
			field: "UUID",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "["+test.body+"]")
			})

			if _, err := client.ListFloatingIPs(context.Background(), "bkk01", nil); err == nil ||
				!strings.Contains(err.Error(), `non-canonical floating IP response field "`+test.field+`"`) {
				t.Fatalf("ListFloatingIPs() error = %v, want non-canonical field rejection", err)
			}
		})
	}
}

func TestFloatingIPCreateCorroboratesLiveSparseHTTP200Response(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	var postCalls atomic.Int32
	var exactReads atomic.Int32
	var listReads atomic.Int32
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/bkk01/network/ip_addresses":
			postCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, sparse)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bkk01/network/ip_addresses/"+floatingIP:
			exactReads.Add(1)
			_, _ = io.WriteString(w, sparse)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bkk01/network/ip_addresses":
			listReads.Add(1)
			_, _ = io.WriteString(w, "["+sparse+"]")
		default:
			http.NotFound(w, r)
		}
	})

	created, err := client.CreateFloatingIP(context.Background(), "bkk01", inspace.CreateFloatingIPRequest{
		Name:             name,
		BillingAccountID: 42,
	})
	if err != nil {
		t.Fatalf("CreateFloatingIP() error = %v", err)
	}
	if created.UUID != sparseFloatingIPUUID || created.Address != floatingIP || created.AssignedTo != "" {
		t.Fatalf("CreateFloatingIP() = %#v", created)
	}
	if postCalls.Load() != 1 || exactReads.Load() != 1 || listReads.Load() != 1 {
		t.Fatalf(
			"POST/exact/list counts = %d/%d/%d, want 1/1/1",
			postCalls.Load(),
			exactReads.Load(),
			listReads.Load(),
		)
	}
}

func TestSparseFloatingIPCreateRequiresRequestedMetadataBeforeReadback(t *testing.T) {
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, "foreign", 42, "")
	var reads atomic.Int32
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, sparse)
	})

	if _, err := client.CreateFloatingIP(context.Background(), "bkk01", inspace.CreateFloatingIPRequest{
		Name:             "cluster-edge-ip",
		BillingAccountID: 42,
	}); err == nil || !strings.Contains(err.Error(), "does not match requested metadata") {
		t.Fatalf("CreateFloatingIP() error = %v, want metadata mismatch", err)
	}
	if reads.Load() != 0 {
		t.Fatalf("readback requests = %d, want none after response metadata mismatch", reads.Load())
	}
}

func TestSparseFloatingIPCreateReadbackFailureDoesNotReplayPOST(t *testing.T) {
	const name = "cluster-edge-ip"
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, name, 42, "")
	var postCalls atomic.Int32
	client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/bkk01/network/ip_addresses":
			postCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, sparse)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/bkk01/network/ip_addresses/"+floatingIP:
			http.Error(w, `{"message":"temporarily unavailable"}`, http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	})

	if _, err := client.CreateFloatingIP(context.Background(), "bkk01", inspace.CreateFloatingIPRequest{
		Name:             name,
		BillingAccountID: 42,
	}); err == nil || !strings.Contains(err.Error(), "could not be corroborated") {
		t.Fatalf("CreateFloatingIP() error = %v, want readback failure", err)
	}
	if postCalls.Load() != 1 {
		t.Fatalf("floating IP POST count = %d, want exactly one", postCalls.Load())
	}
}

func TestNonCreateFloatingIPMutationsKeepSparseResponsesFailClosed(t *testing.T) {
	sparse := sparseFloatingIPLiteral(floatingIP, sparseFloatingIPUUID, "cluster-edge-ip", 42, "")
	tests := []struct {
		name   string
		method string
		path   string
		call   func(context.Context, *inspace.Client) error
	}{
		{
			name:   "update",
			method: http.MethodPatch,
			path:   "/v1/bkk01/network/ip_addresses/" + floatingIP,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{
					Name:             "cluster-edge-ip",
					BillingAccountID: 42,
				})
				return err
			},
		},
		{
			name:   "assign",
			method: http.MethodPost,
			path:   "/v1/bkk01/network/ip_addresses/" + floatingIP + "/assign",
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
				return err
			},
		},
		{
			name:   "unassign",
			method: http.MethodPost,
			path:   "/v1/bkk01/network/ip_addresses/" + floatingIP + "/unassign",
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := newFloatingIPContractClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != test.method || r.URL.Path != test.path {
					t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.Path, test.method, test.path)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, sparse)
			})
			if err := test.call(context.Background(), client); err == nil ||
				!strings.Contains(err.Error(), "assignment tuple is sparse") {
				t.Fatalf("%s error = %v, want sparse mutation-response rejection", test.name, err)
			}
			if requests.Load() != 1 {
				t.Fatalf("%s request count = %d, want exactly one mutation and no readback", test.name, requests.Load())
			}
		})
	}
}

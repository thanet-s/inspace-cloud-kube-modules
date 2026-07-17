package inspace_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client/internal/testutil/fakeapi"
)

func TestSmoke(t *testing.T) {
	fake := fakeapi.New("test-key")
	t.Cleanup(fake.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: fake.URL(), APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	locations, err := client.ListLocations(ctx)
	if err != nil || len(locations) != 1 || locations[0].Slug != "bkk01" {
		t.Fatalf("ListLocations() = %#v, %v", locations, err)
	}
	pools, err := client.ListHostPools(ctx, "bkk01")
	if err != nil || len(pools) != 1 {
		t.Fatalf("ListHostPools() = %#v, %v", pools, err)
	}
	noPublicIP := false
	created, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
		Name:               "smoke-worker",
		OSName:             "ubuntu",
		OSVersion:          "24.04",
		DiskGiB:            40,
		VCPU:               4,
		MemoryMiB:          8192,
		DesignatedPoolUUID: pools[0].UUID,
		NetworkUUID:        "11111111-2222-3333-4444-555555555555",
		ReservePublicIP:    &noPublicIP,
	})
	if err != nil {
		t.Fatalf("CreateVM(): %v", err)
	}
	if created.UUID != fakeapi.VMUUID || created.VCPU != 4 || created.MemoryMiB != 8192 {
		t.Fatalf("CreateVM() = %#v", created)
	}
	if created.NetworkUUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("CreateVM() network UUID = %q", created.NetworkUUID)
	}
	got, err := client.GetVM(ctx, "bkk01", created.UUID)
	if err != nil || got.UUID != created.UUID {
		t.Fatalf("GetVM() = %#v, %v", got, err)
	}
	vms, err := client.ListVMs(ctx, "bkk01")
	if err != nil || len(vms) != 1 {
		t.Fatalf("ListVMs() = %#v, %v", vms, err)
	}
	if err := client.DeleteVM(ctx, "bkk01", created.UUID); err != nil {
		t.Fatalf("DeleteVM(): %v", err)
	}
	_, err = client.GetVM(ctx, "bkk01", created.UUID)
	if !inspace.IsNotFound(err) {
		t.Fatalf("GetVM() error = %v, want normalized not-found", err)
	}
}

func TestRemoteBaseURLRequiresHTTPS(t *testing.T) {
	_, err := inspace.NewClient(inspace.Options{BaseURL: "http://api.example.invalid", APIKey: "test-key"})
	if err == nil {
		t.Fatal("NewClient() accepted clear-text remote API URL")
	}
}

func TestHTTP408IsClassifiedRetryableWithoutAutomaticReplay(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "request outcome is ambiguous", http.StatusRequestTimeout)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	var apiErr *inspace.APIError
	if !errors.As(err, &apiErr) || !apiErr.Retryable || apiErr.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("ListLocations() error = %#v, want retryable HTTP 408", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP 408 request count = %d, want no automatic replay", got)
	}
}

func TestListResponsesRejectEmptyOrNullHTTP200Bodies(t *testing.T) {
	calls := []struct {
		name string
		call func(context.Context, *inspace.Client) error
	}{
		{name: "locations", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLocations(ctx)
			return err
		}},
		{name: "host pools", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListHostPools(ctx, "bkk01")
			return err
		}},
		{name: "VMs", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "floating IPs", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "firewalls", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFirewalls(ctx, "bkk01")
			return err
		}},
		{name: "load balancers", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "networks", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListNetworks(ctx, "bkk01")
			return err
		}},
		{name: "VM images", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMImages(ctx)
			return err
		}},
		{name: "disks", call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListDisks(ctx, "bkk01")
			return err
		}},
	}
	for _, body := range []struct {
		name string
		data string
	}{
		{name: "empty", data: ""},
		{name: "null", data: "null"},
	} {
		for _, call := range calls {
			t.Run(body.name+"/"+call.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, body.data)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				err = call.call(context.Background(), client)
				if err == nil || !strings.Contains(err.Error(), "expected a non-") {
					t.Fatalf("list call error = %v, want malformed successful-response rejection", err)
				}
			})
		}
	}
}

func TestListResponsesAcceptExplicitEmptyJSONArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "[]")
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.ListVMs(context.Background(), "bkk01")
	if err != nil || items == nil || len(items) != 0 {
		t.Fatalf("ListVMs() = %#v, %v; want a non-nil empty collection", items, err)
	}
}

func TestReadResponsesRejectBodiesLargerThanLimit(t *testing.T) {
	const limit = 4 << 20
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "[]"+strings.Repeat(" ", limit))
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListVMs(context.Background(), "bkk01"); err == nil || !strings.Contains(err.Error(), "body exceeds") {
		t.Fatalf("oversized read response error = %v, want explicit size refusal", err)
	}
}

func TestOversizedErrorBodyPreservesStatusWithoutGrantingAbsence(t *testing.T) {
	const limit = 4 << 20
	for _, test := range []struct {
		name          string
		status        int
		wantRetryable bool
	}{
		{name: "server error remains retryable", status: http.StatusInternalServerError, wantRetryable: true},
		{name: "not found is not absence", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, strings.Repeat("x", limit+1))
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.GetVM(context.Background(), "bkk01", vmUUID)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("oversized HTTP %d error = %#v, want APIError", test.status, err)
			}
			if apiErr.StatusCode != test.status || !apiErr.ResponseBodyIncomplete || apiErr.Retryable != test.wantRetryable {
				t.Fatalf("oversized HTTP %d APIError = %#v", test.status, apiErr)
			}
			if inspace.IsNotFound(err) {
				t.Fatalf("oversized HTTP %d response became authoritative absence", test.status)
			}
		})
	}
}

func TestUnreadableErrorBodyPreservesStatusWithoutGrantingAbsence(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		wantRetryable bool
	}{
		{name: "server error remains retryable", status: http.StatusInternalServerError, wantRetryable: true},
		{name: "not found is not absence", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: test.status,
					Header:     make(http.Header),
					Body: io.NopCloser(io.MultiReader(
						strings.NewReader(`{"message":"partial`),
						failingReader{},
					)),
					Request: req,
				}, nil
			})
			client, err := inspace.NewClient(inspace.Options{
				BaseURL:    "https://api.example.invalid",
				APIKey:     "test-key",
				HTTPClient: &http.Client{Transport: transport},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.GetVM(context.Background(), "bkk01", vmUUID)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("unreadable HTTP %d error = %#v, want APIError", test.status, err)
			}
			if apiErr.StatusCode != test.status || !apiErr.ResponseBodyIncomplete || apiErr.Retryable != test.wantRetryable {
				t.Fatalf("unreadable HTTP %d APIError = %#v", test.status, apiErr)
			}
			if inspace.IsNotFound(err) {
				t.Fatalf("unreadable HTTP %d response became authoritative absence", test.status)
			}
		})
	}
}

func TestDeclaredResponseTruncationNeverBecomesAuthoritative(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
	}{
		{name: "successful collection", status: http.StatusOK},
		{name: "exact not found", status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    test.status,
					Header:        make(http.Header),
					Body:          io.NopCloser(strings.NewReader(`[]`)),
					ContentLength: 100,
					Request:       req,
				}, nil
			})
			client, err := inspace.NewClient(inspace.Options{
				BaseURL:    "https://api.example.invalid",
				APIKey:     "test-key",
				HTTPClient: &http.Client{Transport: transport},
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.status == http.StatusOK {
				_, err = client.ListVMs(context.Background(), "bkk01")
			} else {
				_, err = client.GetVM(context.Background(), "bkk01", vmUUID)
			}
			if err == nil || !strings.Contains(err.Error(), "does not match declared length") {
				t.Fatalf("declared truncation error = %v", err)
			}
			if inspace.IsNotFound(err) {
				t.Fatalf("declared truncated HTTP %d became absence", test.status)
			}
			if test.status != http.StatusOK {
				var apiErr *inspace.APIError
				if !errors.As(err, &apiErr) || !apiErr.ResponseBodyIncomplete {
					t.Fatalf("declared truncated HTTP %d APIError = %#v", test.status, apiErr)
				}
			}
		})
	}
}

func TestExactResourceReadsRejectMalformedSuccessfulBodiesAndWrongIdentity(t *testing.T) {
	const otherUUID = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	calls := []struct {
		name      string
		invoke    func(context.Context, *inspace.Client) error
		wrongBody string
	}{
		{
			name: "VM",
			invoke: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetVM(ctx, "bkk01", vmUUID)
				return err
			},
			wrongBody: `{"uuid":"` + otherUUID + `"}`,
		},
		{
			name: "network",
			invoke: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetNetwork(ctx, "bkk01", networkUUID)
				return err
			},
			wrongBody: `{"uuid":"` + otherUUID + `"}`,
		},
		{
			name: "disk",
			invoke: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetDisk(ctx, "bkk01", diskUUID)
				return err
			},
			wrongBody: `{"uuid":"` + otherUUID + `"}`,
		},
		{
			name: "load balancer",
			invoke: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetLoadBalancer(ctx, "bkk01", lbUUID)
				return err
			},
			wrongBody: `{"uuid":"` + otherUUID + `"}`,
		},
		{
			name: "floating IP",
			invoke: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetFloatingIP(ctx, "bkk01", floatingIP)
				return err
			},
			wrongBody: `{"address":"203.0.113.26","assigned_to":null}`,
		},
	}
	for _, call := range calls {
		for _, body := range []struct {
			name string
			data string
		}{
			{name: "empty body", data: ""},
			{name: "null body", data: "null"},
			{name: "empty object", data: "{}"},
			{name: "object without identity", data: `{"message":"ok"}`},
			{name: "wrong identity", data: call.wrongBody},
		} {
			t.Run(call.name+"/"+body.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, body.data)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				if err := call.invoke(context.Background(), client); err == nil {
					t.Fatalf("%s accepted malformed HTTP-200 body %q", call.name, body.data)
				}
			})
		}
	}
}

func TestFloatingIPResponsesRequireExplicitCoherentAssignmentState(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		call   func(context.Context, *inspace.Client) error
	}{
		{name: "list omits assigned_to", status: http.StatusOK, body: `[{"address":"` + floatingIP + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "exact read omits assigned_to", status: http.StatusOK, body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "create omits assigned_to", status: http.StatusCreated, body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "update omits assigned_to", status: http.StatusOK, body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "assign omits assigned_to", status: http.StatusOK, body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
			return err
		}},
		{name: "unassign omits assigned_to", status: http.StatusOK, body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "unassign mutation omits assigned_to with historical timestamp", status: http.StatusOK, body: `{"address":"` + floatingIP + `","unassigned_at":"2026-07-17T09:54:01Z"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "omitted assignment retains resource type", status: http.StatusOK, body: `[{"address":"` + floatingIP + `","unassigned_at":"2026-07-17T09:54:01Z","assigned_to_resource_type":"virtual_machine"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "unassigned row retains resource type", status: http.StatusOK, body: `[{"address":"` + floatingIP + `","assigned_to":null,"assigned_to_resource_type":"virtual_machine"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "assigned row has malformed UUID", status: http.StatusOK, body: `[{"address":"` + floatingIP + `","assigned_to":"not-a-uuid","assigned_to_resource_type":"virtual_machine"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "assigned row omits resource type", status: http.StatusOK, body: `[{"address":"` + floatingIP + `","assigned_to":"` + vmUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "assigned row has public private-address field", status: http.StatusOK, body: `[{"address":"` + floatingIP + `","assigned_to":"` + vmUUID + `","assigned_to_resource_type":"virtual_machine","assigned_to_private_ip":"203.0.113.40"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(context.Background(), client); err == nil {
				t.Fatalf("accepted malformed floating-IP response %s", test.body)
			}
		})
	}
}

func TestFloatingIPReadResponsesAcceptLiveUnassignedRepresentation(t *testing.T) {
	tests := []struct {
		name string
		body string
		call func(context.Context, *inspace.Client) error
	}{
		{
			name: "list",
			body: `[{"address":"` + floatingIP + `","unassigned_at":"2026-07-17T09:54:01Z"}]`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
				return err
			},
		},
		{
			name: "exact read",
			body: `{"address":"` + floatingIP + `","unassigned_at":"2026-07-17 09:54:01"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.GetFloatingIP(ctx, "bkk01", floatingIP)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(context.Background(), client); err != nil {
				t.Fatalf("rejected live unassigned floating-IP response %s: %v", test.body, err)
			}
		})
	}
}

func TestMutationResponsesRequireCanonicalExpectedIdentity(t *testing.T) {
	port := int32(443)
	firewallRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	tests := []struct {
		name   string
		status int
		body   string
		call   func(context.Context, *inspace.Client) error
	}{
		{name: "created VM malformed UUID", status: http.StatusCreated, body: `{"uuid":"not-a-uuid"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
				Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
			})
			return err
		}},
		{name: "created disk malformed UUID", status: http.StatusCreated, body: `{"uuid":"not-a-uuid"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateDisk(ctx, "bkk01", inspace.CreateDiskRequest{DisplayName: "data", SizeGiB: 40})
			return err
		}},
		{name: "attached wrong disk", status: http.StatusOK, body: `{"uuid":"99999999-aaaa-4bbb-8ccc-dddddddddddd"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AttachDisk(ctx, "bkk01", vmUUID, diskUUID)
			return err
		}},
		{name: "created floating IP malformed address", status: http.StatusCreated, body: `{"address":"10.0.0.1"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "updated wrong floating IP", status: http.StatusOK, body: `{"address":"203.0.113.26"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "assigned floating IP to wrong resource", status: http.StatusOK, body: `{"address":"` + floatingIP + `","assigned_to":"99999999-aaaa-4bbb-8ccc-dddddddddddd","assigned_to_resource_type":"virtual_machine"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
			return err
		}},
		{name: "unassigned floating IP still assigned", status: http.StatusOK, body: `{"address":"` + floatingIP + `","assigned_to":"` + vmUUID + `","assigned_to_resource_type":"virtual_machine"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "created firewall malformed UUID", status: http.StatusCreated, body: `{"uuid":"not-a-uuid"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{
				DisplayName: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "updated wrong firewall", status: http.StatusOK, body: `{"uuid":"99999999-aaaa-4bbb-8ccc-dddddddddddd"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFirewall(ctx, "bkk01", firewallUUID, inspace.UpdateFirewallRequest{
				Name: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "created load balancer malformed UUID", status: http.StatusCreated, body: `{"uuid":"not-a-uuid"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateLoadBalancer(ctx, "bkk01", inspace.CreateLoadBalancerRequest{
				DisplayName: "owned", NetworkUUID: networkUUID,
				Rules: []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}},
			})
			return err
		}},
		{name: "added wrong load balancer target", status: http.StatusOK, body: `{"target_uuid":"99999999-aaaa-4bbb-8ccc-dddddddddddd","target_type":"vm"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
			return err
		}},
		{name: "added mismatched load balancer rule", status: http.StatusOK, body: `{"uuid":"` + ruleUUID + `","protocol":"TCP","source_port":80,"target_port":30080}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerRule(ctx, "bkk01", lbUUID, inspace.LoadBalancerRule{
				Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
			})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(context.Background(), client); err == nil {
				t.Fatalf("mutation accepted mismatched response %s", test.body)
			}
		})
	}
}

func TestAssignFirewallResponseRequiresExactRequestedRelation(t *testing.T) {
	const otherVMUUID = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "empty collection", body: `[]`},
		{name: "requested VM absent", body: `[{"resource_type":"vm","resource_uuid":"` + otherVMUUID + `"}]`},
		{name: "missing resource type", body: `[{"resource_uuid":"` + vmUUID + `"}]`},
		{name: "wrong resource type", body: `[{"resource_type":"service","resource_uuid":"` + vmUUID + `"}]`},
		{name: "malformed VM UUID", body: `[{"resource_type":"vm","resource_uuid":"not-a-uuid"}]`},
		{name: "duplicate requested VM", body: `[{"resource_type":"vm","resource_uuid":"` + vmUUID + `"},{"resource_type":"vm","resource_uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB"}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.AssignFirewallToVM(context.Background(), "bkk01", firewallUUID, vmUUID); err == nil {
				t.Fatalf("AssignFirewallToVM accepted malformed relation response %s", test.body)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(
			w,
			`[{"resource_type":"vm","resource_uuid":"`+otherVMUUID+`"},{"resource_type":"vm","resource_uuid":"`+vmUUID+`"}]`,
		)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AssignFirewallToVM(context.Background(), "bkk01", firewallUUID, vmUUID); err != nil {
		t.Fatalf("AssignFirewallToVM rejected one exact requested relation alongside another valid VM: %v", err)
	}
}

func TestEveryReadEndpointRejectsNon200SuccessStatus(t *testing.T) {
	calls := []struct {
		name string
		body string
		call func(context.Context, *inspace.Client) error
	}{
		{name: "locations", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLocations(ctx)
			return err
		}},
		{name: "host pools", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListHostPools(ctx, "bkk01")
			return err
		}},
		{name: "VMs", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM", body: `{"uuid":"` + vmUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetVM(ctx, "bkk01", vmUUID)
			return err
		}},
		{name: "floating IPs", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
			return err
		}},
		{name: "floating IP", body: `{"address":"` + floatingIP + `","assigned_to":null}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "firewalls", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFirewalls(ctx, "bkk01")
			return err
		}},
		{name: "firewall lookup", body: `[{"uuid":"` + firewallUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetFirewall(ctx, "bkk01", firewallUUID)
			return err
		}},
		{name: "load balancers", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer", body: `{"uuid":"` + lbUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetLoadBalancer(ctx, "bkk01", lbUUID)
			return err
		}},
		{name: "networks", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListNetworks(ctx, "bkk01")
			return err
		}},
		{name: "network", body: `{"uuid":"` + networkUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetNetwork(ctx, "bkk01", networkUUID)
			return err
		}},
		{name: "VM images", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMImages(ctx)
			return err
		}},
		{name: "disks", body: `[]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListDisks(ctx, "bkk01")
			return err
		}},
		{name: "disk", body: `{"uuid":"` + diskUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetDisk(ctx, "bkk01", diskUUID)
			return err
		}},
	}
	for _, status := range []int{
		http.StatusCreated,
		http.StatusAccepted,
		http.StatusNoContent,
		http.StatusPartialContent,
	} {
		for _, call := range calls {
			t.Run(http.StatusText(status)+"/"+call.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, call.body)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				err = call.call(context.Background(), client)
				var apiErr *inspace.APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
					t.Fatalf("%s returned error %#v for HTTP %d, want typed status rejection", call.name, err, status)
				}
			})
		}
	}
}

func TestMutationSuccessResponseShapeAndStatusAreFailClosed(t *testing.T) {
	port := int32(443)
	firewallRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	objectCalls := []struct {
		name          string
		successStatus int
		call          func(context.Context, *inspace.Client) error
	}{
		{name: "CreateVM", successStatus: http.StatusCreated, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
				Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
			})
			return err
		}},
		{name: "CreateDisk", successStatus: http.StatusCreated, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateDisk(ctx, "bkk01", inspace.CreateDiskRequest{DisplayName: "data", SizeGiB: 40})
			return err
		}},
		{name: "AttachDisk", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AttachDisk(ctx, "bkk01", vmUUID, diskUUID)
			return err
		}},
		{name: "DetachDisk", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DetachDisk(ctx, "bkk01", vmUUID, diskUUID)
		}},
		{name: "CreateFloatingIP", successStatus: http.StatusCreated, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "UpdateFloatingIP", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "AssignFloatingIP", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
			return err
		}},
		{name: "UnassignFloatingIP", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "CreateFirewall", successStatus: http.StatusCreated, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{
				DisplayName: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "UpdateFirewall", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFirewall(ctx, "bkk01", firewallUUID, inspace.UpdateFirewallRequest{
				Name: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "AssignFirewallToVM", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.AssignFirewallToVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "CreateLoadBalancer", successStatus: http.StatusCreated, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateLoadBalancer(ctx, "bkk01", inspace.CreateLoadBalancerRequest{
				DisplayName: "owned", NetworkUUID: networkUUID,
				Rules: []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}},
			})
			return err
		}},
		{name: "AddLoadBalancerTarget", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
			return err
		}},
		{name: "AddLoadBalancerRule", successStatus: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerRule(ctx, "bkk01", lbUUID, inspace.LoadBalancerRule{
				Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
			})
			return err
		}},
	}
	for _, body := range []string{"", "null", "{}", `{"unknown":1}`} {
		for _, call := range objectCalls {
			t.Run(call.name+"/"+body, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(call.successStatus)
					_, _ = io.WriteString(w, body)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				if err := call.call(context.Background(), client); err == nil {
					t.Fatalf("%s accepted malformed successful mutation body %q", call.name, body)
				}
			})
		}
	}

	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusPartialContent} {
		t.Run("object/"+http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"uuid":"`+vmUUID+`"}`)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			err = objectCalls[0].call(context.Background(), client)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Fatalf("object mutation HTTP %d error = %#v, want typed status rejection", status, err)
			}
		})
	}
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNoContent, http.StatusPartialContent} {
		t.Run("relationship/"+http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"uuid":"`+diskUUID+`"}`)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.AttachDisk(context.Background(), "bkk01", vmUUID, diskUUID)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Fatalf("relationship mutation HTTP %d error = %#v, want typed status rejection", status, err)
			}
		})
	}
	for _, status := range []int{http.StatusCreated, http.StatusAccepted, http.StatusPartialContent} {
		t.Run("bodyless/"+http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			err = client.DeleteVM(context.Background(), "bkk01", vmUUID)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Fatalf("bodyless mutation HTTP %d error = %#v, want typed status rejection", status, err)
			}
		})
	}
}

func TestDeleteEndpointsRequireTheirDocumentedSuccessStatus(t *testing.T) {
	tests := []struct {
		name    string
		allowed []int
		call    func(context.Context, *inspace.Client) error
	}{
		{name: "DeleteVM", allowed: []int{http.StatusOK, http.StatusNoContent}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteVM(ctx, "bkk01", vmUUID)
		}},
		{name: "DeleteDisk", allowed: []int{http.StatusNoContent}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteDisk(ctx, "bkk01", diskUUID)
		}},
		{name: "DeleteFloatingIP", allowed: []int{http.StatusOK}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFloatingIP(ctx, "bkk01", floatingIP)
		}},
		{name: "DeleteFirewall", allowed: []int{http.StatusNoContent}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFirewall(ctx, "bkk01", firewallUUID)
		}},
		{name: "UnassignFirewallFromVM", allowed: []int{http.StatusNoContent}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "DeleteLoadBalancer", allowed: []int{http.StatusOK}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteLoadBalancer(ctx, "bkk01", lbUUID)
		}},
		{name: "RemoveLoadBalancerTarget", allowed: []int{http.StatusOK}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
		}},
		{name: "RemoveLoadBalancerRule", allowed: []int{http.StatusOK}, call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerRule(ctx, "bkk01", lbUUID, ruleUUID)
		}},
	}
	for _, test := range tests {
		for _, allowed := range test.allowed {
			t.Run(test.name+"/accepted-"+strconv.Itoa(allowed), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(allowed)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				if err := test.call(context.Background(), client); err != nil {
					t.Fatalf("%s rejected allowed HTTP %d: %v", test.name, allowed, err)
				}
			})
		}

		t.Run(test.name+"/wrong-202", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			err = test.call(context.Background(), client)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusAccepted {
				t.Fatalf("%s wrong HTTP 202 error = %#v, want typed rejection", test.name, err)
			}
		})
	}
}

func TestEveryMutationEndpointRejectsUndocumentedSuccessStatuses(t *testing.T) {
	port := int32(443)
	firewallRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	calls := []struct {
		name string
		body string
		call func(context.Context, *inspace.Client) error
	}{
		{name: "CreateVM", body: `{"uuid":"` + vmUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
				Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
			})
			return err
		}},
		{name: "DeleteVM", call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteVM(ctx, "bkk01", vmUUID)
		}},
		{name: "CreateDisk", body: `{"uuid":"` + diskUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateDisk(ctx, "bkk01", inspace.CreateDiskRequest{DisplayName: "data", SizeGiB: 40})
			return err
		}},
		{name: "DeleteDisk", call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteDisk(ctx, "bkk01", diskUUID)
		}},
		{name: "AttachDisk", body: `{"uuid":"` + diskUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AttachDisk(ctx, "bkk01", vmUUID, diskUUID)
			return err
		}},
		{name: "DetachDisk", body: `{"success":true}`, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DetachDisk(ctx, "bkk01", vmUUID, diskUUID)
		}},
		{name: "CreateFloatingIP", body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "UpdateFloatingIP", body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{Name: "owned", BillingAccountID: 42})
			return err
		}},
		{name: "AssignFloatingIP", body: `{"address":"` + floatingIP + `","assigned_to":"` + vmUUID + `","assigned_to_resource_type":"virtual_machine"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
			return err
		}},
		{name: "UnassignFloatingIP", body: `{"address":"` + floatingIP + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "DeleteFloatingIP", call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFloatingIP(ctx, "bkk01", floatingIP)
		}},
		{name: "CreateFirewall", body: `{"uuid":"` + firewallUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{
				DisplayName: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "UpdateFirewall", body: `{"uuid":"` + firewallUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFirewall(ctx, "bkk01", firewallUUID, inspace.UpdateFirewallRequest{
				Name: "owned", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "DeleteFirewall", call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFirewall(ctx, "bkk01", firewallUUID)
		}},
		{name: "AssignFirewallToVM", body: `[{"resource_type":"vm","resource_uuid":"` + vmUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			return client.AssignFirewallToVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "UnassignFirewallFromVM", call: func(ctx context.Context, client *inspace.Client) error {
			return client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "CreateLoadBalancer", body: `{"uuid":"` + lbUUID + `"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateLoadBalancer(ctx, "bkk01", inspace.CreateLoadBalancerRequest{
				DisplayName: "owned", NetworkUUID: networkUUID,
				Rules: []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}},
			})
			return err
		}},
		{name: "DeleteLoadBalancer", call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteLoadBalancer(ctx, "bkk01", lbUUID)
		}},
		{name: "AddLoadBalancerTarget", body: `{"target_uuid":"` + vmUUID + `","target_type":"vm"}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
			return err
		}},
		{name: "RemoveLoadBalancerTarget", call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
		}},
		{name: "AddLoadBalancerRule", body: `{"uuid":"` + ruleUUID + `","protocol":"TCP","source_port":443,"target_port":30443}`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerRule(ctx, "bkk01", lbUUID, inspace.LoadBalancerRule{
				Protocol: "TCP", SourcePort: 443, TargetPort: 30443,
			})
			return err
		}},
		{name: "RemoveLoadBalancerRule", call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerRule(ctx, "bkk01", lbUUID, ruleUUID)
		}},
	}
	if len(calls) != 22 {
		t.Fatalf("mutation route table has %d entries, want all 22 exported mutations", len(calls))
	}
	for _, status := range []int{http.StatusAccepted, http.StatusPartialContent} {
		for _, call := range calls {
			t.Run(call.name+"/"+strconv.Itoa(status), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
					_, _ = io.WriteString(w, call.body)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				err = call.call(context.Background(), client)
				var apiErr *inspace.APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
					t.Fatalf("%s accepted HTTP %d or returned an untyped error: %#v", call.name, status, err)
				}
			})
		}
	}
}

func TestBodylessMutationEndpointsRejectNonEmptySuccessBodies(t *testing.T) {
	tests := []struct {
		name   string
		status int
		call   func(context.Context, *inspace.Client) error
	}{
		{name: "DeleteDisk", status: http.StatusNoContent, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteDisk(ctx, "bkk01", diskUUID)
		}},
		{name: "DeleteFloatingIP", status: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFloatingIP(ctx, "bkk01", floatingIP)
		}},
		{name: "DeleteFirewall", status: http.StatusNoContent, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFirewall(ctx, "bkk01", firewallUUID)
		}},
		{name: "UnassignFirewallFromVM", status: http.StatusNoContent, call: func(ctx context.Context, client *inspace.Client) error {
			return client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "DeleteLoadBalancer", status: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteLoadBalancer(ctx, "bkk01", lbUUID)
		}},
		{name: "RemoveLoadBalancerTarget", status: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
		}},
		{name: "RemoveLoadBalancerRule", status: http.StatusOK, call: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerRule(ctx, "bkk01", lbUUID, ruleUUID)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				resp := response(req, `{"message":"not an empty success"}`)
				resp.StatusCode = test.status
				return resp, nil
			})
			client, err := inspace.NewClient(inspace.Options{
				BaseURL:                   "https://api.example.invalid",
				APIKey:                    "test-key",
				HTTPClient:                &http.Client{Transport: transport},
				DangerouslyAllowMutations: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = test.call(context.Background(), client)
			if err == nil || !strings.Contains(err.Error(), "expected an empty success body") {
				t.Fatalf("%s accepted non-empty HTTP %d success body: %v", test.name, test.status, err)
			}
		})
	}
}

func TestDeleteVMAcceptsOnlyEmptyOrWellFormedOptionalJSONSuccess(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "empty 200", status: http.StatusOK},
		{name: "empty 204", status: http.StatusNoContent},
		{name: "live JSON 200", status: http.StatusOK, body: `{"success":true}`},
		{name: "truncated JSON", status: http.StatusOK, body: `{"success":`, wantErr: true},
		{name: "trailing JSON", status: http.StatusOK, body: `{"success":true}{}`, wantErr: true},
		{name: "duplicate JSON key", status: http.StatusOK, body: `{"success":true,"success":false}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				resp := response(req, test.body)
				resp.StatusCode = test.status
				return resp, nil
			})
			client, err := inspace.NewClient(inspace.Options{
				BaseURL:                   "https://api.example.invalid",
				APIKey:                    "test-key",
				HTTPClient:                &http.Client{Transport: transport},
				DangerouslyAllowMutations: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = client.DeleteVM(context.Background(), "bkk01", vmUUID)
			if test.wantErr && err == nil {
				t.Fatal("accepted malformed optional VM DELETE response")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("rejected valid optional VM DELETE response: %v", err)
			}
		})
	}
}

func TestListResponsesRejectMalformedOrDuplicateElementIdentities(t *testing.T) {
	const uuid = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	calls := []struct {
		name             string
		validElement     string
		duplicateElement string
		malformedElement string
		call             func(context.Context, *inspace.Client) error
	}{
		{
			name: "locations", validElement: `{"slug":"bkk01"}`, duplicateElement: `{"slug":"bkk01"}`,
			malformedElement: `{"slug":"BKK 01"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListLocations(ctx)
				return err
			},
		},
		{
			name: "host pools", validElement: `{"uuid":"` + uuid + `"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB"}`,
			malformedElement: `{"uuid":"not-a-uuid"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListHostPools(ctx, "bkk01")
				return err
			},
		},
		{
			name: "VMs", validElement: `{"uuid":"` + uuid + `","name":"worker-a","status":"running"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB","name":"worker-b","status":"running"}`,
			malformedElement: `{"uuid":"not-a-uuid","name":"worker-a","status":"running"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListVMs(ctx, "bkk01")
				return err
			},
		},
		{
			name: "floating IPs", validElement: `{"address":"203.0.113.25","assigned_to":null}`, duplicateElement: `{"address":"203.0.113.25","assigned_to":null}`,
			malformedElement: `{"address":"10.0.0.25","assigned_to":null}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListFloatingIPs(ctx, "bkk01", nil)
				return err
			},
		},
		{
			name: "firewalls", validElement: `{"uuid":"` + uuid + `","display_name":"owned-a"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB","display_name":"owned-b"}`,
			malformedElement: `{"uuid":"not-a-uuid","display_name":"owned-a"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListFirewalls(ctx, "bkk01")
				return err
			},
		},
		{
			name: "load balancers", validElement: `{"uuid":"` + uuid + `","display_name":"owned-a","network_uuid":"` + networkUUID + `"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB","display_name":"owned-b","network_uuid":"` + networkUUID + `"}`,
			malformedElement: `{"uuid":"not-a-uuid","display_name":"owned-a","network_uuid":"` + networkUUID + `"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListLoadBalancers(ctx, "bkk01")
				return err
			},
		},
		{
			name: "networks", validElement: `{"uuid":"` + uuid + `"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB"}`,
			malformedElement: `{"uuid":"not-a-uuid"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListNetworks(ctx, "bkk01")
				return err
			},
		},
		{
			name: "VM images", validElement: `{"os_name":"ubuntu"}`, duplicateElement: `{"os_name":"Ubuntu"}`,
			malformedElement: `{"os_name":" ubuntu "}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListVMImages(ctx)
				return err
			},
		},
		{
			name: "disks", validElement: `{"uuid":"` + uuid + `"}`, duplicateElement: `{"uuid":"AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB"}`,
			malformedElement: `{"uuid":"not-a-uuid"}`,
			call: func(ctx context.Context, client *inspace.Client) error {
				_, err := client.ListDisks(ctx, "bkk01")
				return err
			},
		},
	}

	for _, call := range calls {
		for _, response := range []struct {
			name      string
			body      string
			wantError string
		}{
			{name: "null element", body: `[null]`, wantError: "invalid list element 0 identity"},
			{name: "empty element", body: `[{}]`, wantError: "invalid list element 0 identity"},
			{name: "malformed identity", body: `[` + call.malformedElement + `]`, wantError: "invalid list element 0 identity"},
			{name: "duplicate identity", body: `[` + call.validElement + `,` + call.duplicateElement + `]`, wantError: "duplicate canonical identity"},
		} {
			t.Run(call.name+"/"+response.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, response.body)
				}))
				t.Cleanup(server.Close)
				client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
				if err != nil {
					t.Fatal(err)
				}
				err = call.call(context.Background(), client)
				if err == nil || !strings.Contains(err.Error(), response.wantError) {
					t.Fatalf("list call error = %v, want %q", err, response.wantError)
				}
			})
		}
	}
}

func TestDeterministicDiscoveryListsRejectPartialUnrelatedRows(t *testing.T) {
	const unrelatedUUID = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	tests := []struct {
		name string
		body string
		call func(context.Context, *inspace.Client) error
	}{
		{name: "VM missing name", body: `[{"uuid":"` + unrelatedUUID + `","status":"running"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM null name", body: `[{"uuid":"` + unrelatedUUID + `","name":null,"status":"running"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM whitespace name", body: `[{"uuid":"` + unrelatedUUID + `","name":"   ","status":"running"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM missing status", body: `[{"uuid":"` + unrelatedUUID + `","name":"unrelated-worker"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM null status", body: `[{"uuid":"` + unrelatedUUID + `","name":"unrelated-worker","status":null}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "VM whitespace status", body: `[{"uuid":"` + unrelatedUUID + `","name":"unrelated-worker","status":"   "}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListVMs(ctx, "bkk01")
			return err
		}},
		{name: "firewall missing name", body: `[{"uuid":"` + unrelatedUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFirewalls(ctx, "bkk01")
			return err
		}},
		{name: "firewall null names", body: `[{"uuid":"` + unrelatedUUID + `","name":null,"display_name":null}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFirewalls(ctx, "bkk01")
			return err
		}},
		{name: "firewall whitespace effective name", body: `[{"uuid":"` + unrelatedUUID + `","display_name":"   "}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListFirewalls(ctx, "bkk01")
			return err
		}},
		{name: "load balancer missing name", body: `[{"uuid":"` + unrelatedUUID + `","network_uuid":"` + networkUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer null name", body: `[{"uuid":"` + unrelatedUUID + `","display_name":null,"network_uuid":"` + networkUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer whitespace name", body: `[{"uuid":"` + unrelatedUUID + `","display_name":"   ","network_uuid":"` + networkUUID + `"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer missing network", body: `[{"uuid":"` + unrelatedUUID + `","display_name":"unrelated-lb"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer null network", body: `[{"uuid":"` + unrelatedUUID + `","display_name":"unrelated-lb","network_uuid":null}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
		{name: "load balancer malformed network", body: `[{"uuid":"` + unrelatedUUID + `","display_name":"unrelated-lb","network_uuid":"not-a-uuid"}]`, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ListLoadBalancers(ctx, "bkk01")
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.call(context.Background(), client); err == nil {
				t.Fatalf("deterministic discovery accepted partial unrelated row %s", test.body)
			}
		})
	}
}

func TestCrossOriginRedirectNeverForwardsAPIKey(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if r.Header.Get("apikey") != "" {
			t.Error("redirect target received API key")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	client, err := inspace.NewClient(inspace.Options{BaseURL: source.URL, APIKey: "redirect-secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	if !errors.Is(err, inspace.ErrCrossOriginRedirect) {
		t.Fatalf("ListLocations() error = %v, want ErrCrossOriginRedirect", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestMutationRedirectIsNeverReplayed(t *testing.T) {
	var sourceRequests atomic.Int32
	var targetRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bkk01/user-resource/vm":
			sourceRequests.Add(1)
			w.Header().Set("Location", "/redirected-mutation")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/redirected-mutation":
			targetRequests.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateVM(context.Background(), "bkk01", inspace.CreateVMRequest{
		Name: "redirected", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
	})
	if !errors.Is(err, inspace.ErrMutationRedirect) {
		t.Fatalf("CreateVM() error = %v, want ErrMutationRedirect", err)
	}
	if got := sourceRequests.Load(); got != 1 {
		t.Fatalf("mutation source request count = %d, want 1", got)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("mutation redirect target request count = %d, want 0", got)
	}
}

func TestDefaultRedirectLimitIsRetained(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	if err == nil {
		t.Fatal("ListLocations() followed an unbounded redirect loop")
	}
}

func TestMutationGuardBlocksBeforeTransport(t *testing.T) {
	transport := &panicTransport{}
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateVM(context.Background(), "bkk01", inspace.CreateVMRequest{
		Name: "blocked", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
	})
	if !errors.Is(err, inspace.ErrMutationBlocked) {
		t.Fatalf("CreateVM() error = %v, want ErrMutationBlocked", err)
	}
}

func TestUpdateFloatingIPValidatesRequestBeforeTransport(t *testing.T) {
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: &panicTransport{}},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		address string
		request inspace.UpdateFloatingIPRequest
	}{
		{name: "private address", address: "10.0.0.10", request: inspace.UpdateFloatingIPRequest{Name: "owned-ip", BillingAccountID: 42}},
		{name: "missing name", address: "203.0.113.10", request: inspace.UpdateFloatingIPRequest{BillingAccountID: 42}},
		{name: "missing billing account", address: "203.0.113.10", request: inspace.UpdateFloatingIPRequest{Name: "owned-ip"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.UpdateFloatingIP(context.Background(), "bkk01", test.address, test.request); err == nil {
				t.Fatal("UpdateFloatingIP accepted invalid input")
			}
		})
	}
}

func TestUpdateFirewallValidatesRequestBeforeTransport(t *testing.T) {
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: &panicTransport{}},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	port := int32(443)
	validRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	tests := []struct {
		name         string
		location     string
		firewallUUID string
		request      inspace.UpdateFirewallRequest
	}{
		{name: "invalid firewall UUID", location: "bkk01", firewallUUID: "not-a-uuid", request: inspace.UpdateFirewallRequest{Name: "owned-firewall", Rules: []inspace.FirewallRule{validRule}}},
		{name: "missing name", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Rules: []inspace.FirewallRule{validRule}}},
		{name: "unsafe name", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "Owned Firewall", Rules: []inspace.FirewallRule{validRule}}},
		{name: "missing rules", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "owned-firewall"}},
		{name: "invalid rule UUID", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{
			Name: "owned-firewall",
			Rules: []inspace.FirewallRule{{
				UUID: "not-a-uuid", Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			}},
		}},
		{name: "invalid rule", location: "bkk01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{
			Name: "owned-firewall",
			Rules: []inspace.FirewallRule{{
				Protocol: "sctp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			}},
		}},
		{name: "invalid location", location: "BKK 01", firewallUUID: firewallUUID, request: inspace.UpdateFirewallRequest{Name: "owned-firewall", Rules: []inspace.FirewallRule{validRule}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.UpdateFirewall(context.Background(), test.location, test.firewallUUID, test.request); err == nil {
				t.Fatal("UpdateFirewall accepted invalid input")
			}
		})
	}
}

func TestReadRequestsHaveBoundedContext(t *testing.T) {
	var observedRemaining time.Duration
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("GET request reached transport without a context deadline")
		} else {
			observedRemaining = time.Until(deadline)
		}
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListLocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observedRemaining < 25*time.Second || observedRemaining > 31*time.Second {
		t.Fatalf("GET request deadline remaining = %s, want about 30s", observedRemaining)
	}
}

func TestReadRequestsPreserveShorterCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	callerDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("caller context has no deadline")
	}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		observedDeadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("GET request reached transport without a context deadline")
		} else if !observedDeadline.Equal(callerDeadline) {
			t.Errorf("GET request deadline = %s, want caller deadline %s", observedDeadline, callerDeadline)
		}
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListLocations(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMutationRequestsRetainLongerClientDeadline(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("mutation request did not retain the HTTP client deadline")
		} else if remaining := time.Until(deadline); remaining < 55*time.Second || remaining > 61*time.Second {
			t.Errorf("mutation request deadline remaining = %s, want about 1m", remaining)
		}
		resp := response(req, `{"uuid":"`+vmUUID+`"}`)
		resp.StatusCode = http.StatusCreated
		return resp, nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:                   "https://api.example.invalid",
		APIKey:                    "test-key",
		HTTPClient:                &http.Client{Transport: transport, Timeout: time.Minute},
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateVM(context.Background(), "bkk01", inspace.CreateVMRequest{
		Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadRequestCancellationInterruptsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	_, err = client.ListLocations(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListLocations() error = %v, want context deadline exceeded", err)
	}
}

func TestSameOriginReadRedirectIsBlocked(t *testing.T) {
	var redirectedRequests atomic.Int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/redirected" {
			redirect := response(req, "")
			redirect.StatusCode = http.StatusTemporaryRedirect
			redirect.Header.Set("Location", "/redirected")
			return redirect, nil
		}
		redirectedRequests.Add(1)
		return response(req, `[]`), nil
	})
	client, err := inspace.NewClient(inspace.Options{
		BaseURL:    "https://api.example.invalid",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListLocations(context.Background())
	if !errors.Is(err, inspace.ErrReadRedirect) {
		t.Fatalf("ListLocations() error = %v, want ErrReadRedirect", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("same-origin redirect target received %d requests, want 0", got)
	}
}

func TestOnlyBoundExactLookup404NormalizesAsNotFound(t *testing.T) {
	tests := []struct {
		name             string
		requested        string
		requestedAddress string
		call             func(context.Context, *inspace.Client) error
	}{
		{name: "VM", requested: vmUUID, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetVM(ctx, "bkk01", vmUUID)
			return err
		}},
		{name: "disk", requested: diskUUID, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetDisk(ctx, "bkk01", diskUUID)
			return err
		}},
		{name: "network", requested: networkUUID, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetNetwork(ctx, "bkk01", networkUUID)
			return err
		}},
		{name: "load balancer", requested: lbUUID, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetLoadBalancer(ctx, "bkk01", lbUUID)
			return err
		}},
		{name: "floating IP", requestedAddress: floatingIP, call: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.GetFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found", http.StatusNotFound)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			err = test.call(context.Background(), client)
			if !inspace.IsNotFound(err) {
				t.Fatalf("bound exact %s lookup error = %v, want not found", test.name, err)
			}
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || !apiErr.ExactLookup {
				t.Fatalf("bound exact %s APIError = %#v", test.name, apiErr)
			}
			if test.requestedAddress != "" {
				if apiErr.RequestedUUID != "" || apiErr.RequestedAddress != test.requestedAddress {
					t.Fatalf("bound exact %s APIError = %#v", test.name, apiErr)
				}
			} else if !strings.EqualFold(apiErr.RequestedUUID, test.requested) || apiErr.RequestedAddress != "" {
				t.Fatalf("bound exact %s APIError = %#v", test.name, apiErr)
			}
		})
	}

	t.Run("synthetic firewall list omission is not exact", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "[]")
		}))
		t.Cleanup(server.Close)
		client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetFirewall(context.Background(), "bkk01", firewallUUID)
		if err == nil || inspace.IsNotFound(err) {
			t.Fatalf("synthetic firewall list omission = %v, must not become exact absence", err)
		}
		var apiErr *inspace.APIError
		if !errors.As(err, &apiErr) || apiErr.ExactLookup || apiErr.RequestedUUID != "" {
			t.Fatalf("synthetic firewall lookup APIError = %#v, want unbound collection omission", apiErr)
		}
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "route not found", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListVMs(context.Background(), "bkk01")
	if err == nil || inspace.IsNotFound(err) {
		t.Fatalf("list-route 404 error = %v, must not become resource absence", err)
	}
	var apiErr *inspace.APIError
	if !errors.As(err, &apiErr) || apiErr.ExactLookup {
		t.Fatalf("list-route 404 APIError = %#v", apiErr)
	}

	if inspace.IsNotFound(&inspace.APIError{
		StatusCode:    http.StatusNotFound,
		Method:        http.MethodGet,
		Path:          "/v1/bkk01/user-resource/vm",
		Message:       "not found",
		RequestedUUID: vmUUID,
	}) {
		t.Fatal("unbound manually constructed 404 became resource absence")
	}
}

func TestDuplicateJSONKeysAreNeverAuthoritative(t *testing.T) {
	t.Run("successful collection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `[{"slug":"bkk01","slug":"bkk02"}]`)
		}))
		t.Cleanup(server.Close)
		client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.ListLocations(context.Background())
		if err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "slug"`) {
			t.Fatalf("duplicate successful JSON error = %v", err)
		}
	})

	t.Run("nested successful object", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"uuid":"`+vmUUID+`","tags":{"owner":"one","owner":"two"}}`)
		}))
		t.Cleanup(server.Close)
		client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetVM(context.Background(), "bkk01", vmUUID)
		if err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "owner"`) {
			t.Fatalf("nested duplicate successful JSON error = %v", err)
		}
	})

	t.Run("semantic HTTP 400", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"message":"permission denied","message":"No such virtual machine exists: `+vmUUID+`"}`)
		}))
		t.Cleanup(server.Close)
		client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.GetVM(context.Background(), "bkk01", vmUUID)
		var apiErr *inspace.APIError
		if !errors.As(err, &apiErr) || !apiErr.ResponseBodyMalformed {
			t.Fatalf("duplicate HTTP 400 APIError = %#v", apiErr)
		}
		if inspace.IsNotFound(err) {
			t.Fatalf("duplicate HTTP 400 became absence: %v", err)
		}
	})
}

func TestIsNotFoundNormalizesInSpaceMissingResourceResponse(t *testing.T) {
	const requestedUUID = "deadbeef-1111-4222-8333-444444444444"
	for _, message := range []string{
		"Error: No such virtual machine exists: " + requestedUUID,
		"No such virtual machine exists. DEADBEEF-1111-4222-8333-444444444444",
		"No such VM exists: " + requestedUUID,
		"No such virtual machine exists",
	} {
		if !inspace.IsNotFound(&inspace.APIError{
			StatusCode:    http.StatusBadRequest,
			Method:        http.MethodGet,
			Path:          "/v1/bkk01/user-resource/vm",
			Message:       message,
			ExactLookup:   true,
			RequestedUUID: requestedUUID,
		}) {
			t.Fatalf("expected InSpace's missing-VM HTTP 400 response %q to normalize as not found", message)
		}
	}
	for _, test := range []struct {
		name  string
		error *inspace.APIError
	}{
		{name: "invalid request", error: &inspace.APIError{Message: "invalid request"}},
		{name: "billing account", error: &inspace.APIError{Message: "No such billing account exists: 42"}},
		{name: "network", error: &inspace.APIError{Message: "No such network exists: deadbeef"}},
		{name: "disk", error: &inspace.APIError{Message: "No such disk exists: deadbeef"}},
		{name: "billing prose", error: &inspace.APIError{Message: "No such virtual machine exists for billing account 42"}},
		{name: "remaining attachment", error: &inspace.APIError{Message: "No such VM exists but remains attached"}},
		{name: "hyphenated prose", error: &inspace.APIError{Message: "No such virtual machine exists-or-is-authorized"}},
		{name: "authorization prose", error: &inspace.APIError{Message: "No such virtual machine exists: for another billing account"}},
		{name: "period prose", error: &inspace.APIError{Message: "No such virtual machine exists. access denied"}},
		{name: "empty suffix", error: &inspace.APIError{Message: "No such virtual machine exists:"}},
		{name: "malformed UUID", error: &inspace.APIError{Message: "No such virtual machine exists: deadbeef"}},
		{name: "trailing prose", error: &inspace.APIError{Message: "No such virtual machine exists: " + requestedUUID + " trailing prose"}},
		{name: "wrong endpoint", error: &inspace.APIError{Path: "/v1/bkk01/storage/disks/" + requestedUUID, Message: "No such virtual machine exists: " + requestedUUID}},
		{name: "list endpoint", error: &inspace.APIError{Path: "/v1/bkk01/user-resource/vm/list", Message: "No such virtual machine exists: " + requestedUUID}},
		{name: "noncanonical endpoint", error: &inspace.APIError{Path: "v1/bkk01/user-resource/vm", Message: "No such virtual machine exists: " + requestedUUID}},
		{name: "mutation method", error: &inspace.APIError{Method: http.MethodDelete, Message: "No such virtual machine exists: " + requestedUUID}},
		{name: "missing requested UUID", error: &inspace.APIError{RequestedUUID: "", Message: "No such virtual machine exists: " + requestedUUID}},
		{name: "different requested UUID", error: &inspace.APIError{RequestedUUID: "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb", Message: "No such virtual machine exists: " + requestedUUID}},
	} {
		test.error.StatusCode = http.StatusBadRequest
		test.error.ExactLookup = true
		if test.error.Method == "" {
			test.error.Method = http.MethodGet
		}
		if test.error.Path == "" {
			test.error.Path = "/v1/bkk01/user-resource/vm"
		}
		if test.error.RequestedUUID == "" && test.name != "missing requested UUID" {
			test.error.RequestedUUID = requestedUUID
		}
		if inspace.IsNotFound(test.error) {
			t.Fatalf("non-VM HTTP 400 case %q (%#v) must not normalize as not found", test.name, test.error)
		}
	}
}

func TestGetVMBindsHTTP400MissingResponseToRequestedUUID(t *testing.T) {
	const requestedUUID = "deadbeef-1111-4222-8333-444444444444"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/bkk01/user-resource/vm" || r.URL.Query().Get("uuid") != requestedUUID {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "No such virtual machine exists: "+requestedUUID, http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetVM(context.Background(), "bkk01", requestedUUID)
	if !inspace.IsNotFound(err) {
		t.Fatalf("GetVM() error = %v, want bound missing-VM normalization", err)
	}
}

func TestNonVMHTTP400MissingTextDoesNotNormalizeAsNotFound(t *testing.T) {
	const requestedUUID = "deadbeef-1111-4222-8333-444444444444"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "No such virtual machine exists: "+requestedUUID, http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetDisk(context.Background(), "bkk01", requestedUUID)
	if err == nil {
		t.Fatal("GetDisk() unexpectedly succeeded")
	}
	if inspace.IsNotFound(err) {
		t.Fatalf("GetDisk() error = %v, must not normalize VM text from a disk endpoint", err)
	}
}

type panicTransport struct{}

func (*panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("mutation guard allowed a request to reach transport")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic response body failure")
}

func response(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

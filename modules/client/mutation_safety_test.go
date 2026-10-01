package inspace_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

type clientMutationCase struct {
	name   string
	method string
	invoke func(context.Context, *inspace.Client) error
}

func TestEveryMutationDispatchesOnceOnHTTP500(t *testing.T) {
	tests := clientMutationInventory()
	if len(tests) != 26 {
		t.Fatalf("mutation inventory contains %d methods, want 26", len(tests))
	}
	covered := make(map[string]struct{}, len(tests))
	for _, test := range tests {
		covered[test.name] = struct{}{}
	}
	mutationPrefixes := []string{"Create", "Delete", "Attach", "Detach", "Assign", "Unassign", "Update", "Add", "Remove", "Resize", "Stop", "Start"}
	clientType := reflect.TypeOf((*inspace.Client)(nil))
	discovered := 0
	for index := 0; index < clientType.NumMethod(); index++ {
		name := clientType.Method(index).Name
		mutation := false
		for _, prefix := range mutationPrefixes {
			mutation = mutation || strings.HasPrefix(name, prefix)
		}
		if !mutation {
			continue
		}
		discovered++
		if _, ok := covered[name]; !ok {
			t.Fatalf("exported mutation-like Client method %s lacks the HTTP 500 single-dispatch contract", name)
		}
	}
	if discovered != len(tests) {
		t.Fatalf("discovered %d mutation-like Client methods, covered %d", discovered, len(tests))
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Method != test.method {
					t.Errorf("HTTP method = %s, want %s", request.Method, test.method)
				}
				http.Error(w, "committed state is unknown", http.StatusInternalServerError)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			err = test.invoke(context.Background(), client)
			var apiErr *inspace.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError || !apiErr.Retryable {
				t.Fatalf("%s error = %#v, want retryable HTTP 500", test.name, err)
			}
			if errors.Is(err, inspace.ErrMutationNotDispatched) {
				t.Fatalf("%s dispatched HTTP 500 was classified as not dispatched", test.name)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("%s dispatched %d requests after HTTP 500, want exactly one", test.name, got)
			}
		})
	}
}

func TestEveryMutationWithDoneContextIsProvablyNotDispatched(t *testing.T) {
	for _, test := range clientMutationInventory() {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				http.Error(w, "must not be reached", http.StatusInternalServerError)
			}))
			t.Cleanup(server.Close)
			client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err = test.invoke(ctx, client)
			if !errors.Is(err, inspace.ErrMutationNotDispatched) || !errors.Is(err, context.Canceled) {
				t.Fatalf("%s error = %v, want not-dispatched context cancellation", test.name, err)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("%s dispatched %d requests with a done context", test.name, got)
			}
		})
	}
}

func TestFirewallMutationLocalValidationIsProvablyNotDispatched(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "must not be reached", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	badPort := int32(0)
	badRule := inspace.FirewallRule{Protocol: "tcp", Direction: "inbound", PortStart: &badPort, PortEnd: &badPort, EndpointSpecType: "any"}
	for name, invoke := range map[string]func() error{
		"CreateFirewall empty name": func() error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{Rules: []inspace.FirewallRule{badRule}})
			return err
		},
		"CreateFirewall invalid rule": func() error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{DisplayName: "owned", Rules: []inspace.FirewallRule{badRule}})
			return err
		},
		"CreateFirewall invalid location": func() error {
			port := int32(443)
			_, err := client.CreateFirewall(ctx, "BKK 01", inspace.CreateFirewallRequest{DisplayName: "owned", Rules: []inspace.FirewallRule{{
				Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
			}}})
			return err
		},
		"UpdateFirewall invalid rule": func() error {
			_, err := client.UpdateFirewall(ctx, "bkk01", firewallUUID, inspace.UpdateFirewallRequest{Name: "owned", Rules: []inspace.FirewallRule{badRule}})
			return err
		},
		"UpdateFirewall invalid UUID": func() error {
			_, err := client.UpdateFirewall(ctx, "bkk01", "not-a-uuid", inspace.UpdateFirewallRequest{Name: "owned", Rules: []inspace.FirewallRule{badRule}})
			return err
		},
		"DeleteFirewall invalid UUID":   func() error { return client.DeleteFirewall(ctx, "bkk01", "not-a-uuid") },
		"AssignFirewallToVM invalid VM": func() error { return client.AssignFirewallToVM(ctx, "bkk01", firewallUUID, "not-a-uuid") },
		"UnassignFirewallFromVM invalid VM": func() error {
			return client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, "not-a-uuid")
		},
	} {
		if err := invoke(); !errors.Is(err, inspace.ErrMutationNotDispatched) {
			t.Fatalf("%s error = %v, want ErrMutationNotDispatched", name, err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("local firewall validation dispatched %d requests", got)
	}
}

func clientMutationInventory() []clientMutationCase {
	port := int32(443)
	firewallRule := inspace.FirewallRule{
		Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "any",
	}
	return []clientMutationCase{
		{name: "CreateVM", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateVM(ctx, "bkk01", inspace.CreateVMRequest{
				Name: "worker", OSName: "ubuntu", OSVersion: "24.04", DiskGiB: 40, VCPU: 2, MemoryMiB: 4096,
			})
			return err
		}},
		{name: "DeleteVM", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteVM(ctx, "bkk01", vmUUID)
		}},
		{name: "CreateDisk", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateDisk(ctx, "bkk01", inspace.CreateDiskRequest{DisplayName: "data", SizeGiB: 40, BillingAccountID: 42})
			return err
		}},
		{name: "DeleteDisk", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteDisk(ctx, "bkk01", diskUUID)
		}},
		{name: "AttachDisk", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AttachDisk(ctx, "bkk01", vmUUID, diskUUID)
			return err
		}},
		{name: "DetachDisk", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DetachDisk(ctx, "bkk01", vmUUID, diskUUID)
		}},
		{name: "StopVM", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.StopVM(ctx, "bkk01", vmUUID)
		}},
		{name: "StartVM", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.StartVM(ctx, "bkk01", vmUUID)
		}},
		{name: "UpdateVMCompute", method: http.MethodPatch, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateVMCompute(ctx, "bkk01", vmUUID, 2, 6144)
			return err
		}},
		{name: "ResizeAttachedDisk", method: http.MethodPatch, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.ResizeAttachedDisk(ctx, "bkk01", vmUUID, diskUUID, 60)
			return err
		}},
		{name: "CreateFloatingIP", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "owned-ip", BillingAccountID: 42})
			return err
		}},
		{name: "UpdateFloatingIP", method: http.MethodPatch, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFloatingIP(ctx, "bkk01", floatingIP, inspace.UpdateFloatingIPRequest{Name: "owned-ip", BillingAccountID: 42})
			return err
		}},
		{name: "AssignFloatingIP", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, lbUUID, "load_balancer")
			return err
		}},
		{name: "UnassignFloatingIP", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP)
			return err
		}},
		{name: "DeleteFloatingIP", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFloatingIP(ctx, "bkk01", floatingIP)
		}},
		{name: "CreateFirewall", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{
				DisplayName: "owned-firewall", BillingAccountID: 42, Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "UpdateFirewall", method: http.MethodPut, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.UpdateFirewall(ctx, "bkk01", firewallUUID, inspace.UpdateFirewallRequest{
				Name: "owned-firewall", Rules: []inspace.FirewallRule{firewallRule},
			})
			return err
		}},
		{name: "DeleteFirewall", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteFirewall(ctx, "bkk01", firewallUUID)
		}},
		{name: "AssignFirewallToVM", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.AssignFirewallToVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "UnassignFirewallFromVM", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, vmUUID)
		}},
		{name: "CreateLoadBalancer", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.CreateLoadBalancer(ctx, "bkk01", inspace.CreateLoadBalancerRequest{
				DisplayName: "owned-lb", BillingAccountID: 42, NetworkUUID: networkUUID,
				Rules: []inspace.LoadBalancerRule{{Protocol: "TCP", SourcePort: 443, TargetPort: 30443}},
			})
			return err
		}},
		{name: "DeleteLoadBalancer", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.DeleteLoadBalancer(ctx, "bkk01", lbUUID)
		}},
		{name: "AddLoadBalancerTarget", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
			return err
		}},
		{name: "RemoveLoadBalancerTarget", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID)
		}},
		{name: "AddLoadBalancerRule", method: http.MethodPost, invoke: func(ctx context.Context, client *inspace.Client) error {
			_, err := client.AddLoadBalancerRule(ctx, "bkk01", lbUUID, inspace.LoadBalancerRule{Protocol: "TCP", SourcePort: 443, TargetPort: 30443})
			return err
		}},
		{name: "RemoveLoadBalancerRule", method: http.MethodDelete, invoke: func(ctx context.Context, client *inspace.Client) error {
			return client.RemoveLoadBalancerRule(ctx, "bkk01", lbUUID, ruleUUID)
		}},
	}
}

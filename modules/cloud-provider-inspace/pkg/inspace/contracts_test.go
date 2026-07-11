package inspace_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace/pkg/inspace"
)

const (
	diskUUID     = "11111111-2222-4333-8444-555555555555"
	vmUUID       = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
	networkUUID  = "22222222-3333-4444-8555-666666666666"
	lbUUID       = "33333333-4444-4555-8666-777777777777"
	ruleUUID     = "44444444-5555-4666-8777-888888888888"
	firewallUUID = "55555555-6666-4777-8888-999999999999"
	floatingIP   = "203.0.113.25"
)

func TestDocumentedResourceContracts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(contractHandler(t)))
	t.Cleanup(server.Close)
	client, err := inspace.NewClient(inspace.Options{BaseURL: server.URL, APIKey: "literal-fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	disk, err := client.CreateDisk(ctx, "bkk01", inspace.CreateDiskRequest{
		DisplayName: "data", SizeGiB: 50, BillingAccountID: 129673,
	})
	if err != nil || disk.UUID != diskUUID || disk.SizeGiB != 50 || disk.StoragePoolUUID == "" {
		t.Fatalf("CreateDisk() = %#v, %v", disk, err)
	}
	gotDisk, err := client.GetDisk(ctx, "bkk01", diskUUID)
	if err != nil || gotDisk.DisplayName != "data" || len(gotDisk.Snapshots) != 1 {
		t.Fatalf("GetDisk() = %#v, %v", gotDisk, err)
	}
	disks, err := client.ListDisks(ctx, "bkk01")
	if err != nil || len(disks) != 1 || disks[0].UUID != diskUUID {
		t.Fatalf("ListDisks() = %#v, %v", disks, err)
	}
	attached, err := client.AttachDisk(ctx, "bkk01", vmUUID, diskUUID)
	if err != nil || attached.UUID != diskUUID || attached.Name != "vdb" {
		t.Fatalf("AttachDisk() = %#v, %v", attached, err)
	}
	if err := client.DetachDisk(ctx, "bkk01", vmUUID, diskUUID); err != nil {
		t.Fatalf("DetachDisk(): %v", err)
	}
	if err := client.DeleteDisk(ctx, "bkk01", diskUUID); err != nil {
		t.Fatalf("DeleteDisk(): %v", err)
	}

	networks, err := client.ListNetworks(ctx, "bkk01")
	if err != nil || len(networks) != 1 || networks[0].UUID != networkUUID || networks[0].Subnet != "10.4.200.0/24" {
		t.Fatalf("ListNetworks() = %#v, %v", networks, err)
	}
	network, err := client.GetNetwork(ctx, "bkk01", networkUUID)
	if err != nil || network.UUID != networkUUID {
		t.Fatalf("GetNetwork() = %#v, %v", network, err)
	}
	images, err := client.ListVMImages(ctx)
	if err != nil || len(images) != 1 || images[0].OSName != "ubuntu" || images[0].Versions[0].OSVersion != "24.04" {
		t.Fatalf("ListVMImages() = %#v, %v", images, err)
	}

	lb, err := client.CreateLoadBalancer(ctx, "bkk01", inspace.CreateLoadBalancerRequest{
		DisplayName: "k8s-owned", BillingAccountID: 129673, NetworkUUID: networkUUID,
		Rules:   []inspace.LoadBalancerRule{{SourcePort: 443, TargetPort: 30443}},
		Targets: []inspace.LoadBalancerTarget{{TargetUUID: vmUUID, TargetType: "vm"}},
	})
	if err != nil || lb.UUID != lbUUID || lb.PrivateAddress != "10.112.231.192" {
		t.Fatalf("CreateLoadBalancer() = %#v, %v", lb, err)
	}
	lbs, err := client.ListLoadBalancers(ctx, "bkk01")
	if err != nil || len(lbs) != 1 || lbs[0].ForwardingRules[0].Protocol != "TCP" {
		t.Fatalf("ListLoadBalancers() = %#v, %v", lbs, err)
	}
	if _, err := client.GetLoadBalancer(ctx, "bkk01", lbUUID); err != nil {
		t.Fatalf("GetLoadBalancer(): %v", err)
	}
	if _, err := client.AddLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID); err != nil {
		t.Fatalf("AddLoadBalancerTarget(): %v", err)
	}
	if _, err := client.AddLoadBalancerRule(ctx, "bkk01", lbUUID, inspace.LoadBalancerRule{SourcePort: 6443, TargetPort: 6443}); err != nil {
		t.Fatalf("AddLoadBalancerRule(): %v", err)
	}
	if err := client.RemoveLoadBalancerTarget(ctx, "bkk01", lbUUID, vmUUID); err != nil {
		t.Fatalf("RemoveLoadBalancerTarget(): %v", err)
	}
	if err := client.RemoveLoadBalancerRule(ctx, "bkk01", lbUUID, ruleUUID); err != nil {
		t.Fatalf("RemoveLoadBalancerRule(): %v", err)
	}
	if err := client.DeleteLoadBalancer(ctx, "bkk01", lbUUID); err != nil {
		t.Fatalf("DeleteLoadBalancer(): %v", err)
	}

	port := int32(6443)
	firewall, err := client.CreateFirewall(ctx, "bkk01", inspace.CreateFirewallRequest{
		DisplayName: "k8s-firewall", BillingAccountID: 129673,
		Rules: []inspace.FirewallRule{{Protocol: "tcp", Direction: "inbound", PortStart: &port, PortEnd: &port, EndpointSpecType: "ip_prefixes", EndpointSpec: []string{"10.4.200.0/24"}}},
	})
	if err != nil || firewall.UUID != firewallUUID {
		t.Fatalf("CreateFirewall() = %#v, %v", firewall, err)
	}
	if items, err := client.ListFirewalls(ctx, "bkk01"); err != nil || len(items) != 1 {
		t.Fatalf("ListFirewalls() = %#v, %v", items, err)
	}
	if got, err := client.GetFirewall(ctx, "bkk01", firewallUUID); err != nil || got.EffectiveName() != "k8s-firewall" {
		t.Fatalf("GetFirewall() = %#v, %v", got, err)
	}
	if err := client.AssignFirewallToVM(ctx, "bkk01", firewallUUID, vmUUID); err != nil {
		t.Fatalf("AssignFirewallToVM(): %v", err)
	}
	if err := client.UnassignFirewallFromVM(ctx, "bkk01", firewallUUID, vmUUID); err != nil {
		t.Fatalf("UnassignFirewallFromVM(): %v", err)
	}
	if err := client.DeleteFirewall(ctx, "bkk01", firewallUUID); err != nil {
		t.Fatalf("DeleteFirewall(): %v", err)
	}

	createdIP, err := client.CreateFloatingIP(ctx, "bkk01", inspace.CreateFloatingIPRequest{Name: "k8s-ip", BillingAccountID: 129673})
	if err != nil || createdIP.Address != floatingIP {
		t.Fatalf("CreateFloatingIP() = %#v, %v", createdIP, err)
	}
	ips, err := client.ListFloatingIPs(ctx, "bkk01", &inspace.FloatingIPFilters{BillingAccountID: 129673, VMUUID: vmUUID})
	if err != nil || len(ips) != 1 || ips[0].Address != floatingIP {
		t.Fatalf("ListFloatingIPs() = %#v, %v", ips, err)
	}
	assignedIP, err := client.AssignFloatingIP(ctx, "bkk01", floatingIP, vmUUID, "virtual_machine")
	if err != nil || assignedIP.AssignedTo != vmUUID {
		t.Fatalf("AssignFloatingIP() = %#v, %v", assignedIP, err)
	}
	if _, err := client.UnassignFloatingIP(ctx, "bkk01", floatingIP); err != nil {
		t.Fatalf("UnassignFloatingIP(): %v", err)
	}
	if err := client.DeleteFloatingIP(ctx, "bkk01", floatingIP); err != nil {
		t.Fatalf("DeleteFloatingIP(): %v", err)
	}
}

func contractHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") != "literal-fixture-key" {
			http.Error(w, `{"message":"bad key"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/bkk01/storage/disks":
			assertForm(t, r, url.Values{"display_name": {"data"}, "size_gb": {"50"}, "billing_account_id": {"129673"}, "source_image_type": {"EMPTY"}})
			writeLiteral(w, http.StatusCreated, diskLiteral(false))
		case "GET /v1/bkk01/storage/disks/" + diskUUID:
			writeLiteral(w, http.StatusOK, diskLiteral(true))
		case "GET /v1/bkk01/storage/disks":
			writeLiteral(w, http.StatusOK, "["+diskLiteral(false)+"]")
		case "DELETE /v1/bkk01/storage/disks/" + diskUUID:
			w.WriteHeader(http.StatusNoContent)
		case "POST /v1/bkk01/user-resource/vm/storage/attach":
			assertForm(t, r, url.Values{"uuid": {vmUUID}, "storage_uuid": {diskUUID}})
			writeLiteral(w, http.StatusOK, `{"uuid":"`+diskUUID+`","name":"vdb","size":50,"primary":false}`)
		case "POST /v1/bkk01/user-resource/vm/storage/detach":
			assertForm(t, r, url.Values{"uuid": {vmUUID}, "storage_uuid": {diskUUID}})
			writeLiteral(w, http.StatusOK, `{"success":true}`)
		case "GET /v1/bkk01/network/networks":
			writeLiteral(w, http.StatusOK, `[{"vlan_id":965,"subnet":"10.4.200.0/24","name":"Private network","uuid":"`+networkUUID+`","type":"private","is_default":true,"vm_uuids":[],"resources_count":0}]`)
		case "GET /v1/bkk01/network/network/" + networkUUID:
			writeLiteral(w, http.StatusOK, `{"vlan_id":965,"subnet":"10.4.200.0/24","name":"Private network","uuid":"`+networkUUID+`","type":"private","is_default":true,"vm_uuids":[],"resources_count":0}`)
		case "GET /v1/config/vm_images":
			writeLiteral(w, http.StatusOK, `[{"os_name":"ubuntu","display_name":"Ubuntu","is_default":true,"is_app_catalog":false,"versions":[{"os_version":"24.04","display_name":"24.04","published":true}]}]`)
		case "POST /v1/bkk01/network/load_balancers":
			var got inspace.CreateLoadBalancerRequest
			decodeJSON(t, r, &got)
			if got.DisplayName != "k8s-owned" || got.NetworkUUID != networkUUID || len(got.Rules) != 1 || got.Rules[0].TargetPort != 30443 {
				t.Errorf("CreateLoadBalancer body = %#v", got)
			}
			writeLiteral(w, http.StatusCreated, loadBalancerLiteral())
		case "GET /v1/bkk01/network/load_balancers":
			writeLiteral(w, http.StatusOK, "["+loadBalancerLiteral()+"]")
		case "GET /v1/bkk01/network/load_balancers/" + lbUUID:
			writeLiteral(w, http.StatusOK, loadBalancerLiteral())
		case "POST /v1/bkk01/network/load_balancers/" + lbUUID + "/targets":
			writeLiteral(w, http.StatusOK, `{"target_uuid":"`+vmUUID+`","target_type":"vm","target_ip_address":"10.0.0.10"}`)
		case "POST /v1/bkk01/network/load_balancers/" + lbUUID + "/forwarding_rules":
			writeLiteral(w, http.StatusOK, `{"uuid":"`+ruleUUID+`","protocol":"TCP","source_port":6443,"target_port":6443}`)
		case "DELETE /v1/bkk01/network/load_balancers/" + lbUUID + "/targets/" + vmUUID,
			"DELETE /v1/bkk01/network/load_balancers/" + lbUUID + "/forwarding_rules/" + ruleUUID,
			"DELETE /v1/bkk01/network/load_balancers/" + lbUUID:
			w.WriteHeader(http.StatusNoContent)
		case "GET /v1/bkk01/network/firewalls":
			writeLiteral(w, http.StatusOK, `[{"uuid":"`+firewallUUID+`","display_name":"k8s-firewall","billing_account_id":129673,"rules":[{"protocol":"tcp","direction":"inbound","port_start":6443,"port_end":6443,"endpoint_spec_type":"ip_prefixes","endpoint_spec":["10.4.200.0/24"]}],"resources_assigned":[]}]`)
		case "POST /v1/bkk01/network/firewalls":
			writeLiteral(w, http.StatusCreated, `{"uuid":"`+firewallUUID+`","display_name":"k8s-firewall","billing_account_id":129673,"rules":[],"resources_assigned":[]}`)
		case "POST /v1/bkk01/network/firewalls/" + firewallUUID + "/vms":
			if r.URL.Query().Get("vm_uuid") != vmUUID {
				t.Errorf("firewall assign query = %s", r.URL.RawQuery)
			}
			writeLiteral(w, http.StatusOK, `[{"resource_type":"vm","resource_uuid":"`+vmUUID+`"}]`)
		case "DELETE /v1/bkk01/network/firewalls/" + firewallUUID + "/vms",
			"DELETE /v1/bkk01/network/firewalls/" + firewallUUID:
			w.WriteHeader(http.StatusNoContent)
		case "POST /v1/bkk01/network/ip_addresses":
			writeLiteral(w, http.StatusCreated, floatingIPLiteral(false))
		case "GET /v1/bkk01/network/ip_addresses":
			if r.URL.Query().Get("billing_account_id") != "129673" || r.URL.Query().Get("vm_uuid") != vmUUID {
				t.Errorf("floating IP query = %s", r.URL.RawQuery)
			}
			writeLiteral(w, http.StatusOK, "["+floatingIPLiteral(false)+"]")
		case "POST /v1/bkk01/network/ip_addresses/" + floatingIP + "/assign":
			writeLiteral(w, http.StatusOK, floatingIPLiteral(true))
		case "POST /v1/bkk01/network/ip_addresses/" + floatingIP + "/unassign":
			writeLiteral(w, http.StatusOK, floatingIPLiteral(false))
		case "DELETE /v1/bkk01/network/ip_addresses/" + floatingIP:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}
}

func diskLiteral(withSnapshot bool) string {
	snapshots := "[]"
	if withSnapshot {
		snapshots = `[{"uuid":"55555555-6666-4777-8888-999999999999","disk_uuid":"` + diskUUID + `","size_gb":50,"display_name":"before update"}]`
	}
	return `{"uuid":"` + diskUUID + `","status":"Active","display_name":"data","billing_account_id":129673,"size_gb":50,"source_image_type":"EMPTY","storage_pool_uuid":"66666666-7777-4888-8999-aaaaaaaaaaaa","snapshots":` + snapshots + `}`
}

func loadBalancerLiteral() string {
	return `{"uuid":"` + lbUUID + `","display_name":"k8s-owned","network_uuid":"` + networkUUID + `","billing_account_id":129673,"private_address":"10.112.231.192","is_deleted":false,"forwarding_rules":[{"uuid":"` + ruleUUID + `","protocol":"TCP","source_port":443,"target_port":30443}],"targets":[{"target_uuid":"` + vmUUID + `","target_type":"vm","target_ip_address":"10.0.0.10"}]}`
}

func floatingIPLiteral(assigned bool) string {
	assignment := `"assigned_to":null`
	if assigned {
		assignment = `"assigned_to":"` + vmUUID + `","assigned_to_resource_type":"virtual_machine","assigned_to_private_ip":"10.4.200.10"`
	}
	return `{"address":"` + floatingIP + `","name":"k8s-ip","billing_account_id":129673,"type":"public","enabled":true,"is_deleted":false,"is_virtual":false,` + assignment + `}`
}

func assertForm(t *testing.T, r *http.Request, want url.Values) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.PostForm, want) {
		t.Errorf("form = %#v, want %#v", r.PostForm, want)
	}
}

func decodeJSON(t *testing.T, r *http.Request, out any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func writeLiteral(w http.ResponseWriter, status int, fixture string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, fixture)
}

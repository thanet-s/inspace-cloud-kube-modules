package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCachedReconcilePublishesBastionAddressAndVPCOnlyRegistry(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	cluster.Spec.BootstrapCache.DirectDownload = false
	reconciler := cacheContractReconciler(api)

	result := reconcileUntilReady(t, reconciler, cluster)
	if !result.Ready {
		t.Fatalf("cached cluster did not become ready: %#v", result)
	}
	hostname := bootstrapCacheHostname(cluster.Metadata.Name)
	bastion := mustVM(t, api.vms, currentBastionName(cluster.Metadata.Name))
	wantEndpoint := "https://" + hostname + ":8443"
	wantRegistry := hostname + ":8443"
	if result.BootstrapCacheEndpoint != wantEndpoint || result.BootstrapCacheRegistry != wantRegistry {
		t.Fatalf("cache endpoints=%q/%q, want %q/%q", result.BootstrapCacheEndpoint, result.BootstrapCacheRegistry, wantEndpoint, wantRegistry)
	}
	if result.BootstrapCacheAddress != bastion.PrivateIPv4 || result.BootstrapCacheAddress != result.BastionPrivateIPv4 {
		t.Fatalf("cache address=%q bastion=%q result-bastion=%q", result.BootstrapCacheAddress, bastion.PrivateIPv4, result.BastionPrivateIPv4)
	}
	if result.BootstrapCacheAddress == "" || result.BootstrapCacheAddress == cluster.Spec.Endpoint.VirtualIPv4 || strings.Contains(result.BootstrapCacheEndpoint, result.BootstrapCacheAddress) {
		t.Fatalf("cache address was treated as a control-plane/cache VIP: %#v", result)
	}

	wantTLS, err := deriveCacheTLS(
		reconciler.BootstrapCacheKey,
		ownerKey(cluster),
		hostname,
		reconciler.BootstrapCacheNotBefore,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.BootstrapCacheCABundle != wantTLS.CACertificate {
		t.Fatal("reconcile result did not publish the exact derived public CA")
	}
	cacheContractCertificate(t, result.BootstrapCacheCABundle)

	resourceNames := currentBootstrapResourceNames(cluster.Metadata.Name, ownerKey(cluster))
	bastionFirewall := mustFirewall(t, api.firewalls, resourceNames.BastionFirewall)
	if err := validateBastionFirewallPolicy(bastionFirewall, reconciler.ManagementCIDR, api.network.Subnet, true); err != nil {
		t.Fatalf("cached bastion firewall is invalid: %v", err)
	}
	cacheIngress := 0
	for _, rule := range bastionFirewall.Rules {
		if rule.Direction == "inbound" && rule.PortStart != nil && *rule.PortStart == BootstrapCachePort {
			cacheIngress++
			if rule.Protocol != "tcp" || rule.PortEnd == nil || *rule.PortEnd != BootstrapCachePort ||
				rule.EndpointSpecType != "ip_prefixes" || len(rule.EndpointSpec) != 1 || rule.EndpointSpec[0] != api.network.Subnet {
				t.Fatalf("cache ingress is not exact VPC TCP/8443: %#v", rule)
			}
		}
	}
	if cacheIngress != 1 {
		t.Fatalf("cache TCP/8443 ingress rule count=%d, want 1", cacheIngress)
	}

	bastionRequest := mustVMRequest(t, api.vmCreates, currentBastionName(cluster.Metadata.Name))
	bastionFiles := cacheContractDecodeCloudInit(t, bastionRequest.CloudInit)
	imageManifest := bastionFiles["/etc/inspace-cache/images.tsv"].Content
	if got := len(strings.Split(strings.TrimSuffix(imageManifest, "\n"), "\n")); got != 32 {
		t.Fatalf("reconciled bastion image manifest entries=%d, want 32 with disabled ingress", got)
	}
	if !strings.Contains(imageManifest, ":"+reconciler.ModuleVersion+"\tthanet-s/inspace-cloud-controller-manager:"+reconciler.ModuleVersion) {
		t.Fatalf("reconciled bastion did not pin the requested module version:\n%s", imageManifest)
	}

	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		request := mustVMRequest(t, api.vmCreates, controlPlaneName(cluster.Metadata.Name, slot))
		files := cacheContractDecodeCloudInit(t, request.CloudInit)
		config := files["/var/lib/inspace/rke2-config"].Content
		script := files["/usr/local/sbin/inspace-bootstrap-rke2"].Content
		registries := files["/etc/rancher/rke2/registries.yaml"].Content
		kubeVIP := files["/var/lib/inspace/rke2-kube-vip"].Content
		for _, required := range []string{
			`system-default-registry: "` + wantRegistry + `"`,
			"cache_address='" + bastion.PrivateIPv4 + "'",
			"cache_hostname='" + hostname + "'",
			`printf '%s %s # inspace-bootstrap-cache\n' "$cache_address" "$cache_hostname" >>/etc/hosts`,
		} {
			if !strings.Contains(config+script, required) {
				t.Errorf("slot %d cached cloud-init lacks %q", slot, required)
			}
		}
		if files["/etc/rancher/rke2/bootstrap-cache-ca.crt"].Content != result.BootstrapCacheCABundle ||
			!strings.Contains(registries, `"`+wantRegistry+`"`) ||
			!strings.Contains(kubeVIP, wantRegistry+"/"+cachedKubeVIPImage) {
			t.Fatalf("slot %d does not use the reconciled cache contract", slot)
		}
		if strings.Contains(config+script+registries+kubeVIP, cluster.Spec.Endpoint.VirtualIPv4+":8443") {
			t.Fatalf("slot %d incorrectly used the control-plane VIP as the cache address", slot)
		}
	}
}

func TestCachedReconcilePropagatesSkipOSUpgradeToEveryFixedVM(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	cluster.Spec.BootstrapCache.DirectDownload = false
	cluster.Spec.RKE2.SkipOSUpgrade = true
	reconciler := cacheContractReconciler(api)
	reconcileUntilReady(t, reconciler, cluster)

	bastionRequest := mustVMRequest(t, api.vmCreates, currentBastionName(cluster.Metadata.Name))
	bastionScript := cacheContractDecodeCloudInit(t, bastionRequest.CloudInit)["/usr/local/sbin/inspace-bootstrap-cache-bastion"].Content
	if strings.Contains(bastionScript, "upgrade -y") || !strings.Contains(bastionScript, "apt-get -o Acquire::Retries=3") ||
		!strings.Contains(bastionScript, "install -y --no-install-recommends ca-certificates curl e2fsprogs gnupg iproute2 skopeo util-linux") {
		t.Fatalf("reconciled cache bastion did not skip only the OS upgrade:\n%s", bastionScript)
	}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		request := mustVMRequest(t, api.vmCreates, controlPlaneName(cluster.Metadata.Name, slot))
		script := cacheContractDecodeCloudInit(t, request.CloudInit)["/usr/local/sbin/inspace-bootstrap-rke2"].Content
		if strings.Contains(script, "upgrade -y") || !strings.Contains(script, "apt-get -o Acquire::Retries=3") ||
			!strings.Contains(script, "install -y --no-install-recommends ca-certificates curl iproute2 procps tar") {
			t.Fatalf("reconciled control plane %d did not skip only the OS upgrade:\n%s", slot, script)
		}
	}
}

func TestCachedReconcileRequiresPersistedKeyTimestampAndModuleBeforeMutation(t *testing.T) {
	notBefore := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	key := []byte("0123456789abcdef0123456789abcdef")
	tests := []struct {
		name      string
		configure func(*Reconciler)
		want      string
	}{
		{
			name: "key",
			configure: func(reconciler *Reconciler) {
				reconciler.BootstrapCacheNotBefore = notBefore
				reconciler.ModuleVersion = "0.3.1-rc.2"
			},
			want: "persisted 32-byte INSPACE_BOOTSTRAP_CACHE_KEY",
		},
		{
			name: "timestamp",
			configure: func(reconciler *Reconciler) {
				reconciler.BootstrapCacheKey = append([]byte(nil), key...)
				reconciler.ModuleVersion = "0.3.1-rc.2"
			},
			want: "persisted UTC time with one-second precision",
		},
		{
			name: "module",
			configure: func(reconciler *Reconciler) {
				reconciler.BootstrapCacheKey = append([]byte(nil), key...)
				reconciler.BootstrapCacheNotBefore = notBefore
			},
			want: "exact released module version",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := newFakeAPI()
			cluster := testCluster()
			cluster.Spec.BootstrapCache.DirectDownload = false
			reconciler := testReconciler(api)
			test.configure(reconciler)

			_, err := reconciler.Reconcile(context.Background(), cluster, "unit-test-secret-token")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("missing cached-mode %s: error=%v, want substring %q", test.name, err, test.want)
			}
			if len(api.vmCreates) != 0 || len(api.firewallCreates) != 0 || len(api.floatingIPs) != 0 || len(api.events) != 0 {
				t.Fatalf("missing cached-mode %s caused mutation: VMs=%d firewalls=%d FIPs=%d events=%v", test.name, len(api.vmCreates), len(api.firewallCreates), len(api.floatingIPs), api.events)
			}
		})
	}
}

func cacheContractReconciler(api *fakeAPI) *Reconciler {
	reconciler := testReconciler(api)
	reconciler.BootstrapCacheKey = []byte("0123456789abcdef0123456789abcdef")
	reconciler.BootstrapCacheNotBefore = time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	reconciler.ModuleVersion = "0.3.1-rc.2"
	return reconciler
}

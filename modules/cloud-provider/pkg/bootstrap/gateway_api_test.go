package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// upstreamGatewayAPIStandardInstallSHA256 is the digest GitHub publishes for
// https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml
// (release asset digest sha256:24d931f2...). It is repeated here so a silent
// edit of either the embedded file or the production pin fails this test.
const upstreamGatewayAPIStandardInstallSHA256 = "24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"

func TestEmbeddedGatewayAPIBundleIsTheExactPinnedUpstreamRelease(t *testing.T) {
	bundle := GatewayAPIStandardInstall()
	sum := sha256.Sum256(bundle)
	if got := hex.EncodeToString(sum[:]); got != upstreamGatewayAPIStandardInstallSHA256 {
		t.Fatalf("embedded Gateway API bundle sha256=%s, want upstream v1.6.1 standard-install.yaml %s", got, upstreamGatewayAPIStandardInstallSHA256)
	}
	if GatewayAPIStandardInstallSHA256 != upstreamGatewayAPIStandardInstallSHA256 {
		t.Fatalf("production pin %s differs from the upstream release digest", GatewayAPIStandardInstallSHA256)
	}
	if GatewayAPIBundleVersion != "v1.6.1" {
		t.Fatalf("Gateway API bundle version = %s, want v1.6.1", GatewayAPIBundleVersion)
	}
	if bytes.Contains(bundle, []byte("\r")) {
		t.Fatal("embedded Gateway API bundle contains CR bytes; keep the upstream LF file unmodified")
	}
	text := string(bundle)
	if strings.Count(text, "gateway.networking.k8s.io/bundle-version: v1.6.1") < 10 ||
		strings.Contains(text, "gateway.networking.k8s.io/channel: experimental") {
		t.Fatal("embedded bundle is not the v1.6.1 standard channel")
	}
	// Cilium 1.20 requires the first seven v1 kinds and enables TCPRoute,
	// UDPRoute, and ListenerSet only when their CRDs exist at operator start.
	for _, crd := range []string{
		"gatewayclasses", "gateways", "httproutes", "grpcroutes", "tlsroutes",
		"referencegrants", "backendtlspolicies", "listenersets", "tcproutes", "udproutes",
	} {
		if !strings.Contains(text, "\n  name: "+crd+".gateway.networking.k8s.io\n") {
			t.Errorf("embedded bundle lacks the %s CRD", crd)
		}
	}
	// Callers get a copy; the embedded bytes cannot be mutated through it.
	bundle[0] ^= 0xff
	if bytes.Equal(bundle, GatewayAPIStandardInstall()) {
		t.Fatal("GatewayAPIStandardInstall returned the shared embedded slice")
	}
}

func TestDefaultControlPlaneCloudInitHasNoGatewayAPIBytes(t *testing.T) {
	for _, cached := range []bool{false, true} {
		input := cacheContractControlPlaneInput()
		if cached {
			input.BootstrapCache = gatewayAPITestCache(t)
		}
		files := cacheContractDecodeCloudInit(t, mustRenderCloudInit(t, input))
		for path, file := range files {
			if strings.Contains(file.Content, "gateway") || strings.Contains(file.Content, "gatewayAPI") {
				t.Fatalf("default cached=%t cloud-init file %s mentions Gateway API", cached, path)
			}
		}
	}
}

func TestGatewayAPIControlPlaneWaitsForPinnedBundleBeforeStartingRKE2(t *testing.T) {
	for _, cached := range []bool{false, true} {
		for _, single := range []bool{false, true} {
			input := cacheContractControlPlaneInput()
			input.GatewayAPI = true
			input.SingleControlPlane = single
			if cached {
				input.BootstrapCache = gatewayAPITestCache(t)
			}
			files := cacheContractDecodeCloudInit(t, mustRenderCloudInit(t, input))
			for path := range files {
				if strings.Contains(path, "gateway") {
					t.Fatalf("the %d-byte bundle must never be embedded in cloud-init, found %s", len(GatewayAPIStandardInstall()), path)
				}
			}
			cilium := files["/var/lib/inspace/rke2-cilium-config"].Content
			if !strings.HasSuffix(cilium, "    k8sServicePort: 6443\n    gatewayAPI:\n      enabled: true\n      gatewayClass:\n        create: \"true\"\n") {
				t.Fatalf("Gateway API Cilium values are not the exact opt-in:\n%s", cilium)
			}
			script := files["/usr/local/sbin/inspace-bootstrap-rke2"].Content
			wait := strings.Index(script, "gateway_api_bundle='/var/lib/inspace/gateway-api-standard-install.yaml'")
			install := strings.Index(script, `install -m 0600 "$gateway_api_bundle" /var/lib/rancher/rke2/server/manifests/inspace-gateway-api-crds.yaml`)
			start := strings.Index(script, "systemctl start --no-block rke2-server.service")
			ciliumInstall := strings.Index(script, "/var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml")
			if wait < 0 || install < wait || start < install || ciliumInstall > wait {
				t.Fatalf("bundle wait/install must follow the Cilium values and precede RKE2 start:\n%s", script)
			}
			for _, required := range []string{
				"gateway_api_sha256='" + upstreamGatewayAPIStandardInstallSHA256 + "'",
				"gateway_api_deadline=$(( $(date +%s) + 1800 ))",
				`sha256sum "$gateway_api_bundle" | awk '{print $1}'`,
				"inspace-cluster-controller --print-gateway-api-crds",
			} {
				if !strings.Contains(script, required) {
					t.Errorf("cached=%t single=%t Gateway API install lacks %q", cached, single, required)
				}
			}
			if single != strings.Contains(script, "rke2-coredns-config.yaml") {
				t.Fatalf("single=%t CoreDNS override placement changed", single)
			}
			cacheContractAssertShell(t, script)
		}
	}
}

func TestGatewayAPIOnRKE2V137ReliesOnItsBundledCRDChart(t *testing.T) {
	input := cacheContractControlPlaneInput()
	input.RKE2Version = "v1.37.0+rke2r1"
	input.GatewayAPI = true
	files := cacheContractDecodeCloudInit(t, mustRenderCloudInit(t, input))
	if !strings.Contains(files["/var/lib/inspace/rke2-cilium-config"].Content, "    gatewayAPI:\n      enabled: true\n") {
		t.Fatal("RKE2 v1.37 Gateway API cluster lacks the Cilium opt-in")
	}
	script := files["/usr/local/sbin/inspace-bootstrap-rke2"].Content
	if strings.Contains(script, "gateway") {
		t.Fatalf("RKE2 v1.37 owns the Gateway API CRDs through rke2-gateway-api-crd; bootstrap must not wait for or install its own:\n%s", script)
	}
	cacheContractAssertShell(t, script)
}

// Gateway API adds no image: Cilium serves it from the Envoy embedded in the
// agent image (rke2-cilium 1.20.200 keeps envoy.enabled=false), and the
// cache already mirrors the chart's cilium-envoy tag should a cluster later
// switch to the Envoy DaemonSet.
func TestCachedClusterMirrorsEveryGatewayAPIImage(t *testing.T) {
	manifest, err := renderCacheImageManifest(bootstrapCacheRKE2Version, "0.3.1-rc.2", []string{"rke2-ingress-nginx", "rke2-traefik"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"\trancher/mirrored-cilium-cilium:v1.20.2\n",
		"\trancher/mirrored-cilium-operator-generic:v1.20.2\n",
		"\trancher/mirrored-cilium-cilium-envoy:v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82\n",
	} {
		if !strings.Contains(manifest, target) {
			t.Errorf("bootstrap cache lacks Gateway API image %q", strings.TrimSpace(target))
		}
	}
}

func TestReconcilePropagatesGatewayAPIToEveryFixedServerOnly(t *testing.T) {
	for _, cached := range []bool{false, true} {
		api := newFakeAPI()
		cluster := testCluster()
		// testCluster pins the audited v1.36.5 release, which bundles Cilium 1.20.2.
		cluster.Spec.Network.GatewayAPI.Enabled = true
		cluster.Spec.RKE2.Disable = append(cluster.Spec.RKE2.Disable, "rke2-traefik-crd")
		reconciler := testReconciler(api)
		if cached {
			cluster.Spec.BootstrapCache.DirectDownload = false
			reconciler = cacheContractReconciler(api)
		}
		reconcileUntilReady(t, reconciler, cluster)

		bastion := mustVMRequest(t, api.vmCreates, currentBastionName(cluster.Metadata.Name))
		if strings.Contains(bastion.CloudInit, "gateway") {
			t.Fatalf("cached=%t: the bastion must not carry Gateway API bootstrap", cached)
		}
		for slot := 0; slot < ControlPlaneReplicas; slot++ {
			request := mustVMRequest(t, api.vmCreates, controlPlaneName(cluster.Metadata.Name, slot))
			files := cacheContractDecodeCloudInit(t, request.CloudInit)
			if !strings.Contains(files["/var/lib/inspace/rke2-cilium-config"].Content, "    gatewayAPI:\n      enabled: true\n") ||
				!strings.Contains(files["/usr/local/sbin/inspace-bootstrap-rke2"].Content, "gateway_api_sha256='"+GatewayAPIStandardInstallSHA256+"'") {
				t.Fatalf("cached=%t: control plane %d did not receive the Gateway API bootstrap", cached, slot)
			}
		}
	}
}

func TestReconcileRejectsGatewayAPIOnCilium119BeforeMutation(t *testing.T) {
	api := newFakeAPI()
	cluster := testCluster()
	cluster.Spec.RKE2.Version = "v1.36.4+rke2r1"
	cluster.Spec.Network.GatewayAPI.Enabled = true
	_, err := testReconciler(api).Reconcile(context.Background(), cluster, "unit-test-secret-token")
	if err == nil || !strings.Contains(err.Error(), "spec.network.gatewayAPI.enabled") {
		t.Fatalf("Gateway API on RKE2 %s error=%v, want a spec.network.gatewayAPI.enabled rejection", cluster.Spec.RKE2.Version, err)
	}
	if len(api.vmCreates) != 0 || len(api.firewallCreates) != 0 || len(api.floatingIPs) != 0 || len(api.events) != 0 {
		t.Fatalf("rejected Gateway API spec caused mutation: events=%v", api.events)
	}
}

func mustRenderCloudInit(t *testing.T, input CloudInitInput) string {
	t.Helper()
	raw, err := RenderCloudInitJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gatewayAPITestCache(t *testing.T) *NodeCacheConfig {
	t.Helper()
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS([]byte("0123456789abcdef0123456789abcdef"), "default/unit:4d7ca80d", hostname, time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return &NodeCacheConfig{Address: "10.20.30.21", Hostname: hostname, CABundle: material.CACertificate}
}

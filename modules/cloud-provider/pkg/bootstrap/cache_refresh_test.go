package bootstrap

import (
	"strings"
	"testing"
	"time"
)

func cacheRefreshBastionFiles(t *testing.T, moduleVersion string, disabled []string, digests map[string]string) map[string]cacheContractDecodedFile {
	t.Helper()
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS([]byte("0123456789abcdef0123456789abcdef"), "default/unit:4d7ca80d", hostname, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
		NodeName: "unit-bastion", PrivateSubnet: "10.20.30.0/24", CacheHostname: hostname,
		RKE2Version: bootstrapCacheRKE2Version, ModuleVersion: moduleVersion, ModuleImageDigests: digests, Disable: disabled,
		CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cacheContractDecodeCloudInit(t, raw)
}

func cacheRefreshTargets(t *testing.T, manifest string) map[string]string {
	t.Helper()
	targets := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(manifest, "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] != "image" {
			continue
		}
		targets[fields[2]] = fields[1]
	}
	return targets
}

// The refresh manifest `deploy update` imports must be the exact cache
// contract a newly built bastion seeds, never a second hand-kept inventory.
func TestCacheRefreshManifestEqualsTheBootstrapSeedContract(t *testing.T) {
	disabled := []string{"rke2-ingress-nginx", "rke2-traefik"}
	digests := map[string]string{
		"inspace-cloud-controller-manager": "sha256:" + strings.Repeat("1", 64),
		"inspace-csi-driver":               "sha256:" + strings.Repeat("2", 64),
		"karpenter-provider-inspace":       "sha256:" + strings.Repeat("3", 64),
	}
	for name, pinned := range map[string]map[string]string{"tag-sourced": nil, "digest-pinned": digests} {
		t.Run(name, func(t *testing.T) {
			seed := cacheRefreshBastionFiles(t, "1.2.0", disabled, pinned)["/etc/inspace-cache/images.tsv"].Content
			refresh, err := RenderCacheRefreshManifest(bootstrapCacheRKE2Version, "1.2.0", disabled, pinned)
			if err != nil {
				t.Fatal(err)
			}
			header := "rke2\t" + bootstrapCacheRKE2Version + "\t" + bootstrapCacheRKE2SHA256 + "\n"
			if !strings.HasPrefix(refresh, header) {
				t.Fatalf("refresh manifest does not start with the audited RKE2 artifact %q:\n%s", header, refresh)
			}
			var want strings.Builder
			want.WriteString(header)
			for _, line := range strings.Split(strings.TrimSuffix(seed, "\n"), "\n") {
				want.WriteString("image\t" + line + "\n")
			}
			if refresh != want.String() {
				t.Fatalf("refresh manifest differs from the bastion seed contract:\n got=%s\nwant=%s", refresh, want.String())
			}
		})
	}
}

// A module-only upgrade keeps the running RKE2 release, so it must not demand
// this build's pinned RKE2 inventory; only chart-owned images are listed.
func TestCacheRefreshManifestWithoutRKE2ListsOnlyChartOwnedImages(t *testing.T) {
	refresh, err := RenderCacheRefreshManifest("", "1.2.0", []string{"rke2-ingress-nginx", "rke2-traefik"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(refresh, "rke2\t") || strings.Contains(refresh, "rancher/") {
		t.Fatalf("module-only refresh lists RKE2 content:\n%s", refresh)
	}
	targets := cacheRefreshTargets(t, refresh)
	if len(targets) != len(fixedCacheImages)+len(moduleImageNames) || strings.Count(refresh, "\n") != len(targets) {
		t.Fatalf("module-only refresh has %d entries, want %d:\n%s", len(targets), len(fixedCacheImages)+len(moduleImageNames), refresh)
	}
	for _, image := range fixedCacheImages {
		if targets[image.Target] != image.Source {
			t.Fatalf("module-only refresh lacks fixed image %s", image.Target)
		}
	}
	for _, component := range moduleImageNames {
		if targets["thanet-s/"+component+":1.2.0"] != "docker://ghcr.io/thanet-s/"+component+":1.2.0" {
			t.Fatalf("module-only refresh lacks %s:1.2.0", component)
		}
	}
}

func TestCacheRefreshManifestFailsClosed(t *testing.T) {
	for name, call := range map[string]func() (string, error){
		"unaudited RKE2": func() (string, error) {
			return RenderCacheRefreshManifest("v1.36.4+rke2r1", "1.2.0", nil, nil)
		},
		"development module version": func() (string, error) {
			return RenderCacheRefreshManifest(bootstrapCacheRKE2Version, "dev", nil, nil)
		},
		"module-only development version": func() (string, error) {
			return RenderCacheRefreshManifest("", "", nil, nil)
		},
		"partial module digests": func() (string, error) {
			return RenderCacheRefreshManifest("", "1.2.0", nil, map[string]string{"inspace-csi-driver": "sha256:" + strings.Repeat("a", 64)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifest, err := call()
			if err == nil || manifest != "" {
				t.Fatalf("manifest=%q err=%v, want refusal without output", manifest, err)
			}
		})
	}
	_, err := RenderCacheRefreshManifest("v1.36.4+rke2r1", "1.2.0", nil, nil)
	if err == nil || !strings.Contains(err.Error(), bootstrapCacheRKE2Version) || !strings.Contains(err.Error(), "directDownload") {
		t.Fatalf("unaudited RKE2 refusal does not name the supported release and direct mode: %v", err)
	}
}

// An offline refresh plan for a cluster whose cache was seeded by an earlier
// release (RKE2 v1.36.4, modules 1.1.0-rc.3, before csi-resizer existed) that
// `deploy update` moves to this build's RKE2 release and module 1.2.0.
func TestCacheRefreshPlanForRKE2AndModuleUpgradeAddsTheNewImages(t *testing.T) {
	previousSeed := map[string]struct{}{}
	for _, target := range []string{
		"rancher/rke2-runtime:v1.36.4-rke2r1",
		"rancher/hardened-kubernetes:v1.36.4-rke2r1-build20260812",
		"rancher/hardened-coredns:v1.14.7-build20260909",
		"rancher/mirrored-pause:3.10.2",
		"rancher/mirrored-cilium-cilium:v1.19.4",
		"kube-vip/kube-vip:v1.2.1",
		"sig-storage/csi-provisioner:v5.2.0",
		"sig-storage/csi-attacher:v4.8.1",
		"sig-storage/csi-node-driver-registrar:v2.13.0",
		"sig-storage/livenessprobe:v2.15.0",
		"thanet-s/inspace-cloud-controller-manager:1.1.0-rc.3",
		"thanet-s/inspace-csi-driver:1.1.0-rc.3",
		"thanet-s/karpenter-provider-inspace:1.1.0-rc.3",
	} {
		previousSeed[target] = struct{}{}
	}
	refresh, err := RenderCacheRefreshManifest(bootstrapCacheRKE2Version, "1.2.0", []string{"rke2-ingress-nginx", "rke2-traefik"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]struct{}{}
	for target := range cacheRefreshTargets(t, refresh) {
		if _, cached := previousSeed[target]; !cached {
			missing[target] = struct{}{}
		}
	}
	for _, want := range []string{
		"rancher/rke2-runtime:v1.36.5-rke2r1",
		"rancher/hardened-kubernetes:v1.36.5-rke2r1-build20260923",
		"rancher/mirrored-cilium-cilium:v1.20.2",
		"sig-storage/csi-resizer:v1.13.2",
		"thanet-s/inspace-cloud-controller-manager:1.2.0",
		"thanet-s/inspace-csi-driver:1.2.0",
		"thanet-s/karpenter-provider-inspace:1.2.0",
	} {
		if _, ok := missing[want]; !ok {
			t.Errorf("refresh plan does not add %s", want)
		}
	}
	for _, unchanged := range []string{"rancher/mirrored-pause:3.10.2", "kube-vip/kube-vip:v1.2.1", "sig-storage/csi-provisioner:v5.2.0"} {
		if _, ok := missing[unchanged]; ok {
			t.Errorf("refresh plan re-adds unchanged %s", unchanged)
		}
	}
	for _, disabled := range []string{"rancher/hardened-traefik:", "rancher/nginx-ingress-controller:"} {
		if strings.Contains(refresh, disabled) {
			t.Errorf("refresh plan re-admits disabled add-on image %s", disabled)
		}
	}
	if !strings.HasPrefix(refresh, "rke2\t"+bootstrapCacheRKE2Version+"\t"+bootstrapCacheRKE2SHA256+"\n") {
		t.Fatalf("refresh plan lacks the checksum-pinned RKE2 artifact for Karpenter workers:\n%s", refresh)
	}
}

// Refreshed RKE2 releases are served to Karpenter workers for the rest of the
// cluster's life. Daily maintenance must never age them out; nginx reads do
// not update a release directory's atime.
func TestCacheMaintenanceNeverPrunesVerifiedRKE2Releases(t *testing.T) {
	if strings.Contains(cacheMaintenanceScript, "artifacts/rke2") || strings.Contains(cacheMaintenanceScript, "rm -rf") ||
		strings.Contains(cacheMaintenanceScript, "pinned_version") {
		t.Fatalf("cache maintenance still prunes RKE2 release artifacts:\n%s", cacheMaintenanceScript)
	}
	for _, required := range []string{
		`test "$(findmnt -n -o TARGET "$cache_root")" = "$cache_root"`,
		"docker container prune --force --filter until=720h",
		"docker image prune --force --filter until=720h",
		`if [ "$available" -lt 1000000000 ]; then`,
	} {
		if !strings.Contains(cacheMaintenanceScript, required) {
			t.Errorf("cache maintenance lacks %q", required)
		}
	}
	if got := cacheRefreshBastionFiles(t, "1.2.0", nil, nil)["/usr/local/sbin/inspace-cache-maintain"].Content; got != cacheMaintenanceScript {
		t.Fatalf("bastion cloud-init maintenance script differs from the shared constant:\n%s", got)
	}
}

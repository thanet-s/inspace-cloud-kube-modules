package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	rke2VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$`)
	nodeNamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

const kubeVIPImage = "ghcr.io/kube-vip/kube-vip:v1.2.1@sha256:49b77655f9f109bedc5eb25723bb0e4c57d8513ba33cc69c31be3f243eb2386d"

const kubernetesSysctlConfig = `# Managed by InSpace Kubernetes bootstrap.
net.ipv4.ip_forward = 1
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
`

const kubernetesLimitsConfig = `# Managed by InSpace Kubernetes bootstrap.
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
`

const rke2ServerLimitsConfig = `[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
LimitMEMLOCK=infinity
TasksMax=infinity
`

const automaticAPTUpdatesDisabledConfig = `// Managed by InSpace cluster bootstrap.
APT::Periodic::Enable "0";
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "0";
Unattended-Upgrade::Automatic-Reboot "false";
`

const ubuntuAPTMirrorListConfig = `http://mirror1.totbb.net/ubuntu/	priority:1
https://mirror.kku.ac.th/ubuntu/	priority:2
`

const ubuntuAPTSourcesConfig = `Types: deb
URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

const staticGoogleResolverConfig = `# Managed by InSpace Kubernetes bootstrap.
nameserver 8.8.8.8
nameserver 8.8.4.4
options edns0
`

func renderUbuntuRepositoryAndResolverCommands(nodeName string) string {
	return `node_name=` + shellSingleQuote(nodeName) + `
sed -Ei '/^[[:space:]]*127\.0\.1\.1([[:space:]]|$)/d' /etc/hosts
printf '127.0.1.1\t%s\n' "$node_name" >>/etc/hosts
hostname_attempt=0
until getent hosts "$node_name" | grep -Eq '^127\.0\.1\.1[[:space:]]'; do
  hostname_attempt=$((hostname_attempt + 1))
  if [ "$hostname_attempt" -ge 30 ]; then
    echo "generated hostname did not resolve to 127.0.1.1" >&2
    exit 1
  fi
  sleep 1
done
install -d -m 0755 /etc/apt/mirrors /etc/apt/sources.list.d
install -m 0644 /var/lib/inspace/ubuntu-mirrors.list /etc/apt/mirrors/inspace-ubuntu.list
install -m 0644 /var/lib/inspace/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources
rm -f /etc/apt/sources.list
rm -f /etc/resolv.conf
install -m 0644 /var/lib/inspace/static-resolv.conf /etc/resolv.conf
systemctl disable --now systemd-resolved.service >/dev/null
systemctl mask systemd-resolved.service >/dev/null
test ! -L /etc/resolv.conf
grep -Fqx 'nameserver 8.8.8.8' /etc/resolv.conf
grep -Fqx 'nameserver 8.8.4.4' /etc/resolv.conf
test "$(systemctl is-enabled systemd-resolved.service 2>/dev/null || true)" = masked
! systemctl is-active --quiet systemd-resolved.service
grep -Fqx 'http://mirror1.totbb.net/ubuntu/	priority:1' /etc/apt/mirrors/inspace-ubuntu.list
grep -Fqx 'https://mirror.kku.ac.th/ubuntu/	priority:2' /etc/apt/mirrors/inspace-ubuntu.list
test "$(grep -Fc 'URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list' /etc/apt/sources.list.d/ubuntu.sources)" -eq 2
`
}

func renderAPTUpgradeContinuation(skip bool, indent string) string {
	if skip {
		return ""
	}
	return indent + `run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y && \` + "\n"
}

func renderAPTUpgradeSuffix(skip bool, indent string) string {
	if skip {
		return ""
	}
	return " && \\\n" + indent + `run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y`
}

type CloudInitInput struct {
	NodeName                     string
	NodeExternalIPv4             string
	PrivateSubnet                string
	VirtualIPv4                  string
	RKE2Version                  string
	RKE2Token                    string
	Initialize                   bool
	ServerAddress                string
	PodCIDR                      string
	ServiceCIDR                  string
	PrivateLoadBalancerPoolStart string
	PrivateLoadBalancerPoolStop  string
	TLSSubjectAltNames           []string
	Disable                      []string
	BootstrapCache               *NodeCacheConfig
	// SingleControlPlane sizes packaged components that otherwise require two
	// distinct schedulable nodes. It must remain false for the established
	// three-control-plane cloud-init contract.
	SingleControlPlane bool
	// SkipOSUpgrade removes only apt-get upgrade from the bounded package
	// stage. Repository setup, apt-get update, and required installs remain.
	SkipOSUpgrade bool
}

// RenderCloudInitJSON returns the JSON object expected by InSpace's
// cloud_init form field. The guest discovers its RFC1918 NIC at boot and never
// treats the floating IPv4 as a local interface address.
func RenderCloudInitJSON(input CloudInitInput) (string, error) {
	if input.NodeName == "" || input.RKE2Token == "" || input.PrivateSubnet == "" || input.VirtualIPv4 == "" || input.PodCIDR == "" || input.ServiceCIDR == "" ||
		input.PrivateLoadBalancerPoolStart == "" || input.PrivateLoadBalancerPoolStop == "" {
		return "", errors.New("bootstrap: node name, token, private subnet, virtual IPv4, pod CIDR, service CIDR, and private load-balancer pool are required")
	}
	if !nodeNamePattern.MatchString(input.NodeName) {
		return "", errors.New("bootstrap: node name must be a lowercase DNS label of at most 63 characters")
	}
	if input.NodeExternalIPv4 != "" {
		externalAddress, err := netip.ParseAddr(input.NodeExternalIPv4)
		if err != nil || !externalAddress.Is4() || !externalAddress.IsGlobalUnicast() || externalAddress.IsPrivate() {
			return "", errors.New("bootstrap: node external IP must be empty or an allocated public IPv4")
		}
	}
	if !rke2VersionPattern.MatchString(input.RKE2Version) {
		return "", errors.New("bootstrap: RKE2 version must be an exact vX.Y.Z+rke2rN release")
	}
	if !input.Initialize && input.ServerAddress == "" {
		return "", errors.New("bootstrap: joining server requires a server address")
	}
	if err := validateNetworkCIDRs(input.PrivateSubnet, input.PodCIDR, input.ServiceCIDR); err != nil {
		return "", err
	}
	if err := validateVirtualIPv4(input.PrivateSubnet, input.VirtualIPv4); err != nil {
		return "", err
	}
	if err := validateNodeCacheConfig(input.BootstrapCache, input.PrivateSubnet); err != nil {
		return "", err
	}
	if input.BootstrapCache != nil && input.BootstrapCache.Address == input.VirtualIPv4 {
		return "", errors.New("bootstrap: cache address must not equal the control-plane virtual IPv4")
	}
	privatePool, err := validatePrivateLoadBalancerPool(
		input.PrivateSubnet, input.PodCIDR, input.ServiceCIDR, input.VirtualIPv4,
		input.PrivateLoadBalancerPoolStart, input.PrivateLoadBalancerPoolStop,
	)
	if err != nil {
		return "", err
	}
	config := renderRKE2Config(input)
	ciliumConfig := renderRKE2CiliumConfig(input.PodCIDR, privatePool.AddressCount, input.SingleControlPlane)
	ciliumLoadBalancerConfig := renderCiliumPrivateLoadBalancerManifest(input.PrivateLoadBalancerPoolStart, input.PrivateLoadBalancerPoolStop)
	kubeVIPConfig := renderKubeVIPStaticPod(input.VirtualIPv4, input.BootstrapCache)
	script := renderInstallScript(input)
	payload := struct {
		Hostname         string `json:"hostname"`
		PreserveHostname bool   `json:"preserve_hostname"`
		WriteFiles       []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		} `json:"write_files"`
		RunCmd []string `json:"runcmd"`
	}{Hostname: input.NodeName, PreserveHostname: false}
	addFile := func(path, content, permissions string) {
		payload.WriteFiles = append(payload.WriteFiles, struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		}{
			Path: path, Content: base64.StdEncoding.EncodeToString([]byte(content)),
			Permissions: permissions, Encoding: "b64", Owner: "root:root",
		})
	}
	addFile("/usr/local/sbin/inspace-bootstrap-rke2", script, "0700")
	addFile("/var/lib/inspace/rke2-config", config, "0600")
	addFile("/var/lib/inspace/rke2-cilium-config", ciliumConfig, "0600")
	addFile("/var/lib/inspace/rke2-cilium-private-load-balancer", ciliumLoadBalancerConfig, "0600")
	addFile("/var/lib/inspace/rke2-kube-vip", kubeVIPConfig, "0600")
	if input.BootstrapCache != nil {
		addFile("/etc/rancher/rke2/bootstrap-cache-ca.crt", input.BootstrapCache.CABundle, "0644")
		addFile("/etc/rancher/rke2/registries.yaml", renderCacheRegistriesConfig(input.BootstrapCache), "0600")
	}
	addFile("/etc/sysctl.d/90-inspace-kubernetes.conf", kubernetesSysctlConfig, "0644")
	addFile("/etc/security/limits.d/90-inspace-kubernetes.conf", kubernetesLimitsConfig, "0644")
	addFile("/etc/systemd/system/rke2-server.service.d/20-inspace-node-limits.conf", rke2ServerLimitsConfig, "0644")
	addFile("/var/lib/inspace/apt-periodic-disabled", automaticAPTUpdatesDisabledConfig, "0644")
	addFile("/var/lib/inspace/ubuntu-mirrors.list", ubuntuAPTMirrorListConfig, "0644")
	addFile("/var/lib/inspace/ubuntu.sources", ubuntuAPTSourcesConfig, "0644")
	addFile("/var/lib/inspace/static-resolv.conf", staticGoogleResolverConfig, "0644")
	payload.RunCmd = []string{"/usr/local/sbin/inspace-bootstrap-rke2"}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RenderBastionCloudInitJSON sets the deterministic guest hostname, performs
// one bounded package update and upgrade, disables automatic APT updates, and
// disables any image-provided host firewall. All packet policy is enforced by
// the separately owned InSpace bastion firewall.
func RenderBastionCloudInitJSON(nodeName string) (string, error) {
	return renderBastionCloudInitJSON(nodeName, false)
}

func renderBastionCloudInitJSON(nodeName string, skipOSUpgrade bool) (string, error) {
	if !nodeNamePattern.MatchString(nodeName) {
		return "", errors.New("bootstrap: bastion node name must be a lowercase DNS label of at most 63 characters")
	}
	payload := struct {
		Hostname         string `json:"hostname"`
		PreserveHostname bool   `json:"preserve_hostname"`
		WriteFiles       []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		} `json:"write_files"`
		RunCmd []string `json:"runcmd"`
	}{
		Hostname: nodeName, PreserveHostname: false,
		WriteFiles: []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		}{
			{
				Path: "/usr/local/sbin/inspace-bootstrap-bastion", Content: base64.StdEncoding.EncodeToString([]byte(renderBastionBootstrapScript(nodeName, skipOSUpgrade))),
				Permissions: "0700", Encoding: "b64", Owner: "root:root",
			},
			{
				Path: "/var/lib/inspace/apt-periodic-disabled", Content: base64.StdEncoding.EncodeToString([]byte(automaticAPTUpdatesDisabledConfig)),
				Permissions: "0644", Encoding: "b64", Owner: "root:root",
			},
		},
		RunCmd: []string{"/usr/local/sbin/inspace-bootstrap-bastion"},
	}
	for _, file := range []struct{ path, content string }{
		{"/var/lib/inspace/ubuntu-mirrors.list", ubuntuAPTMirrorListConfig},
		{"/var/lib/inspace/ubuntu.sources", ubuntuAPTSourcesConfig},
		{"/var/lib/inspace/static-resolv.conf", staticGoogleResolverConfig},
	} {
		payload.WriteFiles = append(payload.WriteFiles, struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		}{Path: file.path, Content: base64.StdEncoding.EncodeToString([]byte(file.content)), Permissions: "0644", Encoding: "b64", Owner: "root:root"})
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func renderRKE2Config(input CloudInitInput) string {
	lines := []string{
		"token: " + yamlString(input.RKE2Token),
		"node-name: " + yamlString(input.NodeName),
		"node-ip: __PRIVATE_IP__",
		"advertise-address: __PRIVATE_IP__",
		"cluster-cidr: " + yamlString(input.PodCIDR),
		"service-cidr: " + yamlString(input.ServiceCIDR),
		"cni: cilium",
		"disable-kube-proxy: true",
		"disable-cloud-controller: true",
		"write-kubeconfig-mode: \"0600\"",
		"node-taint:",
		"  - node-role.kubernetes.io/control-plane=true:NoSchedule",
		"kubelet-arg:",
		"  - cloud-provider=external",
	}
	if input.BootstrapCache != nil {
		lines = append(lines, "system-default-registry: "+yamlString(input.BootstrapCache.Registry()))
	}
	if input.NodeExternalIPv4 != "" {
		lines = append(lines, "node-external-ip: "+yamlString(input.NodeExternalIPv4))
	}
	if !input.Initialize {
		lines = append(lines, "server: "+yamlString("https://"+input.ServerAddress+":9345"))
	}
	tlsNames := sortedUniqueStrings(input.TLSSubjectAltNames)
	if len(tlsNames) != 0 {
		lines = append(lines, "tls-san:")
		for _, name := range tlsNames {
			lines = append(lines, "  - "+yamlString(name))
		}
	}
	disabled := sortedUniqueStrings(input.Disable)
	if len(disabled) != 0 {
		lines = append(lines, "disable:")
		for _, component := range disabled {
			lines = append(lines, "  - "+yamlString(component))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderRKE2CiliumConfig(podCIDR string, privateLoadBalancerAddressCount uint64, singleControlPlane bool) string {
	qps := (privateLoadBalancerAddressCount + 4) / 5
	if qps < 10 {
		qps = 10
	}
	burst := qps * 2
	if burst < 20 {
		burst = 20
	}
	operatorValues := ""
	if singleControlPlane {
		operatorValues = "    operator:\n      replicas: 1\n"
	}
	return fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-cilium
  namespace: kube-system
spec:
  valuesContent: |-
%s    routingMode: native
    ipv4NativeRoutingCIDR: %s
    autoDirectNodeRoutes: true
    kubeProxyReplacement: true
    enableIPv4Masquerade: true
    bpf:
      masquerade: true
    l2announcements:
      enabled: true
    defaultLBServiceIPAM: none
    k8sClientRateLimit:
      qps: %d
      burst: %d
    ipam:
      mode: kubernetes
    k8sServiceHost: localhost
    k8sServicePort: 6443
`, operatorValues, yamlString(podCIDR), qps, burst)
}

func renderCiliumPrivateLoadBalancerManifest(start, stop string) string {
	return fmt.Sprintf(`apiVersion: cilium.io/v2
kind: CiliumLoadBalancerIPPool
metadata:
  name: inspace-private
spec:
  disabled: false
  blocks:
    - start: %s
      stop: %s
  serviceSelector:
    matchLabels:
      inspace.cloud/load-balancer-scope: private
---
apiVersion: cilium.io/v2alpha1
kind: CiliumL2AnnouncementPolicy
metadata:
  name: inspace-private
spec:
  serviceSelector:
    matchLabels:
      inspace.cloud/load-balancer-scope: private
  nodeSelector:
    matchExpressions:
      - key: kubernetes.io/os
        operator: In
        values:
          - linux
      - key: inspace.cloud/l2-announcement-disabled
        operator: DoesNotExist
  externalIPs: false
  loadBalancerIPs: true
`, yamlString(start), yamlString(stop))
}

func renderKubeVIPStaticPod(virtualIPv4 string, cache *NodeCacheConfig) string {
	image := kubeVIPImage
	if cache != nil {
		image = cache.Registry() + "/" + cachedKubeVIPImage
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: kube-vip
  namespace: kube-system
  labels:
    app.kubernetes.io/name: kube-vip
    app.kubernetes.io/component: control-plane-vip
spec:
  hostNetwork: true
  hostAliases:
    - ip: "127.0.0.1"
      hostnames:
        - "kubernetes"
  priorityClassName: system-node-critical
  containers:
    - name: kube-vip
      image: %s
      imagePullPolicy: IfNotPresent
      args: ["manager"]
      env:
        - name: vip_arp
          value: "true"
        - name: vip_arpRate
          value: "500"
        - name: vip_interface
          value: "__PRIVATE_IFACE__"
        - name: vip_subnet
          value: "32"
        - name: cp_enable
          value: "true"
        - name: cp_namespace
          value: "kube-system"
        - name: vip_nodename
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: svc_enable
          value: "false"
        - name: vip_leaderelection
          value: "true"
        - name: vip_leaseduration
          value: "5"
        - name: vip_renewdeadline
          value: "3"
        - name: vip_retryperiod
          value: "1"
        - name: vip_leasename
          value: "inspace-control-plane-vip"
        - name: address
          value: %s
        - name: port
          value: "6443"
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["NET_ADMIN", "NET_RAW"]
      volumeMounts:
        - name: kubeconfig
          mountPath: /etc/kubernetes/admin.conf
          readOnly: true
  volumes:
    - name: kubeconfig
      hostPath:
        path: /etc/rancher/rke2/rke2.yaml
        type: File
`, image, yamlString(virtualIPv4))
}

func renderCacheRegistriesConfig(cache *NodeCacheConfig) string {
	return fmt.Sprintf(`configs:
  %s:
    tls:
      ca_file: /etc/rancher/rke2/bootstrap-cache-ca.crt
`, yamlString(cache.Registry()))
}

func renderNodeCacheHostsSetup(cache *NodeCacheConfig) string {
	if cache == nil {
		return ":"
	}
	return fmt.Sprintf(`cache_address=%s
cache_hostname=%s
cache_hosts_tmp="$(mktemp)"
awk -v host="$cache_hostname" '{ keep=1; for (i=2; i<=NF; i++) if ($i == host) keep=0; if (keep) print }' /etc/hosts >"$cache_hosts_tmp"
install -m 0644 "$cache_hosts_tmp" /etc/hosts
rm -f "$cache_hosts_tmp"
printf '%%s %%s # inspace-bootstrap-cache\n' "$cache_address" "$cache_hostname" >>/etc/hosts
getent ahostsv4 "$cache_hostname" | awk -v expected="$cache_address" '$1 == expected { found=1 } END { exit !found }'
`, shellSingleQuote(cache.Address), shellSingleQuote(cache.Hostname))
}

func renderDisableUFWScript() string {
	return `#!/bin/sh
set -eu
if command -v ufw >/dev/null 2>&1; then
  ufw --force disable
  ufw_status="$(ufw status)"
  printf '%s\n' "$ufw_status" | grep -Fqx "Status: inactive"
fi
ufw_unit_list=""
if ! ufw_unit_list="$(systemctl list-unit-files --type=service --no-legend ufw.service 2>/dev/null)"; then
  exit 1
fi
if printf '%s\n' "$ufw_unit_list" | grep -q '^ufw\.service'; then
  systemctl disable --now ufw.service >/dev/null 2>&1
  if systemctl is-active --quiet ufw.service; then exit 1; fi
  ufw_unit_state="$(systemctl is-enabled ufw.service 2>/dev/null || true)"
  case "$ufw_unit_state" in disabled|masked) ;; *) exit 1 ;; esac
fi
`
}

func renderDisableAutomaticAPTUpdatesCommands() string {
	return `install -D -m 0644 /var/lib/inspace/apt-periodic-disabled /etc/apt/apt.conf.d/99-inspace-disable-periodic
cmp -s /var/lib/inspace/apt-periodic-disabled /etc/apt/apt.conf.d/99-inspace-disable-periodic
for apt_unit in apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
  systemctl mask --now "$apt_unit" >/dev/null
done
for apt_unit in apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
  if systemctl is-active --quiet "$apt_unit"; then exit 1; fi
  apt_unit_state="$(systemctl is-enabled "$apt_unit" 2>/dev/null || true)"
  test "$apt_unit_state" = masked
done
`
}

func renderBastionBootstrapScript(nodeName string, skipOSUpgrade bool) string {
	return `#!/bin/sh
set -eu

` + renderUbuntuRepositoryAndResolverCommands(nodeName) + `

package_deadline=$(( $(date +%s) + 600 ))
run_package_command() {
  package_remaining=$(( package_deadline - $(date +%s) ))
  [ "$package_remaining" -gt 0 ] || return 124
  timeout --kill-after=30s "${package_remaining}s" "$@"
}
attempt=0
until run_package_command apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update` + renderAPTUpgradeSuffix(skipOSUpgrade, "      ") + `; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ] || [ "$(date +%s)" -ge "$package_deadline" ]; then exit 1; fi
  sleep 10
done

` + renderDisableAutomaticAPTUpdatesCommands() + `
` + strings.TrimSpace(strings.TrimPrefix(renderDisableUFWScript(), "#!/bin/sh\nset -eu\n")) + "\n"
}

func renderInstallScript(input CloudInitInput) string {
	if input.BootstrapCache == nil {
		return renderDirectInstallScript(input)
	}
	releaseBase := "https://github.com/rancher/rke2/releases/download/" + url.PathEscape(input.RKE2Version)
	cacheWait := "cache_curl_option=\n"
	cacheHostsSetup := renderNodeCacheHostsSetup(input.BootstrapCache)
	if input.BootstrapCache != nil {
		releaseBase = input.BootstrapCache.Endpoint() + "/rke2/" + url.PathEscape(input.RKE2Version)
		cacheWait = fmt.Sprintf(`cache_curl_option="--cacert /etc/rancher/rke2/bootstrap-cache-ca.crt"
cache_deadline=$(( $(date +%%s) + 2700 ))
until curl --fail --silent --show-error --cacert /etc/rancher/rke2/bootstrap-cache-ca.crt --connect-timeout 5 --max-time 10 %s/healthz >/dev/null; do
  if [ "$(date +%%s)" -ge "$cache_deadline" ]; then
    echo "bootstrap cache did not become ready" >&2
    exit 1
  fi
  sleep 5
done
`, shellSingleQuote(input.BootstrapCache.Endpoint()))
	}
	return fmt.Sprintf(`#!/bin/sh
set -eu

swapoff -a
if [ -f /etc/fstab ]; then
  sed -Ei '/^[[:space:]]*#/! { /[[:space:]]swap[[:space:]]/ s/^/#/; }' /etc/fstab
fi
%s

package_deadline=$(( $(date +%%s) + 600 ))
run_package_command() {
  package_remaining=$(( package_deadline - $(date +%%s) ))
  [ "$package_remaining" -gt 0 ] || return 124
  timeout --kill-after=30s "${package_remaining}s" "$@"
}
attempt=0
until run_package_command apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
%s	  run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl iproute2 procps tar; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ] || [ "$(date +%%s)" -ge "$package_deadline" ]; then exit 1; fi
  sleep 10
done

%s

sysctl --system >/dev/null
test "$(sysctl -n net.ipv4.ip_forward)" -eq 1
test "$(sysctl -n fs.inotify.max_user_instances)" -ge 8192
test "$(sysctl -n fs.inotify.max_user_watches)" -ge 524288
test -z "$(swapon --show --noheadings)"
install -d -m 0755 /var/lib/inspace
: > /var/lib/inspace/kubernetes-node-prepared-v1
chmod 0600 /var/lib/inspace/kubernetes-node-prepared-v1

vpc_subnet='%s'
virtual_ip='%s'
vpc_identities="$(ip -o -4 addr show to "$vpc_subnet" scope global | awk -v vip="$virtual_ip" '$3 == "inet" { split($4, address, "/"); if (address[1] != vip) print $2, address[1] }')"
test -n "$vpc_identities"
test "$(printf '%%s\n' "$vpc_identities" | awk 'NF { count++ } END { print count + 0 }')" -eq 1
set -- $vpc_identities
PRIVATE_IF=${1%%%%@*}
PRIVATE_IP=$2
test -n "$PRIVATE_IF"
test -n "$PRIVATE_IP"

%s

install -d -m 0700 /etc/rancher/rke2 /var/lib/rancher/rke2/server/manifests /var/lib/rancher/rke2/agent/pod-manifests
install -m 0600 /var/lib/inspace/rke2-config /etc/rancher/rke2/config.yaml
sed -i "s/__PRIVATE_IP__/$PRIVATE_IP/g" /etc/rancher/rke2/config.yaml
chmod 0600 /etc/rancher/rke2/config.yaml
install -m 0600 /var/lib/inspace/rke2-cilium-config /var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml
install -m 0600 /var/lib/inspace/rke2-cilium-private-load-balancer /var/lib/rancher/rke2/server/manifests/inspace-private-load-balancer.yaml
install -m 0600 /var/lib/inspace/rke2-kube-vip /var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml
sed -i "s/__PRIVATE_IFACE__/$PRIVATE_IF/g" /var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml

%s

%s

version='%s'
release_base='%s'
if ! [ -x /usr/local/bin/rke2 ] || ! [ -f /usr/local/lib/systemd/system/rke2-server.service ] || ! /usr/local/bin/rke2 --version 2>/dev/null | grep -F -- "rke2 version $version" >/dev/null; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM
  attempt=0
  until curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors $cache_curl_option --output "$tmpdir/rke2.linux-amd64.tar.gz" "$release_base/rke2.linux-amd64.tar.gz" && \
        curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors $cache_curl_option --output "$tmpdir/sha256sum-amd64.txt" "$release_base/sha256sum-amd64.txt"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then exit 1; fi
    sleep 10
  done
  expected="$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" {print $1; exit}' "$tmpdir/sha256sum-amd64.txt")"
  test -n "$expected"
  actual="$(sha256sum "$tmpdir/rke2.linux-amd64.tar.gz" | awk '{print $1}')"
  test "$actual" = "$expected"
  tar --extract --gzip --file "$tmpdir/rke2.linux-amd64.tar.gz" --directory /usr/local
fi
/usr/local/bin/rke2 --version | grep -F -- "rke2 version $version" >/dev/null
systemctl daemon-reload
systemctl enable rke2-server.service
systemctl start --no-block rke2-server.service
attempt=0
until systemctl is-active --quiet rke2-server.service && [ -s /etc/rancher/rke2/rke2.yaml ]; do
  attempt=$((attempt + 1))
  if systemctl is-failed --quiet rke2-server.service || [ "$attempt" -ge 180 ]; then exit 1; fi
  sleep 5
done
`, strings.TrimSpace(renderUbuntuRepositoryAndResolverCommands(input.NodeName)), renderAPTUpgradeContinuation(input.SkipOSUpgrade, "\t  "), strings.TrimSpace(renderDisableAutomaticAPTUpdatesCommands()), input.PrivateSubnet, input.VirtualIPv4, cacheHostsSetup, strings.TrimSpace(strings.TrimPrefix(renderDisableUFWScript(), "#!/bin/sh\nset -eu\n")), cacheWait, input.RKE2Version, releaseBase)
}

func renderDirectInstallScript(input CloudInitInput) string {
	releaseBase := "https://github.com/rancher/rke2/releases/download/" + url.PathEscape(input.RKE2Version)
	return fmt.Sprintf(`#!/bin/sh
set -eu

swapoff -a
if [ -f /etc/fstab ]; then
  sed -Ei '/^[[:space:]]*#/! { /[[:space:]]swap[[:space:]]/ s/^/#/; }' /etc/fstab
fi
%s

package_deadline=$(( $(date +%%s) + 600 ))
run_package_command() {
  package_remaining=$(( package_deadline - $(date +%%s) ))
  [ "$package_remaining" -gt 0 ] || return 124
  timeout --kill-after=30s "${package_remaining}s" "$@"
}
attempt=0
until run_package_command apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
%s	  run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl iproute2 procps tar; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ] || [ "$(date +%%s)" -ge "$package_deadline" ]; then exit 1; fi
  sleep 10
done

%s

sysctl --system >/dev/null
test "$(sysctl -n net.ipv4.ip_forward)" -eq 1
test "$(sysctl -n fs.inotify.max_user_instances)" -ge 8192
test "$(sysctl -n fs.inotify.max_user_watches)" -ge 524288
test -z "$(swapon --show --noheadings)"
install -d -m 0755 /var/lib/inspace
: > /var/lib/inspace/kubernetes-node-prepared-v1
chmod 0600 /var/lib/inspace/kubernetes-node-prepared-v1

vpc_subnet='%s'
virtual_ip='%s'
vpc_identities="$(ip -o -4 addr show to "$vpc_subnet" scope global | awk -v vip="$virtual_ip" '$3 == "inet" { split($4, address, "/"); if (address[1] != vip) print $2, address[1] }')"
test -n "$vpc_identities"
test "$(printf '%%s\n' "$vpc_identities" | awk 'NF { count++ } END { print count + 0 }')" -eq 1
set -- $vpc_identities
PRIVATE_IF=${1%%%%@*}
PRIVATE_IP=$2
test -n "$PRIVATE_IF"
test -n "$PRIVATE_IP"

install -d -m 0700 /etc/rancher/rke2 /var/lib/rancher/rke2/server/manifests /var/lib/rancher/rke2/agent/pod-manifests
install -m 0600 /var/lib/inspace/rke2-config /etc/rancher/rke2/config.yaml
sed -i "s/__PRIVATE_IP__/$PRIVATE_IP/g" /etc/rancher/rke2/config.yaml
chmod 0600 /etc/rancher/rke2/config.yaml
install -m 0600 /var/lib/inspace/rke2-cilium-config /var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml
install -m 0600 /var/lib/inspace/rke2-cilium-private-load-balancer /var/lib/rancher/rke2/server/manifests/inspace-private-load-balancer.yaml
install -m 0600 /var/lib/inspace/rke2-kube-vip /var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml
sed -i "s/__PRIVATE_IFACE__/$PRIVATE_IF/g" /var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml

%s

version='%s'
release_base='%s'
if ! [ -x /usr/local/bin/rke2 ] || ! [ -f /usr/local/lib/systemd/system/rke2-server.service ] || ! /usr/local/bin/rke2 --version 2>/dev/null | grep -F -- "rke2 version $version" >/dev/null; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM
  attempt=0
  until curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --output "$tmpdir/rke2.linux-amd64.tar.gz" "$release_base/rke2.linux-amd64.tar.gz" && \
        curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --output "$tmpdir/sha256sum-amd64.txt" "$release_base/sha256sum-amd64.txt"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then exit 1; fi
    sleep 10
  done
  expected="$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" {print $1; exit}' "$tmpdir/sha256sum-amd64.txt")"
  test -n "$expected"
  actual="$(sha256sum "$tmpdir/rke2.linux-amd64.tar.gz" | awk '{print $1}')"
  test "$actual" = "$expected"
  tar --extract --gzip --file "$tmpdir/rke2.linux-amd64.tar.gz" --directory /usr/local
fi
/usr/local/bin/rke2 --version | grep -F -- "rke2 version $version" >/dev/null
systemctl daemon-reload
systemctl enable rke2-server.service
systemctl start --no-block rke2-server.service
attempt=0
until systemctl is-active --quiet rke2-server.service && [ -s /etc/rancher/rke2/rke2.yaml ]; do
  attempt=$((attempt + 1))
  if systemctl is-failed --quiet rke2-server.service || [ "$attempt" -ge 180 ]; then exit 1; fi
  sleep 5
done
`, strings.TrimSpace(renderUbuntuRepositoryAndResolverCommands(input.NodeName)), renderAPTUpgradeContinuation(input.SkipOSUpgrade, "\t  "), strings.TrimSpace(renderDisableAutomaticAPTUpdatesCommands()), input.PrivateSubnet, input.VirtualIPv4, strings.TrimSpace(strings.TrimPrefix(renderDisableUFWScript(), "#!/bin/sh\nset -eu\n")), input.RKE2Version, releaseBase)
}

func sortedUniquePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func yamlString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

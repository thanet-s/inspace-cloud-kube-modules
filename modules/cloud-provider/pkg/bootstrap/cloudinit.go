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

var rke2VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$`)

const kubeVIPImage = "ghcr.io/kube-vip/kube-vip:v1.2.1@sha256:49b77655f9f109bedc5eb25723bb0e4c57d8513ba33cc69c31be3f243eb2386d"

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
}

// RenderCloudInitJSON returns the JSON object expected by InSpace's
// cloud_init form field. The guest discovers its RFC1918 NIC at boot and never
// treats the floating IPv4 as a local interface address.
func RenderCloudInitJSON(input CloudInitInput) (string, error) {
	if input.NodeName == "" || input.RKE2Token == "" || input.PrivateSubnet == "" || input.VirtualIPv4 == "" || input.PodCIDR == "" || input.ServiceCIDR == "" ||
		input.PrivateLoadBalancerPoolStart == "" || input.PrivateLoadBalancerPoolStop == "" {
		return "", errors.New("bootstrap: node name, token, private subnet, virtual IPv4, pod CIDR, service CIDR, and private load-balancer pool are required")
	}
	externalAddress, err := netip.ParseAddr(input.NodeExternalIPv4)
	if err != nil || !externalAddress.Is4() || !externalAddress.IsGlobalUnicast() || externalAddress.IsPrivate() {
		return "", errors.New("bootstrap: node external IP must be the allocated public IPv4")
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
	privatePool, err := validatePrivateLoadBalancerPool(
		input.PrivateSubnet, input.PodCIDR, input.ServiceCIDR, input.VirtualIPv4,
		input.PrivateLoadBalancerPoolStart, input.PrivateLoadBalancerPoolStop,
	)
	if err != nil {
		return "", err
	}
	config := renderRKE2Config(input)
	ciliumConfig := renderRKE2CiliumConfig(input.PodCIDR, privatePool.AddressCount)
	ciliumLoadBalancerConfig := renderCiliumPrivateLoadBalancerManifest(input.PrivateLoadBalancerPoolStart, input.PrivateLoadBalancerPoolStop)
	kubeVIPConfig := renderKubeVIPStaticPod(input.VirtualIPv4)
	script := renderInstallScript(input)
	payload := struct {
		WriteFiles []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		} `json:"write_files"`
		RunCmd []string `json:"runcmd"`
	}{}
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
	payload.RunCmd = []string{"/usr/local/sbin/inspace-bootstrap-rke2"}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RenderBastionCloudInitJSON disables any image-provided host firewall. All
// packet policy is enforced by the separately owned InSpace bastion firewall.
func RenderBastionCloudInitJSON() (string, error) {
	payload := struct {
		WriteFiles []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		} `json:"write_files"`
		RunCmd []string `json:"runcmd"`
	}{
		WriteFiles: []struct {
			Path        string `json:"path"`
			Content     string `json:"content"`
			Permissions string `json:"permissions"`
			Encoding    string `json:"encoding"`
			Owner       string `json:"owner"`
		}{{
			Path: "/usr/local/sbin/inspace-disable-ufw", Content: base64.StdEncoding.EncodeToString([]byte(renderDisableUFWScript())),
			Permissions: "0700", Encoding: "b64", Owner: "root:root",
		}},
		RunCmd: []string{"/usr/local/sbin/inspace-disable-ufw"},
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
		"node-external-ip: " + yamlString(input.NodeExternalIPv4),
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

func renderRKE2CiliumConfig(podCIDR string, privateLoadBalancerAddressCount uint64) string {
	qps := (privateLoadBalancerAddressCount + 4) / 5
	if qps < 10 {
		qps = 10
	}
	burst := qps * 2
	if burst < 20 {
		burst = 20
	}
	return fmt.Sprintf(`apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-cilium
  namespace: kube-system
spec:
  valuesContent: |-
    routingMode: native
    ipv4NativeRoutingCIDR: %s
    autoDirectNodeRoutes: true
    kubeProxyReplacement: true
    enableIPv4Masquerade: true
    l2announcements:
      enabled: true
    defaultLBServiceIPAM: none
    nodeIPAM:
      enabled: false
    k8sClientRateLimit:
      qps: %d
      burst: %d
    ipam:
      mode: kubernetes
    k8sServiceHost: localhost
    k8sServicePort: 6443
`, yamlString(podCIDR), qps, burst)
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

func renderKubeVIPStaticPod(virtualIPv4 string) string {
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
  priorityClassName: system-node-critical
  containers:
    - name: kube-vip
      image: %s
      imagePullPolicy: IfNotPresent
      args: ["manager"]
      env:
        - name: vip_arp
          value: "true"
        - name: vip_interface
          value: "__PRIVATE_IFACE__"
        - name: vip_subnet
          value: "32"
        - name: cp_enable
          value: "true"
        - name: cp_namespace
          value: "kube-system"
        - name: svc_enable
          value: "false"
        - name: vip_leaderelection
          value: "true"
        - name: vip_leasename
          value: "inspace-control-plane-vip"
        - name: address
          value: %s
        - name: port
          value: "6443"
        - name: k8s_config_file
          value: "/etc/rancher/rke2/rke2.yaml"
      securityContext:
        capabilities:
          add: ["NET_ADMIN", "NET_RAW"]
      volumeMounts:
        - name: kubeconfig
          mountPath: /etc/rancher/rke2/rke2.yaml
          readOnly: true
  volumes:
    - name: kubeconfig
      hostPath:
        path: /etc/rancher/rke2/rke2.yaml
        type: File
`, kubeVIPImage, yamlString(virtualIPv4))
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

func renderInstallScript(input CloudInitInput) string {
	releaseBase := "https://github.com/rancher/rke2/releases/download/" + url.PathEscape(input.RKE2Version)
	return fmt.Sprintf(`#!/bin/sh
set -eu

attempt=0
until apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl iproute2 tar; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then exit 1; fi
  sleep 10
done

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
`, input.PrivateSubnet, input.VirtualIPv4, strings.TrimSpace(strings.TrimPrefix(renderDisableUFWScript(), "#!/bin/sh\nset -eu\n")), input.RKE2Version, releaseBase)
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

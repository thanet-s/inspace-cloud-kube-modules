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

var k3sVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$`)

type CloudInitInput struct {
	NodeName           string
	NodeExternalIPv4   string
	PrivateSubnet      string
	K3sVersion         string
	K3sToken           string
	ClusterInit        bool
	ServerAddress      string
	PodCIDR            string
	ServiceCIDR        string
	TLSSubjectAltNames []string
	Disable            []string
	ManagementCIDR     string
	ManagementTCPPorts []int
}

// RenderCloudInitJSON returns the JSON object expected by InSpace's
// cloud_init form field. The guest discovers its RFC1918 NIC at boot and never
// treats the floating IPv4 as a local interface address.
func RenderCloudInitJSON(input CloudInitInput) (string, error) {
	if input.NodeName == "" || input.K3sToken == "" || input.PrivateSubnet == "" {
		return "", errors.New("bootstrap: node name, token, and private subnet are required")
	}
	externalAddress, err := netip.ParseAddr(input.NodeExternalIPv4)
	if err != nil || !externalAddress.Is4() || !externalAddress.IsGlobalUnicast() || externalAddress.IsPrivate() {
		return "", errors.New("bootstrap: node external IP must be the allocated public IPv4")
	}
	if !k3sVersionPattern.MatchString(input.K3sVersion) {
		return "", errors.New("bootstrap: K3s version must be an exact vX.Y.Z+k3sN release")
	}
	if !input.ClusterInit && input.ServerAddress == "" {
		return "", errors.New("bootstrap: joining server requires a server address")
	}
	if err := validateManagementAccess(input.ManagementCIDR, input.ManagementTCPPorts); err != nil {
		return "", err
	}
	config := renderK3sConfig(input)
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
	payload.WriteFiles = append(payload.WriteFiles, struct {
		Path        string `json:"path"`
		Content     string `json:"content"`
		Permissions string `json:"permissions"`
		Encoding    string `json:"encoding"`
		Owner       string `json:"owner"`
	}{
		Path: "/usr/local/sbin/inspace-bootstrap-k3s", Content: base64.StdEncoding.EncodeToString([]byte(script)),
		Permissions: "0700", Encoding: "b64", Owner: "root:root",
	})
	payload.WriteFiles = append(payload.WriteFiles, struct {
		Path        string `json:"path"`
		Content     string `json:"content"`
		Permissions string `json:"permissions"`
		Encoding    string `json:"encoding"`
		Owner       string `json:"owner"`
	}{
		Path: "/var/lib/inspace/k3s-config", Content: base64.StdEncoding.EncodeToString([]byte(config)),
		Permissions: "0600", Encoding: "b64", Owner: "root:root",
	})
	payload.WriteFiles = append(payload.WriteFiles, struct {
		Path        string `json:"path"`
		Content     string `json:"content"`
		Permissions string `json:"permissions"`
		Encoding    string `json:"encoding"`
		Owner       string `json:"owner"`
	}{
		Path: "/etc/systemd/system/k3s.service", Content: base64.StdEncoding.EncodeToString([]byte(k3sServerUnit)),
		Permissions: "0644", Encoding: "b64", Owner: "root:root",
	})
	payload.RunCmd = []string{"/usr/local/sbin/inspace-bootstrap-k3s"}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func renderK3sConfig(input CloudInitInput) string {
	lines := []string{
		"token: " + yamlString(input.K3sToken),
		"node-name: " + yamlString(input.NodeName),
		"node-ip: __PRIVATE_IP__",
		"node-external-ip: " + yamlString(input.NodeExternalIPv4),
		"advertise-address: __PRIVATE_IP__",
		"flannel-iface: __PRIVATE_IFACE__",
		"cluster-cidr: " + yamlString(input.PodCIDR),
		"service-cidr: " + yamlString(input.ServiceCIDR),
		"disable-cloud-controller: true",
		"write-kubeconfig-mode: \"0600\"",
		"node-taint:",
		"  - node-role.kubernetes.io/control-plane=true:NoSchedule",
		"kubelet-arg:",
		"  - cloud-provider=external",
	}
	if input.ClusterInit {
		lines = append(lines, "cluster-init: true")
	} else {
		lines = append(lines, "server: "+yamlString("https://"+input.ServerAddress+":6443"))
	}
	tlsNames := append([]string(nil), input.TLSSubjectAltNames...)
	sort.Strings(tlsNames)
	if len(tlsNames) != 0 {
		lines = append(lines, "tls-san:")
		for _, name := range tlsNames {
			lines = append(lines, "  - "+yamlString(name))
		}
	}
	disabled := append([]string(nil), input.Disable...)
	sort.Strings(disabled)
	if len(disabled) != 0 {
		lines = append(lines, "disable:")
		for _, component := range disabled {
			lines = append(lines, "  - "+yamlString(component))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderInstallScript(input CloudInitInput) string {
	releaseBase := "https://github.com/k3s-io/k3s/releases/download/" + url.PathEscape(input.K3sVersion)
	var firewallRules strings.Builder
	fmt.Fprintf(&firewallRules, "  ufw allow from %s\n", input.PrivateSubnet)
	for _, port := range sortedUniquePorts(input.ManagementTCPPorts) {
		fmt.Fprintf(&firewallRules, "  ufw allow proto tcp from %s to any port %d\n", input.ManagementCIDR, port)
	}
	return fmt.Sprintf(`#!/bin/sh
set -eu

attempt=0
until apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl iproute2 ufw; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then exit 1; fi
  sleep 10
done

find_private_ip() {
  for cidr in $(ip -o -4 addr show scope global | awk '{print $4}'); do
    address=${cidr%%/*}
    case "$address" in
      10.*|192.168.*) printf '%%s\n' "$address"; return 0 ;;
      172.*)
        second=$(printf '%%s' "$address" | cut -d. -f2)
        if [ "$second" -ge 16 ] && [ "$second" -le 31 ]; then printf '%%s\n' "$address"; return 0; fi
        ;;
    esac
  done
  return 1
}

PRIVATE_IP="$(find_private_ip)"
PRIVATE_IFACE="$(ip -o -4 addr show | awk -v ip="$PRIVATE_IP" '$4 ~ ("^" ip "/") {print $2; exit}')"
test -n "$PRIVATE_IP"
test -n "$PRIVATE_IFACE"

install -d -m 0700 /etc/rancher/k3s
install -m 0600 /var/lib/inspace/k3s-config /etc/rancher/k3s/config.yaml
sed -i "s/__PRIVATE_IP__/$PRIVATE_IP/g; s/__PRIVATE_IFACE__/$PRIVATE_IFACE/g" /etc/rancher/k3s/config.yaml
chmod 0600 /etc/rancher/k3s/config.yaml

if command -v ufw >/dev/null 2>&1; then
  ufw default deny incoming
  ufw default allow outgoing
%s
  ufw --force enable
fi

version='%s'
release_base='%s'
if ! [ -x /usr/local/bin/k3s ] || ! /usr/local/bin/k3s --version 2>/dev/null | grep -F -- "k3s version $version" >/dev/null; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM
  attempt=0
  until curl --fail --location --silent --show-error --connect-timeout 10 --output "$tmpdir/k3s" "$release_base/k3s" && \
        curl --fail --location --silent --show-error --connect-timeout 10 --output "$tmpdir/sha256sum-amd64.txt" "$release_base/sha256sum-amd64.txt"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then exit 1; fi
    sleep 10
  done
  expected="$(awk '$2 == "k3s" || $2 == "./k3s" {print $1; exit}' "$tmpdir/sha256sum-amd64.txt")"
  test -n "$expected"
  actual="$(sha256sum "$tmpdir/k3s" | awk '{print $1}')"
  test "$actual" = "$expected"
  install -o root -g root -m 0755 "$tmpdir/k3s" /usr/local/bin/k3s
fi
/usr/local/bin/k3s --version | grep -F -- "k3s version $version" >/dev/null
systemctl daemon-reload
systemctl enable --now k3s.service
`, strings.TrimRight(firewallRules.String(), "\n"), input.K3sVersion, releaseBase)
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

func yamlString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

const k3sServerUnit = `[Unit]
Description=Lightweight Kubernetes Server
After=network-online.target
Wants=network-online.target
ConditionPathIsExecutable=/usr/local/bin/k3s

[Service]
Type=notify
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
ExecStart=/usr/local/bin/k3s server
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

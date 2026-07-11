package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

// SchemaVersion must be bumped whenever generated bootstrap semantics change.
// It is included in the provider drift hash so existing nodes are replaced.
const (
	SchemaVersion           = "stock-ubuntu-k3s-v3"
	ExternalIPv4Placeholder = "__INSPACE_FLOATING_IPV4__"
)

type Config struct {
	NodeName         string
	Server           string
	Token            string
	K3sVersion       string
	Labels           map[string]string
	Taints           []corev1.Taint
	AdditionalScript string
}

type document struct {
	WriteFiles []writeFile `json:"write_files"`
	RunCmd     [][]string  `json:"runcmd"`
}

type writeFile struct {
	Path        string `json:"path"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Content     string `json:"content"`
}

// RenderCloudInit returns the JSON object expected by the InSpace cloud_init
// form field. It bootstraps a stock Ubuntu image and pins both the K3s binary
// and checksum asset to the exact NodeClass version.
func RenderCloudInit(config Config) (string, error) {
	if config.NodeName == "" || config.Server == "" || config.Token == "" || config.K3sVersion == "" {
		return "", fmt.Errorf("node name, server, token, and K3s version are required")
	}
	taints := ensureRegistrationTaint(config.Taints)

	var k3s strings.Builder
	fmt.Fprintf(&k3s, "server: %s\n", quote(config.Server))
	fmt.Fprintf(&k3s, "token: %s\n", quote(config.Token))
	fmt.Fprintf(&k3s, "node-name: %s\n", quote(config.NodeName))
	fmt.Fprintf(&k3s, "node-external-ip: %s\n", quote(ExternalIPv4Placeholder))
	k3s.WriteString("kubelet-arg:\n  - cloud-provider=external\n")

	labelKeys := make([]string, 0, len(config.Labels))
	for key := range config.Labels {
		labelKeys = append(labelKeys, key)
	}
	sort.Strings(labelKeys)
	if len(labelKeys) != 0 {
		k3s.WriteString("node-label:\n")
		for _, key := range labelKeys {
			fmt.Fprintf(&k3s, "  - %s\n", quote(key+"="+config.Labels[key]))
		}
	}
	if len(taints) != 0 {
		k3s.WriteString("node-taint:\n")
		for _, taint := range taints {
			fmt.Fprintf(&k3s, "  - %s\n", quote(formatTaint(taint)))
		}
	}

	unit := `[Unit]
Description=Lightweight Kubernetes Agent
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
ExecStartPre=/usr/local/sbin/inspace-detect-private-ip
ExecStart=/usr/local/bin/k3s agent
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
	privateIP := `#!/bin/sh
set -eu
private_ip="$(ip -4 -o addr show scope global | awk '
  {
    split($4, cidr, "/"); split(cidr[1], octet, ".")
    if (octet[1] == 10 || (octet[1] == 172 && octet[2] >= 16 && octet[2] <= 31) || (octet[1] == 192 && octet[2] == 168)) {
      print cidr[1]; exit
    }
  }
')"
[ -n "$private_ip" ]
install -d -o root -g root -m 0700 /etc/rancher/k3s/config.yaml.d
umask 077
printf 'node-ip: "%s"\n' "$private_ip" > /etc/rancher/k3s/config.yaml.d/10-private-node-ip.yaml
`
	firewall := `#!/bin/sh
set -eu
private_if="$(ip -4 -o addr show scope global | awk '
  {
    split($4, cidr, "/"); split(cidr[1], octet, ".")
    if (octet[1] == 10 || (octet[1] == 172 && octet[2] >= 16 && octet[2] <= 31) || (octet[1] == 192 && octet[2] == 168)) {
      print $2; exit
    }
  }
')"
[ -n "$private_if" ]
ufw --force default deny incoming
ufw --force default allow outgoing
ufw allow in on "$private_if" from 10.0.0.0/8
ufw allow in on "$private_if" from 172.16.0.0/12
ufw allow in on "$private_if" from 192.168.0.0/16
ufw --force enable
`
	prerequisites := `#!/bin/sh
set -eu
attempt=0
while :; do
  attempt=$((attempt + 1))
  if apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
     DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl iproute2 ufw; then
    exit 0
  fi
  echo "waiting for floating-IP egress before package installation (attempt $attempt)" >&2
  sleep 5
done
`

	versionURL := url.PathEscape(config.K3sVersion)
	releaseBase := "https://github.com/k3s-io/k3s/releases/download/" + versionURL
	install := fmt.Sprintf(`#!/bin/sh
set -eu
version=%s
if [ -x /usr/local/bin/k3s ] && /usr/local/bin/k3s --version 2>/dev/null | grep -F -- "k3s version $version" >/dev/null; then
  exit 0
fi
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
download_asset() {
  url="$1"
  output="$2"
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    if curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --output "$output" "$url"; then
      return 0
    fi
    sleep 5
  done
}
download_asset %s/k3s "$tmpdir/k3s"
download_asset %s/sha256sum-amd64.txt "$tmpdir/sha256sum-amd64.txt"
expected="$(awk '$2 == "k3s" || $2 == "./k3s" { print $1; exit }' "$tmpdir/sha256sum-amd64.txt")"
[ -n "$expected" ]
actual="$(sha256sum "$tmpdir/k3s" | awk '{ print $1 }')"
[ "$actual" = "$expected" ]
install -o root -g root -m 0755 "$tmpdir/k3s" /usr/local/bin/k3s
/usr/local/bin/k3s --version | grep -F -- "k3s version $version" >/dev/null
`, shellQuote(config.K3sVersion), shellQuote(releaseBase), shellQuote(releaseBase))

	doc := document{
		WriteFiles: []writeFile{
			{Path: "/etc/rancher/k3s/config.yaml", Owner: "root:root", Permissions: "0600", Content: k3s.String()},
			{Path: "/etc/systemd/system/k3s-agent.service", Owner: "root:root", Permissions: "0644", Content: unit},
			{Path: "/usr/local/sbin/inspace-install-prerequisites", Owner: "root:root", Permissions: "0700", Content: prerequisites},
			{Path: "/usr/local/sbin/inspace-install-k3s", Owner: "root:root", Permissions: "0700", Content: install},
			{Path: "/usr/local/sbin/inspace-detect-private-ip", Owner: "root:root", Permissions: "0700", Content: privateIP},
			{Path: "/usr/local/sbin/inspace-firewall", Owner: "root:root", Permissions: "0700", Content: firewall},
		},
		RunCmd: [][]string{{"/usr/local/sbin/inspace-install-prerequisites"}, {"/usr/local/sbin/inspace-install-k3s"}, {"/usr/local/sbin/inspace-detect-private-ip"}, {"/usr/local/sbin/inspace-firewall"}},
	}
	if strings.TrimSpace(config.AdditionalScript) != "" {
		doc.WriteFiles = append(doc.WriteFiles, writeFile{
			Path:        "/usr/local/sbin/inspace-additional-user-data",
			Owner:       "root:root",
			Permissions: "0700",
			Content:     "#!/bin/sh\nset -eu\n" + strings.TrimRight(config.AdditionalScript, "\n") + "\n",
		})
		// cloud-init-per's once semaphore makes the extension safe if runcmd is
		// manually replayed during troubleshooting.
		doc.RunCmd = append(doc.RunCmd, []string{"cloud-init-per", "once", "inspace-additional-user-data", "/bin/sh", "/usr/local/sbin/inspace-additional-user-data"})
	}
	doc.RunCmd = append(doc.RunCmd,
		[]string{"systemctl", "daemon-reload"},
		[]string{"systemctl", "enable", "--now", "k3s-agent.service"},
	)

	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal cloud-init JSON: %w", err)
	}
	return string(data), nil
}

// ValidateExternalIPv4Template ensures adapter substitution is deterministic
// and cannot silently leave a worker advertising a placeholder address.
func ValidateExternalIPv4Template(cloudInitJSON string) error {
	var object map[string]any
	if err := json.Unmarshal([]byte(cloudInitJSON), &object); err != nil || object == nil {
		return fmt.Errorf("cloud-init must be a JSON object")
	}
	if count := strings.Count(cloudInitJSON, ExternalIPv4Placeholder); count != 1 {
		return fmt.Errorf("cloud-init must contain exactly one external IPv4 placeholder, found %d", count)
	}
	return nil
}

// ResolveExternalIPv4 replaces the single strict template token immediately
// before VM creation, after the adapter has allocated the named floating IP.
func ResolveExternalIPv4(cloudInitJSON, address string) (string, error) {
	if err := ValidateExternalIPv4Template(cloudInitJSON); err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", fmt.Errorf("external node IP must be a public IPv4 address")
	}
	resolved := strings.Replace(cloudInitJSON, ExternalIPv4Placeholder, address, 1)
	if strings.Contains(resolved, ExternalIPv4Placeholder) {
		return "", fmt.Errorf("cloud-init contains an unresolved external IPv4 placeholder")
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(resolved), &object); err != nil || object == nil {
		return "", fmt.Errorf("resolved cloud-init must remain a JSON object")
	}
	return resolved, nil
}

func ensureRegistrationTaint(taints []corev1.Taint) []corev1.Taint {
	result := make([]corev1.Taint, 0, len(taints)+1)
	for _, taint := range taints {
		if taint.Key == karpv1.UnregisteredTaintKey {
			continue
		}
		result = append(result, taint)
	}
	result = append(result, karpv1.UnregisteredNoExecuteTaint)
	sort.Slice(result, func(i, j int) bool { return formatTaint(result[i]) < formatTaint(result[j]) })
	return result
}

func formatTaint(taint corev1.Taint) string {
	value := taint.Key
	if taint.Value != "" {
		value += "=" + taint.Value
	}
	return value + ":" + string(taint.Effect)
}

func quote(value string) string { return strconv.Quote(value) }

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

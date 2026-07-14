package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
)

// SchemaVersion must be bumped whenever generated bootstrap semantics change.
// It is included in the provider drift hash so existing nodes are replaced.
const (
	SchemaVersion         = "stock-ubuntu-rke2-v11"
	VPCSubnetPlaceholder  = "__INSPACE_VPC_SUBNET__"
	NativeRoutingPodCIDR  = "10.42.0.0/16"
	KubernetesServiceCIDR = "10.43.0.0/16"
	bootstrapCacheCAPath  = "/etc/rancher/rke2/bootstrap-cache-ca.crt"
)

var exactRKE2VersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+\+rke2r[0-9]+$`)

type Config struct {
	NodeName         string
	Server           string
	Token            string
	RKE2Version      string
	Labels           map[string]string
	Taints           []corev1.Taint
	AdditionalScript string
	// BootstrapCache is nil only for the explicit direct-download mode.
	BootstrapCache *CacheConfig
}

type CacheConfig struct {
	Host     string
	Address  string
	CABundle string
}

type document struct {
	Hostname         string      `json:"hostname,omitempty"`
	PreserveHostname bool        `json:"preserve_hostname"`
	WriteFiles       []writeFile `json:"write_files"`
	RunCmd           []string    `json:"runcmd"`
}

type writeFile struct {
	Path        string `json:"path"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
}

// RenderCloudInit returns the JSON object expected by the InSpace cloud_init
// form field. It bootstraps a stock Ubuntu image and pins both the RKE2
// distribution tarball and checksum asset to the exact NodeClass version. A
// configured private cache rewrites only RKE2-owned system images and assets;
// it never installs public-registry mirrors for arbitrary workloads.
func RenderCloudInit(config Config) (string, error) {
	if config.NodeName == "" || config.Server == "" || config.Token == "" || config.RKE2Version == "" {
		return "", fmt.Errorf("node name, server, token, and RKE2 version are required")
	}
	if messages := k8svalidation.IsDNS1123Label(config.NodeName); len(messages) != 0 {
		return "", fmt.Errorf("node name must be a DNS-1123 hostname label: %s", strings.Join(messages, "; "))
	}
	if !exactRKE2VersionPattern.MatchString(config.RKE2Version) {
		return "", fmt.Errorf("RKE2 version must be an exact vX.Y.Z+rke2rN release")
	}
	if err := validateCacheConfig(config.BootstrapCache); err != nil {
		return "", err
	}
	server, err := url.Parse(config.Server)
	if err != nil || server.Scheme != "https" || server.Port() != "9345" || server.Path != "" || server.RawPath != "" || server.Opaque != "" || server.User != nil || server.RawQuery != "" || server.ForceQuery || server.Fragment != "" {
		return "", fmt.Errorf("RKE2 server must be https://<RFC1918-IPv4>:9345 without a path, query, fragment, or userinfo")
	}
	serverVIP, err := netip.ParseAddr(server.Hostname())
	if err != nil || !serverVIP.Is4() || !serverVIP.IsPrivate() ||
		netip.MustParsePrefix(NativeRoutingPodCIDR).Contains(serverVIP) ||
		netip.MustParsePrefix(KubernetesServiceCIDR).Contains(serverVIP) ||
		config.Server != "https://"+serverVIP.String()+":9345" {
		return "", fmt.Errorf("RKE2 server host must be a canonical literal RFC1918 IPv4 outside pod CIDR %s and Service CIDR %s", NativeRoutingPodCIDR, KubernetesServiceCIDR)
	}
	taints := ensureRegistrationTaint(config.Taints)

	var rke2 strings.Builder
	fmt.Fprintf(&rke2, "server: %s\n", quote(config.Server))
	fmt.Fprintf(&rke2, "token: %s\n", quote(config.Token))
	fmt.Fprintf(&rke2, "node-name: %s\n", quote(config.NodeName))
	cacheRegistry := ""
	if config.BootstrapCache != nil {
		cacheRegistry = fmt.Sprintf("%s:%d", config.BootstrapCache.Host, inspacev1.BootstrapCachePort)
		fmt.Fprintf(&rke2, "system-default-registry: %s\n", quote(cacheRegistry))
	}
	rke2.WriteString("kubelet-arg:\n  - cloud-provider=external\n")

	labelKeys := make([]string, 0, len(config.Labels))
	for key := range config.Labels {
		labelKeys = append(labelKeys, key)
	}
	sort.Strings(labelKeys)
	if len(labelKeys) != 0 {
		rke2.WriteString("node-label:\n")
		for _, key := range labelKeys {
			fmt.Fprintf(&rke2, "  - %s\n", quote(key+"="+config.Labels[key]))
		}
	}
	if len(taints) != 0 {
		rke2.WriteString("node-taint:\n")
		for _, taint := range taints {
			fmt.Fprintf(&rke2, "  - %s\n", quote(formatTaint(taint)))
		}
	}

	serviceDropIn := `[Service]
ExecStartPre=/usr/local/sbin/inspace-detect-private-ip
ExecStartPre=/usr/local/sbin/inspace-verify-host-firewall
`
	nodeLimitsDropIn := `[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
LimitMEMLOCK=infinity
TasksMax=infinity
`
	sysctlConfig := `net.ipv4.ip_forward = 1
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
`
	securityLimits := `* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
`
	disablePeriodicAPTConfig := `APT::Periodic::Enable "0";
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
`
	ubuntuMirrorList := `http://mirror1.totbb.net/ubuntu/	priority:1
https://mirror.kku.ac.th/ubuntu/	priority:2
`
	ubuntuSources := `Types: deb
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
	staticResolver := `# Managed by InSpace Kubernetes bootstrap.
nameserver 8.8.8.8
nameserver 8.8.4.4
options edns0
`
	cacheHostsCommands := ""
	if config.BootstrapCache != nil {
		cacheHostsCommands = fmt.Sprintf(`cache_host=%s
cache_ipv4=%s
cache_entry="$cache_ipv4 $cache_host # inspace-bootstrap-cache"
sed -i '\|[[:space:]]# inspace-bootstrap-cache$|d' /etc/hosts
printf '%%s\n' "$cache_entry" >> /etc/hosts
grep -Fqx -- "$cache_entry" /etc/hosts
`, shellQuote(config.BootstrapCache.Host), shellQuote(config.BootstrapCache.Address))
	}
	prepareHost := fmt.Sprintf(`#!/bin/sh
set -eu
expected_hostname=%s
hostnamectl set-hostname --static "$expected_hostname"
[ "$(hostnamectl --static)" = "$expected_hostname" ]
sed -Ei '/^[[:space:]]*127\.0\.1\.1([[:space:]]|$)/d' /etc/hosts
printf '127.0.1.1\t%%s\n' "$expected_hostname" >>/etc/hosts
hostname_attempt=0
until getent hosts "$expected_hostname" | grep -Eq '^127\.0\.1\.1[[:space:]]'; do
  hostname_attempt=$((hostname_attempt + 1))
  if [ "$hostname_attempt" -ge 30 ]; then
    echo "generated hostname did not resolve to 127.0.1.1" >&2
    exit 1
  fi
  sleep 1
done
%s
swapoff -a
if [ -f /etc/fstab ]; then
  sed -Ei '/^[[:space:]]*#/! { /[[:space:]]swap[[:space:]]/ s/^/#/; }' /etc/fstab
fi
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
`, shellQuote(config.NodeName), strings.TrimSpace(cacheHostsCommands))
	applyNodeTuning := `#!/bin/sh
set -eu
sysctl --system >/dev/null
[ "$(sysctl -n net.ipv4.ip_forward)" -eq 1 ]
[ "$(sysctl -n fs.inotify.max_user_instances)" -ge 8192 ]
[ "$(sysctl -n fs.inotify.max_user_watches)" -ge 524288 ]
[ -z "$(swapon --show --noheadings)" ]
install -d -m 0755 /var/lib/inspace
: > /var/lib/inspace/kubernetes-node-prepared-v1
chmod 0600 /var/lib/inspace/kubernetes-node-prepared-v1
`
	privateIP := fmt.Sprintf(`#!/bin/sh
set -eu
vpc_subnet='%s'
supervisor_vip='%s'
vpc_identities="$(ip -o -4 addr show to "$vpc_subnet" scope global | awk -v vip="$supervisor_vip" '$3 == "inet" { split($4, address, "/"); if (address[1] != vip) print $2, address[1] }')"
[ -n "$vpc_identities" ]
[ "$(printf '%%s\n' "$vpc_identities" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ]
set -- $vpc_identities
private_if=${1%%%%@*}
private_ip=$2
[ -n "$private_if" ]
[ -n "$private_ip" ]
config=/etc/rancher/rke2/config.yaml
[ -f "$config" ]
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM
awk -v private_ip="$private_ip" '
  BEGIN { replaced = 0 }
  /^node-ip:/ {
    if (!replaced) {
	      printf "node-ip: \"%%s\"\n", private_ip
      replaced = 1
    }
    next
  }
  { print }
  END {
    if (!replaced) {
	      printf "node-ip: \"%%s\"\n", private_ip
    }
  }
' "$config" > "$tmp"
install -o root -g root -m 0600 "$tmp" "$config"
`, VPCSubnetPlaceholder, serverVIP.String())
	verifyHostFirewallBody := `if command -v ufw >/dev/null 2>&1; then
	LC_ALL=C ufw status | grep -Fq "Status: inactive"
fi
if command -v systemctl >/dev/null 2>&1; then
	unit_state="$(systemctl list-unit-files ufw.service --no-legend 2>/dev/null | awk '$1 == "ufw.service" { print $2; exit }')"
	if [ -n "$unit_state" ]; then
		if systemctl is-active --quiet ufw.service; then
			echo "ufw.service is still active" >&2
			exit 1
		fi
		enabled_state="$(systemctl is-enabled ufw.service 2>/dev/null || true)"
		case "$enabled_state" in
			disabled|masked) ;;
			*) echo "ufw.service is not disabled (state: $enabled_state)" >&2; exit 1 ;;
		esac
	fi
fi
`
	verifyHostFirewall := "#!/bin/sh\nset -eu\n" + verifyHostFirewallBody
	disableHostFirewall := `#!/bin/sh
set -eu
if command -v ufw >/dev/null 2>&1; then
	ufw --force disable
fi
if command -v systemctl >/dev/null 2>&1; then
	unit_state="$(systemctl list-unit-files ufw.service --no-legend 2>/dev/null | awk '$1 == "ufw.service" { print $2; exit }')"
	if [ -n "$unit_state" ]; then
		systemctl disable --now ufw.service
	fi
fi
` + verifyHostFirewallBody
	startAgent := `#!/bin/sh
set -eu
systemctl daemon-reload
systemctl enable rke2-agent.service
systemctl start --no-block rke2-agent.service
attempt=0
until systemctl is-active --quiet rke2-agent.service; do
	attempt=$((attempt + 1))
	if systemctl is-failed --quiet rke2-agent.service || [ "$attempt" -ge 180 ]; then
		echo "rke2-agent.service failed to become active after $attempt checks" >&2
		exit 1
	fi
	sleep 5
done
`
	prerequisites := `#!/bin/sh
set -eu
package_deadline=$(( $(date +%s) + 600 ))
run_package_command() {
  package_remaining=$(( package_deadline - $(date +%s) ))
  [ "$package_remaining" -gt 0 ] || return 124
  timeout --kill-after=30s "${package_remaining}s" "$@"
}
attempt=0
while [ "$attempt" -lt 60 ]; do
  attempt=$((attempt + 1))
  if run_package_command apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
     run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y && \
     run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl gzip iproute2 procps tar; then
    exit 0
  fi
  echo "waiting for floating-IP egress before package installation (attempt $attempt)" >&2
  if [ "$attempt" -lt 60 ] && [ "$(date +%s)" -lt "$package_deadline" ]; then
    sleep 5
  else
    break
  fi
done
echo "package installation failed after $attempt attempts" >&2
exit 1
`
	disableAutomaticAPTUpdates := `#!/bin/sh
set -eu
periodic_config="${INSPACE_APT_PERIODIC_CONFIG:-/etc/apt/apt.conf.d/99-inspace-disable-periodic}"
periodic_tmp="$(mktemp)"
trap 'rm -f "$periodic_tmp"' EXIT INT TERM
cat > "$periodic_tmp" <<'INSPACE_APT_PERIODIC'
APT::Periodic::Enable "0";
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
INSPACE_APT_PERIODIC
install -d -m 0755 "$(dirname "$periodic_config")"
install -m 0644 "$periodic_tmp" "$periodic_config"
for directive in \
  'APT::Periodic::Enable "0";' \
  'APT::Periodic::Update-Package-Lists "0";' \
  'APT::Periodic::Download-Upgradeable-Packages "0";' \
  'APT::Periodic::AutocleanInterval "0";' \
  'APT::Periodic::Unattended-Upgrade "0";'; do
  grep -Fqx "$directive" "$periodic_config"
done
if command -v systemctl >/dev/null 2>&1; then
  for unit in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service; do
    load_state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null || true)"
    [ "$load_state" = "not-found" ] && continue
    systemctl mask --now "$unit"
    if systemctl is-active --quiet "$unit"; then
      echo "$unit is still active" >&2
      exit 1
    fi
    enabled_state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    [ "$enabled_state" = "masked" ] || {
      echo "$unit is not masked (state: $enabled_state)" >&2
      exit 1
    }
  done
fi
`

	versionURL := url.PathEscape(config.RKE2Version)
	releaseBase := "https://github.com/rancher/rke2/releases/download/" + versionURL
	cacheCA := ""
	cacheHealthURL := ""
	if config.BootstrapCache != nil {
		releaseBase = "https://" + cacheRegistry + "/rke2/" + versionURL
		cacheCA = bootstrapCacheCAPath
		cacheHealthURL = "https://" + cacheRegistry + "/healthz"
	}
	install := fmt.Sprintf(`#!/bin/sh
set -eu
version=%s
cache_ca=%s
cache_health_url=%s
if [ -n "$cache_ca" ]; then
  [ -s "$cache_ca" ]
  attempt=0
  until curl --fail --silent --show-error --connect-timeout 5 --max-time 15 --retry 2 --retry-all-errors --cacert "$cache_ca" --output /dev/null "$cache_health_url"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      echo "bootstrap cache did not become healthy after $attempt attempts" >&2
      exit 1
    fi
    sleep 5
  done
fi
if [ -x /usr/local/bin/rke2 ] && \
   [ -f /usr/local/lib/systemd/system/rke2-agent.service ] && \
   /usr/local/bin/rke2 --version 2>/dev/null | grep -F -- "rke2 version $version" >/dev/null; then
  exit 0
fi
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
download_asset() {
  url="$1"
  output="$2"
  cache_ca=${cache_ca:-}
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    attempt=$((attempt + 1))
    if [ -n "$cache_ca" ]; then
      curl_result=0
      curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --cacert "$cache_ca" --output "$output" "$url" || curl_result=$?
    else
      curl_result=0
      curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors --output "$output" "$url" || curl_result=$?
    fi
    if [ "$curl_result" -eq 0 ]; then
      return 0
    fi
    if [ "$attempt" -lt 60 ]; then
      sleep 5
    fi
  done
  echo "download of $url failed after $attempt attempts" >&2
  return 1
}
download_asset %s/rke2.linux-amd64.tar.gz "$tmpdir/rke2.linux-amd64.tar.gz"
download_asset %s/sha256sum-amd64.txt "$tmpdir/sha256sum-amd64.txt"
expected="$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" { print $1; exit }' "$tmpdir/sha256sum-amd64.txt")"
[ -n "$expected" ]
actual="$(sha256sum "$tmpdir/rke2.linux-amd64.tar.gz" | awk '{ print $1 }')"
[ "$actual" = "$expected" ]
tar -xzf "$tmpdir/rke2.linux-amd64.tar.gz" -C /usr/local
/usr/local/bin/rke2 --version | grep -F -- "rke2 version $version" >/dev/null
`, shellQuote(config.RKE2Version), shellQuote(cacheCA), shellQuote(cacheHealthURL), shellQuote(releaseBase), shellQuote(releaseBase))

	doc := document{
		Hostname:         config.NodeName,
		PreserveHostname: false,
		WriteFiles: []writeFile{
			encodedWriteFile("/etc/hostname", "0644", config.NodeName+"\n"),
			encodedWriteFile("/etc/rancher/rke2/config.yaml", "0600", rke2.String()),
			encodedWriteFile("/etc/systemd/system/rke2-agent.service.d/10-inspace-private-ip.conf", "0644", serviceDropIn),
			encodedWriteFile("/etc/systemd/system/rke2-agent.service.d/20-inspace-node-limits.conf", "0644", nodeLimitsDropIn),
			encodedWriteFile("/etc/sysctl.d/90-inspace-kubernetes.conf", "0644", sysctlConfig),
			encodedWriteFile("/etc/security/limits.d/90-inspace-kubernetes.conf", "0644", securityLimits),
			encodedWriteFile("/etc/apt/apt.conf.d/99-inspace-disable-periodic", "0644", disablePeriodicAPTConfig),
			encodedWriteFile("/var/lib/inspace/ubuntu-mirrors.list", "0644", ubuntuMirrorList),
			encodedWriteFile("/var/lib/inspace/ubuntu.sources", "0644", ubuntuSources),
			encodedWriteFile("/var/lib/inspace/static-resolv.conf", "0644", staticResolver),
			encodedWriteFile("/usr/local/sbin/inspace-prepare-kubernetes-node", "0700", prepareHost),
			encodedWriteFile("/usr/local/sbin/inspace-install-prerequisites", "0700", prerequisites),
			encodedWriteFile("/usr/local/sbin/inspace-disable-automatic-apt-updates", "0700", disableAutomaticAPTUpdates),
			encodedWriteFile("/usr/local/sbin/inspace-install-rke2", "0700", install),
			encodedWriteFile("/usr/local/sbin/inspace-apply-node-tuning", "0700", applyNodeTuning),
			encodedWriteFile("/usr/local/sbin/inspace-detect-private-ip", "0700", privateIP),
			encodedWriteFile("/usr/local/sbin/inspace-disable-host-firewall", "0700", disableHostFirewall),
			encodedWriteFile("/usr/local/sbin/inspace-verify-host-firewall", "0700", verifyHostFirewall),
			encodedWriteFile("/usr/local/sbin/inspace-start-rke2-agent", "0700", startAgent),
		},
	}
	if config.BootstrapCache != nil {
		registryConfig := fmt.Sprintf("configs:\n  %s:\n    tls:\n      ca_file: %s\n", quote(cacheRegistry), quote(bootstrapCacheCAPath))
		doc.WriteFiles = append(doc.WriteFiles,
			encodedWriteFile(bootstrapCacheCAPath, "0644", config.BootstrapCache.CABundle),
			encodedWriteFile("/etc/rancher/rke2/registries.yaml", "0600", registryConfig),
		)
	}
	var orchestrator strings.Builder
	orchestrator.WriteString(`#!/bin/sh
set -eu
/usr/local/sbin/inspace-prepare-kubernetes-node
/usr/local/sbin/inspace-install-prerequisites
/usr/local/sbin/inspace-disable-automatic-apt-updates
/usr/local/sbin/inspace-install-rke2
/usr/local/sbin/inspace-detect-private-ip
`)
	if strings.TrimSpace(config.AdditionalScript) != "" {
		doc.WriteFiles = append(doc.WriteFiles, encodedWriteFile(
			"/usr/local/sbin/inspace-additional-user-data",
			"0700",
			"#!/bin/sh\nset -eu\n"+strings.TrimRight(config.AdditionalScript, "\n")+"\n",
		))
		// cloud-init-per's once semaphore makes the extension safe if the
		// fail-fast orchestrator is manually replayed during troubleshooting.
		orchestrator.WriteString("cloud-init-per once inspace-additional-user-data /bin/sh /usr/local/sbin/inspace-additional-user-data\n")
	}
	orchestrator.WriteString(`/usr/local/sbin/inspace-disable-automatic-apt-updates
/usr/local/sbin/inspace-apply-node-tuning
/usr/local/sbin/inspace-disable-host-firewall
/usr/local/sbin/inspace-verify-host-firewall
/usr/local/sbin/inspace-start-rke2-agent
`)
	doc.WriteFiles = append(doc.WriteFiles, encodedWriteFile("/usr/local/sbin/inspace-bootstrap-rke2-agent", "0700", orchestrator.String()))
	doc.RunCmd = []string{"/usr/local/sbin/inspace-bootstrap-rke2-agent"}

	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal cloud-init JSON: %w", err)
	}
	return string(data), nil
}

func validateCacheConfig(cache *CacheConfig) error {
	if cache == nil {
		return nil
	}
	if messages := k8svalidation.IsDNS1123Subdomain(cache.Host); len(messages) != 0 {
		return fmt.Errorf("bootstrap cache host must be a DNS-1123 subdomain: %s", strings.Join(messages, "; "))
	}
	if err := inspacev1.ValidateBootstrapCache(inspacev1.BootstrapCacheSpec{
		Address:  cache.Address,
		CABundle: cache.CABundle,
	}); err != nil {
		return fmt.Errorf("bootstrap cache: %w", err)
	}
	return nil
}

// ValidateVPCSubnetTemplate ensures the production adapter can bind private-IP
// discovery to the exact API-reported VPC prefix before the VM is created.
func ValidateVPCSubnetTemplate(cloudInitJSON string) error {
	doc, err := parseDocument(cloudInitJSON)
	if err != nil {
		return err
	}
	count, err := placeholderCount(doc, cloudInitJSON, VPCSubnetPlaceholder)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("cloud-init must contain exactly one VPC subnet placeholder, found %d", count)
	}
	return nil
}

// ResolveVPCSubnet replaces the exact private-network prefix after the adapter
// has read and validated the selected InSpace network and before VM creation.
func ResolveVPCSubnet(cloudInitJSON, subnet string) (string, error) {
	if err := ValidateVPCSubnetTemplate(cloudInitJSON); err != nil {
		return "", err
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !isRFC1918Prefix(prefix) {
		return "", fmt.Errorf("worker VPC subnet must be an RFC1918 IPv4 prefix")
	}
	if prefix.Bits() > 27 {
		return "", fmt.Errorf("worker VPC subnet prefix length must be /27 or shorter")
	}
	for _, reserved := range []struct {
		description string
		cidr        string
	}{
		{description: "pod CIDR", cidr: NativeRoutingPodCIDR},
		{description: "Service CIDR", cidr: KubernetesServiceCIDR},
	} {
		if prefixesOverlap(prefix, netip.MustParsePrefix(reserved.cidr)) {
			return "", fmt.Errorf("worker VPC subnet %s must not overlap %s %s", prefix, reserved.description, reserved.cidr)
		}
	}
	return resolvePlaceholder(cloudInitJSON, VPCSubnetPlaceholder, prefix.Masked().String(), "VPC subnet")
}

func encodedWriteFile(path, permissions, content string) writeFile {
	return writeFile{
		Path: path, Owner: "root:root", Permissions: permissions, Encoding: "b64",
		Content: base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

func parseDocument(cloudInitJSON string) (document, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(cloudInitJSON), &object); err != nil || object == nil {
		return document{}, fmt.Errorf("cloud-init must be a JSON object")
	}
	var doc document
	if err := json.Unmarshal([]byte(cloudInitJSON), &doc); err != nil {
		return document{}, fmt.Errorf("decode cloud-init document: %w", err)
	}
	return doc, nil
}

func placeholderCount(doc document, rawJSON, placeholder string) (int, error) {
	count := strings.Count(rawJSON, placeholder)
	for _, file := range doc.WriteFiles {
		content, err := decodeWriteFile(file)
		if err != nil {
			return 0, err
		}
		count += strings.Count(content, placeholder)
	}
	return count, nil
}

func resolvePlaceholder(cloudInitJSON, placeholder, replacement, description string) (string, error) {
	doc, err := parseDocument(cloudInitJSON)
	if err != nil {
		return "", err
	}
	replaced := false
	for i := range doc.WriteFiles {
		content, err := decodeWriteFile(doc.WriteFiles[i])
		if err != nil {
			return "", err
		}
		if strings.Contains(content, placeholder) {
			content = strings.Replace(content, placeholder, replacement, 1)
			doc.WriteFiles[i].Content = base64.StdEncoding.EncodeToString([]byte(content))
			replaced = true
		}
	}
	if !replaced {
		return "", fmt.Errorf("cloud-init contains no %s placeholder", description)
	}
	resolved, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal resolved cloud-init JSON: %w", err)
	}
	count, err := placeholderCount(doc, string(resolved), placeholder)
	if err != nil {
		return "", err
	}
	if count != 0 {
		return "", fmt.Errorf("cloud-init contains an unresolved %s placeholder", description)
	}
	return string(resolved), nil
}

func isRFC1918Prefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return false
	}
	for _, allowed := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func prefixesOverlap(first, second netip.Prefix) bool {
	return first.IsValid() && second.IsValid() && first.Addr().BitLen() == second.Addr().BitLen() &&
		(first.Contains(second.Masked().Addr()) || second.Contains(first.Masked().Addr()))
}

func decodeWriteFile(file writeFile) (string, error) {
	if file.Encoding != "b64" {
		return "", fmt.Errorf("cloud-init write_files entry %q must use b64 encoding", file.Path)
	}
	content, err := base64.StdEncoding.DecodeString(file.Content)
	if err != nil {
		return "", fmt.Errorf("decode cloud-init write_files entry %q: %w", file.Path, err)
	}
	return string(content), nil
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

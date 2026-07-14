package bootstrap

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type CacheBastionCloudInitInput struct {
	NodeName          string
	PrivateSubnet     string
	CacheHostname     string
	RKE2Version       string
	ModuleVersion     string
	CACertificate     string
	ServerCertificate string
	ServerPrivateKey  string
}

type cacheCloudInitFile struct {
	Path        string `json:"path"`
	Content     string `json:"content"`
	Permissions string `json:"permissions"`
	Encoding    string `json:"encoding"`
	Owner       string `json:"owner"`
}

// RenderCacheBastionCloudInitJSON renders the cache-by-default bastion. The
// cache is reachable only through the bastion's allocator-assigned private
// address and serves a preverified RKE2 archive plus a curated, read-only OCI
// registry. CacheHostname gives that changing address a stable TLS identity.
func RenderCacheBastionCloudInitJSON(input CacheBastionCloudInitInput) (string, error) {
	if !nodeNamePattern.MatchString(input.NodeName) {
		return "", errors.New("bootstrap: bastion node name must be a lowercase DNS label of at most 63 characters")
	}
	if !rke2VersionPattern.MatchString(input.RKE2Version) {
		return "", errors.New("bootstrap: RKE2 version must be an exact vX.Y.Z+rke2rN release")
	}
	privateSubnet, err := netip.ParsePrefix(input.PrivateSubnet)
	if err != nil || !privateSubnet.Addr().Is4() || !privateSubnet.Addr().IsPrivate() {
		return "", errors.New("bootstrap: cache bastion private subnet must be an RFC1918 IPv4 prefix")
	}
	if !bootstrapCacheHostPattern.MatchString(input.CacheHostname) {
		return "", errors.New("bootstrap: cache hostname must be cache.<cluster>.inspace.internal")
	}
	if err := validateCacheTLSMaterial(input); err != nil {
		return "", err
	}
	imageManifest, err := renderCacheImageManifest(input.RKE2Version, input.ModuleVersion)
	if err != nil {
		return "", err
	}
	files := []struct {
		path, content, permissions string
	}{
		{"/usr/local/sbin/inspace-bootstrap-cache-bastion", renderCacheBastionBootstrapScript(input), "0700"},
		{"/usr/local/sbin/inspace-cache-start", renderCacheStartScript(input), "0700"},
		{"/usr/local/sbin/inspace-cache-maintain", renderCacheMaintenanceScript(input.RKE2Version), "0700"},
		{"/etc/docker/daemon.json", cacheDockerDaemonJSON, "0644"},
		{"/etc/inspace-cache/nginx.conf", renderCacheNginxConfig(), "0644"},
		{"/etc/inspace-cache/registry.yml", cacheRegistryConfig, "0644"},
		{"/etc/inspace-cache/images.tsv", imageManifest, "0644"},
		{"/etc/inspace-cache/tls/ca.crt", input.CACertificate, "0644"},
		{"/etc/inspace-cache/tls/server.crt", input.ServerCertificate, "0644"},
		{"/etc/inspace-cache/tls/server.key", input.ServerPrivateKey, "0600"},
		{"/opt/inspace-cache/compose.yaml", cacheComposeYAML, "0644"},
		{"/etc/systemd/system/inspace-cache.service", cacheServiceUnit, "0644"},
		{"/etc/systemd/system/inspace-cache-maintenance.service", cacheMaintenanceServiceUnit, "0644"},
		{"/etc/systemd/system/inspace-cache-maintenance.timer", cacheMaintenanceTimerUnit, "0644"},
		{"/var/lib/inspace/apt-periodic-disabled", automaticAPTUpdatesDisabledConfig, "0644"},
	}
	payload := struct {
		Hostname         string               `json:"hostname"`
		PreserveHostname bool                 `json:"preserve_hostname"`
		WriteFiles       []cacheCloudInitFile `json:"write_files"`
		RunCmd           []string             `json:"runcmd"`
	}{Hostname: input.NodeName, PreserveHostname: false, RunCmd: []string{"/usr/local/sbin/inspace-bootstrap-cache-bastion"}}
	for _, file := range files {
		payload.WriteFiles = append(payload.WriteFiles, cacheCloudInitFile{
			Path: file.path, Content: base64.StdEncoding.EncodeToString([]byte(file.content)),
			Permissions: file.permissions, Encoding: "b64", Owner: "root:root",
		})
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal cache bastion cloud-init: %w", err)
	}
	return string(data), nil
}

func validateCacheTLSMaterial(input CacheBastionCloudInitInput) error {
	parseCertificate := func(name, value string) (*x509.Certificate, error) {
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("bootstrap: cache %s must contain exactly one PEM certificate", name)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: parse cache %s: %w", name, err)
		}
		return certificate, nil
	}
	ca, err := parseCertificate("CA certificate", input.CACertificate)
	if err != nil {
		return err
	}
	if !ca.IsCA {
		return errors.New("bootstrap: cache CA certificate is not a CA")
	}
	server, err := parseCertificate("server certificate", input.ServerCertificate)
	if err != nil {
		return err
	}
	if err := server.VerifyHostname(input.CacheHostname); err != nil {
		return fmt.Errorf("bootstrap: cache server certificate does not cover hostname: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, DNSName: input.CacheHostname}); err != nil {
		return fmt.Errorf("bootstrap: cache server certificate is not signed by the supplied CA: %w", err)
	}
	keyBlock, rest := pem.Decode([]byte(input.ServerPrivateKey))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("bootstrap: cache server key must contain exactly one PKCS#8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("bootstrap: parse cache server key: %w", err)
	}
	publicKey, ok := key.(crypto.Signer)
	if !ok || !publicKeysEqual(publicKey.Public(), server.PublicKey) {
		return errors.New("bootstrap: cache server certificate and private key do not match")
	}
	return nil
}

func publicKeysEqual(first, second any) bool {
	firstDER, firstErr := x509.MarshalPKIXPublicKey(first)
	secondDER, secondErr := x509.MarshalPKIXPublicKey(second)
	return firstErr == nil && secondErr == nil && string(firstDER) == string(secondDER)
}

const cacheDockerDaemonJSON = `{
  "data-root": "/var/lib/inspace/bootstrap-cache/docker",
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "local",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "compress": "true"
  }
}
`

const cacheRegistryConfig = `version: 0.1
log:
  level: warn
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: false
  maintenance:
    uploadpurging:
      enabled: true
      age: 24h
      interval: 24h
      dryrun: false
http:
  addr: 127.0.0.1:5000
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
`

const cacheComposeYAML = `services:
  registry:
    image: ` + cacheRegistryImage + `
    network_mode: host
    user: "1000:1000"
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    environment:
      REGISTRY_CONFIGURATION_PATH: /etc/distribution/config.yml
      REGISTRY_STORAGE_MAINTENANCE_READONLY_ENABLED: "${REGISTRY_READONLY:-true}"
    volumes:
      - /etc/inspace-cache/registry.yml:/etc/distribution/config.yml:ro
      - /var/lib/inspace/bootstrap-cache/registry:/var/lib/registry
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
    healthcheck:
      test: ["CMD", "/bin/registry", "--version"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 10s
    logging:
      driver: local
      options:
        max-size: 10m
        max-file: "3"
        compress: "true"
  nginx:
    image: ` + cacheNginxImage + `
    network_mode: host
    user: "101:101"
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    entrypoint: ["/usr/sbin/nginx"]
    command: ["-g", "daemon off;"]
    volumes:
      - /etc/inspace-cache/nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/inspace-cache/tls:/etc/inspace-cache/tls:ro
      - /var/lib/inspace/bootstrap-cache/artifacts:/srv/artifacts:ro
      - /var/lib/inspace/bootstrap-cache/state:/srv/state:ro
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=32m
    healthcheck:
      test: ["CMD", "/usr/sbin/nginx", "-t", "-c", "/etc/nginx/nginx.conf"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 10s
    logging:
      driver: local
      options:
        max-size: 10m
        max-file: "3"
        compress: "true"
`

func renderCacheNginxConfig() string {
	return `worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;

events {
  worker_connections 1024;
}

http {
  access_log /dev/stdout combined;
  server_tokens off;
  client_body_temp_path /tmp/client_temp;
  proxy_temp_path /tmp/proxy_temp;
  fastcgi_temp_path /tmp/fastcgi_temp;
  uwsgi_temp_path /tmp/uwsgi_temp;
  scgi_temp_path /tmp/scgi_temp;

  server {
    listen __PRIVATE_IP__:8443 ssl;
    ssl_certificate /etc/inspace-cache/tls/server.crt;
    ssl_certificate_key /etc/inspace-cache/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;

    location = /healthz {
      auth_request /registry-health;
      root /srv;
      default_type text/plain;
      try_files /state/ready =503;
    }

    location = /registry-health {
      internal;
      proxy_pass http://127.0.0.1:5000/v2/;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
    }

    location ^~ /rke2/ {
      limit_except GET HEAD { deny all; }
      root /srv/artifacts;
      try_files $uri =404;
    }

    location ^~ /v2/ {
      limit_except GET HEAD { deny all; }
      proxy_pass http://127.0.0.1:5000;
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 300s;
    }

    location / { return 404; }
  }
}
`
}

const cacheServiceUnit = `[Unit]
Description=InSpace bootstrap artifact and image cache
Requires=docker.service containerd.service
After=docker.service containerd.service network-online.target
RequiresMountsFor=/var/lib/inspace/bootstrap-cache /var/lib/containerd

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/inspace-cache-start
RemainAfterExit=yes
TimeoutStartSec=45min

[Install]
WantedBy=multi-user.target
`

const cacheMaintenanceServiceUnit = `[Unit]
Description=Maintain bounded InSpace bootstrap cache
RequiresMountsFor=/var/lib/inspace/bootstrap-cache
After=inspace-cache.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/inspace-cache-maintain
`

const cacheMaintenanceTimerUnit = `[Unit]
Description=Daily InSpace bootstrap cache maintenance

[Timer]
OnBootSec=1h
OnUnitActiveSec=24h
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
`

func renderCacheBastionBootstrapScript(input CacheBastionCloudInitInput) string {
	replacer := strings.NewReplacer(
		"__NODE_NAME__", shellSingleQuote(input.NodeName),
		"__PRIVATE_SUBNET__", shellSingleQuote(input.PrivateSubnet),
		"__CACHE_HOSTNAME__", shellSingleQuote(input.CacheHostname),
		"__CACHE_BYTES__", fmt.Sprint(BootstrapCacheDiskBytes),
	)
	return replacer.Replace(`#!/bin/sh
set -eu

hostnamectl set-hostname --static __NODE_NAME__
test "$(hostnamectl --static)" = __NODE_NAME__
for ubuntu_sources in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
  [ -f "$ubuntu_sources" ] || continue
  sed -E -i 's|https?://archive\.ubuntu\.com|http://th.archive.ubuntu.com|g' "$ubuntu_sources"
  if grep -E 'https?://archive\.ubuntu\.com' "$ubuntu_sources" >/dev/null; then exit 1; fi
done

package_deadline=$(( $(date +%s) + 1200 ))
run_package_command() {
  package_remaining=$(( package_deadline - $(date +%s) ))
  [ "$package_remaining" -gt 0 ] || return 124
  timeout --kill-after=30s "${package_remaining}s" "$@"
}
attempt=0
until run_package_command apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 update && \
      run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 upgrade -y && \
      run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends ca-certificates curl e2fsprogs gnupg iproute2 skopeo util-linux; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ] || [ "$(date +%s)" -ge "$package_deadline" ]; then exit 1; fi
  sleep 10
done

install -d -m 0755 /etc/apt/keyrings
docker_key_tmp="$(mktemp)"
created_policy_rc=false
cleanup() {
  rm -f "$docker_key_tmp"
  if [ "$created_policy_rc" = true ]; then rm -f /usr/sbin/policy-rc.d; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --retry 5 --retry-all-errors \
  https://download.docker.com/linux/ubuntu/gpg --output "$docker_key_tmp"
gpg --show-keys --with-colons "$docker_key_tmp" | grep -Fq 'fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:'
install -m 0644 "$docker_key_tmp" /etc/apt/keyrings/docker.asc
. /etc/os-release
docker_codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
  "$(dpkg --print-architecture)" "$docker_codename" >/etc/apt/sources.list.d/docker.list
run_package_command apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update

# Package post-install scripts must not start Docker before the bounded cache
# filesystem is mounted. Preserve an image-provided policy-rc.d if one exists.
if [ ! -e /usr/sbin/policy-rc.d ]; then
  printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
  chmod 0755 /usr/sbin/policy-rc.d
  created_policy_rc=true
fi
systemctl mask docker.service docker.socket containerd.service >/dev/null 2>&1
run_package_command env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
if [ "$created_policy_rc" = true ]; then
  rm -f /usr/sbin/policy-rc.d
  created_policy_rc=false
fi
systemctl unmask docker.service docker.socket containerd.service >/dev/null 2>&1

` + renderDisableAutomaticAPTUpdatesCommands() + `
` + strings.TrimSpace(strings.TrimPrefix(renderDisableUFWScript(), "#!/bin/sh\nset -eu\n")) + `

vpc_subnet=__PRIVATE_SUBNET__
cache_hostname=__CACHE_HOSTNAME__
vpc_identities="$(ip -o -4 addr show to "$vpc_subnet" scope global | awk '$3 == "inet" { split($4, address, "/"); print $2, address[1] }')"
test -n "$vpc_identities"
test "$(printf '%s\n' "$vpc_identities" | awk 'NF { count++ } END { print count + 0 }')" -eq 1
set -- $vpc_identities
private_if=${1%%@*}
private_ip=$2
test -n "$private_if"
test -n "$private_ip"
sed -i "s/__PRIVATE_IP__/$private_ip/g" /etc/inspace-cache/nginx.conf
if grep -Fq '__PRIVATE_IP__' /etc/inspace-cache/nginx.conf; then exit 1; fi
hosts_tmp="$(mktemp)"
awk -v host="$cache_hostname" '{ keep=1; for (i=2; i<=NF; i++) if ($i == host) keep=0; if (keep) print }' /etc/hosts >"$hosts_tmp"
install -m 0644 "$hosts_tmp" /etc/hosts
rm -f "$hosts_tmp"
printf '%s %s\n' "$private_ip" "$cache_hostname" >>/etc/hosts
getent ahostsv4 "$cache_hostname" | awk -v expected="$private_ip" '$1 == expected { found=1 } END { exit !found }'

systemctl stop docker.service docker.socket containerd.service >/dev/null 2>&1 || true
install -d -m 0755 /var/lib/inspace /var/lib/inspace/bootstrap-cache /var/lib/containerd
# These paths are dedicated to this newly created bastion. Remove any data a
# package post-install script might have written before the cache mount.
if ! mountpoint -q /var/lib/inspace/bootstrap-cache; then
  find /var/lib/inspace/bootstrap-cache -mindepth 1 -delete
fi
if ! mountpoint -q /var/lib/containerd; then
  find /var/lib/containerd -mindepth 1 -delete
fi
cache_image=/var/lib/inspace/bootstrap-cache.img
if [ ! -e "$cache_image" ]; then
  available="$(df --output=avail -B1 /var/lib/inspace | tail -1 | tr -d ' ')"
  test "$available" -ge 11000000000
  fallocate -l __CACHE_BYTES__ "$cache_image"
  test "$(stat -c %s "$cache_image")" = __CACHE_BYTES__
  mkfs.ext4 -F -b 1024 -m 0 -L inspace-bootstrap-cache "$cache_image" >/dev/null
fi
test "$(stat -c %s "$cache_image")" = __CACHE_BYTES__
grep -Fq "$cache_image /var/lib/inspace/bootstrap-cache ext4" /etc/fstab || \
  printf '%s %s ext4 loop,nosuid,nodev 0 0\n' "$cache_image" /var/lib/inspace/bootstrap-cache >>/etc/fstab
grep -Fq '/var/lib/inspace/bootstrap-cache/containerd /var/lib/containerd none bind' /etc/fstab || \
  printf '%s %s none bind 0 0\n' /var/lib/inspace/bootstrap-cache/containerd /var/lib/containerd >>/etc/fstab
mountpoint -q /var/lib/inspace/bootstrap-cache || mount /var/lib/inspace/bootstrap-cache
install -d -m 0711 /var/lib/inspace/bootstrap-cache/docker
install -d -m 0755 /var/lib/inspace/bootstrap-cache/containerd /var/lib/inspace/bootstrap-cache/artifacts /var/lib/inspace/bootstrap-cache/state
install -d -o 1000 -g 1000 -m 0750 /var/lib/inspace/bootstrap-cache/registry
mountpoint -q /var/lib/containerd || mount /var/lib/containerd
test "$(findmnt -n -o FSTYPE /var/lib/inspace/bootstrap-cache)" = ext4
test "$(stat -c %s "$cache_image")" = __CACHE_BYTES__

chown 101:101 /etc/inspace-cache/tls/server.key
chmod 0400 /etc/inspace-cache/tls/server.key
chmod 0444 /etc/inspace-cache/tls/ca.crt /etc/inspace-cache/tls/server.crt
systemctl daemon-reload
systemctl enable --now containerd.service docker.service
docker info >/dev/null
systemctl enable --now inspace-cache.service
systemctl enable --now inspace-cache-maintenance.timer
curl --fail --silent --show-error --cacert /etc/inspace-cache/tls/ca.crt \
  "https://$cache_hostname:8443/healthz" >/dev/null
`)
}

func renderCacheStartScript(input CacheBastionCloudInitInput) string {
	replacer := strings.NewReplacer(
		"__CACHE_HOSTNAME__", shellSingleQuote(input.CacheHostname),
		"__RKE2_VERSION__", shellSingleQuote(input.RKE2Version),
		"__RKE2_SHA256__", shellSingleQuote(bootstrapCacheRKE2SHA256),
		"__CACHE_MIN_FREE__", fmt.Sprint(BootstrapCacheMinFree),
	)
	return replacer.Replace(`#!/bin/sh
set -eu
exec 9>/var/lib/inspace/bootstrap-cache/locks-seed
flock 9

cache_hostname=__CACHE_HOSTNAME__
version=__RKE2_VERSION__
expected_rke2_sha=__RKE2_SHA256__
cache_root=/var/lib/inspace/bootstrap-cache
state_dir="$cache_root/state"
ready_file="$state_dir/ready"
rm -f "$ready_file"
test "$(stat -c %s /var/lib/inspace/bootstrap-cache.img)" = 10000000000
test "$(findmnt -n -o TARGET "$cache_root")" = "$cache_root"
install -d -m 0755 "$state_dir" "$cache_root/artifacts/rke2/$version"

ensure_capacity() {
  available="$(df --output=avail -B1 "$cache_root" | tail -1 | tr -d ' ')"
  test "$available" -ge __CACHE_MIN_FREE__
}
ensure_capacity

artifact_dir="$cache_root/artifacts/rke2/$version"
release_base="https://github.com/rancher/rke2/releases/download/$(printf '%s' "$version" | sed 's/+/%2B/g')"
download() {
  url="$1"
  output="$2"
  tmp="$output.part"
  rm -f "$tmp"
  curl --fail --location --silent --show-error --connect-timeout 15 --max-time 600 --retry 8 --retry-all-errors \
    --proto '=https' --proto-redir '=https' --output "$tmp" "$url"
  sync "$tmp"
  mv -f "$tmp" "$output"
}
if [ ! -s "$artifact_dir/rke2.linux-amd64.tar.gz" ] || \
   [ "$(sha256sum "$artifact_dir/rke2.linux-amd64.tar.gz" | awk '{print $1}')" != "$expected_rke2_sha" ]; then
  ensure_capacity
  download "$release_base/rke2.linux-amd64.tar.gz" "$artifact_dir/rke2.linux-amd64.tar.gz"
fi
if [ ! -s "$artifact_dir/sha256sum-amd64.txt" ]; then
  download "$release_base/sha256sum-amd64.txt" "$artifact_dir/sha256sum-amd64.txt"
fi
actual_rke2_sha="$(sha256sum "$artifact_dir/rke2.linux-amd64.tar.gz" | awk '{print $1}')"
test "$actual_rke2_sha" = "$expected_rke2_sha"
listed_rke2_sha="$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" { print $1; exit }' "$artifact_dir/sha256sum-amd64.txt")"
test "$listed_rke2_sha" = "$expected_rke2_sha"
chmod 0444 "$artifact_dir/rke2.linux-amd64.tar.gz" "$artifact_dir/sha256sum-amd64.txt"

cd /opt/inspace-cache
manifest_hash="$(sha256sum /etc/inspace-cache/images.tsv | awk '{print $1}')"
seeded_hash="$(cat "$state_dir/images.sha256" 2>/dev/null || true)"
if [ "$seeded_hash" != "$manifest_hash" ]; then
  REGISTRY_READONLY=false docker compose up -d --wait registry
  attempt=0
  until curl --fail --silent --show-error http://127.0.0.1:5000/v2/ >/dev/null; do
    attempt=$((attempt + 1))
    test "$attempt" -lt 60
    sleep 2
  done
  while IFS="$(printf '\t')" read -r source target; do
    [ -n "$source" ] || continue
    ensure_capacity
    skopeo copy --retry-times 8 --preserve-digests --override-os linux --override-arch amd64 \
      --dest-tls-verify=false "$source" "docker://127.0.0.1:5000/$target"
    skopeo inspect --tls-verify=false "docker://127.0.0.1:5000/$target" >/dev/null
  done </etc/inspace-cache/images.tsv
  printf '%s\n' "$manifest_hash" >"$state_dir/images.sha256.tmp"
  mv -f "$state_dir/images.sha256.tmp" "$state_dir/images.sha256"
fi

REGISTRY_READONLY=true docker compose up -d --force-recreate --wait registry nginx
curl --fail --silent --show-error http://127.0.0.1:5000/v2/ >/dev/null
test "$(cat "$state_dir/images.sha256")" = "$manifest_hash"
ensure_capacity
printf 'ready\n' >"$ready_file.tmp"
chmod 0444 "$ready_file.tmp"
mv -f "$ready_file.tmp" "$ready_file"
attempt=0
until curl --fail --silent --show-error --cacert /etc/inspace-cache/tls/ca.crt \
  "https://$cache_hostname:8443/healthz" >/dev/null && \
  curl --fail --silent --show-error --cacert /etc/inspace-cache/tls/ca.crt \
  "https://$cache_hostname:8443/v2/" >/dev/null; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 60
  sleep 2
done
`)
}

func renderCacheMaintenanceScript(pinnedVersion string) string {
	return strings.ReplaceAll(`#!/bin/sh
set -eu
cache_root=/var/lib/inspace/bootstrap-cache
pinned_version=__PINNED_VERSION__
test "$(findmnt -n -o TARGET "$cache_root")" = "$cache_root"
find "$cache_root/artifacts/rke2" -mindepth 1 -maxdepth 1 -type d ! -name "$pinned_version" -atime +30 -exec rm -rf -- {} +
docker container prune --force --filter until=720h >/dev/null
docker image prune --force --filter until=720h >/dev/null
available="$(df --output=avail -B1 "$cache_root" | tail -1 | tr -d ' ')"
if [ "$available" -lt 1000000000 ]; then
  rm -f "$cache_root/state/ready"
  echo "bootstrap cache has less than 1 GB free" >&2
  exit 1
fi
`, "__PINNED_VERSION__", pinnedVersion)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

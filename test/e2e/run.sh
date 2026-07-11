#!/usr/bin/env bash
# shellcheck disable=SC2016 # jq programs intentionally use single-quoted $variables.
set -Eeuo pipefail

# Full, destructive, isolated-account E2E. This script intentionally requires
# a released OCI chart/images and a billing-account confirmation. It reads the
# SSH public key only; the private key remains in ~/.ssh and is used by ssh(1).

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$workspace"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source ./.env
  set +a
fi

required_commands=(awk bash curl diff docker go helm jq kubectl openssl python3 seq shasum sort ssh ssh-keyscan ssh-keygen stat tee)
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null || { echo "missing required command: $command_name" >&2; exit 2; }
done

: "${INSPACE_API_URL:?INSPACE_API_URL is required}"
: "${INSPACE_API_TOKEN:?INSPACE_API_TOKEN is required}"
: "${INSPACE_LOCATION:?INSPACE_LOCATION is required}"
: "${INSPACE_BILLING_ACCOUNT_ID:?INSPACE_BILLING_ACCOUNT_ID is required}"
: "${INSPACE_NETWORK_UUID:?INSPACE_NETWORK_UUID is required}"
: "${INSPACE_INTEL_HOST_POOL_UUID:?INSPACE_INTEL_HOST_POOL_UUID is required}"
: "${INSPACE_E2E_VERSION:?Set INSPACE_E2E_VERSION to a published SemVer such as 0.1.0-rc.1}"

if [[ ${CONFIRM_INSPACE_CLUSTER_E2E:-} != "$INSPACE_BILLING_ACCOUNT_ID" ]]; then
  echo "refusing cluster mutations: set CONFIRM_INSPACE_CLUSTER_E2E to the isolated billing-account ID" >&2
  exit 2
fi
if [[ ${INSPACE_E2E_KEEP_RESOURCES:-false} != false && ${INSPACE_E2E_KEEP_RESOURCES:-false} != true ]]; then
  echo "INSPACE_E2E_KEEP_RESOURCES must be true or false" >&2
  exit 2
fi

ssh_private_key=${INSPACE_E2E_SSH_PRIVATE_KEY:-$HOME/.ssh/id_rsa}
ssh_public_key=${INSPACE_E2E_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
[[ -f "$ssh_private_key" && -f "$ssh_public_key" ]] || { echo "SSH keypair is missing" >&2; exit 2; }
[[ $(stat -f '%Lp' "$ssh_private_key") == 600 ]] || { echo "SSH private key must have mode 0600" >&2; exit 2; }
derived_public_key=$(ssh-keygen -y -f "$ssh_private_key" | awk '{print $1, $2}')
configured_public_key=$(awk 'NF >= 2 {print $1, $2; exit}' "$ssh_public_key")
[[ $derived_public_key == "$configured_public_key" ]] || { echo "SSH public key does not match the private key" >&2; exit 2; }

umask 077
run_id=${INSPACE_E2E_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)}
[[ ${#run_id} -le 24 && $run_id =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || {
  echo "E2E run ID must be a lowercase DNS label of at most 24 characters" >&2
  exit 2
}
cluster_resource_name="inspace-e2e-$run_id"
cluster_resource_namespace=inspace-e2e
cluster_name="inspace-e2e-$run_id"
nodeclass_name="inspace-e2e-workers-$run_id"
nodepool_name="inspace-e2e-$run_id"
state_dir=${INSPACE_E2E_STATE_DIR:-$workspace/.e2e/$run_id}
mkdir -p "$state_dir"
chmod 700 "$state_dir"
state_file=$state_dir/state.json
cluster_file=$state_dir/cluster.yaml
kubeconfig=$state_dir/kubeconfig.yaml
known_hosts=$state_dir/known_hosts
k3s_token_file=$state_dir/k3s-token
controller_bin=$state_dir/inspace-cluster-controller
controller_child_pid=""
validated_worker_claim_json=""
validated_worker_node_json=""
bootstrap_timeout_seconds=2700
raw_cleanup_attempts=90
raw_cleanup_interval_seconds=10
raw_cleanup_timeout_seconds=900
kubernetes_reachability_timeout_seconds=300
kubernetes_quiesce_timeout_seconds=1800
kubernetes_quiesce_attempts=6
touch "$known_hosts"
chmod 600 "$known_hosts"

api_base=${INSPACE_API_URL%/}/v1/$INSPACE_LOCATION
api_get() {
  local path=$1
  local deadline=${2:-}
  local timeout_seconds=60
  if [[ -n $deadline ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 60) || return 124
  fi
  curl --fail --silent --show-error --max-time "$timeout_seconds" -H "apikey: $INSPACE_API_TOKEN" "$api_base/$path"
}
api_delete_json() {
  local path=$1
  local deadline=${2:-}
  local timeout_seconds=300
  if [[ -n $deadline ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 300) || return 124
  fi
  curl --fail --silent --show-error --max-time "$timeout_seconds" -X DELETE -H "apikey: $INSPACE_API_TOKEN" \
    -H 'Content-Type: application/json' "$api_base/$path" >/dev/null
}
api_post_json() {
  local path=$1
  local deadline=${2:-}
  local timeout_seconds=300
  if [[ -n $deadline ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 300) || return 124
  fi
  curl --fail --silent --show-error --max-time "$timeout_seconds" -X POST -H "apikey: $INSPACE_API_TOKEN" \
    -H 'Content-Type: application/json' "$api_base/$path" >/dev/null
}
api_delete_vm() {
  local uuid=$1
  local deadline=${2:-}
  local timeout_seconds=300
  if [[ -n $deadline ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 300) || return 124
  fi
  curl --fail --silent --show-error --max-time "$timeout_seconds" -X DELETE -H "apikey: $INSPACE_API_TOKEN" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uuid=$uuid" "$api_base/user-resource/vm" >/dev/null
}
api_detach_disk() {
  curl --fail --silent --show-error --max-time 300 -X POST -H "apikey: $INSPACE_API_TOKEN" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uuid=$1" --data-urlencode "storage_uuid=$2" \
    "$api_base/user-resource/vm/storage/detach" >/dev/null
}

state_update() {
  local filter=$1
  shift
  local temporary=$state_file.tmp
  jq "$@" "$filter" "$state_file" >"$temporary"
  mv "$temporary" "$state_file"
  chmod 600 "$state_file"
}

sha16() {
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1,1,16)}'
}

require_public_ipv4() {
  python3 - "$1" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or address.is_private or address.is_loopback or address.is_multicast:
    raise SystemExit("address must be one public IPv4")
PY
}

owner=$(sha16 "$cluster_resource_namespace/$cluster_resource_name")
management_ip=${INSPACE_E2E_MANAGEMENT_IP:-$(curl --fail --silent --show-error --max-time 30 https://api.ipify.org)}
require_public_ipv4 "$management_ip" || { echo "management address must be one public IPv4" >&2; exit 2; }
management_cidr=$management_ip/32
k3s_token=$(openssl rand -hex 32)
printf '%s' "$k3s_token" >"$k3s_token_file"
chmod 600 "$k3s_token_file"

jq -n \
  --arg runID "$run_id" --arg owner "$owner" --arg clusterName "$cluster_name" \
  --arg clusterResourceName "$cluster_resource_name" --arg clusterResourceNamespace "$cluster_resource_namespace" \
  --arg nodeClassName "$nodeclass_name" --arg nodePoolName "$nodepool_name" --arg managementCIDR "$management_cidr" \
  --arg version "$INSPACE_E2E_VERSION" \
  '{runID:$runID,owner:$owner,clusterName:$clusterName,clusterResourceName:$clusterResourceName,
    clusterResourceNamespace:$clusterResourceNamespace,nodeClassName:$nodeClassName,nodePoolName:$nodePoolName,
    managementCIDR:$managementCIDR,version:$version,workerFloatingIPNames:[],kubernetesOwnersPossible:false}' >"$state_file"
chmod 600 "$state_file"

cat >"$cluster_file" <<EOF
apiVersion: infrastructure.inspace.cloud/v1alpha1
kind: InSpaceCluster
metadata:
  name: $cluster_resource_name
  namespace: $cluster_resource_namespace
spec:
  location: $INSPACE_LOCATION
  billingAccountID: $INSPACE_BILLING_ACCOUNT_ID
  credentialsSecretRef:
    name: inspace-cloud-credentials
    key: api-token
  controlPlane:
    replicas: 3
    machine:
      vcpu: 2
      memoryMiB: 4096
      rootDiskGiB: 30
      hostPoolUUID: $INSPACE_INTEL_HOST_POOL_UUID
      image:
        osName: ${INSPACE_OS_NAME:-ubuntu}
        osVersion: "${INSPACE_OS_VERSION:-24.04}"
  k3s:
    version: v1.35.6+k3s1
    tokenSecretRef:
      name: inspace-k3s-agent-token
      key: token
    disable: [servicelb, traefik]
  network:
    uuid: $INSPACE_NETWORK_UUID
    podCIDR: 10.42.0.0/16
    serviceCIDR: 10.43.0.0/16
  firewall:
    managed: true
  publicIPv4:
    managed: true
  endpoint:
    host: $cluster_resource_name.invalid
    port: 6443
    public: true
EOF
chmod 600 "$cluster_file"

export INSPACE_ALLOW_REMOTE_MUTATIONS=true
export INSPACE_K3S_TOKEN=$k3s_token
export KUBECONFIG=$kubeconfig

ssh_options=(-n -i "$ssh_private_key" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 \
  -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
  -o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes)
ssh_user=${INSPACE_E2E_SSH_USERNAME:-inspacee2e}

wait_until() {
  local timeout_seconds=$1
  local description=$2
  shift 2
  local deadline=$((SECONDS + timeout_seconds))
  until "$@"; do
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for $description" >&2
      return 1
    fi
    sleep 10
  done
}

remaining_timeout_seconds() {
  local deadline=$1
  local maximum=$2
  local remaining=$((deadline - SECONDS))
  (( remaining > 0 )) || return 1
  if (( remaining > maximum )); then
    remaining=$maximum
  fi
  printf '%d\n' "$remaining"
}

wait_until_deadline() {
  local deadline=$1
  local description=$2
  local sleep_seconds status
  shift 2
  while true; do
    if "$@"; then
      return 0
    else
      status=$?
    fi
    if (( status == 2 || status == 124 )); then
      return "$status"
    fi
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for $description" >&2
      return 1
    fi
    sleep_seconds=$((deadline - SECONDS))
    if (( sleep_seconds > 10 )); then
      sleep_seconds=10
    fi
    sleep "$sleep_seconds"
  done
}

ssh_ready() {
  local ip=$1
  local scan=$state_dir/known-host-$ip
  if ! ssh-keyscan -T 5 -H "$ip" >"$scan" 2>/dev/null; then
    return 1
  fi
  cat "$scan" >>"$known_hosts"
  sort -u "$known_hosts" -o "$known_hosts"
  ssh "${ssh_options[@]}" "$ssh_user@$ip" true >/dev/null 2>&1
}

k3s_agent_ready() {
  local ip=$1
  ssh "${ssh_options[@]}" "$ssh_user@$ip" \
    "sudo timeout --kill-after=5s 45s bash -o pipefail -c '(cloud-init status --wait >/dev/null 2>&1 || test \$? -eq 2) &&
     systemctl is-active --quiet k3s-agent &&
     . /etc/os-release && test \"\$ID\" = ubuntu && test \"\$VERSION_ID\" = 24.04'" >/dev/null 2>&1
}

k3s_etcd_ready() {
  local ip=$1
  # InSpace's generated cloud-config currently triggers recoverable schema
  # warnings. cloud-init uses status 2 for degraded completion; K3s and etcd
  # health below remain mandatory.
  ssh "${ssh_options[@]}" "$ssh_user@$ip" \
    "sudo timeout --kill-after=5s 45s bash -o pipefail -c '(cloud-init status --wait >/dev/null 2>&1 || test \$? -eq 2) &&
     systemctl is-active --quiet k3s &&
     timeout 20s k3s kubectl get --raw=\"/readyz?verbose\" 2>/dev/null |
       grep -F \"[+]etcd ok\"'" >/dev/null 2>&1
}

kubectl_available() {
  local timeout_seconds=${1:-10}
  kubectl --request-timeout="${timeout_seconds}s" get --raw=/readyz >/dev/null 2>&1
}

wait_for_kubernetes_available_until() {
  local deadline=$1
  local timeout_seconds sleep_seconds
  while (( SECONDS < deadline )); do
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || break
    if kubectl_available "$timeout_seconds"; then
      return 0
    fi
    sleep_seconds=$((deadline - SECONDS))
    if (( sleep_seconds > 10 )); then
      sleep_seconds=10
    fi
    if (( sleep_seconds > 0 )); then
      sleep "$sleep_seconds"
    fi
  done
  echo "timed out waiting for the Kubernetes API to become reachable" >&2
  return 1
}

e2e_pods_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local pods timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  pods=$(kubectl --request-timeout="${timeout_seconds}s" -n default get pods \
    -l 'app in (inspace-e2e-web,inspace-e2e-trigger)' -o json 2>/dev/null) || return 1
  jq -e '.items | length == 0' >/dev/null <<<"$pods"
}

pv_and_attachments_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local pv pv_name attachments timeout_seconds
  pv=$(jq -r '.pvName // ""' "$state_file")
  [[ -n $pv ]] || return 0
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  pv_name=$(kubectl --request-timeout="${timeout_seconds}s" get pv "$pv" \
    --ignore-not-found -o name) || return 1
  if [[ -n $pv_name ]]; then
    return 1
  fi
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  attachments=$(kubectl --request-timeout="${timeout_seconds}s" get volumeattachments -o json 2>/dev/null) || return 1
  jq -e --arg pv "$pv" 'all(.items[]; .spec.source.persistentVolumeName != $pv)' >/dev/null <<<"$attachments"
}

owned_nodeclaims_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local claims timeout_seconds workers
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  claims=$(kubectl --request-timeout="${timeout_seconds}s" get nodeclaims -o json 2>/dev/null) || return 1
  jq -e --arg pool "$nodepool_name" --arg prefix "$nodepool_name-" --argjson workers "$workers" '
    [.items[] | . as $claim | select(
      ((.metadata.name // "") | startswith($prefix)) or
      .metadata.labels["karpenter.sh/nodepool"] == $pool or
      any($workers[]; .name == $claim.metadata.name))] | length == 0' >/dev/null <<<"$claims"
}

persist_service_ownership_from_cluster() {
  local deadline=${1:-$((SECONDS + 10))}
  local service_json service_uid expected_lb expected_ip current_lb current_ip timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  service_json=$(kubectl --request-timeout="${timeout_seconds}s" -n default get service inspace-e2e-web \
    --ignore-not-found -o json) || return 1
  if [[ -z $service_json ]]; then
    return 0
  fi
  service_uid=$(jq -r '.metadata.uid // ""' <<<"$service_json") || return 1
  [[ -n $service_uid ]] || { echo "refusing to persist Service ownership without a UID" >&2; return 1; }
  expected_lb="k8s-$(sha16 "$cluster_name")-$(sha16 "$service_uid")"
  expected_ip="$expected_lb-ip"
  current_lb=$(jq -r '.serviceLoadBalancerName // ""' "$state_file") || return 1
  current_ip=$(jq -r '.serviceFloatingIPName // ""' "$state_file") || return 1
  if [[ -n $current_lb && $current_lb != "$expected_lb" ]] || [[ -n $current_ip && $current_ip != "$expected_ip" ]]; then
    echo "refusing to replace mismatched Service ownership in E2E state" >&2
    return 1
  fi
  state_update '. + {serviceUID:$uid,serviceLoadBalancerName:$lb,serviceFloatingIPName:$ip}' \
    --arg uid "$service_uid" --arg lb "$expected_lb" --arg ip "$expected_ip"
}

persist_pvc_ownership_from_cluster() {
  local deadline=${1:-$((SECONDS + 10))}
  local pvc_json pvc_uid expected_disk current_uid current_disk discovered_pv timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  pvc_json=$(kubectl --request-timeout="${timeout_seconds}s" -n default get pvc inspace-e2e-rwo \
    --ignore-not-found -o json) || return 1
  if [[ -z $pvc_json ]]; then
    return 0
  fi
  pvc_uid=$(jq -r '.metadata.uid // ""' <<<"$pvc_json") || return 1
  [[ -n $pvc_uid ]] || { echo "refusing to persist PVC ownership without a UID" >&2; return 1; }
  expected_disk="pvc-$pvc_uid"
  current_uid=$(jq -r '.pvcUID // ""' "$state_file") || return 1
  current_disk=$(jq -r '.pvcDiskName // ""' "$state_file") || return 1
  if [[ -n $current_uid && $current_uid != "$pvc_uid" ]] || [[ -n $current_disk && $current_disk != "$expected_disk" ]]; then
    echo "refusing to replace mismatched PVC ownership in E2E state" >&2
    return 1
  fi
  discovered_pv=$(jq -r '.spec.volumeName // ""' <<<"$pvc_json") || return 1
  state_update '. + {pvcUID:$uid,pvcDiskName:$disk} | if $pv == "" then . else .pvName=$pv end' \
    --arg uid "$pvc_uid" --arg disk "$expected_disk" --arg pv "$discovered_pv"
}

validate_worker_records() {
  local records=$1
  local uuid_pattern='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  if ! jq -e --arg prefix "$nodepool_name-" --arg uuidPattern "$uuid_pattern" '
      type == "array" and all(.[];
        (.uuid | type) == "string" and (.uuid | test($uuidPattern)) and
        (.name | type) == "string" and (.name | startswith($prefix)) and (.name | length) > ($prefix | length) and
        (.fip | type) == "string" and (.fip | startswith($prefix)) and (.fip | length) > ($prefix | length))' \
      >/dev/null <<<"$records"; then
    echo "refusing invalid persisted worker ownership record" >&2
    return 2
  fi
}

persist_worker_ownership_from_cloud() {
  local deadline=${1:-}
  local all_vms matching invalid_workers discovered current combined merged fips
  all_vms=$(api_get user-resource/vm/list "$deadline") || return $?
  matching=$(jq -c --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '[.[] | . as $vm |
    ((((.description // "{}") | fromjson?) // {})) as $record |
    select($record.cluster==$cluster or (($vm.name // "") | startswith($prefix))) |
    {vm:$vm,record:$record}] | sort_by(.vm.name)' <<<"$all_vms") || return 1
  invalid_workers=$(jq --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '[.[] | select(
    .record.schema != "karpenter.inspace.cloud/v1" or .record.cluster != $cluster or
    .record.nodeClaim != .vm.name or ((.vm.name // "") | startswith($prefix) | not) or
    ((.record.floatingIPName // "") | startswith($prefix) | not))] | length' <<<"$matching") || return 1
  if [[ $invalid_workers != 0 ]]; then
    echo "refusing to persist incomplete or mismatched worker cloud ownership" >&2
    return 2
  fi
  discovered=$(jq -c '[.[] | {uuid:.vm.uuid,name:.vm.name,fip:.record.floatingIPName}]' <<<"$matching") || return 1
  current=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$discovered" || return 2
  validate_worker_records "$current" || return 2
  combined=$(jq -c -n --argjson current "$current" --argjson discovered "$discovered" '$current + $discovered') || return 1
  if ! jq -e 'group_by(.uuid) | all(map([.name,.fip]) | unique | length == 1)' >/dev/null <<<"$combined"; then
    echo "refusing conflicting persisted worker UUID ownership" >&2
    return 2
  fi
  merged=$(jq -c 'unique_by(.uuid) | sort_by([.name,.uuid])' <<<"$combined") || return 1
  fips=$(jq -c '[.[].fip] | unique' <<<"$merged") || return 1
  state_update '.workerVMs=$workers | .workerFloatingIPNames=$fips' --argjson workers "$merged" --argjson fips "$fips"
}

owned_worker_public_ip() {
  local fip_name all_ips
  fip_name=$(jq -er '
    (.workerVMs // []) as $workers |
    if ($workers | length) == 1 then $workers[0].fip else error("expected exactly one persisted worker") end' \
    "$state_file") || return 1
  all_ips=$(api_get network/ip_addresses) || return 1
  jq -er --arg name "$fip_name" '
    [.[] | select(.name==$name and ((.is_deleted // false) | not))] |
    if length == 1 then .[0].address else error("expected exactly one owned worker floating IP") end' \
    <<<"$all_ips"
}

owned_worker_vpc_ready() {
  local node_name=$1
  local internal_ip network node subnet worker_name worker_uuid workers
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  [[ $(jq -r 'length' <<<"$workers") == 1 ]] || return 2
  worker_uuid=$(jq -er '.[0].uuid' <<<"$workers") || return 2
  worker_name=$(jq -er '.[0].name' <<<"$workers") || return 2
  [[ $worker_name == "$node_name" ]] || return 2
  network=$(api_get "network/network/$INSPACE_NETWORK_UUID") || return 1
  if ! jq -e --arg network "$INSPACE_NETWORK_UUID" --arg worker "$worker_uuid" '
      .uuid == $network and (.vm_uuids | type) == "array" and
      ([.vm_uuids[] | select(. == $worker)] | length) == 1' >/dev/null <<<"$network"; then
    return 1
  fi
  subnet=$(jq -er '.subnet' <<<"$network") || return 1
  node=$(kubectl --request-timeout=10s get node "$node_name" -o json) || return 1
  jq -e --arg name "$worker_name" --arg provider "inspace://$INSPACE_LOCATION/$worker_uuid" '
    .metadata.name == $name and .spec.providerID == $provider' >/dev/null <<<"$node" || return 2
  internal_ip=$(jq -er '
    [.status.addresses[]? | select(.type == "InternalIP") | .address] |
    if length == 1 then .[0] else error("expected exactly one worker InternalIP") end' <<<"$node") || return 1
  python3 - "$subnet" "$internal_ip" <<'PY'
import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
address = ipaddress.ip_address(sys.argv[2])
private_ranges = tuple(ipaddress.ip_network(prefix) for prefix in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
))
if (network.version != 4 or
        not any(network.subnet_of(prefix) for prefix in private_ranges) or
        address.version != 4 or address not in network):
    raise SystemExit("worker InternalIP is not in the configured private VPC subnet")
PY
}

karpenter_pods_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local pods timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  pods=$(kubectl --request-timeout="${timeout_seconds}s" -n kube-system get pods \
    -l app.kubernetes.io/component=karpenter -o json 2>/dev/null) || return 1
  jq -e '.items | length == 0' >/dev/null <<<"$pods"
}

owned_worker_node_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local workers nodes timeout_seconds
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  nodes=$(kubectl --request-timeout="${timeout_seconds}s" get nodes -o json) || return 1
  jq -e --arg pool "$nodepool_name" --arg prefix "$nodepool_name-" --argjson workers "$workers" '
    [.items[] | . as $node | select(
      ((.metadata.name // "") | startswith($prefix)) or
      .metadata.labels["karpenter.sh/nodepool"] == $pool or
      any($workers[]; .name == $node.metadata.name))] | length == 0' >/dev/null <<<"$nodes"
}

owned_worker_nodeclaim_absent() {
  local deadline=${1:-$((SECONDS + 10))}
  local claim node_name timeout_seconds workers
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  [[ $(jq -r 'length' <<<"$workers") == 1 ]] || return 2
  node_name=$(jq -er '.[0].name' <<<"$workers") || return 2
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  claim=$(kubectl --request-timeout="${timeout_seconds}s" get nodeclaim "$node_name" \
    --ignore-not-found -o name) || return 1
  [[ -z $claim ]]
}

worker_volume_attachments_absent() {
  local deadline=$1
  local node_name=$2
  local attachments timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  attachments=$(kubectl --request-timeout="${timeout_seconds}s" get volumeattachments -o json) || return 1
  jq -e --arg node "$node_name" 'all(.items[]; .spec.nodeName != $node)' >/dev/null <<<"$attachments"
}

forced_worker_cloud_snapshot() {
  local deadline=$1
  local all_ips all_vms snapshot workers
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  [[ $(jq -r 'length' <<<"$workers") == 1 ]] || {
    echo "refusing forced worker cleanup without exactly one persisted worker" >&2
    return 2
  }
  all_vms=$(api_get user-resource/vm/list "$deadline") || return 1
  all_ips=$(api_get network/ip_addresses "$deadline") || return 1
  if ! snapshot=$(jq -ce -n \
      --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" \
      --argjson workers "$workers" --argjson vms "$all_vms" --argjson ips "$all_ips" '
      $workers[0] as $worker |
      [$vms[] | . as $vm |
        ((((.description // "{}") | fromjson?) // {})) as $record |
        select($vm.uuid == $worker.uuid or $vm.name == $worker.name or
          $record.cluster == $cluster or (($vm.name // "") | startswith($prefix))) |
        {vm:$vm,record:$record}] as $ownedVMs |
      [$ips[] | select(
        ((.is_deleted // false) | not) and
        (.name == $worker.fip or ((.name // "") | startswith($prefix)) or
          (.assigned_to // "") == $worker.uuid))] as $ownedIPs |
      if (($ownedVMs | length) <= 1) and
          all($ownedVMs[];
            .vm.uuid == $worker.uuid and .vm.name == $worker.name and
            .record.schema == "karpenter.inspace.cloud/v1" and
            .record.cluster == $cluster and .record.nodeClaim == $worker.name and
            .record.floatingIPName == $worker.fip) and
          (($ownedIPs | length) <= 1) and
          all($ownedIPs[];
            .name == $worker.fip and
            ((.assigned_to // "") == "" or
              ((.assigned_to == $worker.uuid) and
               (.assigned_to_resource_type == "virtual_machine"))))
      then {
        worker:$worker,
        vm:(if ($ownedVMs | length) == 1 then $ownedVMs[0].vm else null end),
        floatingIP:(if ($ownedIPs | length) == 1 then $ownedIPs[0] else null end)
      }
      else error("cloud worker candidates do not equal the exact persisted worker")
      end'); then
    echo "refusing forced worker cleanup because cloud ownership is not exact" >&2
    return 2
  fi
  printf '%s\n' "$snapshot"
}

forced_worker_resources_absent() {
  local deadline=$1
  local snapshot
  snapshot=$(forced_worker_cloud_snapshot "$deadline") || return $?
  jq -e '.vm == null and .floatingIP == null' >/dev/null <<<"$snapshot"
}

cleanup_forced_worker_resources_once() {
  local deadline=$1
  local address assigned snapshot uuid
  snapshot=$(forced_worker_cloud_snapshot "$deadline") || return $?
  if [[ $(jq -r '.floatingIP != null' <<<"$snapshot") == true ]]; then
    address=$(jq -er '.floatingIP.address' <<<"$snapshot") || return 2
    require_public_ipv4 "$address" || {
      echo "refusing invalid forced-cleanup worker floating IPv4" >&2
      return 2
    }
    assigned=$(jq -r '.floatingIP.assigned_to // ""' <<<"$snapshot") || return 1
    if [[ -n $assigned ]]; then
      api_post_json "network/ip_addresses/$address/unassign" "$deadline" || return 1
    else
      api_delete_json "network/ip_addresses/$address" "$deadline" || return 1
    fi
    return 0
  fi
  if [[ $(jq -r '.vm != null' <<<"$snapshot") == true ]]; then
    uuid=$(jq -er '.vm.uuid' <<<"$snapshot") || return 2
    api_delete_vm "$uuid" "$deadline" || return 1
  fi
  return 0
}

cleanup_forced_worker_resources() {
  local deadline=$1
  local absent_status attempt sleep_seconds status
  local maximum_deadline=$((SECONDS + raw_cleanup_timeout_seconds))
  if (( deadline > maximum_deadline )); then deadline=$maximum_deadline; fi
  for attempt in $(seq 1 "$raw_cleanup_attempts"); do
    if cleanup_forced_worker_resources_once "$deadline"; then
      status=0
    else
      status=$?
    fi
    if (( status == 2 )); then
      echo "refusing to retry exact worker cleanup after an ownership or safety mismatch" >&2
      return 2
    fi
    if forced_worker_resources_absent "$deadline"; then
      return 0
    else
      absent_status=$?
    fi
    if (( absent_status == 2 )); then
      echo "refusing to retry exact worker cleanup after an ownership or safety mismatch" >&2
      return 2
    fi
    if (( SECONDS >= deadline )); then break; fi
    if (( attempt < raw_cleanup_attempts )); then
      sleep_seconds=$(remaining_timeout_seconds "$deadline" "$raw_cleanup_interval_seconds") || break
      sleep "$sleep_seconds"
    fi
  done
  echo "exact Karpenter worker cleanup did not converge within the bounded retry window" >&2
  return 1
}

validate_forced_worker_cleanup_state() {
  local deadline=$1
  local workers worker_name nodepool nodeclass claims nodes timeout_seconds
  validated_worker_claim_json=""
  validated_worker_node_json=""
  e2e_pods_absent "$deadline" || return 1
  pv_and_attachments_absent "$deadline" || return 1
  persist_worker_ownership_from_cloud "$deadline" || return $?
  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  validate_worker_records "$workers" || return 2
  [[ $(jq -r 'length' <<<"$workers") == 1 ]] || {
    echo "refusing forced worker cleanup without exactly one persisted worker" >&2
    return 2
  }
  worker_name=$(jq -er '.[0].name' <<<"$workers") || return 2
  worker_volume_attachments_absent "$deadline" "$worker_name" || return 1

  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  nodepool=$(kubectl --request-timeout="${timeout_seconds}s" get nodepool "$nodepool_name" -o json) || return 1
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  nodeclass=$(kubectl --request-timeout="${timeout_seconds}s" get inspacenodeclass "$nodeclass_name" -o json) || return 1
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  claims=$(kubectl --request-timeout="${timeout_seconds}s" get nodeclaims -o json) || return 1
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 1
  nodes=$(kubectl --request-timeout="${timeout_seconds}s" get nodes -o json) || return 1

  if ! jq -e -n \
      --arg location "$INSPACE_LOCATION" --arg prefix "$nodepool_name-" \
      --arg pool "$nodepool_name" --arg class "$nodeclass_name" \
      --arg cluster "$cluster_name" --arg billing "$INSPACE_BILLING_ACCOUNT_ID" \
      --arg network "$INSPACE_NETWORK_UUID" \
      --argjson workers "$workers" --argjson nodepool "$nodepool" \
      --argjson nodeclass "$nodeclass" --argjson claims "$claims" --argjson nodes "$nodes" '
      $workers[0] as $worker |
      [$claims.items[] | select(
        ((.metadata.name // "") | startswith($prefix)) or
        .metadata.labels["karpenter.sh/nodepool"] == $pool)] as $ownedClaims |
      $ownedClaims[0] as $claim |
      [$nodes.items[] | select(
        .metadata.name == $worker.name or
        ((.metadata.name // "") | startswith($prefix)) or
        .metadata.labels["karpenter.sh/nodepool"] == $pool)] as $ownedNodes |
      ($nodepool.metadata.name == $pool) and
      (($nodepool.metadata.deletionTimestamp // "") == "") and
      ($nodeclass.metadata.name == $class) and
      (($nodeclass.metadata.deletionTimestamp // "") == "") and
      ($nodeclass.spec.clusterName == $cluster) and
      (($nodeclass.spec.billingAccountID | tostring) == $billing) and
      ($nodeclass.spec.location == $location) and
      ($nodeclass.spec.networkUUID == $network) and
      ($nodepool.spec.template.spec.nodeClassRef.group == "karpenter.inspace.cloud") and
      ($nodepool.spec.template.spec.nodeClassRef.kind == "InSpaceNodeClass") and
      ($nodepool.spec.template.spec.nodeClassRef.name == $class) and
      (($ownedClaims | length) == 1) and
      ($claim.metadata.name == $worker.name) and
      ($claim.metadata.deletionTimestamp != null) and
      (($claim.metadata.finalizers // []) == ["karpenter.sh/termination"]) and
      ($claim.status.providerID == ("inspace://" + $location + "/" + $worker.uuid)) and
      ($claim.status.nodeName == $worker.name) and
      ($claim.spec.nodeClassRef.group == "karpenter.inspace.cloud") and
      ($claim.spec.nodeClassRef.kind == "InSpaceNodeClass") and
      ($claim.spec.nodeClassRef.name == $class) and
      ($claim.metadata.labels["karpenter.sh/nodepool"] == $pool) and
      any($claim.metadata.ownerReferences[]?;
        .apiVersion == "karpenter.sh/v1" and .kind == "NodePool" and
        .name == $pool and .uid == $nodepool.metadata.uid) and
      any($claim.status.conditions[]?; .type == "Drained" and .status == "True") and
      any($claim.status.conditions[]?; .type == "VolumesDetached" and .status == "True") and
      (($ownedNodes | length) <= 1) and
      (($ownedNodes | length) == 0 or (
        ($ownedNodes[0].metadata.name == $worker.name) and
        ($ownedNodes[0].metadata.deletionTimestamp != null) and
        (($ownedNodes[0].metadata.finalizers // []) == ["karpenter.sh/termination"]) and
        any($ownedNodes[0].metadata.ownerReferences[]?;
          .apiVersion == "karpenter.sh/v1" and .kind == "NodeClaim" and
          .name == $claim.metadata.name and .uid == $claim.metadata.uid)))' >/dev/null; then
    echo "refusing forced worker cleanup because Kubernetes ownership or drain state is not exact" >&2
    return 2
  fi
  validated_worker_claim_json=$(jq -ce --arg name "$worker_name" '
    [.items[] | select(.metadata.name == $name)] |
    if length == 1 then .[0] else error("validated NodeClaim snapshot is no longer exact") end' \
    <<<"$claims") || return 2
  validated_worker_node_json=$(jq -c --arg name "$worker_name" '
    [.items[] | select(.metadata.name == $name)] |
    if length == 0 then empty
    elif length == 1 then .[0]
    else error("validated Node snapshot is no longer exact")
    end' <<<"$nodes") || return 2
}

force_finalize_drained_owned_worker() {
  local deadline=$1
  local claim_json claim_patch deployment deployment_rv node_json node_patch replicas workers worker_name timeout_seconds
  validate_forced_worker_cleanup_state "$deadline" || return $?

  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  deployment=$(kubectl --request-timeout="${timeout_seconds}s" -n kube-system get deployment inspace-karpenter -o json) || return 1
  if ! jq -e '
      .metadata.name == "inspace-karpenter" and
      .metadata.namespace == "kube-system" and
      .metadata.deletionTimestamp == null and
      .metadata.labels["app.kubernetes.io/managed-by"] == "Helm" and
      .metadata.labels["app.kubernetes.io/instance"] == "inspace" and
      .metadata.labels["app.kubernetes.io/component"] == "karpenter" and
      .spec.selector.matchLabels["app.kubernetes.io/name"] == "inspace-karpenter" and
      .spec.selector.matchLabels["app.kubernetes.io/component"] == "karpenter" and
      .spec.template.metadata.labels["app.kubernetes.io/name"] == "inspace-karpenter" and
      .spec.template.metadata.labels["app.kubernetes.io/component"] == "karpenter" and
      (.spec.replicas == 0 or .spec.replicas == 1)' >/dev/null <<<"$deployment"; then
    echo "refusing to scale a Karpenter Deployment whose identity is not exact" >&2
    return 2
  fi
  replicas=$(jq -er '.spec.replicas' <<<"$deployment") || return 1
  deployment_rv=$(jq -er '.metadata.resourceVersion' <<<"$deployment") || return 1
  if [[ $replicas != 0 ]]; then
    [[ $replicas == 1 ]] || {
      echo "refusing to scale unexpected Karpenter replica count $replicas" >&2
      return 2
    }
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 30) || return 124
    kubectl --request-timeout="${timeout_seconds}s" -n kube-system scale deployment inspace-karpenter \
      --current-replicas="$replicas" --resource-version="$deployment_rv" --replicas=0 >/dev/null || return 1
  fi
  wait_until_deadline "$deadline" "Karpenter controller pods to stop" \
    karpenter_pods_absent "$deadline" || return 1

  # Close the race with the controller before using the local, ownership-bound
  # fallback. All safety predicates are re-read after its Pods are gone.
  validate_forced_worker_cleanup_state "$deadline" || return $?
  cleanup_forced_worker_resources "$deadline" || return $?
  (( SECONDS < deadline )) || return 124
  forced_worker_resources_absent "$deadline" || return $?

  # Bind every finalizer mutation to a post-cloud-cleanup Kubernetes snapshot.
  # UID and resourceVersion JSON Patch tests make replacement or concurrent
  # mutation fail atomically instead of finalizing a different object.
  validate_forced_worker_cleanup_state "$deadline" || return $?

  workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
  [[ $(jq -r 'length' <<<"$workers") == 1 ]] || return 2
  worker_name=$(jq -er '.[0].name' <<<"$workers") || return 2
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  node_json=$validated_worker_node_json
  if [[ -n $node_json ]]; then
    node_patch=$(jq -ce '[
      {op:"test",path:"/metadata/uid",value:.metadata.uid},
      {op:"test",path:"/metadata/resourceVersion",value:.metadata.resourceVersion},
      {op:"test",path:"/metadata/deletionTimestamp",value:.metadata.deletionTimestamp},
      {op:"test",path:"/metadata/finalizers",value:["karpenter.sh/termination"]},
      {op:"remove",path:"/metadata/finalizers/0"}
    ]' <<<"$node_json") || return 2
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
    kubectl --request-timeout="${timeout_seconds}s" patch node "$worker_name" \
      --type=json -p="$node_patch" >/dev/null || return 2
    wait_until_deadline "$deadline" "owned Karpenter Node to terminate" \
      owned_worker_node_absent "$deadline" || return $?
  fi

  validate_forced_worker_cleanup_state "$deadline" || return $?
  claim_json=$validated_worker_claim_json
  claim_patch=$(jq -ce '[
    {op:"test",path:"/metadata/uid",value:.metadata.uid},
    {op:"test",path:"/metadata/resourceVersion",value:.metadata.resourceVersion},
    {op:"test",path:"/metadata/deletionTimestamp",value:.metadata.deletionTimestamp},
    {op:"test",path:"/metadata/finalizers",value:["karpenter.sh/termination"]},
    {op:"remove",path:"/metadata/finalizers/0"}
  ]' <<<"$claim_json") || return 2
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  kubectl --request-timeout="${timeout_seconds}s" patch nodeclaim "$worker_name" \
    --type=json -p="$claim_patch" >/dev/null || return 2
  wait_until_deadline "$deadline" "owned Karpenter NodeClaim to terminate" \
    owned_worker_nodeclaim_absent "$deadline" || return $?
  owned_nodeclaims_absent "$deadline" || return $?
}

# Quiesce every Kubernetes owner before removing controllers or falling back
# to raw cloud cleanup. This prevents CSI detach/delete and Karpenter deletion
# from racing mounted pods or recreating resources after the audit.
kubernetes_e2e_quiesce() {
  local deadline=$1
  local claim_grace_deadline claim_wait_status crd_name discovered_pv pvc_json timeout_seconds
  (( SECONDS < deadline )) || return 124
  persist_service_ownership_from_cluster "$deadline" || return 1
  (( SECONDS < deadline )) || return 124
  persist_pvc_ownership_from_cluster "$deadline" || return 1
  (( SECONDS < deadline )) || return 124
  persist_worker_ownership_from_cloud "$deadline" || return $?
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 600) || return 124
  kubectl --request-timeout="${timeout_seconds}s" -n default delete service inspace-e2e-web \
    --ignore-not-found --wait=true --timeout="${timeout_seconds}s" >/dev/null || return 1
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 600) || return 124
  kubectl --request-timeout="${timeout_seconds}s" -n default delete deployment inspace-e2e-web inspace-e2e-trigger \
    --ignore-not-found --wait=true --timeout="${timeout_seconds}s" >/dev/null || return 1
  wait_until_deadline "$deadline" "E2E workload pods to terminate" e2e_pods_absent "$deadline" || return $?
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  pvc_json=$(kubectl --request-timeout="${timeout_seconds}s" -n default get pvc inspace-e2e-rwo \
    --ignore-not-found -o json) || return 1
  if [[ -n $pvc_json ]]; then
    discovered_pv=$(jq -r '.spec.volumeName // ""' <<<"$pvc_json") || return 1
    if [[ -n $discovered_pv ]]; then
      state_update '.pvName=$pv' --arg pv "$discovered_pv" || return 1
    fi
  fi
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 600) || return 124
  kubectl --request-timeout="${timeout_seconds}s" -n default delete pvc inspace-e2e-rwo \
    --ignore-not-found --wait=true --timeout="${timeout_seconds}s" >/dev/null || return 1
  wait_until_deadline "$deadline" "E2E PV and VolumeAttachment deletion" \
    pv_and_attachments_absent "$deadline" || return $?

  (( SECONDS < deadline )) || return 124
  persist_worker_ownership_from_cloud "$deadline" || return $?
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  crd_name=$(kubectl --request-timeout="${timeout_seconds}s" get crd nodeclaims.karpenter.sh \
    --ignore-not-found -o name) || return 1
  if [[ -n $crd_name ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 30) || return 124
    # Keep the NodePool available while Karpenter drains each NodeClaim. Its
    # state controllers resolve NodeClaim labels back to the NodePool during
    # termination; deleting the parent first can stall finalization.
    kubectl --request-timeout="${timeout_seconds}s" delete nodeclaims \
      -l "karpenter.sh/nodepool=$nodepool_name" \
      --ignore-not-found --wait=false --timeout="${timeout_seconds}s" >/dev/null || return 1
    claim_grace_deadline=$((SECONDS + 300))
    if (( claim_grace_deadline > deadline )); then claim_grace_deadline=$deadline; fi
    if wait_until_deadline "$claim_grace_deadline" "normal Karpenter NodeClaim termination" \
        owned_nodeclaims_absent "$claim_grace_deadline"; then
      :
    else
      claim_wait_status=$?
      if (( claim_wait_status == 2 || claim_wait_status == 124 )); then
        return "$claim_wait_status"
      fi
      echo "normal Karpenter deletion stalled; entering guarded E2E-only worker fallback" >&2
      force_finalize_drained_owned_worker "$deadline" || return $?
    fi
    wait_until_deadline "$deadline" "owned Karpenter Node to terminate" \
      owned_worker_node_absent "$deadline" || return $?
  fi
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  crd_name=$(kubectl --request-timeout="${timeout_seconds}s" get crd nodepools.karpenter.sh \
    --ignore-not-found -o name) || return 1
  if [[ -n $crd_name ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 300) || return 124
    kubectl --request-timeout="${timeout_seconds}s" delete nodepool "$nodepool_name" \
      --ignore-not-found --wait=true --timeout="${timeout_seconds}s" >/dev/null || return 1
  fi
  timeout_seconds=$(remaining_timeout_seconds "$deadline" 10) || return 124
  crd_name=$(kubectl --request-timeout="${timeout_seconds}s" get crd \
    inspacenodeclasses.karpenter.inspace.cloud --ignore-not-found -o name) || return 1
  if [[ -n $crd_name ]]; then
    timeout_seconds=$(remaining_timeout_seconds "$deadline" 300) || return 124
    kubectl --request-timeout="${timeout_seconds}s" delete inspacenodeclass "$nodeclass_name" \
      --ignore-not-found --wait=true --timeout="${timeout_seconds}s" >/dev/null || return 1
  fi
  return 0
}

quiesce_kubernetes_e2e_owners_bounded() {
  local attempt status sleep_seconds
  local deadline=$((SECONDS + kubernetes_quiesce_timeout_seconds))
  for attempt in $(seq 1 "$kubernetes_quiesce_attempts"); do
    if kubernetes_e2e_quiesce "$deadline"; then
      return 0
    else
      status=$?
    fi
    if (( status == 2 || status == 124 || SECONDS >= deadline )); then
      break
    fi
    sleep_seconds=$(remaining_timeout_seconds "$deadline" 10) || break
    sleep "$sleep_seconds"
    wait_for_kubernetes_available_until "$deadline" || break
  done
  echo "Kubernetes E2E owners did not quiesce within the bounded retry window" >&2
  return 1
}

owned_audit_json() {
  local vms firewalls ips lbs disks
  vms=$(api_get user-resource/vm/list)
  firewalls=$(api_get network/firewalls)
  ips=$(api_get network/ip_addresses)
  lbs=$(api_get network/load_balancers)
  disks=$(api_get storage/disks)
  jq -n \
    --arg owner "$owner" --arg cluster "$cluster_name" --arg workerPrefix "$nodepool_name" \
    --arg serviceLB "$(jq -r '.serviceLoadBalancerName // ""' "$state_file")" \
    --arg serviceIP "$(jq -r '.serviceFloatingIPName // ""' "$state_file")" \
    --arg diskUUID "$(jq -r '.diskUUID // ""' "$state_file")" \
    --arg diskName "$(jq -r '.pvcDiskName // ""' "$state_file")" \
    --argjson vms "$vms" --argjson firewalls "$firewalls" --argjson ips "$ips" --argjson lbs "$lbs" --argjson disks "$disks" '
      def ownedvm:
        ((.name // "") | startswith("k3s-" + $owner + "-")) or
        ((.name // "") | startswith($workerPrefix + "-")) or
        ((((.description // "{}") | fromjson?) // {}) | .cluster == $cluster);
      {
        vms: [$vms[] | select(ownedvm) | {uuid,name}],
        firewalls: [$firewalls[] | select((.display_name // .name // "") == ("k3s-"+$owner+"-nodes")) | {uuid,name:(.display_name // .name)}],
        floatingIPs: [$ips[] | select(((.name // "") | startswith("k3s-"+$owner+"-")) or ((.name // "") | startswith($workerPrefix + "-")) or ($serviceIP != "" and .name == $serviceIP)) | {address,name,assigned_to}],
        loadBalancers: [$lbs[] | select((.display_name // "") == ("k3s-"+$owner+"-api") or ($serviceLB != "" and .display_name == $serviceLB)) | {uuid,name:.display_name}],
        disks: [$disks[] | select(($diskUUID != "" and .uuid == $diskUUID) or ($diskName != "" and .display_name == $diskName)) | {uuid,name:.display_name}]
      } | .count = ([.vms,.firewalls,.floatingIPs,.loadBalancers,.disks] | map(length) | add)'
}

converge_raw_cleanup() {
  local description=$1
  local attempt_function=$2
  local absent_function=$3
  local attempt status
  local deadline=$((SECONDS + raw_cleanup_timeout_seconds))
  for attempt in $(seq 1 "$raw_cleanup_attempts"); do
    if "$attempt_function"; then
      status=0
    else
      status=$?
    fi
    if "$absent_function"; then
      return 0
    fi
    if (( status == 2 )); then
      echo "refusing to retry $description after an ownership or safety mismatch" >&2
      return 2
    fi
    if (( SECONDS >= deadline )); then
      break
    fi
    if (( attempt < raw_cleanup_attempts )); then
      sleep "$raw_cleanup_interval_seconds"
    fi
  done
  echo "$description did not converge within the bounded retry window" >&2
  return 1
}

service_resources_absent() {
  local lb_name ip_name load_balancers ip_addresses
  lb_name=$(jq -r '.serviceLoadBalancerName // ""' "$state_file") || return 1
  ip_name=$(jq -r '.serviceFloatingIPName // ""' "$state_file") || return 1
  [[ -n $lb_name ]] || return 0
  load_balancers=$(api_get network/load_balancers) || return 1
  ip_addresses=$(api_get network/ip_addresses) || return 1
  jq -e -n --arg lb "$lb_name" --arg ip "$ip_name" \
    --argjson lbs "$load_balancers" --argjson ips "$ip_addresses" '
      ([$lbs[] | select(.display_name==$lb and ((.is_deleted // false) | not))] | length) == 0 and
      ($ip == "" or ([$ips[] | select(.name==$ip and ((.is_deleted // false) | not))] | length) == 0)' >/dev/null
}

cleanup_service_resources_once() {
  local lb_name lb_uuid lb_json load_balancers ip_name ip_address assigned assigned_type ip_addresses ip_json
  lb_name=$(jq -r '.serviceLoadBalancerName // ""' "$state_file") || return 1
  ip_name=$(jq -r '.serviceFloatingIPName // ""' "$state_file") || return 1
  [[ -n $lb_name ]] || return 0
  load_balancers=$(api_get network/load_balancers) || return 1
  lb_json=$(jq -c --arg name "$lb_name" '
    [.[] | select(.display_name==$name and ((.is_deleted // false) | not))] |
    if length == 0 then empty elif length == 1 then .[0] else error("duplicate Service load balancer name") end' <<<"$load_balancers") || return 2
  lb_uuid=""
  if [[ -n $lb_json ]]; then
    lb_uuid=$(jq -r '.uuid // ""' <<<"$lb_json")
    [[ $lb_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
      echo "refusing Service load balancer with an invalid UUID" >&2
      return 2
    }
    if ! jq -e --arg network "$INSPACE_NETWORK_UUID" --arg billing "$INSPACE_BILLING_ACCOUNT_ID" '
        .network_uuid == $network and
        ((.billing_account_id // 0) == 0 or ((.billing_account_id | tostring) == $billing))' >/dev/null <<<"$lb_json"; then
      echo "refusing Service load balancer outside the E2E network or billing account" >&2
      return 2
    fi
  fi
  if [[ -n $ip_name ]]; then
    ip_addresses=$(api_get network/ip_addresses) || return 1
    ip_json=$(jq -c --arg name "$ip_name" '
      [.[] | select(.name==$name and ((.is_deleted // false) | not))] |
      if length == 0 then empty elif length == 1 then .[0] else error("duplicate Service floating IP name") end' <<<"$ip_addresses") || return 2
    if [[ -n $ip_json ]]; then
      ip_address=$(jq -r '.address' <<<"$ip_json")
      require_public_ipv4 "$ip_address" || { echo "refusing invalid Service floating IPv4" >&2; return 2; }
      assigned=$(jq -r '.assigned_to // ""' <<<"$ip_json")
      assigned_type=$(jq -r '.assigned_to_resource_type // ""' <<<"$ip_json")
      if [[ -n $assigned ]]; then
        if [[ $assigned_type != load_balancer ]]; then
          echo "refusing unexpected Service FIP assignment" >&2
          return 2
        fi
        if [[ -z $lb_uuid ]]; then
          echo "waiting for the assigned Service load balancer to become visible" >&2
          return 1
        fi
        if [[ $assigned != "$lb_uuid" ]]; then
          echo "refusing unexpected Service FIP assignment" >&2
          return 2
        fi
        api_post_json "network/ip_addresses/$ip_address/unassign" || return 1
        return 0
      fi
      api_delete_json "network/ip_addresses/$ip_address" || return 1
      return 0
    fi
  fi
  if [[ -n $lb_uuid ]]; then
    api_delete_json "network/load_balancers/$lb_uuid" || return 1
  fi
  return 0
}

cleanup_service_resources() {
  converge_raw_cleanup "raw Service load balancer cleanup" cleanup_service_resources_once service_resources_absent
}

disk_resource_absent() {
  local disk_uuid disk_name disks
  disk_uuid=$(jq -r '.diskUUID // ""' "$state_file") || return 1
  disk_name=$(jq -r '.pvcDiskName // ""' "$state_file") || return 1
  [[ -n $disk_uuid || -n $disk_name ]] || return 0
  disks=$(api_get storage/disks) || return 1
  jq -e --arg uuid "$disk_uuid" --arg name "$disk_name" '
    [.[] | select(($uuid != "" and .uuid==$uuid) or ($name != "" and .display_name==$name))] | length == 0' \
    >/dev/null <<<"$disks"
}

cleanup_disk_resource_once() {
  local disk_uuid disk_name disks disk_matches disk_json disk_details attachment_vms bad_attachments attachment_count
  disk_uuid=$(jq -r '.diskUUID // ""' "$state_file") || return 1
  disk_name=$(jq -r '.pvcDiskName // ""' "$state_file") || return 1
  [[ -n $disk_uuid || -n $disk_name ]] || return 0
  disks=$(api_get storage/disks) || return 1
  if [[ -z $disk_uuid && -n $disk_name ]]; then
    disk_matches=$(jq -c --arg name "$disk_name" '[.[] | select(.display_name==$name)]' <<<"$disks") || return 1
    if [[ $(jq -r 'length' <<<"$disk_matches") -gt 1 ]]; then
      echo "refusing duplicate CSI disk ownership name" >&2
      return 2
    fi
    disk_uuid=$(jq -r 'if length==1 then .[0].uuid else "" end' <<<"$disk_matches") || return 1
  fi
  [[ -n $disk_uuid ]] || return 0
  [[ $disk_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
    echo "refusing invalid CSI disk UUID from state" >&2
    return 2
  }
  disk_matches=$(jq -c --arg uuid "$disk_uuid" '[.[] | select(.uuid==$uuid)]' <<<"$disks") || return 1
  if [[ $(jq -r 'length' <<<"$disk_matches") -gt 1 ]]; then
    echo "refusing duplicate CSI disk UUID" >&2
    return 2
  fi
  disk_json=$(jq -c 'if length==1 then .[0] else empty end' <<<"$disk_matches") || return 1
  [[ -n $disk_json ]] || return 0
  if [[ -z $disk_name || $(jq -r '.display_name // ""' <<<"$disk_json") != "$disk_name" ]]; then
    echo "refusing CSI disk whose UUID/name ownership does not match the E2E state" >&2
    return 2
  fi
  if [[ $(jq -r '.diskUUID // ""' "$state_file") == "" ]]; then
    state_update '.diskUUID=$disk' --arg disk "$disk_uuid" || return 1
  fi
  disk_details=$(api_get "storage/disks/$disk_uuid") || return 1
  if [[ $(jq -r '(.snapshots // []) | length' <<<"$disk_details") != 0 ]]; then
    echo "refusing to delete E2E disk while snapshots exist" >&2
    return 2
  fi

  attachment_vms=$(api_get user-resource/vm/list) || return 1
  bad_attachments=$(jq --arg disk "$disk_uuid" --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '
    [.[] | select(any(.storage[]?; .uuid==$disk)) | . as $vm |
      (((.description // "{}") | fromjson?) // {}) as $record |
      select($record.schema != "karpenter.inspace.cloud/v1" or $record.cluster != $cluster or
             $record.nodeClaim != $vm.name or (($vm.name // "") | startswith($prefix) | not))] | length' <<<"$attachment_vms") || return 1
  if [[ $bad_attachments != 0 ]]; then
    echo "refusing to detach the E2E disk from a VM without exact Karpenter ownership" >&2
    return 2
  fi
  attachment_count=$(jq -r --arg disk "$disk_uuid" '[.[] | select(any(.storage[]?; .uuid==$disk))] | length' <<<"$attachment_vms") || return 1
  if [[ $attachment_count != 0 ]]; then
    local vm_uuid
    while IFS= read -r vm_uuid; do
      [[ -n $vm_uuid ]] || continue
      api_detach_disk "$vm_uuid" "$disk_uuid" || return 1
    done < <(jq -r --arg disk "$disk_uuid" '.[] | select(any(.storage[]?; .uuid==$disk)) | .uuid' <<<"$attachment_vms")
    return 0
  fi
  api_delete_json "storage/disks/$disk_uuid" || return 1
  return 0
}

cleanup_disk_resource() {
  converge_raw_cleanup "raw CSI disk cleanup" cleanup_disk_resource_once disk_resource_absent
}

worker_resources_absent() {
  local all_vms all_ips remaining_vms remaining_ips
  all_vms=$(api_get user-resource/vm/list) || return 1
  all_ips=$(api_get network/ip_addresses) || return 1
  remaining_vms=$(jq -r --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '[.[] | . as $vm |
    ((((.description // "{}") | fromjson?) // {})) as $record |
    select($record.cluster==$cluster or (($vm.name // "") | startswith($prefix)))] | length' <<<"$all_vms") || return 1
  remaining_ips=$(jq -r --arg prefix "$nodepool_name-" '[.[] |
    select(((.is_deleted // false) | not) and ((.name // "") | startswith($prefix)))] | length' <<<"$all_ips") || return 1
  [[ $remaining_vms == 0 && $remaining_ips == 0 ]]
}

cleanup_worker_resources_once() {
  local all_vms all_ips matching invalid_workers worker_count uuid name fip_name fip_json address assigned assigned_type orphan_json orphan_name persisted_workers expected_count
  all_vms=$(api_get user-resource/vm/list) || return 1
  matching=$(jq -c --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '[.[] | . as $vm |
    ((((.description // "{}") | fromjson?) // {})) as $record |
    select($record.cluster==$cluster or (($vm.name // "") | startswith($prefix))) |
    {vm:$vm,record:$record}] | sort_by(.vm.name)' <<<"$all_vms") || return 1
  invalid_workers=$(jq --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '[.[] | select(
    .record.schema != "karpenter.inspace.cloud/v1" or .record.cluster != $cluster or
    .record.nodeClaim != .vm.name or ((.vm.name // "") | startswith($prefix) | not) or
    ((.record.floatingIPName // "") | startswith($prefix) | not))] | length' <<<"$matching") || return 1
  if [[ $invalid_workers != 0 ]]; then
    echo "refusing raw worker cleanup because cloud ownership metadata is incomplete or mismatched" >&2
    return 2
  fi
  worker_count=$(jq -r 'length' <<<"$matching") || return 1
  if [[ $worker_count != 0 ]]; then
    IFS=$'\t' read -r uuid name fip_name < <(jq -r '.[0] | [.vm.uuid,.vm.name,.record.floatingIPName] | @tsv' <<<"$matching")
    [[ $uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
      echo "refusing worker VM with an invalid UUID" >&2
      return 2
    }
    all_ips=$(api_get network/ip_addresses) || return 1
    fip_json=$(jq -c --arg name "$fip_name" '
      [.[] | select(.name==$name and ((.is_deleted // false) | not))] |
      if length == 0 then empty elif length == 1 then .[0] else error("duplicate worker floating IP name") end' <<<"$all_ips") || return 2
    if [[ -n $fip_json ]]; then
      address=$(jq -r '.address' <<<"$fip_json")
      require_public_ipv4 "$address" || { echo "refusing invalid worker floating IPv4" >&2; return 2; }
      assigned=$(jq -r '.assigned_to // ""' <<<"$fip_json")
      assigned_type=$(jq -r '.assigned_to_resource_type // ""' <<<"$fip_json")
      if [[ -n $assigned && ($assigned != "$uuid" || $assigned_type != virtual_machine) ]]; then
        echo "refusing unexpected worker FIP assignment for $name" >&2
        return 2
      fi
      if [[ -n $assigned ]]; then
        api_post_json "network/ip_addresses/$address/unassign" || return 1
        return 0
      fi
      api_delete_json "network/ip_addresses/$address" || return 1
      return 0
    fi
    api_delete_vm "$uuid" || return 1
    return 0
  fi

  # Clean a late unassigned FIP whose deterministic worker VM never became visible.
  all_ips=$(api_get network/ip_addresses) || return 1
  orphan_json=$(jq -c --arg prefix "$nodepool_name-" '[.[] |
    select(((.is_deleted // false) | not) and ((.name // "") | startswith($prefix)))] | sort_by([.name,.address]) |
    if length == 0 then empty else .[0] end' <<<"$all_ips") || return 1
  [[ -n $orphan_json ]] || return 0
  address=$(jq -r '.address' <<<"$orphan_json")
  orphan_name=$(jq -r '.name // ""' <<<"$orphan_json")
  require_public_ipv4 "$address" || { echo "refusing invalid orphan worker floating IPv4" >&2; return 2; }
  assigned=$(jq -r '.assigned_to // ""' <<<"$orphan_json")
  if [[ -n $assigned ]]; then
    assigned_type=$(jq -r '.assigned_to_resource_type // ""' <<<"$orphan_json")
    if [[ $assigned_type != virtual_machine ]]; then
      echo "refusing assigned orphan worker FIP $address with unexpected resource type" >&2
      return 2
    fi
    persisted_workers=$(jq -c '.workerVMs // []' "$state_file") || return 1
    validate_worker_records "$persisted_workers" || return 2
    expected_count=$(jq -r --arg fip "$orphan_name" --arg uuid "$assigned" \
      '[.[] | select(.fip==$fip and .uuid==$uuid)] | length' <<<"$persisted_workers") || return 1
    if [[ $expected_count != 1 ]]; then
      echo "waiting to validate assigned orphan worker FIP $address against a visible or persisted VM" >&2
      return 1
    fi
    api_post_json "network/ip_addresses/$address/unassign" || return 1
    return 0
  fi
  api_delete_json "network/ip_addresses/$address" || return 1
  return 0
}

cleanup_worker_resources() {
  converge_raw_cleanup "raw Karpenter worker cleanup" cleanup_worker_resources_once worker_resources_absent
}

terminate_controller_child() {
  local pid=${controller_child_pid:-}
  local grace_deadline
  [[ -n $pid ]] || return 0
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -TERM "$pid" >/dev/null 2>&1 || true
    grace_deadline=$((SECONDS + 10))
    while kill -0 "$pid" >/dev/null 2>&1 && (( SECONDS < grace_deadline )); do
      sleep 1
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  fi
  wait "$pid" >/dev/null 2>&1 || true
  controller_child_pid=""
}

wait_for_controller_child_until() {
  local deadline=$1
  local pid=${controller_child_pid:-}
  local status=0
  [[ -n $pid ]] || return 1
  while kill -0 "$pid" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      terminate_controller_child
      return 124
    fi
    # This sleep is foreground and therefore reaped on every iteration; there
    # is no detached watchdog timer process to orphan during shutdown.
    sleep 1
  done
  wait "$pid" || status=$?
  controller_child_pid=""
  return "$status"
}

stop_bootstrap_controller() {
  terminate_controller_child
}

run_bootstrap_controller_bounded() {
  local results_file=$state_dir/reconcile-results.jsonl
  local controller_status=0
  local deadline=$((SECONDS + bootstrap_timeout_seconds))
  : >"$results_file"

  "$controller_bin" --cluster-config "$cluster_file" --ssh-public-key-file "$ssh_public_key" --ssh-username "$ssh_user" \
    --management-cidr "$management_cidr" --management-tcp-ports 22,6443,30080 \
    --until-ready --interval 15s --output=json >"$results_file" &
  controller_child_pid=$!
  wait_for_controller_child_until "$deadline" || controller_status=$?
  awk '1' "$results_file"

  if (( controller_status == 124 )); then
    echo "bootstrap controller timed out after $bootstrap_timeout_seconds seconds" >&2
  fi
  return "$controller_status"
}

destroy_control_plane_once() {
  local deadline=$1
  local results_file=$state_dir/destroy-attempt.json
  local output controller_status=0
  [[ -x $controller_bin && -f $cluster_file ]] || return 0
  if (( SECONDS >= deadline )); then
    return 124
  fi
  : >"$results_file"
  "$controller_bin" --cluster-config "$cluster_file" --delete --once --output=json \
    --management-cidr "$management_cidr" --management-tcp-ports 22,6443,30080 \
    >"$results_file" 2>>"$state_dir/destroy.log" &
  controller_child_pid=$!
  wait_for_controller_child_until "$deadline" || controller_status=$?
  if (( controller_status != 0 )); then
    return "$controller_status"
  fi
  output=$(awk '1' "$results_file") || return 1
  printf '%s\n' "$output" >>"$state_dir/destroy-results.jsonl"
  if jq -e '.done == true' >/dev/null <<<"$output"; then
    return 0
  fi
  return 3
}

destroy_control_plane() {
  local status
  local deadline=$((SECONDS + raw_cleanup_timeout_seconds))
  for _ in $(seq 1 "$raw_cleanup_attempts"); do
    if destroy_control_plane_once "$deadline"; then
      return 0
    else
      status=$?
    fi
    printf 'control-plane destroy attempt returned status %d\n' "$status" >>"$state_dir/destroy.log"
    if (( status == 124 || SECONDS >= deadline )); then
      break
    fi
    sleep "$raw_cleanup_interval_seconds"
  done
  echo "control-plane teardown did not converge within the bounded retry window" >&2
  return 1
}

wait_for_zero_owned_audit() {
  local allow_late_cleanup=$1
  local audit=""
  local attempt status
  local retry_service=$allow_late_cleanup
  local retry_disk=$allow_late_cleanup
  local retry_worker=$allow_late_cleanup
  local retry_control_plane=$allow_late_cleanup
  local deadline=$((SECONDS + raw_cleanup_timeout_seconds))
  : >"$state_dir/final-audit.err"
  : >"$state_dir/final-audit-results.jsonl"
  for attempt in $(seq 1 "$raw_cleanup_attempts"); do
    if audit=$(owned_audit_json 2>>"$state_dir/final-audit.err"); then
      printf '%s\n' "$audit" >"$state_dir/final-audit.json"
      printf '%s\n' "$audit" >>"$state_dir/final-audit-results.jsonl"
      if jq -e '.count == 0' >/dev/null <<<"$audit"; then
        printf '%s\n' "$audit"
        return 0
      fi
    fi
    if [[ $retry_service == true ]]; then
      if cleanup_service_resources_once; then
        :
      else
        status=$?
        printf 'late Service cleanup attempt failed with status %d\n' "$status" >>"$state_dir/final-audit.err"
        if (( status == 2 )); then retry_service=false; fi
      fi
    fi
    if [[ $retry_disk == true ]]; then
      if cleanup_disk_resource_once; then
        :
      else
        status=$?
        printf 'late disk cleanup attempt failed with status %d\n' "$status" >>"$state_dir/final-audit.err"
        if (( status == 2 )); then retry_disk=false; fi
      fi
    fi
    if [[ $retry_worker == true ]]; then
      if cleanup_worker_resources_once; then
        :
      else
        status=$?
        printf 'late worker cleanup attempt failed with status %d\n' "$status" >>"$state_dir/final-audit.err"
        if (( status == 2 )); then retry_worker=false; fi
      fi
    fi
    if [[ $retry_control_plane == true ]]; then
      if destroy_control_plane_once "$deadline"; then
        :
      else
        status=$?
        printf 'late control-plane cleanup attempt returned status %d\n' "$status" >>"$state_dir/final-audit.err"
        if (( status == 124 )); then retry_control_plane=false; fi
      fi
    fi
    if (( SECONDS >= deadline )); then
      break
    fi
    if (( attempt < raw_cleanup_attempts )); then
      sleep "$raw_cleanup_interval_seconds"
    fi
  done
  [[ -z $audit ]] || printf '%s\n' "$audit"
  echo "owned-resource audit did not converge to zero within the bounded retry window" >&2
  return 1
}

cleanup() {
  local original_status=$?
  local cleanup_status=0
  local raw_cleanup_allowed=true
  local kubernetes_owners_possible
  local reachability_deadline
  trap - EXIT
  trap 'echo "cleanup already in progress; ignoring interrupt" >&2' INT TERM
  set +e
  stop_bootstrap_controller
  if [[ ${INSPACE_E2E_KEEP_RESOURCES:-false} == true ]]; then
    echo "E2E resources retained by explicit INSPACE_E2E_KEEP_RESOURCES=true; state: $state_dir" >&2
    exit "$original_status"
  fi
  if ! kubernetes_owners_possible=$(jq -er '
      if (.kubernetesOwnersPossible | type) == "boolean" then
        (.kubernetesOwnersPossible | tostring)
      else
        error("kubernetesOwnersPossible must be boolean")
      end' "$state_file"); then
    echo "E2E ownership state is missing or invalid; refusing raw cloud cleanup" >&2
    raw_cleanup_allowed=false
    cleanup_status=1
  elif [[ $kubernetes_owners_possible == true ]]; then
    # The flag is persisted before controller installation can partially
    # succeed. From that point onward, raw cloud deletion is safe only after
    # every Kubernetes owner was proven quiescent.
    raw_cleanup_allowed=false
    if [[ ! -s $kubeconfig ]]; then
      echo "Kubernetes owners may exist but kubeconfig is missing; refusing raw cloud cleanup" >&2
      cleanup_status=1
    else
      reachability_deadline=$((SECONDS + kubernetes_reachability_timeout_seconds))
      if ! wait_for_kubernetes_available_until "$reachability_deadline"; then
        echo "Kubernetes API remained unreachable; refusing concurrent raw cloud cleanup" >&2
        cleanup_status=1
      elif ! quiesce_kubernetes_e2e_owners_bounded; then
        echo "Kubernetes E2E owners did not quiesce; refusing concurrent raw cloud cleanup" >&2
        cleanup_status=1
      else
        raw_cleanup_allowed=true
        helm uninstall inspace -n kube-system --ignore-not-found --wait --timeout 5m \
          >/dev/null 2>&1 || cleanup_status=1
        helm uninstall inspace-crds -n kube-system --ignore-not-found --wait --timeout 5m \
          >/dev/null 2>&1 || cleanup_status=1
        kubectl --request-timeout=30s -n kube-system delete secret inspace-cloud-credentials \
          inspace-k3s-agent-token --ignore-not-found --wait=false >/dev/null 2>&1 || cleanup_status=1
      fi
    fi
  fi
  if [[ $raw_cleanup_allowed == true ]]; then
    cleanup_service_resources || cleanup_status=1
    cleanup_disk_resource || cleanup_status=1
    cleanup_worker_resources || cleanup_status=1
    destroy_control_plane || cleanup_status=1
  fi
  wait_for_zero_owned_audit "$raw_cleanup_allowed" || cleanup_status=1
  if (( original_status != 0 || cleanup_status != 0 )); then
    exit 1
  fi
  exit 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> preflight released OCI artifacts"
helm show chart "oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds" --version "$INSPACE_E2E_VERSION" >/dev/null
helm show chart "oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules" --version "$INSPACE_E2E_VERSION" >/dev/null
for image in inspace-cloud-controller-manager inspace-csi-driver karpenter-provider-inspace; do
  docker manifest inspect "ghcr.io/thanet-s/$image:$INSPACE_E2E_VERSION" >/dev/null
done

echo "==> build local bootstrap controller"
(cd modules/cloud-provider && GOWORK=off go build -trimpath -o "$controller_bin" ./cmd/inspace-cluster-controller)

baseline=$(owned_audit_json)
if [[ $(jq -r '.count' <<<"$baseline") != 0 ]]; then
  printf '%s\n' "$baseline" >&2
  echo "refusing to adopt pre-existing resources for this E2E identity" >&2
  exit 1
fi

echo "==> provision exactly three control-plane VMs"
run_bootstrap_controller_bounded
reconcile_result=$(tail -n 1 "$state_dir/reconcile-results.jsonl")
jq -e '.ready == true and (.controlPlaneVMs | length == 3)' >/dev/null <<<"$reconcile_result"
state_update '. + {firewallUUID:$firewall,apiLoadBalancerUUID:$lb,apiPublicIPv4:$public,privateEndpoint:$private,controlPlaneVMs:$vms}' \
  --arg firewall "$(jq -r '.firewallUUID' <<<"$reconcile_result")" \
  --arg lb "$(jq -r '.apiLoadBalancerUUID' <<<"$reconcile_result")" \
  --arg public "$(jq -r '.allocatedEndpointIPv4' <<<"$reconcile_result")" \
  --arg private "$(jq -r '.privateControlPlaneEndpoint' <<<"$reconcile_result")" \
  --argjson vms "$(jq '.controlPlaneVMs' <<<"$reconcile_result")"

control_plane_vms=$(jq -c '.controlPlaneVMs' "$state_file")
control_plane_assignments=$(api_get network/ip_addresses | jq -c --argjson vms "$control_plane_vms" '
  [.[] |
    select(((.is_deleted // false) | not) and (.enabled // true)) |
    select(.assigned_to_resource_type == "virtual_machine") |
    select(.assigned_to as $id | $vms | index($id)) |
    {address,assigned_to}]')
jq -e --argjson vms "$control_plane_vms" '
  length == ($vms | length) and
  ([.[].assigned_to] | sort) == ($vms | sort) and
  ([.[].address] | unique | length) == ($vms | length)' >/dev/null <<<"$control_plane_assignments"
control_plane_ips=$(jq -c '[.[].address] | unique' <<<"$control_plane_assignments")
while IFS= read -r ip; do
  require_public_ipv4 "$ip"
done < <(jq -r '.[]' <<<"$control_plane_ips")
state_update '.controlPlanePublicIPv4s=$ips' --argjson ips "$control_plane_ips"

echo "==> verify SSH, cloud-init, K3s readiness, and embedded etcd"
control_plane_readiness_deadline=$((SECONDS + 1800))
while IFS= read -r ip; do
  wait_until_deadline "$control_plane_readiness_deadline" "SSH on $ip" ssh_ready "$ip"
  wait_until_deadline "$control_plane_readiness_deadline" "K3s and embedded etcd on $ip" k3s_etcd_ready "$ip"
done < <(jq -r '.[]' <<<"$control_plane_ips")

cp0_ip=$(jq -r '.[0]' <<<"$control_plane_ips")
ssh "${ssh_options[@]}" "$ssh_user@$cp0_ip" 'sudo cat /etc/rancher/k3s/k3s.yaml' >"$kubeconfig"
chmod 600 "$kubeconfig"
api_public_ip=$(jq -r '.apiPublicIPv4' "$state_file")
kubectl config set-cluster default --server="https://$api_public_ip:6443" >/dev/null
wait_until 600 "public API NLB" kubectl_available
kubectl wait --for=condition=Ready node --all --timeout=10m
jq -e '.items | length == 3 and all(.[]; any(.status.conditions[]; .type=="Ready" and .status=="True"))' < <(kubectl get nodes -o json) >/dev/null
kubectl get --raw='/readyz?verbose' | grep -F '[+]etcd ok' >/dev/null

echo "==> install released CRDs and controller chart"
kubectl -n kube-system create secret generic inspace-cloud-credentials \
  --from-literal="api-token=$INSPACE_API_TOKEN" --from-literal="billing-account-id=$INSPACE_BILLING_ACCOUNT_ID" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n kube-system create secret generic inspace-k3s-agent-token \
  --from-literal="token=$k3s_token" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
helm upgrade --install inspace-crds oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version "$INSPACE_E2E_VERSION" -n kube-system --wait --timeout 5m
state_update '.kubernetesOwnersPossible=true'
helm upgrade --install inspace oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules \
  --version "$INSPACE_E2E_VERSION" -n kube-system --wait --timeout 15m \
  --set fullnameOverride=inspace \
  --set global.inspace.networkUUID="$INSPACE_NETWORK_UUID" \
  --set global.inspace.clusterID="$cluster_name" \
  --set ccm.replicaCount=1 \
  --set karpenter.replicaCount=1 \
  --set karpenter.clusterName="$cluster_name" \
  --set karpenter.defaultNodeClass="$nodeclass_name"
kubectl -n kube-system rollout status deployment/inspace-ccm --timeout=10m
kubectl -n kube-system rollout status deployment/inspace-csi-controller --timeout=10m
kubectl -n kube-system rollout status daemonset/inspace-csi-node --timeout=10m
kubectl -n kube-system rollout status deployment/inspace-karpenter --timeout=10m

echo "==> verify CCM node identity/address convergence"
wait_until 600 "CCM node initialization" bash -c '
  kubectl get nodes -o json | jq -e '\''
    .items | length == 3 and all(.[];
      (.spec.providerID | startswith("inspace://bkk01/")) and
      any(.status.addresses[]; .type=="InternalIP") and
      any(.status.addresses[]; .type=="ExternalIP") and
      all(.spec.taints[]?; .key!="node.cloudprovider.kubernetes.io/uninitialized"))'\'' >/dev/null'

private_endpoint=$(jq -r '.privateEndpoint' "$state_file")
cat >"$state_dir/karpenter.yaml" <<EOF
apiVersion: karpenter.inspace.cloud/v1alpha1
kind: InSpaceNodeClass
metadata:
  name: $nodeclass_name
spec:
  clusterName: $cluster_name
  billingAccountID: $INSPACE_BILLING_ACCOUNT_ID
  location: $INSPACE_LOCATION
  networkUUID: $INSPACE_NETWORK_UUID
  reservePublicIPv4: true
  firewallUUID: $(jq -r '.firewallUUID' "$state_file")
  imageSelector:
    osName: ${INSPACE_OS_NAME:-ubuntu}
    osVersion: "${INSPACE_OS_VERSION:-24.04}"
  hostPoolSelector:
    class: intel-scalable
  rootDiskGiB: 30
  k3s:
    version: v1.35.6+k3s1
    server: $private_endpoint
    tokenSecretRef:
      name: inspace-k3s-agent-token
      key: token
  sshUsername: $ssh_user
  sshPublicKey: "$configured_public_key"
  additionalUserData: |
    ufw allow proto tcp from $management_cidr to any port 22
    ufw allow proto tcp from $management_cidr to any port 30080
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: $nodepool_name
spec:
  limits:
    cpu: "2"
    memory: 4Gi
  template:
    spec:
      nodeClassRef:
        group: karpenter.inspace.cloud
        kind: InSpaceNodeClass
        name: $nodeclass_name
      requirements:
        - key: inspace.cloud/instance-family
          operator: In
          values: [general]
        - key: karpenter.sh/capacity-type
          operator: In
          values: [on-demand]
        - key: kubernetes.io/arch
          operator: In
          values: [amd64]
        - key: kubernetes.io/os
          operator: In
          values: [linux]
  disruption:
    consolidationPolicy: WhenEmpty
    consolidateAfter: 1m
EOF
kubectl apply -f "$state_dir/karpenter.yaml"
kubectl wait --for=condition=Ready "inspacenodeclass/$nodeclass_name" --timeout=10m

cat >"$state_dir/trigger.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inspace-e2e-trigger
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels: {app: inspace-e2e-trigger}
  template:
    metadata:
      labels: {app: inspace-e2e-trigger}
    spec:
      nodeSelector:
        karpenter.sh/nodepool: $nodepool_name
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.10.1
          resources:
            requests: {cpu: 100m, memory: 64Mi}
EOF
echo "==> force and verify one Karpenter worker"
kubectl apply -f "$state_dir/trigger.yaml"
kubectl -n default rollout status deployment/inspace-e2e-trigger --timeout=20m
kubectl wait --for=condition=Ready node -l "karpenter.sh/nodepool=$nodepool_name" --timeout=10m
jq -e '.items | length == 1 and all(.[]; any(.status.conditions[]; .type=="Ready" and .status=="True"))' < <(kubectl get nodeclaims -l "karpenter.sh/nodepool=$nodepool_name" -o json) >/dev/null
worker_node=$(kubectl get node -l "karpenter.sh/nodepool=$nodepool_name" -o jsonpath='{.items[0].metadata.name}')
[[ -n $worker_node ]]

persist_worker_ownership_from_cloud
workers=$(jq -c '.workerVMs // []' "$state_file")
jq -e 'length == 1' >/dev/null <<<"$workers"
wait_until 300 "Karpenter worker attachment to the configured private VPC" \
  owned_worker_vpc_ready "$worker_node"
worker_public_ip=$(owned_worker_public_ip)
require_public_ipv4 "$worker_public_ip"
state_update '.workerPublicIPv4=$ip' --arg ip "$worker_public_ip"
wait_until 600 "SSH on Karpenter worker" ssh_ready "$worker_public_ip"
wait_until 600 "worker cloud-init, Ubuntu 24.04, and K3s agent" k3s_agent_ready "$worker_public_ip"
state_update '.workerNode=$node' --arg node "$worker_node"
kubectl -n kube-system rollout status daemonset/inspace-csi-node --timeout=10m
kubectl get csinode "$worker_node" >/dev/null

marker="inspace-e2e-$run_id"
cat >"$state_dir/workload.yaml" <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: inspace-e2e-rwo
  namespace: default
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: inspace-rwo
  resources:
    requests: {storage: 1Gi}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inspace-e2e-web
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels: {app: inspace-e2e-web}
  template:
    metadata:
      labels: {app: inspace-e2e-web}
    spec:
      nodeSelector:
        karpenter.sh/nodepool: $nodepool_name
      initContainers:
        - name: initialize
          image: busybox:1.36.1
          command: [sh, -ec]
          args: ['test -f /data/index.html || printf "%s\\n" "$marker" > /data/index.html']
          volumeMounts: [{name: data, mountPath: /data}]
      containers:
        - name: nginx
          image: nginx:1.27.5-alpine
          ports: [{name: http, containerPort: 80}]
          volumeMounts: [{name: data, mountPath: /usr/share/nginx/html}]
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: inspace-e2e-rwo}
---
apiVersion: v1
kind: Service
metadata:
  name: inspace-e2e-web
  namespace: default
  annotations:
    service.beta.kubernetes.io/inspace-load-balancer-public: "true"
spec:
  type: LoadBalancer
  externalTrafficPolicy: Cluster
  selector: {app: inspace-e2e-web}
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
      nodePort: 30080
EOF

echo "==> verify RWO CSI mount, persistence, and TCP public LoadBalancer"
if ! kubectl apply -f "$state_dir/workload.yaml"; then
  partial_apply_persistence_status=0
  if ! persist_service_ownership_from_cluster; then
    partial_apply_persistence_status=1
  fi
  if ! persist_pvc_ownership_from_cluster; then
    partial_apply_persistence_status=1
  fi
  if (( partial_apply_persistence_status != 0 )); then
    echo "partial workload apply failed and ownership recovery was incomplete" >&2
  fi
  exit 1
fi
pvc_uid=$(kubectl -n default get pvc inspace-e2e-rwo -o jsonpath='{.metadata.uid}')
service_uid=$(kubectl -n default get service inspace-e2e-web -o jsonpath='{.metadata.uid}')
pvc_disk_name="pvc-$pvc_uid"
service_lb_name="k8s-$(sha16 "$cluster_name")-$(sha16 "$service_uid")"
state_update '. + {pvcUID:$pvcUID,pvcDiskName:$diskName,serviceUID:$serviceUID,serviceLoadBalancerName:$lb,serviceFloatingIPName:($lb+"-ip")}' \
  --arg pvcUID "$pvc_uid" --arg diskName "$pvc_disk_name" --arg serviceUID "$service_uid" --arg lb "$service_lb_name"
kubectl -n default rollout status deployment/inspace-e2e-web --timeout=20m
kubectl -n default wait --for=jsonpath='{.status.phase}'=Bound pvc/inspace-e2e-rwo --timeout=10m
pv_name=$(kubectl -n default get pvc inspace-e2e-rwo -o jsonpath='{.spec.volumeName}')
volume_handle=$(kubectl get pv "$pv_name" -o jsonpath='{.spec.csi.volumeHandle}')
disk_uuid=${volume_handle##*/}
state_update '. + {pvName:$pv,volumeHandle:$handle,diskUUID:$disk}' --arg pv "$pv_name" --arg handle "$volume_handle" --arg disk "$disk_uuid"
wait_until 600 "attached VolumeAttachment" bash -c "kubectl get volumeattachments -o json | jq -e --arg pv '$pv_name' 'any(.items[]; .spec.source.persistentVolumeName==\$pv and .status.attached==true)' >/dev/null"

service_ip=""
for _ in $(seq 1 90); do
  service_ip=$(kubectl -n default get service inspace-e2e-web -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  [[ -n $service_ip ]] && break
  sleep 10
done
[[ -n $service_ip ]]
require_public_ipv4 "$service_ip"
state_update '.servicePublicIPv4=$ip' --arg ip "$service_ip"
wait_until 600 "public TCP NLB marker" bash -c "[[ \$(curl --fail --silent --show-error --max-time 10 'http://$service_ip/') == '$marker' ]]"

old_pod=$(kubectl -n default get pod -l app=inspace-e2e-web -o jsonpath='{.items[0].metadata.name}')
kubectl -n default delete pod "$old_pod" --wait=true --timeout=5m
kubectl -n default rollout status deployment/inspace-e2e-web --timeout=10m
new_pod=$(kubectl -n default get pod -l app=inspace-e2e-web -o jsonpath='{.items[0].metadata.name}')
[[ $new_pod != "$old_pod" ]]
[[ $(kubectl -n default exec "$new_pod" -c nginx -- cat /usr/share/nginx/html/index.html) == "$marker" ]]
[[ $(curl --fail --silent --show-error --max-time 10 "http://$service_ip/") == "$marker" ]]

state_update '.completed=true'
echo "full InSpace K3s/CCM/CSI/Karpenter E2E passed; cleanup will now run"

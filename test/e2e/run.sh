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
touch "$known_hosts"
chmod 600 "$known_hosts"

api_base=${INSPACE_API_URL%/}/v1/$INSPACE_LOCATION
api_get() {
  curl --fail --silent --show-error --max-time 60 -H "apikey: $INSPACE_API_TOKEN" "$api_base/$1"
}
api_delete_json() {
  curl --fail --silent --show-error --max-time 300 -X DELETE -H "apikey: $INSPACE_API_TOKEN" -H 'Content-Type: application/json' "$api_base/$1" >/dev/null
}
api_post_json() {
  curl --fail --silent --show-error --max-time 300 -X POST -H "apikey: $INSPACE_API_TOKEN" -H 'Content-Type: application/json' "$api_base/$1" >/dev/null
}
api_delete_vm() {
  curl --fail --silent --show-error --max-time 300 -X DELETE -H "apikey: $INSPACE_API_TOKEN" \
    -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uuid=$1" "$api_base/user-resource/vm" >/dev/null
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
    managementCIDR:$managementCIDR,version:$version,workerFloatingIPNames:[]}' >"$state_file"

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

kubectl_available() {
  kubectl --request-timeout=10s get --raw=/readyz >/dev/null 2>&1
}

e2e_pods_absent() {
  local pods
  pods=$(kubectl -n default get pods -l 'app in (inspace-e2e-web,inspace-e2e-trigger)' -o json 2>/dev/null) || return 1
  jq -e '.items | length == 0' >/dev/null <<<"$pods"
}

pv_and_attachments_absent() {
  local pv attachments
  pv=$(jq -r '.pvName // ""' "$state_file")
  [[ -n $pv ]] || return 0
  if kubectl get pv "$pv" >/dev/null 2>&1; then
    return 1
  fi
  attachments=$(kubectl get volumeattachments -o json 2>/dev/null) || return 1
  jq -e --arg pv "$pv" 'all(.items[]; .spec.source.persistentVolumeName != $pv)' >/dev/null <<<"$attachments"
}

owned_nodeclaims_absent() {
  local claims
  claims=$(kubectl get nodeclaims -l "karpenter.sh/nodepool=$nodepool_name" -o json 2>/dev/null) || return 1
  jq -e '.items | length == 0' >/dev/null <<<"$claims"
}

# Quiesce every Kubernetes owner before removing controllers or falling back
# to raw cloud cleanup. This prevents CSI detach/delete and Karpenter deletion
# from racing mounted pods or recreating resources after the audit.
kubernetes_e2e_quiesce() {
  local discovered_pv
  kubectl -n default delete service inspace-e2e-web --ignore-not-found --wait=true --timeout=10m >/dev/null || return 1
  kubectl -n default delete deployment inspace-e2e-web inspace-e2e-trigger --ignore-not-found --wait=true --timeout=10m >/dev/null || return 1
  wait_until 300 "E2E workload pods to terminate" e2e_pods_absent || return 1
  if kubectl -n default get pvc inspace-e2e-rwo >/dev/null 2>&1; then
    discovered_pv=$(kubectl -n default get pvc inspace-e2e-rwo -o jsonpath='{.spec.volumeName}') || return 1
    if [[ -n $discovered_pv ]]; then
      state_update '.pvName=$pv' --arg pv "$discovered_pv" || return 1
    fi
  fi
  kubectl -n default delete pvc inspace-e2e-rwo --ignore-not-found --wait=true --timeout=10m >/dev/null || return 1
  wait_until 600 "E2E PV and VolumeAttachment deletion" pv_and_attachments_absent || return 1

  if kubectl get crd nodepools.karpenter.sh >/dev/null 2>&1; then
    kubectl delete nodepool "$nodepool_name" --ignore-not-found --wait=true --timeout=15m >/dev/null || return 1
    wait_until 600 "owned Karpenter NodeClaims to terminate" owned_nodeclaims_absent || return 1
  fi
  if kubectl get crd inspacenodeclasses.karpenter.inspace.cloud >/dev/null 2>&1; then
    kubectl delete inspacenodeclass "$nodeclass_name" --ignore-not-found --wait=true --timeout=5m >/dev/null || return 1
  fi
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

cleanup_service_resources() {
  local lb_name lb_uuid lb_json load_balancers ip_name ip_address assigned assigned_type ip_addresses
  lb_name=$(jq -r '.serviceLoadBalancerName // ""' "$state_file")
  ip_name=$(jq -r '.serviceFloatingIPName // ""' "$state_file")
  [[ -n $lb_name ]] || return 0
  load_balancers=$(api_get network/load_balancers) || return 1
  lb_json=$(jq -c --arg name "$lb_name" '
    [.[] | select(.display_name==$name and ((.is_deleted // false) | not))] |
    if length == 0 then empty elif length == 1 then .[0] else error("duplicate Service load balancer name") end' <<<"$load_balancers") || return 1
  lb_uuid=""
  if [[ -n $lb_json ]]; then
    lb_uuid=$(jq -r '.uuid // ""' <<<"$lb_json")
    if ! jq -e --arg network "$INSPACE_NETWORK_UUID" --arg billing "$INSPACE_BILLING_ACCOUNT_ID" '
        .network_uuid == $network and
        ((.billing_account_id // 0) == 0 or ((.billing_account_id | tostring) == $billing))' >/dev/null <<<"$lb_json"; then
      echo "refusing Service load balancer outside the E2E network or billing account" >&2
      return 1
    fi
  fi
  if [[ -n $ip_name ]]; then
    local ip_json
    ip_addresses=$(api_get network/ip_addresses) || return 1
    ip_json=$(jq -c --arg name "$ip_name" '
      [.[] | select(.name==$name and ((.is_deleted // false) | not))] |
      if length == 0 then empty elif length == 1 then .[0] else error("duplicate Service floating IP name") end' <<<"$ip_addresses") || return 1
    if [[ -n $ip_json ]]; then
      ip_address=$(jq -r '.address' <<<"$ip_json")
      assigned=$(jq -r '.assigned_to // ""' <<<"$ip_json")
      assigned_type=$(jq -r '.assigned_to_resource_type // ""' <<<"$ip_json")
      if [[ -n $assigned ]]; then
        [[ -n $lb_uuid && $assigned == "$lb_uuid" && $assigned_type == load_balancer ]] || {
          echo "refusing unexpected Service FIP assignment" >&2
          return 1
        }
        api_post_json "network/ip_addresses/$ip_address/unassign" || return 1
      fi
      api_delete_json "network/ip_addresses/$ip_address" || true
    fi
  fi
  [[ -z $lb_uuid ]] || api_delete_json "network/load_balancers/$lb_uuid" || true
}

cleanup_disk_resource() {
  local disk_uuid disk_name disks disk_json disk_details attachment_vms bad_attachments remaining
  disk_uuid=$(jq -r '.diskUUID // ""' "$state_file")
  disk_name=$(jq -r '.pvcDiskName // ""' "$state_file")
  disks=$(api_get storage/disks) || return 1
  if [[ -z $disk_uuid && -n $disk_name ]]; then
    disk_uuid=$(jq -r --arg name "$disk_name" '[.[] | select(.display_name==$name)] | if length==1 then .[0].uuid else "" end' <<<"$disks")
  fi
  [[ -n $disk_uuid ]] || return 0
  [[ $disk_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || {
    echo "refusing invalid CSI disk UUID from state" >&2
    return 1
  }
  disk_json=$(jq -c --arg uuid "$disk_uuid" '[.[] | select(.uuid==$uuid)] | if length==1 then .[0] else empty end' <<<"$disks")
  [[ -n $disk_json ]] || return 0
  if [[ -z $disk_name || $(jq -r '.display_name // ""' <<<"$disk_json") != "$disk_name" ]]; then
    echo "refusing CSI disk whose UUID/name ownership does not match the E2E state" >&2
    return 1
  fi
  disk_details=$(api_get "storage/disks/$disk_uuid") || return 1
  if [[ $(jq -r '(.snapshots // []) | length' <<<"$disk_details") != 0 ]]; then
    echo "refusing to delete E2E disk while snapshots exist" >&2
    return 1
  fi

  attachment_vms=$(api_get user-resource/vm/list) || return 1
  bad_attachments=$(jq --arg disk "$disk_uuid" --arg cluster "$cluster_name" --arg prefix "$nodepool_name-" '
    [.[] | select(any(.storage[]?; .uuid==$disk)) | . as $vm |
      (((.description // "{}") | fromjson?) // {}) as $record |
      select($record.schema != "karpenter.inspace.cloud/v1" or $record.cluster != $cluster or
             $record.nodeClaim != $vm.name or (($vm.name // "") | startswith($prefix) | not))] | length' <<<"$attachment_vms")
  if [[ $bad_attachments != 0 ]]; then
    echo "refusing to detach the E2E disk from a VM without exact Karpenter ownership" >&2
    return 1
  fi

  local vm_uuid
  while IFS= read -r vm_uuid; do
    [[ -n $vm_uuid ]] || continue
    api_detach_disk "$vm_uuid" "$disk_uuid" || true
  done < <(jq -r --arg disk "$disk_uuid" '.[] | select(any(.storage[]?; .uuid==$disk)) | .uuid' <<<"$attachment_vms")
  for _ in $(seq 1 30); do
    remaining=$(api_get user-resource/vm/list | jq --arg disk "$disk_uuid" '[.[] | select(any(.storage[]?; .uuid==$disk))] | length') || return 1
    [[ $remaining == 0 ]] && break
    sleep 10
  done
  [[ ${remaining:-1} == 0 ]] || { echo "E2E disk did not detach; refusing raw delete" >&2; return 1; }
  api_delete_json "storage/disks/$disk_uuid"
}

cleanup_worker_resources() {
  local all_vms all_ips matching workers invalid_workers
  all_vms=$(api_get user-resource/vm/list) || return 1
  matching=$(jq -c --arg cluster "$cluster_name" '[.[] | . as $vm | ((((.description // "{}") | fromjson?) // {})) as $record | select($record.cluster==$cluster) | {vm:$vm,record:$record}]' <<<"$all_vms")
  invalid_workers=$(jq --arg prefix "$nodepool_name-" '[.[] | select(
    .record.schema != "karpenter.inspace.cloud/v1" or .record.nodeClaim != .vm.name or
    ((.vm.name // "") | startswith($prefix) | not) or
    ((.record.floatingIPName // "") | startswith($prefix) | not))] | length' <<<"$matching")
  if [[ $invalid_workers != 0 ]]; then
    echo "refusing raw worker cleanup because cloud ownership metadata is incomplete or mismatched" >&2
    return 1
  fi
  workers=$(jq -c '[.[] | {uuid:.vm.uuid,name:.vm.name,fip:.record.floatingIPName}]' <<<"$matching")
  while IFS=$'\t' read -r uuid name fip_name; do
    [[ -n $uuid ]] || continue
    local fip_json address assigned assigned_type
    all_ips=$(api_get network/ip_addresses) || return 1
    fip_json=$(jq -c --arg name "$fip_name" '
      [.[] | select(.name==$name and ((.is_deleted // false) | not))] |
      if length == 0 then empty elif length == 1 then .[0] else error("duplicate worker floating IP name") end' <<<"$all_ips") || return 1
    if [[ -n $fip_json ]]; then
      address=$(jq -r '.address' <<<"$fip_json")
      assigned=$(jq -r '.assigned_to // ""' <<<"$fip_json")
      assigned_type=$(jq -r '.assigned_to_resource_type // ""' <<<"$fip_json")
      if [[ -n $assigned && ($assigned != "$uuid" || $assigned_type != virtual_machine) ]]; then
        echo "refusing unexpected worker FIP assignment for $name" >&2
        return 1
      fi
      [[ -z $assigned ]] || api_post_json "network/ip_addresses/$address/unassign" || return 1
      api_delete_json "network/ip_addresses/$address" || true
    fi
    api_delete_vm "$uuid" || true
  done < <(jq -r '.[] | [.uuid,.name,.fip] | @tsv' <<<"$workers")

  # Clean a late unassigned FIP whose deterministic worker VM never became visible.
  all_ips=$(api_get network/ip_addresses) || return 1
  while IFS=$'\t' read -r address assigned; do
    [[ -n $address ]] || continue
    if [[ -n $assigned ]]; then
      echo "refusing assigned orphan worker FIP $address" >&2
      return 1
    fi
    api_delete_json "network/ip_addresses/$address" || true
  done < <(jq -r --arg prefix "$nodepool_name-" '.[] | select((.name // "") | startswith($prefix)) | [.address,(.assigned_to // "")] | @tsv' <<<"$all_ips")
}

destroy_control_plane() {
  [[ -x $controller_bin && -f $cluster_file ]] || return 0
  local output
  for _ in $(seq 1 90); do
    if ! output=$($controller_bin --cluster-config "$cluster_file" --delete --once --output=json 2>>"$state_dir/destroy.log"); then
      sleep 10
      continue
    fi
    printf '%s\n' "$output" >>"$state_dir/destroy-results.jsonl"
    if jq -e '.done == true' >/dev/null <<<"$output"; then
      return 0
    fi
    sleep 10
  done
  echo "control-plane teardown did not converge" >&2
  return 1
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  if [[ ${INSPACE_E2E_KEEP_RESOURCES:-false} == true ]]; then
    echo "E2E resources retained by explicit INSPACE_E2E_KEEP_RESOURCES=true; state: $state_dir" >&2
    exit "$original_status"
  fi
  set +e
  local cleanup_status=0
  local raw_cleanup_allowed=true
  if [[ -s $kubeconfig ]] && kubectl_available; then
    if ! kubernetes_e2e_quiesce; then
      echo "Kubernetes E2E owners did not quiesce; refusing concurrent raw cloud cleanup" >&2
      cleanup_status=1
      raw_cleanup_allowed=false
    else
      if helm status inspace -n kube-system >/dev/null 2>&1; then
        helm uninstall inspace -n kube-system --wait --timeout 5m >/dev/null 2>&1 || cleanup_status=1
      fi
      if helm status inspace-crds -n kube-system >/dev/null 2>&1; then
        helm uninstall inspace-crds -n kube-system --wait --timeout 5m >/dev/null 2>&1 || cleanup_status=1
      fi
      kubectl -n kube-system delete secret inspace-cloud-credentials inspace-k3s-agent-token --ignore-not-found --wait=false >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if [[ $raw_cleanup_allowed == true ]]; then
    cleanup_service_resources || cleanup_status=1
    cleanup_disk_resource || cleanup_status=1
    cleanup_worker_resources || cleanup_status=1
    destroy_control_plane || cleanup_status=1
  fi
  local audit
  audit=$(owned_audit_json 2>"$state_dir/final-audit.err") || cleanup_status=1
  [[ -n ${audit:-} ]] && printf '%s\n' "$audit" | tee "$state_dir/final-audit.json"
  if [[ -n ${audit:-} && $(jq -r '.count' <<<"$audit") != 0 ]]; then
    cleanup_status=1
  fi
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
(cd modules/cloud-provider-inspace && GOWORK=off go build -trimpath -o "$controller_bin" ./cmd/inspace-cluster-controller)

baseline=$(owned_audit_json)
if [[ $(jq -r '.count' <<<"$baseline") != 0 ]]; then
  printf '%s\n' "$baseline" >&2
  echo "refusing to adopt pre-existing resources for this E2E identity" >&2
  exit 1
fi

echo "==> provision exactly three control-plane VMs"
$controller_bin --cluster-config "$cluster_file" --ssh-public-key-file "$ssh_public_key" --ssh-username "$ssh_user" \
  --management-cidr "$management_cidr" --management-tcp-ports 22,6443,30080 \
  --until-ready --interval 15s --output=json | tee "$state_dir/reconcile-results.jsonl"
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
while IFS= read -r ip; do
  wait_until 900 "SSH on $ip" ssh_ready "$ip"
  ssh -n "${ssh_options[@]}" "$ssh_user@$ip" \
    "sudo cloud-init status --wait >/dev/null && sudo systemctl is-active --quiet k3s && sudo k3s kubectl get --raw='/readyz?verbose' | grep -F '[+]etcd ok'" >/dev/null
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
  additionalUserData: |
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

workers=$(api_get user-resource/vm/list | jq -c --arg cluster "$cluster_name" '[.[] | . as $vm | ((((.description // "{}") | fromjson?) // {})) as $owner | select($owner.cluster==$cluster) | {uuid:$vm.uuid,name:$vm.name,fip:$owner.floatingIPName}]')
jq -e 'length == 1' >/dev/null <<<"$workers"
worker_fip_names=$(jq '[.[].fip]' <<<"$workers")
state_update '.workerVMs=$workers | .workerFloatingIPNames=$fips | .workerNode=$node' --argjson workers "$workers" --argjson fips "$worker_fip_names" --arg node "$worker_node"
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
kubectl apply -f "$state_dir/workload.yaml"
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

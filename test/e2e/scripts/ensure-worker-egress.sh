#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: ensure-worker-egress.sh --kubeconfig PATH --nodepool NAME --probe-template PATH --result PATH
EOF
  exit 2
}

kubeconfig=
nodepool=
probe_template=
result_file=
while (($#)); do
  case "$1" in
    --kubeconfig) kubeconfig=${2:-}; shift 2 ;;
    --nodepool) nodepool=${2:-}; shift 2 ;;
    --probe-template) probe_template=${2:-}; shift 2 ;;
    --result) result_file=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$kubeconfig" && -n "$nodepool" && -n "$probe_template" && -n "$result_file" ]] || usage
[[ -r "$kubeconfig" && -r "$probe_template" ]] || {
  echo "kubeconfig and probe template must be readable" >&2
  exit 1
}

readonly max_attempts=3
readonly schedule_timeout=20m
readonly pull_timeout=5m
readonly identity_timeout_seconds=600
readonly cleanup_timeout_seconds=1200
readonly candidate_cpu=2
readonly candidate_memory_gi=4
readonly overlap_cpu=$((max_attempts * candidate_cpu))
readonly overlap_memory_gi=$((max_attempts * candidate_memory_gi))
readonly probe_label='inspace.cloud/e2e-egress-gate=true'
readonly public_ip_annotation='karpenter.inspace.cloud/public-ipv4'
readonly floating_ip_annotation='karpenter.inspace.cloud/floating-ip-name'
readonly billing_annotation='karpenter.inspace.cloud/billing-account-id'

kubectl_cluster=(kubectl --kubeconfig "$kubeconfig")
kubectl_default=("${kubectl_cluster[@]}" -n default)
temporary_dir=$(mktemp -d)
cleanup() {
  rm -rf "$temporary_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077

log() {
  printf '[worker-egress] %s\n' "$*" >&2
}

pod_diagnostics() {
  local pod=$1
  "${kubectl_default[@]}" get pod "$pod" -o json 2>/dev/null | jq -r '
    [(.status.initContainerStatuses[]?), (.status.containerStatuses[]?)][]? |
    [ .name,
      (.state.waiting.reason // .state.terminated.reason // ""),
      (.state.waiting.message // .state.terminated.message // "") ] | @tsv' || true
  "${kubectl_default[@]}" get events -o json \
    --field-selector "involvedObject.kind=Pod,involvedObject.name=$pod" 2>/dev/null | jq -r '
      .items[]? | [.reason, .message] | @tsv' || true
}

wait_for_identity() {
  local node=$1 deadline node_json claims match
  deadline=$(( $(date +%s) + identity_timeout_seconds ))
  while (( $(date +%s) < deadline )); do
    node_json=$("${kubectl_cluster[@]}" get node "$node" -o json 2>/dev/null || true)
    claims=$("${kubectl_cluster[@]}" get nodeclaims \
      -l "karpenter.sh/nodepool=$nodepool" -o json 2>/dev/null || true)
    if [[ -n "$node_json" && -n "$claims" ]]; then
      match=$(jq -c --arg node "$node" '[.items[] | select(.status.nodeName == $node)]' <<<"$claims")
      if jq -e 'length == 1 and
          any(.[0].status.conditions[]?; .type == "Ready" and .status == "True") and
          (.[0].metadata.annotations["karpenter.inspace.cloud/public-ipv4"] // "" | length) > 0 and
          (.[0].metadata.annotations["karpenter.inspace.cloud/floating-ip-name"] // "" | length) > 0 and
          (.[0].metadata.annotations["karpenter.inspace.cloud/billing-account-id"] // "" | test("^[1-9][0-9]*$"))' \
          <<<"$match" >/dev/null &&
        jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' \
          <<<"$node_json" >/dev/null; then
        jq -cn --argjson node "$node_json" --argjson claim "$(jq '.[0]' <<<"$match")" \
          '{node:$node,claim:$claim}'
        return 0
      fi
    fi
    sleep 5
  done
  log "node $node did not converge to one Ready NodeClaim with durable FIP identity"
  return 1
}

assert_identity() {
  local identity=$1 expected_node=${2:-} node claim node_name claim_name public_ip
  node=$(jq -c '.node' <<<"$identity") || return 1
  claim=$(jq -c '.claim' <<<"$identity") || return 1
  node_name=$(jq -er '.metadata.name' <<<"$node") || return 1
  claim_name=$(jq -er '.metadata.name' <<<"$claim") || return 1
  public_ip=$(jq -er --arg key "$public_ip_annotation" '.metadata.annotations[$key]' <<<"$claim") || return 1
  [[ -z "$expected_node" || "$node_name" == "$expected_node" ]] || return 1
  jq -e --arg node "$node_name" '.status.nodeName == $node' <<<"$claim" >/dev/null || return 1
  jq -e --arg ip "$public_ip" '[.status.addresses[]? | select(.type == "ExternalIP") | .address] == [$ip]' \
    <<<"$node" >/dev/null || return 1
  jq -e --arg floating "$floating_ip_annotation" --arg billing "$billing_annotation" '
    (.metadata.annotations[$floating] | length) > 0 and
    (.metadata.annotations[$billing] | test("^[1-9][0-9]*$"))' <<<"$claim" >/dev/null || return 1
  printf '%s\t%s\t%s\n' "$node_name" "$claim_name" "$public_ip"
}

reprove_rejected() {
  local index claim node expected_ip actual_ip identity
  for ((index = 0; index < rejected_count; index++)); do
    claim=${rejected_claims[$index]}
    node=${rejected_nodes[$index]}
    expected_ip=${rejected_ips[$index]}
    actual_ip=$("${kubectl_cluster[@]}" get nodeclaim "$claim" -o json | jq -er \
      --arg key "$public_ip_annotation" '.metadata.annotations[$key]')
    [[ "$actual_ip" == "$expected_ip" ]]
    identity=$(wait_for_identity "$node")
    [[ "$(assert_identity "$identity" "$node" | cut -f3)" == "$expected_ip" ]]
  done
}

nodepool_json=$("${kubectl_cluster[@]}" get nodepool "$nodepool" -o json)
original_cpu=$(jq -er '.spec.limits.cpu | select(test("^[1-9][0-9]*$"))' <<<"$nodepool_json")
original_memory=$(jq -er '.spec.limits.memory | select(test("^[1-9][0-9]*Gi$"))' <<<"$nodepool_json")
original_memory_gi=${original_memory%Gi}
((original_cpu >= candidate_cpu && original_memory_gi >= candidate_memory_gi))
surge_cpu=$((original_cpu > overlap_cpu ? original_cpu : overlap_cpu))
surge_memory_gi=$((original_memory_gi > overlap_memory_gi ? original_memory_gi : overlap_memory_gi))
surge_memory="${surge_memory_gi}Gi"
readonly original_cpu original_memory original_memory_gi surge_cpu surge_memory_gi surge_memory
[[ $("${kubectl_cluster[@]}" get nodes -l "karpenter.sh/nodepool=$nodepool" -o json | jq '.items | length') -eq 1 ]]
[[ $("${kubectl_cluster[@]}" get nodeclaims -l "karpenter.sh/nodepool=$nodepool" -o json | jq '.items | length') -eq 1 ]]
[[ $("${kubectl_default[@]}" get pods -l "$probe_label" -o json | jq '.items | length') -eq 0 ]] || {
  log "refusing to mutate a resumed gate with existing probe pods"
  exit 1
}

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_epoch=$(date +%s)
surged=false
winner_node=
winner_claim=
winner_ip=
rejected_nodes=()
rejected_claims=()
rejected_ips=()
rejected_pods=()
rejected_count=0

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  probe="inspace-e2e-egress-probe-$attempt"
  rendered="$temporary_dir/$probe.yaml"
  sed "s/name: inspace-e2e-egress-probe-attempt/name: $probe/" "$probe_template" >"$rendered"
  log "attempt $attempt/$max_attempts: scheduling direct Docker Hub and GHCR probe"
  "${kubectl_default[@]}" create -f "$rendered" >/dev/null

  if ! "${kubectl_default[@]}" wait --for=condition=PodScheduled "pod/$probe" \
    --timeout="$schedule_timeout" >/dev/null; then
    log "probe $probe never scheduled; this is a provisioning failure, not an FIP timeout"
    pod_diagnostics "$probe" >&2
    exit 1
  fi
  node=$("${kubectl_default[@]}" get pod "$probe" -o jsonpath='{.spec.nodeName}')
  [[ -n "$node" ]]
  identity=$(wait_for_identity "$node")
  identity_fields=$(assert_identity "$identity" "$node")
  claim=$(cut -f2 <<<"$identity_fields")
  public_ip=$(cut -f3 <<<"$identity_fields")

  for ((index = 0; index < rejected_count; index++)); do
    [[ "$public_ip" != "${rejected_ips[$index]}" ]] || {
      log "candidate $node reused retained rejected FIP $public_ip"
      exit 1
    }
  done
  reprove_rejected
  log "candidate node=$node nodeclaim=$claim fip=$public_ip; all prior rejected FIPs remain retained"

  if "${kubectl_default[@]}" wait --for=condition=Ready "pod/$probe" \
    --timeout="$pull_timeout" >/dev/null; then
    winner_node=$node
    winner_claim=$claim
    winner_ip=$public_ip
    log "candidate $node passed direct Docker Hub and GHCR blob pulls"
    break
  fi

  diagnostics=$(pod_diagnostics "$probe")
  printf '%s\n' "$diagnostics" >&2
  if grep -Eiq 'unauthorized|authentication required|denied|not found|manifest unknown|pull access denied|no match for platform|too many requests|429' <<<"$diagnostics"; then
    log "probe failed with a non-network registry error; refusing pointless FIP rotation"
    exit 1
  fi
  if ! grep -Eiq 'i/o timeout|tls handshake timeout|client\.timeout exceeded|context deadline exceeded|connection timed out|dial tcp[^[:cntrl:]]*timeout|network is unreachable|no route to host' <<<"$diagnostics"; then
    log "probe did not expose a recognized timeout signature; refusing speculative FIP rotation"
    exit 1
  fi

  "${kubectl_cluster[@]}" label node "$node" \
    node.kubernetes.io/exclude-from-external-load-balancers=true --overwrite >/dev/null
  "${kubectl_cluster[@]}" cordon "$node" >/dev/null
  rejected_nodes+=("$node")
  rejected_claims+=("$claim")
  rejected_ips+=("$public_ip")
  rejected_pods+=("$probe")
  rejected_count=$((rejected_count + 1))
  log "retaining timed-out node=$node nodeclaim=$claim fip=$public_ip while a replacement is allocated"

  if ((attempt < max_attempts)) && [[ "$surged" == false ]] &&
     [[ "$surge_cpu" != "$original_cpu" || "$surge_memory" != "$original_memory" ]]; then
    "${kubectl_cluster[@]}" patch nodepool "$nodepool" --type=merge -p \
      "{\"spec\":{\"limits\":{\"cpu\":\"$surge_cpu\",\"memory\":\"$surge_memory\"}}}" >/dev/null
    "${kubectl_cluster[@]}" get nodepool "$nodepool" -o json | jq -e \
      --arg cpu "$surge_cpu" --arg memory "$surge_memory" \
      '.spec.limits.cpu == $cpu and .spec.limits.memory == $memory' >/dev/null
    surged=true
    log "temporarily expanded NodePool to cpu=$surge_cpu memory=$surge_memory for bounded overlap"
  fi
done

[[ -n "$winner_node" ]] || {
  log "all $max_attempts FIPs timed out; retaining every rejected VM/FIP for explicit debugging or destroy"
  exit 1
}

"${kubectl_cluster[@]}" uncordon "$winner_node" >/dev/null
"${kubectl_cluster[@]}" label node "$winner_node" \
  node.kubernetes.io/exclude-from-external-load-balancers- >/dev/null 2>&1 || true

# The passing probe holds the winner while the normal capacity trigger is
# detached from a rejected incumbent and every old provider finalizer runs.
"${kubectl_default[@]}" scale deployment/inspace-e2e-trigger --replicas 0 >/dev/null
"${kubectl_default[@]}" rollout status deployment/inspace-e2e-trigger --timeout=5m >/dev/null
reprove_rejected
winner_identity=$(wait_for_identity "$winner_node")
[[ "$(assert_identity "$winner_identity" "$winner_node" | cut -f3)" == "$winner_ip" ]]

for ((index = 0; index < rejected_count; index++)); do
  "${kubectl_default[@]}" delete pod "${rejected_pods[$index]}" \
    --ignore-not-found --wait=true --timeout=2m >/dev/null
done
for ((index = 0; index < rejected_count; index++)); do
  "${kubectl_cluster[@]}" delete nodeclaim "${rejected_claims[$index]}" \
    --ignore-not-found --wait=false >/dev/null
done

deadline=$(( $(date +%s) + cleanup_timeout_seconds ))
while ((rejected_count > 0 && $(date +%s) < deadline)); do
  remaining=0
  for ((index = 0; index < rejected_count; index++)); do
    if "${kubectl_cluster[@]}" get nodeclaim "${rejected_claims[$index]}" >/dev/null 2>&1 ||
       "${kubectl_cluster[@]}" get node "${rejected_nodes[$index]}" >/dev/null 2>&1; then
      remaining=$((remaining + 1))
    fi
  done
  ((remaining == 0)) && break
  sleep 5
done
for ((index = 0; index < rejected_count; index++)); do
  ! "${kubectl_cluster[@]}" get nodeclaim "${rejected_claims[$index]}" >/dev/null 2>&1
  ! "${kubectl_cluster[@]}" get node "${rejected_nodes[$index]}" >/dev/null 2>&1
done
log "all rejected NodeClaims converged absent after provider FIP cleanup"

"${kubectl_default[@]}" scale deployment/inspace-e2e-trigger --replicas 1 >/dev/null
"${kubectl_default[@]}" rollout status deployment/inspace-e2e-trigger --timeout=10m >/dev/null
trigger_node=$("${kubectl_default[@]}" get pods -l app=inspace-e2e-trigger -o json | jq -er '
  if (.items | length) == 1 and
     any(.items[0].status.conditions[]?; .type == "Ready" and .status == "True")
  then .items[0].spec.nodeName else error("capacity trigger did not converge to one Ready pod") end')
[[ "$trigger_node" == "$winner_node" ]]
"${kubectl_default[@]}" delete pod -l "$probe_label" --ignore-not-found --wait=true --timeout=2m >/dev/null

if [[ "$surged" == true ]]; then
  "${kubectl_cluster[@]}" patch nodepool "$nodepool" --type=merge -p \
    "{\"spec\":{\"limits\":{\"cpu\":\"$original_cpu\",\"memory\":\"$original_memory\"}}}" >/dev/null
fi
"${kubectl_cluster[@]}" get nodepool "$nodepool" -o json | jq -e \
  --arg cpu "$original_cpu" --arg memory "$original_memory" \
  '.spec.limits.cpu == $cpu and .spec.limits.memory == $memory' >/dev/null
"${kubectl_cluster[@]}" get nodeclaims -l "karpenter.sh/nodepool=$nodepool" -o json | jq -e \
  --arg claim "$winner_claim" '.items | length == 1 and .[0].metadata.name == $claim and
    any(.[0].status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null
"${kubectl_cluster[@]}" get nodes -l "karpenter.sh/nodepool=$nodepool" -o json | jq -e \
  --arg node "$winner_node" '.items | length == 1 and .[0].metadata.name == $node and
    any(.[0].status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null

rejected_json='[]'
for ((index = 0; index < rejected_count; index++)); do
  rejected_json=$(jq -c --arg node "${rejected_nodes[$index]}" \
    --arg claim "${rejected_claims[$index]}" --arg ip "${rejected_ips[$index]}" \
    '. + [{node:$node,nodeClaim:$claim,publicIPv4:$ip}]' <<<"$rejected_json")
done
result_tmp=$(mktemp "${result_file}.tmp.XXXXXX")
jq -n --arg startedAt "$started_at" --argjson elapsedSeconds "$(( $(date +%s) - started_epoch ))" \
  --argjson attempts "$((rejected_count + 1))" --arg node "$winner_node" \
  --arg claim "$winner_claim" --arg ip "$winner_ip" --argjson rejected "$rejected_json" \
  '{startedAt:$startedAt,elapsedSeconds:$elapsedSeconds,attempts:$attempts,
    winner:{node:$node,nodeClaim:$claim,publicIPv4:$ip},rejected:$rejected}' >"$result_tmp"
chmod 0600 "$result_tmp"
mv "$result_tmp" "$result_file"
cat "$result_file"

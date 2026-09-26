#!/usr/bin/env bash
# Prove every Cilium agent runs the current kube-system/cilium-config.
#
# Cilium reflects cilium-config into its DynamicConfig table, and its drift
# checker publishes cilium_drift_checker_config_delta: the number of ConfigMap
# keys whose value differs from the settings the running agent started with.
# A non-zero value means a setting changed without an agent restart. The gauge
# is read with `cilium-dbg metrics list`, so no Prometheus endpoint is needed.
# The deploy and E2E copies of this script are kept byte-identical.
set -euo pipefail

namespace=kube-system

fail() {
  printf 'cilium config drift: %s\n' "$*" >&2
  exit 1
}

config=$(kubectl -n "$namespace" get configmap cilium-config -o json) ||
  fail "cannot read ConfigMap $namespace/cilium-config"
# A disabled checker never updates the gauge, so its zero would prove nothing.
jq -e '.data["enable-dynamic-config"] == "true" and .data["enable-drift-checker"] == "true"' \
  <<<"$config" >/dev/null ||
  fail "cilium-config must set enable-dynamic-config and enable-drift-checker to \"true\""
daemonset=$(kubectl -n "$namespace" get daemonset cilium -o json) ||
  fail "cannot read DaemonSet $namespace/cilium"
pods=$(kubectl -n "$namespace" get pods -l k8s-app=cilium -o json) ||
  fail "cannot list Cilium agent pods"
jq -e --argjson daemonset "$daemonset" '
  ($daemonset.status.desiredNumberScheduled // -1) as $desired |
  $desired > 0 and
  ($daemonset.status.updatedNumberScheduled // -1) == $desired and
  ($daemonset.status.numberReady // -1) == $desired and
  (.items | length) == $desired and
  all(.items[]; .status.phase == "Running" and .metadata.deletionTimestamp == null)' \
  <<<"$pods" >/dev/null ||
  fail "DaemonSet $namespace/cilium is not fully rolled out with one Running agent per scheduled node"

drifted=0
while IFS=$'\t' read -r pod node; do
  metrics=$(timeout --kill-after=5s 60s kubectl -n "$namespace" exec "$pod" -c cilium-agent -- \
    cilium-dbg metrics list -p drift_checker_config_delta -o json) ||
    fail "cannot read metrics from Cilium agent $pod on node $node"
  delta=$(jq -er '
    [.[] | select(.name == "cilium_drift_checker_config_delta") | .value] |
    if length == 1 and (.[0] | type) == "number" then .[0] else error("absent") end' \
    <<<"$metrics" 2>/dev/null) ||
    fail "Cilium agent $pod on node $node does not publish cilium_drift_checker_config_delta"
  if jq -en --argjson delta "$delta" '$delta == 0' >/dev/null; then
    printf 'Cilium agent %s on node %s runs the current cilium-config\n' "$pod" "$node"
  else
    printf 'cilium config drift: agent %s on node %s has %s cilium-config key(s) that differ from its running settings\n' \
      "$pod" "$node" "$delta" >&2
    drifted=1
  fi
done < <(jq -r '.items[] | [.metadata.name, .spec.nodeName] | @tsv' <<<"$pods")

if [ "$drifted" -ne 0 ]; then
  fail "review the pending cilium-config change (each agent logs the keys as \"Mismatch found\" or \"No local entry found\"), then restart the agents, for example: kubectl -n $namespace rollout restart daemonset/cilium"
fi

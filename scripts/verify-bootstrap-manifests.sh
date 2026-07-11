#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
chart=$workspace/charts/inspace-cloud-kube-modules
values=$chart/ci/test-values.yaml
standalone_ccm=$workspace/modules/cloud-provider/config/ccm/cloud-controller-manager.yaml
standalone_csi=$workspace/modules/csi-driver/deploy/kubernetes/controller.yaml
standalone_karpenter=$workspace/modules/karpenter-provider/config/controller/controller.yaml
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

require_toleration() {
  awk '
    function finish_item() {
      if (key && operator && effect) {
        valid = 1
      }
      key = operator = effect = 0
    }
    /^[[:space:]]*-[[:space:]]/ { finish_item() }
    index($0, "key: node.cloudprovider.kubernetes.io/uninitialized") { key = 1 }
    index($0, "operator: Exists") { operator = 1 }
    index($0, "effect: NoSchedule") { effect = 1 }
    END {
      finish_item()
      exit !valid
    }
  ' "$1"
}

helm template bootstrap "$chart" --namespace inspace-system --values "$values" \
  --show-only templates/ccm-rbac.yaml >"$tmpdir/ccm-rbac.yaml"
grep -Fx 'kind: RoleBinding' "$tmpdir/ccm-rbac.yaml" >/dev/null
test "$(grep -Fc '  namespace: kube-system' "$tmpdir/ccm-rbac.yaml")" -eq 1
test "$(grep -Fc '    namespace: inspace-system' "$tmpdir/ccm-rbac.yaml")" -eq 2
grep -Fx '  kind: Role' "$tmpdir/ccm-rbac.yaml" >/dev/null
grep -Fx '  name: extension-apiserver-authentication-reader' "$tmpdir/ccm-rbac.yaml" >/dev/null
grep -Fx '    verbs: ["get", "list", "watch", "patch", "update", "delete"]' "$tmpdir/ccm-rbac.yaml" >/dev/null
grep -Fx '    resources: ["tokenreviews"]' "$tmpdir/ccm-rbac.yaml" >/dev/null
grep -Fx '    resources: ["subjectaccessreviews"]' "$tmpdir/ccm-rbac.yaml" >/dev/null

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/ccm-deployment.yaml >"$tmpdir/ccm-deployment.yaml"
grep -Fx '      dnsPolicy: Default' "$tmpdir/ccm-deployment.yaml" >/dev/null

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-controller.yaml"
require_toleration "$tmpdir/csi-controller.yaml"
test "$(grep -Fc '        fsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1
test "$(grep -Fc '            runAsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/karpenter-deployment.yaml >"$tmpdir/karpenter.yaml"
require_toleration "$tmpdir/karpenter.yaml"

grep -Fx 'kind: RoleBinding' "$standalone_ccm" >/dev/null
grep -Fx '  name: extension-apiserver-authentication-reader' "$standalone_ccm" >/dev/null
grep -Fx '      dnsPolicy: Default' "$standalone_ccm" >/dev/null
grep -Fx '    verbs: ["get", "list", "watch", "patch", "update", "delete"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["tokenreviews"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["subjectaccessreviews"]' "$standalone_ccm" >/dev/null
require_toleration "$standalone_csi"
require_toleration "$standalone_karpenter"

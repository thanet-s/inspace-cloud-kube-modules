#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
chart=$workspace/charts/inspace-cloud-kube-modules
values=$chart/ci/test-values.yaml
standalone_ccm=$workspace/modules/cloud-provider/config/ccm/cloud-controller-manager.yaml
standalone_csi=$workspace/modules/csi-driver/deploy/kubernetes/controller.yaml
standalone_karpenter=$workspace/modules/karpenter-provider/config/controller/controller.yaml
root_readme=$workspace/README.md
chart_readme=$chart/README.md
chart_notes=$chart/templates/NOTES.txt
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
  --show-only templates/ccm-configmap.yaml >"$tmpdir/ccm-configmap.yaml"
grep -Fx '  controlPlaneVIP: "10.20.30.10"' "$tmpdir/ccm-configmap.yaml" >/dev/null
grep -Fx '  privateLoadBalancerPoolStart: "10.20.30.200"' "$tmpdir/ccm-configmap.yaml" >/dev/null
grep -Fx '  privateLoadBalancerPoolStop: "10.20.30.239"' "$tmpdir/ccm-configmap.yaml" >/dev/null

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/ccm-deployment.yaml >"$tmpdir/ccm-deployment.yaml"
grep -Fx '      dnsPolicy: Default' "$tmpdir/ccm-deployment.yaml" >/dev/null
test "$(grep -Fc '            - name: INSPACE_CONTROL_PLANE_VIP' "$tmpdir/ccm-deployment.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_START' "$tmpdir/ccm-deployment.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP' "$tmpdir/ccm-deployment.yaml")" -eq 1
grep -Fx '                  key: controlPlaneVIP' "$tmpdir/ccm-deployment.yaml" >/dev/null
grep -Fx '                  key: privateLoadBalancerPoolStart' "$tmpdir/ccm-deployment.yaml" >/dev/null
grep -Fx '                  key: privateLoadBalancerPoolStop' "$tmpdir/ccm-deployment.yaml" >/dev/null

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-controller.yaml"
require_toleration "$tmpdir/csi-controller.yaml"
test "$(grep -Fc '        fsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1
test "$(grep -Fc '            runAsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/karpenter-deployment.yaml >"$tmpdir/karpenter.yaml"
require_toleration "$tmpdir/karpenter.yaml"
test "$(grep -Fc '            - name: INSPACE_NETWORK_UUID' "$tmpdir/karpenter.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_CONTROL_PLANE_VIP' "$tmpdir/karpenter.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_START' "$tmpdir/karpenter.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP' "$tmpdir/karpenter.yaml")" -eq 1
grep -Fx '              value: "11111111-1111-4111-8111-111111111111"' "$tmpdir/karpenter.yaml" >/dev/null
grep -Fx '              value: "10.20.30.10"' "$tmpdir/karpenter.yaml" >/dev/null
grep -Fx '              value: "10.20.30.200"' "$tmpdir/karpenter.yaml" >/dev/null
grep -Fx '              value: "10.20.30.239"' "$tmpdir/karpenter.yaml" >/dev/null

if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=10.20.30.240 \
  --set-string global.inspace.privateLoadBalancerPool.stop=10.20.30.200 >/dev/null 2>&1; then
  echo "reversed private load-balancer pool unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=203.0.113.10 >/dev/null 2>&1; then
  echo "public private-load-balancer pool address unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=10.20.30.200 \
  --set-string global.inspace.privateLoadBalancerPool.stop=10.20.30.214 >/dev/null 2>&1; then
  echo "private load-balancer pool smaller than 16 addresses unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=10.20.30.1 \
  --set-string global.inspace.privateLoadBalancerPool.stop=10.20.31.1 >/dev/null 2>&1; then
  echo "private load-balancer pool larger than 256 addresses unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.controlPlaneVIP=10.20.30.210 >/dev/null 2>&1; then
  echo "control-plane VIP inside the private load-balancer pool unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.controlPlaneVIP=10.42.0.10 >/dev/null 2>&1; then
  echo "control-plane VIP inside the pod CIDR unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.controlPlaneVIP=10.43.0.10 >/dev/null 2>&1; then
  echo "control-plane VIP inside the Service CIDR unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=10.41.255.250 \
  --set-string global.inspace.privateLoadBalancerPool.stop=10.42.0.9 >/dev/null 2>&1; then
  echo "private load-balancer pool overlapping the pod CIDR unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.privateLoadBalancerPool.start=10.42.255.250 \
  --set-string global.inspace.privateLoadBalancerPool.stop=10.43.0.9 >/dev/null 2>&1; then
  echo "private load-balancer pool overlapping the Service CIDR unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set ccm.enabled=false --set csi.enabled=false --set karpenter.enabled=true \
  --set-string global.inspace.networkUUID= >/dev/null 2>&1; then
  echo "Karpenter unexpectedly rendered without its controller-wide network UUID" >&2
  exit 1
fi

grep -Fx 'kind: RoleBinding' "$standalone_ccm" >/dev/null
grep -Fx '  name: extension-apiserver-authentication-reader' "$standalone_ccm" >/dev/null
grep -Fx '      dnsPolicy: Default' "$standalone_ccm" >/dev/null
grep -Fx '    verbs: ["get", "list", "watch", "patch", "update", "delete"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["tokenreviews"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["subjectaccessreviews"]' "$standalone_ccm" >/dev/null
require_toleration "$standalone_csi"
require_toleration "$standalone_karpenter"
grep -F '            - name: INSPACE_NETWORK_UUID' "$standalone_karpenter" >/dev/null
grep -F '            - name: INSPACE_CONTROL_PLANE_VIP' "$standalone_karpenter" >/dev/null

for user_document in "$root_readme" "$chart_readme" "$chart_notes" "$workspace/modules/karpenter-provider/README.md"; do
  if grep -F 'hostPoolSelector' "$user_document" >/dev/null; then
    echo "removed hostPoolSelector is still documented in $user_document" >&2
    exit 1
  fi
done

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
egress_example=$chart/examples/egress-gateway-static.yaml
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
  >"$tmpdir/direct-system-images.yaml"
for image in \
  'ghcr.io/thanet-s/inspace-cloud-controller-manager:0.1.0' \
  'ghcr.io/thanet-s/inspace-csi-driver:0.1.0' \
  'ghcr.io/thanet-s/karpenter-provider-inspace:0.1.0' \
  'registry.k8s.io/sig-storage/csi-provisioner:v5.2.0' \
  'registry.k8s.io/sig-storage/csi-attacher:v4.8.1' \
  'registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.13.0' \
  'registry.k8s.io/sig-storage/livenessprobe:v2.15.0'; do
  grep -F "          image: $image" "$tmpdir/direct-system-images.yaml" >/dev/null
done

cache_registry=cache.cluster.inspace.internal:8443
helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --set-string "global.inspace.systemImageRegistry=$cache_registry" \
  >"$tmpdir/cached-system-images.yaml"
for image in \
  "$cache_registry/thanet-s/inspace-cloud-controller-manager:0.1.0" \
  "$cache_registry/thanet-s/inspace-csi-driver:0.1.0" \
  "$cache_registry/thanet-s/karpenter-provider-inspace:0.1.0" \
  "$cache_registry/sig-storage/csi-provisioner:v5.2.0" \
  "$cache_registry/sig-storage/csi-attacher:v4.8.1" \
  "$cache_registry/sig-storage/csi-node-driver-registrar:v2.13.0" \
  "$cache_registry/sig-storage/livenessprobe:v2.15.0"; do
  grep -F "          image: $image" "$tmpdir/cached-system-images.yaml" >/dev/null
done
if grep -E 'image: (ghcr\.io/thanet-s/|registry\.k8s\.io/sig-storage/)' \
  "$tmpdir/cached-system-images.yaml" >/dev/null; then
  echo "cache registry left a chart-owned system image on its direct origin" >&2
  exit 1
fi

digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/ccm-deployment.yaml \
  --set-string "global.inspace.systemImageRegistry=$cache_registry" \
  --set-string "ccm.image.digest=$digest" >"$tmpdir/cached-digest.yaml"
grep -F "          image: $cache_registry/thanet-s/inspace-cloud-controller-manager@$digest" \
  "$tmpdir/cached-digest.yaml" >/dev/null

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --set-string "global.inspace.systemImageRegistry=$cache_registry" \
  --set-string ccm.image.repository=quay.io/example/custom-ccm \
  --set-string csi.sidecars.provisioner.image=quay.io/example/custom-provisioner:v1 \
  >"$tmpdir/custom-system-images.yaml"
grep -F '          image: quay.io/example/custom-ccm:0.1.0' \
  "$tmpdir/custom-system-images.yaml" >/dev/null
grep -F '          image: quay.io/example/custom-provisioner:v1' \
  "$tmpdir/custom-system-images.yaml" >/dev/null

if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set-string global.inspace.systemImageRegistry=https://cache.example.test >/dev/null 2>&1; then
  echo "system image registry with a URL scheme unexpectedly rendered" >&2
  exit 1
fi

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-controller.yaml"
require_toleration "$tmpdir/csi-controller.yaml"
test "$(grep -Fc '        fsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1
test "$(grep -Fc '            runAsGroup: 65532' "$tmpdir/csi-controller.yaml")" -eq 1
test "$(grep -Fc '            - name: INSPACE_NETWORK_UUID' "$tmpdir/csi-controller.yaml")" -eq 1
grep -Fx '              value: "11111111-1111-4111-8111-111111111111"' "$tmpdir/csi-controller.yaml" >/dev/null
test "$(grep -Fc '            - --timeout=600s' "$tmpdir/csi-controller.yaml")" -eq 2

helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --set csi.sidecars.provisioner.timeoutSeconds=720 \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-controller-long-timeout.yaml"
test "$(grep -Fc '            - --timeout=720s' "$tmpdir/csi-controller-long-timeout.yaml")" -eq 1
test "$(grep -Fc '            - --timeout=600s' "$tmpdir/csi-controller-long-timeout.yaml")" -eq 1
helm template bootstrap "$chart" --namespace kube-system --values "$values" \
  --set csi.sidecars.attacher.timeoutSeconds=720 \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-controller-long-attacher-timeout.yaml"
test "$(grep -Fc '            - --timeout=720s' "$tmpdir/csi-controller-long-attacher-timeout.yaml")" -eq 1
test "$(grep -Fc '            - --timeout=600s' "$tmpdir/csi-controller-long-attacher-timeout.yaml")" -eq 1
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set csi.sidecars.provisioner.timeoutSeconds=599 >/dev/null 2>&1; then
  echo "unsafe CSI provisioner timeout unexpectedly rendered" >&2
  exit 1
fi
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set csi.sidecars.attacher.timeoutSeconds=599 >/dev/null 2>&1; then
  echo "unsafe CSI attacher timeout unexpectedly rendered" >&2
  exit 1
fi

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
if helm template invalid "$chart" --namespace kube-system --values "$values" \
  --set ccm.enabled=false --set ccm.nodeLoadBalancer.enabled=false \
  --set csi.enabled=true --set karpenter.enabled=false \
  --set-string global.inspace.networkUUID= >/dev/null 2>&1; then
  echo "CSI unexpectedly rendered without its attachment-inventory network UUID" >&2
  exit 1
fi
helm template csi-only "$chart" --namespace kube-system --values "$values" \
  --set ccm.enabled=false --set ccm.nodeLoadBalancer.enabled=false \
  --set csi.enabled=true --set karpenter.enabled=false \
  --show-only templates/csi-controller.yaml >"$tmpdir/csi-only.yaml"
grep -Fx '              value: "11111111-1111-4111-8111-111111111111"' "$tmpdir/csi-only.yaml" >/dev/null

grep -Fx 'kind: RoleBinding' "$standalone_ccm" >/dev/null
grep -Fx '  name: extension-apiserver-authentication-reader' "$standalone_ccm" >/dev/null
grep -Fx '      dnsPolicy: Default' "$standalone_ccm" >/dev/null
grep -Fx '    verbs: ["get", "list", "watch", "patch", "update", "delete"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["tokenreviews"]' "$standalone_ccm" >/dev/null
grep -Fx '    resources: ["subjectaccessreviews"]' "$standalone_ccm" >/dev/null
require_toleration "$standalone_csi"
require_toleration "$standalone_karpenter"
test "$(grep -Fc '            - --timeout=600s' "$standalone_csi")" -eq 2
grep -F '            - name: INSPACE_NETWORK_UUID' "$standalone_karpenter" >/dev/null
grep -F '            - name: INSPACE_CONTROL_PLANE_VIP' "$standalone_karpenter" >/dev/null

test "$(grep -Fc '  replicas: 2' "$egress_example")" -eq 1
test "$(grep -Fc '    nodes: 2' "$egress_example")" -eq 1
test "$(grep -Fc 'inspace.cloud.node-restriction.kubernetes.io/egress-gateway: payment' "$egress_example")" -eq 2
grep -Fx '        - key: inspace.cloud/egress-gateway' "$egress_example" >/dev/null
grep -Fx 'kind: CiliumEgressGatewayPolicy' "$egress_example" >/dev/null
grep -Fx '          io.kubernetes.pod.namespace: payments' "$egress_example" >/dev/null
grep -Fx '          app.kubernetes.io/name: payment-gateway' "$egress_example" >/dev/null
grep -Fx '    - 0.0.0.0/0' "$egress_example" >/dev/null
if grep -Eq '^[[:space:]]+(egressIP|interface):' "$egress_example"; then
  echo "static egress example pins an egress IP or interface" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]+tolerations:' "$egress_example"; then
  echo "static egress example lets an application tolerate the gateway taint" >&2
  exit 1
fi

for user_document in "$root_readme" "$chart_readme" "$chart_notes" "$workspace/modules/karpenter-provider/README.md"; do
  if grep -F 'hostPoolSelector' "$user_document" >/dev/null; then
    echo "removed hostPoolSelector is still documented in $user_document" >&2
    exit 1
  fi
done

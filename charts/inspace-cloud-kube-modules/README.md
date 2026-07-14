# InSpace Cloud Kubernetes Modules Helm chart

This chart deploys the external cloud-controller-manager, the RWO CSI driver,
and the InSpace Karpenter provider. Install it into `kube-system`. Its CRDs are
published as a separate chart so CRD upgrades are explicit and happen before
controller upgrades.

## Network prerequisites

The fixed RKE2 control plane uses a private kube-vip address inside the shared
InSpace VPC for TCP/6443 and TCP/9345; it does not use a control-plane NLB or a
public API address. Because InSpace has no managed outbound NAT, each control
plane and Karpenter worker still needs one floating IPv4 for egress. Those node
addresses must have no public inbound firewall rules. Operator SSH and the
private API tunnel enter through the separately firewalled bastion only.

Set each `InSpaceNodeClass.spec.rke2.server` to the canonical literal private
VIP URL on port 9345. Its existing worker firewall must allow all TCP, UDP, and
ICMP traffic from the VPC and Cilium pod CIDR `10.42.0.0/16`, allow matching
outbound traffic to any destination, and reject all public inbound sources.

Private workload load balancers use Cilium LoadBalancer IPAM with L2
Announcements. LB IPAM allocates a unique private VIP per Service, so different
Services can reuse the same port without creating paid InSpace load balancers.
This chart does not install the Cilium pool or announcement policy: cluster
bootstrap renders those resources against RKE2's bundled Cilium CRDs. Bootstrap
enables `l2announcements`, keeps `nodeIPAM.enabled=false`, and sets
`defaultLBServiceIPAM: none`. Consequently, Cilium claims the explicit
`io.cilium/l2-announcer` class while Kubernetes' generic external CCM can own
the deliberately classless public InSpace path without two controllers acting
on one Service.

Configure the same inclusive range at
`global.inspace.privateLoadBalancerPool.start` and `.stop` that was configured
in `InSpaceCluster.spec.network`. Both values are required canonical RFC1918
IPv4 addresses, `start` must not be greater than `stop`, and the inclusive
range must contain 16-256 addresses without overlapping pod CIDR
`10.42.0.0/16` or Service CIDR `10.43.0.0/16`. Before bootstrap,
the operator must exclude the whole range from InSpace VM and NLB allocation.
The current InSpace API has no range-reservation operation, so neither this
chart nor the controllers can reserve it. The controllers only detect
collisions and fail closed. The range is an immutable cluster networking
contract; editing a live Cilium pool can reassign Service VIPs.

Set `global.inspace.controlPlaneVIP` to the same canonical RFC1918 kube-vip
address used by `InSpaceCluster.spec.endpoint.virtualIPv4`. It is required and
must be outside the private Service range, pod CIDR `10.42.0.0/16`, and Service
CIDR `10.43.0.0/16`. Karpenter also requires every NodeClass network UUID and
supervisor VIP to exactly match these global chart values. CCM uses both contracts to reject
and clean up a public InSpace NLB whose private address collides with either
reserved address space.

Use the supported private Service contract:

```yaml
metadata:
  labels:
    inspace.cloud/load-balancer-scope: private
spec:
  type: LoadBalancer
  loadBalancerClass: io.cilium/l2-announcer
  externalTrafficPolicy: Cluster
```

Cilium Node IPAM is intentionally disabled and unsupported. Do not use
`loadBalancerClass: io.cilium/node`; it exposes node addresses rather than a
unique private VIP per Service. Cilium L2 Announcements is a beta feature and
works only if the InSpace VPC accepts ARP and gratuitous ARP for VIPs that are
not assigned to a VM NIC. Validate this behavior in the target VPC. Keep
`externalTrafficPolicy: Cluster`; Cilium documents `Local` as incompatible with
L2 Announcements.

Public exposure remains an explicit, paid, TCP-only InSpace NLB. A public
Service deliberately leaves `loadBalancerClass` unset for Kubernetes' generic
cloud service controller and sets both the public scope label and
`service.beta.kubernetes.io/inspace-load-balancer-public: "true"` annotation.
Public Services may use `externalTrafficPolicy: Local`; the CCM watches
EndpointSlices and makes the NLB target set exactly the Ready, non-terminating
local endpoint nodes that are themselves Ready and eligible for load balancing.
The resulting `healthCheckNodePort` is not probed by InSpace because its NLB API
has no health-check contract; endpoint and node informer events drive target
convergence instead. For both `Local` and `Cluster`, nodes labeled
`node-role.kubernetes.io/control-plane` or the legacy
`node-role.kubernetes.io/master` are excluded from public NLB targets.
Kubernetes defaults an omitted policy to `Cluster`, so public Services that
need local-endpoint targeting must set `externalTrafficPolicy: Local`
explicitly. Private Cilium L2 Services must remain `Cluster`.
See [`service-private-l2.yaml`](examples/service-private-l2.yaml) and
[`service-public-nlb.yaml`](examples/service-public-nlb.yaml).

## Secret contracts

The chart deliberately does not create the InSpace API Secret. All three
controllers refer to one existing Secret in the release namespace:

| Value | Default | Meaning |
| --- | --- | --- |
| `global.inspace.apiSecret.name` | `inspace-cloud-credentials` | Existing Secret name |
| `global.inspace.apiSecret.tokenKey` | `api-token` | InSpace API token key |
| `global.inspace.apiSecret.billingAccountIDKey` | `billing-account-id` | Required positive decimal billing account ID key |

Karpenter's RKE2 join token is intentionally separate. The provider validates
the fixed `Secret/inspace-rke2-agent-token` key `token`; it cannot be pointed at
the cloud API credential. Prefer creating both Secrets outside Helm. Setting
`karpenter.agentTokenSecret.create=true` is provided for automation but stores
the agent token in Helm release data.

By default Karpenter runs in the Helm release namespace, so installing the
chart into `kube-system` needs exactly one cloud API Secret object. Set
`karpenter.namespace` to run it elsewhere and optionally set
`karpenter.createNamespace=true`; Kubernetes cannot use a Secret across
namespaces, so the same existing cloud API Secret contract must then also be
provisioned in that namespace. The chart never copies secret data.

## Install

```sh
export VERSION=0.1.0

helm upgrade --install inspace-cloud-kube-modules-crds \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version "$VERSION"

kubectl -n kube-system create secret generic inspace-cloud-credentials \
  --from-file=api-token=/secure/path/inspace-api-token \
  --from-file=billing-account-id=/secure/path/inspace-billing-account-id

kubectl -n kube-system create secret generic inspace-rke2-agent-token \
  --from-file=token=/secure/path/rke2-agent-token

helm upgrade --install inspace-cloud-kube-modules \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules \
  --version "$VERSION" \
  --namespace kube-system \
  --values values.yaml
```

Start from [`examples/values.yaml`](examples/values.yaml) and ensure its VPC,
control-plane VIP, and private load-balancer range exactly match both bootstrap
and every NodeClass. Pin image
digests in production with each component's `image.digest` value; when set,
the digest takes precedence over `image.tag`.

The chart is licensed under Apache-2.0.

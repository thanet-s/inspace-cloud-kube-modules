# InSpace Cloud Kubernetes Modules Helm chart

This chart deploys the external cloud-controller-manager, the RWO CSI driver,
and the InSpace Karpenter provider. Install it into `kube-system`. Its CRDs are
published as a separate chart so CRD upgrades are explicit and happen before
controller upgrades.

## Network prerequisites

The fixed RKE2 control plane uses a private kube-vip address inside the shared
InSpace VPC for TCP/6443 and TCP/9345; it does not use a control-plane NLB or a
public API address. Because InSpace has no managed outbound NAT, each control
plane and Karpenter worker still needs one floating IPv4 for egress. Ordinary
node addresses must have no public inbound firewall rules; CCM-managed
load-balancer nodes retain the private base firewall, receive exact
per-Service TCP/UDP firewalls, and reuse one cluster-wide portless ICMP-from-Any
firewall. Bastion SSH and ICMP use Any by default or one explicitly configured
management `/32`; the private API tunnel enters through the separately
firewalled bastion only.

Set each `InSpaceNodeClass.spec.rke2.server` to the canonical literal private
VIP URL on port 9345. Its existing worker firewall must allow all TCP, UDP, and
ICMP traffic from the VPC and Cilium pod CIDR `10.42.0.0/16`, allow matching
outbound traffic to any destination, and reject all public inbound sources.

Private workload load balancers use Cilium LoadBalancer IPAM with L2
Announcements. LB IPAM allocates a unique private VIP per Service, so different
Services can reuse the same port without creating paid InSpace load balancers.
This chart does not install the Cilium pool or announcement policy: cluster
bootstrap renders those resources against RKE2's bundled Cilium CRDs. Bootstrap
enables `l2announcements`, leaves Node IPAM disabled, and sets
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

Use `loadBalancerClass: inspace.cloud/node`; CCM creates an exact-owned,
same-namespace `inlb-dp-<service-identity>` Service with the internal
`inspace.cloud/node-datapath` class. The identity is the first 52 lowercase hex
characters of SHA-256 over `namespace NUL name NUL Service-UID` and is repeated
in the `inspace.cloud/node-lb-service-id` label. Its status publishes private
Node InternalIPs as `ipMode: VIP`, while the user Service publishes the paired
public FIPs as `ipMode: Proxy`. InSpace DNAT therefore reaches Cilium's private
low-port frontend without Kubernetes NodePorts or `externalIPs`. The Node
identity and readiness labels use the
`inspace.cloud.node-restriction.kubernetes.io/*` prefix and therefore require
the RKE2 NodeRestriction admission plugin.

This is a trusted-administrator contract, not tenant isolation. In a
multi-tenant cluster, admission and RBAC must reserve the internal
`inspace.cloud/node-datapath` class, `Service.spec.externalIPs`, and the Node-LB
taint/toleration and selector surface for the controllers. The
`NoSchedule` taint keeps ordinary workloads off LB nodes, but a user allowed to
tolerate it or select a node directly can bypass that placement guard. Cilium
L2 Announcements is a beta feature and
works only if the InSpace VPC accepts ARP and gratuitous ARP for VIPs that are
not assigned to a VM NIC. Validate this behavior in the target VPC. Keep
`externalTrafficPolicy: Cluster`; Cilium documents `Local` as incompatible with
L2 Announcements.

The node-load-balancer class defaults to shared mode when the mode annotation is
omitted:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: LoadBalancer
  loadBalancerClass: inspace.cloud/node
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Cluster
  selector:
    app: web
  ports:
    - port: 443
      targetPort: 8443
      protocol: TCP
```

Shared Services reuse a shard whenever their public `(protocol, port)` claims
do not conflict. A conflict automatically creates another shard. The optional
`service.inspace.cloud/node-lb-nodes-per-shard` annotation overrides
`ccm.nodeLoadBalancer.nodesPerShard`; both default to `1`. Each replica has its
own FIP, so values above one publish multiple addresses rather than one virtual
IP.

Dedicated mode always creates a separate shard and supports an exact catalog
shape through Service annotations:

```yaml
metadata:
  annotations:
    service.inspace.cloud/node-lb-mode: public-node-dedicated
    service.inspace.cloud/node-lb-cpu: "4"
    service.inspace.cloud/node-lb-memory: 8Gi
spec:
  type: LoadBalancer
  loadBalancerClass: inspace.cloud/node
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Cluster
  selector:
    app: web
```

CPU and memory default to `1` core and `4Gi`; explicit dedicated shapes must
provide at least `1` core and `4Gi`. Generated static NodePools always use
AMD EPYC, Linux/amd64, on-demand capacity, a 30 GiB root disk, and the
`inspace.cloud/node-lb=true:NoSchedule` taint. Application pods stay on private
workload nodes; Cilium forwards traffic from the LB nodes with
`externalTrafficPolicy: Cluster`. CCM creates one exact TCP/UDP-only ingress
firewall per Service and attaches one reusable cluster-wide firewall containing
exactly one portless inbound ICMP-from-Any rule. `loadBalancerSourceRanges`
restricts only that Service's TCP/UDP rules; it never restricts ping. InSpace
does not expose ICMP type/code filtering, so the shared rule permits all IPv4
ICMP from Any.

A node is advertised only while its full NodePool/NodeClaim/NodeClass identity
is authoritative, it is Ready with exactly one authoritative FIP, Karpenter's
private base-firewall contract is valid, and the shared ICMP assignment is
visible. Per-Service firewalls are not part of this shard-wide readiness label;
CCM audits each one as a separate activation gate after its private VIP exists.
Any node-identity or shared-infrastructure drift removes the protected ready
label. Karpenter may use one temporary surge node during drift replacement;
steady state remains the configured shard replica count.

Public-node Services require a non-empty selector and explicit
`allocateLoadBalancerNodePorts: false`. Selectorless Services, allocated
NodePorts, `externalIPs`, `loadBalancerIP`, and non-IPv4 source ranges fail
before any node capacity is created. CCM keeps the previous shard advertised
during replacement-capacity preparation, then performs a fail-closed,
break-before-make cutover. It withdraws the old Service firewall and status pair
before storing `service.inspace.cloud/node-lb-datapath-active-shard` for the
replacement. Activation then proceeds as private VIP, persisted assignment
fence, exact Service-firewall assignment readback, and public Proxy status.
Node additions follow that order; removals detach and read back the stale edge
before either status shrinks.

Disabling Node-LB or uninstalling its CCM/Karpenter controllers is not a
teardown operation. First delete every `inspace.cloud/node` Service and wait
for its provider finalizer, datapath Service, managed NodePools/NodeClaims/Nodes,
FIPs, and both Service and shared ICMP firewalls to disappear. Removing the
controllers earlier stops authoritative cleanup and can retain billable cloud
resources.

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
See [`service-private-l2.yaml`](examples/service-private-l2.yaml),
[`service-public-nlb.yaml`](examples/service-public-nlb.yaml),
[`service-public-node-shared.yaml`](examples/service-public-node-shared.yaml),
and [`service-public-node-dedicated.yaml`](examples/service-public-node-dedicated.yaml).

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

## System image registry

`global.inspace.systemImageRegistry` optionally redirects only the system
images owned by this chart through one registry host. It does not select the
cluster bootstrap mode. For the default cached mode, set it to the stable
bastion endpoint after its ECDSA P-256 CA trust has been installed on every
node. Bootstrap mints that CA and the server certificate from the persisted
real cluster-initialization instant for exactly 15 calendar years. Leave it
empty (the chart default) only for explicit direct-download mode. Use a host
without a URL scheme or path, for example:

```yaml
global:
  inspace:
    systemImageRegistry: cache.<cluster>.inspace.internal:8443
```

When set, the chart applies these exact rewrites while preserving tags and
digests:

| Source | Rendered repository prefix |
| --- | --- |
| `ghcr.io/thanet-s/*` | `cache.<cluster>.inspace.internal:8443/thanet-s/*` |
| `registry.k8s.io/sig-storage/*` | `cache.<cluster>.inspace.internal:8443/sig-storage/*` |

The setting covers the CCM, CSI, Karpenter, and CSI sidecar images rendered by
this chart. It does not rewrite kubelet, RKE2, Cilium, kube-vip, user-supplied
repositories outside those two prefixes, or arbitrary workload images. The
registry and its CA trust must already be configured on every node before
enabling this value. The bastion registry is private and read-only: its TLS
frontend accepts only `GET` and `HEAD`, and it must not be exposed through a
public load balancer.

## Install

```sh
export VERSION='<release-version>'

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

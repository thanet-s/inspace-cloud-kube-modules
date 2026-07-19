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
load-balancer nodes retain the private base firewall, reuse one cluster-wide
portless ICMP-from-Any firewall, and receive at most one mutable aggregate
TCP/UDP firewall for their shard. Endpoint-local edge nodes instead use a
separate `public-node-local` NodeClass profile that permits only exact
CCM-owned per-Service TCP/UDP firewalls. Bastion SSH and ICMP use Any by
default or one explicitly configured management `/32`; the private API tunnel
enters through the separately firewalled bastion only.

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

CPU and memory default to `1` core and `2Gi`; explicit dedicated shapes must
provide at least `1` core and `2Gi`. Generated static NodePools always use
AMD EPYC, Linux/amd64, on-demand capacity, a 30 GiB root disk, and the
`inspace.cloud/node-lb=true:NoSchedule` taint. Application pods stay on private
workload nodes; Cilium forwards traffic from the LB nodes with
`externalTrafficPolicy: Cluster`. Every shard owns one mutable public firewall
named `inlb-<cluster-ownership-hash>-shard-<shard-hash>`. Its policy is the
canonical union of the shard's unique TCP/UDP `(protocol, port)` claims. Each
rule uses the owning Service's exact canonical IPv4
`loadBalancerSourceRanges`, or Any when the field is empty. The stable name and
UUID do not change with policy updates. CCM also attaches one reusable
cluster-wide firewall containing exactly one portless inbound ICMP-from-Any
rule. Source ranges never restrict ping. InSpace does not expose ICMP type/code
filtering, so the shared rule permits all IPv4 ICMP from Any. A Node-LB VM has
exactly the private base and cluster ICMP firewalls, plus at most one shard
aggregate firewall.

A node is advertised only while its full NodePool/NodeClaim/NodeClass identity
is authoritative, it is Ready with exactly one authoritative FIP, Karpenter's
private base-firewall contract is valid, and the shared ICMP and exact aggregate
assignments are visible. Any node-identity or shared-infrastructure drift
removes the protected ready label. If the Node becomes NotReady, CCM withdraws
its readiness and public/private status but leaves the aggregate firewall
attached while kubelet connectivity recovers. Detachment is reserved for node
deletion or replacement and last-owner shard cleanup. Karpenter may use one
temporary surge node during drift replacement; steady state remains the
configured shard replica count.

Managed-shard public-node Services require a non-empty selector and explicit
`allocateLoadBalancerNodePorts: false`. Selectorless Services, allocated
NodePorts, `externalIPs`, `loadBalancerIP`, and non-IPv4 source ranges fail
before any node capacity is created. Shard migration is fail-closed and
break-before-make. CCM closes and reads back the functional child, removes the
Service UID from the old aggregate ledger, and retires the old shard when it has
no peer. It then creates replacement capacity while the child remains closed,
proves the exact aggregate policy and assignment, and only then publishes the
replacement private VIP and public Proxy status.

For a fresh shard, CCM attaches the aggregate once while the node is not
publicly advertised, verifies assignment and Node recovery, and then enables
readiness and status. It does not detach and reattach the policy during ordinary
readiness loss.

For an established shared shard, CCM changes the aggregate in place with
`PUT`, retaining provider UUIDs for unchanged `(protocol, port)` rules and
requiring exact cloud readback. Adding a Service stages its child spec with an
empty VIP status, widens the aggregate, then publishes the private VIP and new
public status. Removing one
first narrows the aggregate, then removes only that Service's statuses and
child. Sibling NodePool, VM, FIP, firewall UUID, status, and traffic identities
remain unchanged. The last Service anchors cleanup until its exposure and
capacity are gone, and three spaced authoritative reads prove the aggregate
firewall is unassigned and deleted. A CCM NodePool finalizer preserves the full
SHA-256 applied ledger and any pending cloud mutation throughout that cleanup.
CCM records a Service-side shard-materialization handoff only after an exact
NodePool/finalizer readback, so lost or drifted state cannot be mistaken for a
never-created prospective shard. New surge/replacement nodes stay ineligible
through their firewall-attach pass without withdrawing protected siblings.
Before either aggregate or shared-ICMP firewall POST, CCM persists a durable
issued marker. An ambiguous issued create is never retried from empty list
responses; its state finalizer remains until the exact resource is observable
or the attempt is manually resolved after cloud-side proof.
An ambiguous aggregate-policy PUT is likewise never reissued on a timer; CCM
waits for its exact pending policy or explicit operator resolution so an older
delayed request cannot overwrite a newer generation.
The generated NodeClass independently uses the
`inspace.cloud/node-lb-cluster-state` finalizer to retain the shared ICMP
firewall ledger. Deleting it triggers a fail-closed drain of every managed
shard; CCM releases it only after spaced cloud-absence proof and a durable
Service-side cleanup handoff.
Port and source-range edits also close the owning child first and keep it empty
until the replacement member hash, aggregate `PUT`, and assignment readback are
all authoritative; an old wider rule cannot reach the edited frontend.

Disabling Node-LB or uninstalling its CCM/Karpenter controllers is not a
teardown operation. First delete every `inspace.cloud/node` Service and wait
for its provider finalizer, datapath Service, managed NodePools/NodeClaims/Nodes,
FIPs, shard aggregate firewalls, the shared ICMP firewall, and the generated
NodeClass to disappear.
Removing the controllers earlier stops authoritative cleanup and can retain
billable cloud resources.

### Endpoint-local public nodes

`public-node-local` exposes only selected nodes that currently host a Ready,
non-terminating local endpoint. The user owns the node capacity; CCM never
creates, moves, or deletes its floating IPs. A static Karpenter NodePool is a
good fit when the edge count should be operator-controlled:

```yaml
metadata:
  annotations:
    service.inspace.cloud/node-lb-mode: public-node-local
    service.inspace.cloud/node-lb-pool: edge
spec:
  type: LoadBalancer
  loadBalancerClass: inspace.cloud/node
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Local
  publishNotReadyAddresses: false
  selector:
    app: web
```

The selected NodePool must apply the protected
`inspace.cloud.node-restriction.kubernetes.io/public-local-pool=edge` label
through `spec.template.metadata.labels` and reference a separate
`InSpaceNodeClass` with `spec.firewallProfile: public-node-local`. Taint the
pool and constrain the application so unrelated pods cannot occupy its public
edge. For multiple nodes, spread one serving replica per node. The Service
status contains the sorted public FIP of every selected eligible endpoint node
with `ipMode: Proxy`; DNS clients must be able to use multiple A records.

Manual non-Karpenter nodes are also supported: an administrator must apply the
same protected pool label directly. Kubelets cannot self-apply it. CCM still
requires the Node's providerID, VM, private address, and assigned FIP to match
authoritative cloud metadata. Karpenter-backed nodes use the stricter exact
Node→NodeClaim→NodePool→NodeClass proof above. Karpenter normally synchronizes
the template label after registration; CCM independently proves that chain and
ensures the label is present before exposure. Karpenter-backed nodes must also
use the configured trusted private base firewall with `reservePublicIPv4: true`;
CCM audits the VM's complete base-plus-Service firewall assignment set before
publication. For a manual node, the administrator is explicitly responsible
for an equivalent default-deny base firewall.

For the Cilium datapath, CCM owns a same-namespace
`inlb-dp-<service-identity>` child Service. It has
`loadBalancerClass: inspace.cloud/node-datapath`, the same selector and ports,
`externalTrafficPolicy: Local`, no data-port NodePorts, and publishes the eligible
nodes' private InternalIPs with `ipMode: VIP`. The user-facing parent publishes
only the paired public FIPs. This keeps the public address in Kubernetes
status while programming Cilium against the post-DNAT private node address.
Kubernetes still allocates one `healthCheckNodePort` on both Local
LoadBalancer Services; those ports are not included in the public InSpace
firewall and CCM does not depend on them. `publishNotReadyAddresses: true` is
rejected because Kubernetes can otherwise mark unready endpoints ready in
EndpointSlices, defeating this mode's readiness gate.

CCM creates one deterministic Service firewall containing only its TCP/UDP
ports and canonical IPv4 `loadBalancerSourceRanges` (Any when omitted), then
attaches it to exactly the eligible endpoint VMs. Losing readiness, the pool
label, or the local endpoint withdraws that node's status and firewall
assignment. Deleting the Service deletes only this firewall; the NodePool,
VMs, and their Karpenter-owned FIPs remain. Because addresses belong to nodes,
node replacement may change the published address and terminates connections
to the old node. Use a static NodePool, `expireAfter: Never`, disruption
budgets, and short DNS TTLs according to the availability contract you need.

Within one named pool, every `(protocol, port)` is an exclusive claim across
all `public-node-local` Services, even when their current endpoint-node sets do
not overlap. The lowest lexicographic Service UID wins deterministically. CCM
withdraws the losing Service and emits `PublicNodeLocalPortConflict`; it does
not let two Cilium Services program the same node frontend.

The generic public-NLB path remains an explicit, paid, TCP-only InSpace NLB. A
Service using that path deliberately leaves `loadBalancerClass` unset for
Kubernetes' cloud service controller and sets both the public scope label and
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
[`service-public-node-dedicated.yaml`](examples/service-public-node-dedicated.yaml),
[`service-public-node-local.yaml`](examples/service-public-node-local.yaml), and
[`egress-gateway-static.yaml`](examples/egress-gateway-static.yaml).

## Dedicated workload egress

Bootstrap enables Cilium Egress Gateway together with its required BPF
masquerading and kube-proxy replacement settings. The
[`egress-gateway-static.yaml`](examples/egress-gateway-static.yaml) example
creates a static two-node Karpenter pool and routes public IPv4 traffic from
`app.kubernetes.io/name: payment-gateway` Pods in the `payments` namespace
through that pool.

The gateway nodes carry the permanent
`inspace.cloud/egress-gateway=payment:NoSchedule` taint. Ordinary workloads,
including `payment-gateway`, must not tolerate it; the Pods remain on normal
worker nodes and Cilium redirects only their selected egress traffic. Gateway
selection uses the protected
`inspace.cloud.node-restriction.kubernetes.io/egress-gateway=payment` label so
a kubelet cannot nominate itself. The example reuses
`InSpaceNodeClass/ubuntu-workers`, whose `reservePublicIPv4: true` contract
gives each gateway node one egress-only InSpace floating IPv4.

The policy intentionally omits both `egressIP` and `interface`. Cilium chooses
the first address on the interface that owns the default route, and InSpace
SNAT exposes that node through its floating public IPv4. Once both nodes are
Ready and CCM has published their external addresses, list the addresses to
allowlist with the external provider:

```sh
kubectl get nodes \
  -l inspace.cloud.node-restriction.kubernetes.io/egress-gateway=payment \
  -o 'custom-columns=NAME:.metadata.name,PRIVATE:.status.addresses[?(@.type=="InternalIP")].address,PUBLIC:.status.addresses[?(@.type=="ExternalIP")].address'
```

A single `egressGateway.nodeSelector` matching two nodes uses the first match
in lexical node-name order. The second node becomes the selected gateway after
the first stops matching or is removed; it is not an active-active second
path, so allowlist both public addresses. Gateway changes terminate existing
egress connections. Static Karpenter capacity fixes the node count, not the
lifetime of a floating IP: manual deletion, infrastructure failure, or an
explicitly permitted replacement allocates a new address that must be added to
the provider allowlist. The example disables expiration, voluntary disruption,
consolidation, and surge capacity to minimize that churn.

Cilium policy realization for a newly started Pod is not instantaneous. A
strict external provider allowlist safely rejects any connection that leaves
before the egress policy is active; applications should retry those initial
connections.

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

## CSI controller timeouts

The chart sets both `csi.sidecars.provisioner.timeoutSeconds` and
`csi.sidecars.attacher.timeoutSeconds` to `600`. This allows up to two minutes
for preflight reads and durable-fence acquisition. Immediately before any
CreateDisk, DeleteDisk, AttachDisk, or DetachDisk call, the driver requires
480 seconds to remain: five minutes for the shared client's HTTP mutation
deadline, two minutes for destructive recovery, and one minute for final
readback and Kubernetes Lease persistence. If less remains, no cloud mutation
is issued and only that invocation's exact undispatched Lease is cleared. The
chart accepts larger values up to 3600 seconds, but rejects values below 600
seconds. Shortening either sidecar deadline can cancel and strand the original
no-replay Lease or cause overlapping retries while the mutation proof is still
running.

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

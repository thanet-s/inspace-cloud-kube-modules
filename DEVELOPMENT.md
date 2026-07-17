# Development

This guide covers local development, verification, and maintainer-operated
live tests. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull
request and [RELEASING.md](RELEASING.md) before creating a release tag.

## Workspace

The repository root owns all source, tests, manifests, and E2E tooling.
`go.work` links the four modules for local development, while their separate
`go.mod` files keep controller dependencies bounded. Root verification runs
each module independently with `GOWORK=off` so an accidental workspace-only
dependency cannot pass CI.

Module-specific development notes are available for the
[shared client](modules/client/README.md),
[cloud provider](modules/cloud-provider/README.md),
[CSI driver](modules/csi-driver/README.md), and
[Karpenter provider](modules/karpenter-provider/README.md).

## Network and node contract

This section records implementation invariants for maintainers and release
validation. The root README intentionally keeps only the user-facing summary.

### Public egress and private identity

InSpace does not provide shared outbound NAT for private-only VMs. Every
control-plane, Karpenter worker, and bastion VM therefore requests one floating
public IPv4 in its initial VM create call so internet egress is available to
cloud-init from first boot.

The floating address is not configured on the guest NIC. RKE2 uses the NIC's
RFC1918 address for node identity and cluster traffic, and worker cloud-init does
not set `node-external-ip`. The external CCM reads the exact floating-IP
assignment from the InSpace API and publishes it as `NodeExternalIP`; it does
not infer it from the NIC or a VM `public_ipv4` field.

Only the bastion accepts public management ingress. It defaults to Any
(`0.0.0.0/0`) for TCP/22 and portless ICMP; setting
`INSPACE_MANAGEMENT_CIDR` to one public IPv4 `/32` restricts both rules.
Control-plane and ordinary worker floating IPs are egress-only, and their
firewalls reject all public inbound rules. Private VPC/pod-network ICMP remains
enabled for cluster networking. Ansible reaches private node addresses through
the bastion. A VM is not ready until its intended cloud firewall assignment has
been read back and verified.

The bootstrap-owned bastion is fixed to Ubuntu 24.04, 1 vCPU, 2 GiB RAM, and a
30 GiB root disk. Fixed control-plane nodes require Ubuntu 24.04 with at least
2 vCPUs and 4 GiB RAM.

### Node naming and preparation

The control-plane VM names, guest hostnames, and Kubernetes Node names are
exactly `<InSpaceCluster metadata.name>-cp0`, `-cp1`, and `-cp2`. The bastion is
exactly `<InSpaceCluster metadata.name>-bastion`. Cluster names are limited to
55 characters so every generated hostname remains a DNS label.
Bootstrap FIPs use the same cluster prefix (`-bastion-ip`, `-cp0-ip` through
`-cp2-ip`). Firewall names also begin with the cluster name and retain the
namespace/name owner hash as their final ownership component.

Elastic worker VM names, guest hostnames, and Kubernetes Node names are
`<cluster>-karp-<NodePool>-<random>`. The provider derives the NodePool and
random suffix from the Karpenter NodeClaim name, while the original NodeClaim
identity remains the cloud ownership and deletion key.

Bootstrap creates fixed control-plane VMs in deterministic slot order with a
hard creation bound of one. It must authoritatively read back each VM's
restrictive firewall assignment before sending the next VM POST; already
protected servers may continue booting in parallel.

Immediately after setting the static hostname, every control plane, worker,
and bastion removes any stale `127.0.1.1` mapping, writes exactly
`127.0.1.1 <generated-hostname>` to `/etc/hosts`, and retries the exact
`getent` readback within a fixed bound until that name resolves locally. This
bounded retry accounts for a short NSS readback delay after a successful file
append; package installation and resolver replacement do not begin until the
mapping is visible. Current fixed control-plane ownership records use schema
v8 because kube-vip's explicit 5/3/1-second election timing and 500-millisecond
ARP cadence change their immutable RKE2 cloud-init; bastion ownership remains
v6. Teardown continues to accept schema v7 control planes paired with the same
v6 bastion. Karpenter's current immutable bootstrap drift
schema is `stock-ubuntu-rke2-v12`; this is separate from its cloud VM ownership
record version.

Control planes, workers, and the bastion use TOT as the primary Ubuntu mirror
and KKU as its request-failure fallback for both regular and security suites.
They replace DHCP-provided DNS with static Google resolvers and stop and mask
`systemd-resolved`. Control planes and workers also disable swap and apply
persistent Kubernetes sysctls, PAM limits, and RKE2 systemd limits before
starting RKE2. After the deliberate one-time package update and upgrade, all
nodes disable APT periodic updates and mask the unattended-upgrade units; OS
patching is an explicit operator action. Node firewalls are
validated fail-closed for all-port TCP, UDP, and ICMP coverage from both the VPC
subnet and native-routing pod CIDR, with matching outbound access.

The guarded live E2E templates set `spec.rke2.skipOSUpgrade: true` on both the
fixed cluster and worker NodeClass to reduce disposable-cluster startup time.
This bypasses only the one-time full OS upgrade. Mirror selection, package-index
refresh, required package installation, and automatic-update shutdown are
still exercised. Production examples omit the field and retain the upgrade.

### Bastion bootstrap cache

`InSpaceCluster.spec.bootstrapCache` is required. Its `directDownload` switch
defaults to `false`, so the normal path turns the existing bastion into a
private bootstrap cache and wires the control plane to use it. Setting it to
`true` is an explicit opt-out: the bastion remains the SSH hop, but nodes fetch
RKE2 assets and system images directly from their upstream HTTPS locations.

The cache does not consume a second virtual address. After InSpace allocates
the bastion's RFC1918 NIC address, bootstrap binds it to the deterministic
per-cluster name `cache.<cluster>.inspace.internal` in node `/etc/hosts` files
and serves TLS on TCP/8443. The listener binds only that private address. The
bastion cache pre-seeds the audited RKE2 release assets and an addon-aware
system-image inventory; it is not a general-purpose pull-through proxy. The
complete inventory contains 34 images. When `spec.rke2.disable` contains
`rke2-ingress-nginx`, bootstrap excludes its webhook-certgen and ingress
controller images, producing the 32-image seed used by the E2E cluster. Its
dedicated 10 GB filesystem reserves 1 GB of free space. Daily maintenance
prunes unpinned RKE2 artifacts and local Docker data older than 30 days.

Cached initialization and reconciliation require two persistent controller
inputs. `INSPACE_BOOTSTRAP_CACHE_KEY` is an operator secret containing exactly
64 lowercase hexadecimal characters (32 random bytes).
`INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE` is captured from the real clock at the
actual first initialization and persisted in canonical whole-second UTC
RFC3339 form (`YYYY-MM-DDTHH:MM:SSZ`); it must not be in the future. Together
the inputs derive stable ECDSA P-256 cluster-scoped CA and server certificates
whose validity starts at that persisted instant and ends exactly 15 calendar
years later; only the public CA is copied to nodes.
They never belong in an `InSpaceCluster` or `InSpaceNodeClass` resource.
Preserve both values for the complete cluster lifecycle.

The full-cluster E2E runner persists them as `bootstrap-cache-key` and
`bootstrap-cache-not-before` in its state directory, both with mode `0600`.
It supplies both values to initialization and later cached reconciliation.
Teardown requires and receives neither cache input.

The private cache endpoint permits only `GET` and `HEAD`. Its registry backend
is switched to read-only after the deterministic seed completes, registry
deletion is disabled, and the containers run with read-only roots, dropped
capabilities, `no-new-privileges`, and bounded local logs. VPC firewall policy
and the private listener are the access boundary; the cache must never be
published through the bastion floating IP or an InSpace NLB.

Docker Compose uses `restart: unless-stopped` for both services. Docker and
service logs use the local driver with three compressed 10 MB files per
container, so bootstrap logging cannot consume the cache filesystem without a
bound. Both the writable seed-registry start and final forced recreation of the
read-only registry plus NGINX use bounded incremental retry, with at most nine
Compose attempts, so a transient Docker startup race does not abandon
cloud-init.

### RKE2, Cilium, and the control-plane VIP

RKE2 uses its bundled Cilium chart in native-routing mode. Cilium installs
direct pod-CIDR routes on the shared VPC, performs eBPF IPv4 masquerading for
internet egress, and fully replaces kube-proxy with eBPF service handling.

A private kube-vip address inside the VPC is advertised by control-plane nodes
with ARP leader election. It is the stable RKE2 API endpoint on TCP/6443 and
registration endpoint on TCP/9345. Bootstrap creates neither a control-plane
NLB nor a public API endpoint.

The kube-vip static Pod mounts `/etc/rancher/rke2/rke2.yaml` from the host at
`/etc/kubernetes/admin.conf`, maps the `kubernetes` hostname to `127.0.0.1`, and
does not rely on a `k8s_config_file` override. The downward API supplies
`vip_nodename` from `spec.nodeName`, so the Lease holder is the exact
control-plane Node. The container drops all Linux capabilities and adds only
`NET_ADMIN` and `NET_RAW`.

### Private and public Service load balancing

Private `LoadBalancer` Services use Cilium LoadBalancer IPAM and L2
Announcements. LB IPAM assigns a distinct private VIP to each Service, allowing
multiple Services to reuse the same port without purchasing an InSpace NLB.
The supported private contract is:

```yaml
metadata:
  labels:
    inspace.cloud/load-balancer-scope: private
spec:
  type: LoadBalancer
  loadBalancerClass: io.cilium/l2-announcer
  externalTrafficPolicy: Cluster
```

Bootstrap sets `defaultLBServiceIPAM: none`, so Cilium claims only explicit
classes and cannot race the generic external CCM. The supported user contract
is `loadBalancerClass: inspace.cloud/node`; the internal datapath class is
reserved for CCM-generated Services. The CCM
assigns shared Services by conflict-free `(protocol, port)` claims or gives
dedicated Services an isolated static Karpenter shard. Generated nodes use AMD
EPYC, a 30 GiB disk, a `NoSchedule` taint, and the private base firewall.
Each shard owns one mutable public firewall with the stable name
`inlb-<cluster-ownership-hash>-shard-<shard-hash>`. Its policy is the canonical
union of the shard's unique TCP/UDP `(protocol, port)` claims; each rule carries
the owning Service's exact canonical IPv4 `loadBalancerSourceRanges`, or Any
when the field is empty. The policy hash is stored separately from the stable
firewall name. CCM changes the rules in place with `PUT`, preserves provider
rule UUIDs for unchanged `(protocol, port)` claims, and requires exact
authoritative readback before publishing a new edge. One separately owned
cluster firewall containing a single portless inbound ICMP-from-Any rule is
reused by every authorized Node-LB VM. Source ranges affect only TCP/UDP rules
and never restrict ping. An authorized Node-LB VM therefore has exactly its
private base firewall, the shared cluster ICMP firewall, and at most one shard
public firewall.

The CCM eligibility gate uses protected
`inspace.cloud.node-restriction.kubernetes.io/*` labels. CCM validates the full
rendered NodePool profile, including its taint, plus the exact
Node→NodeClaim→NodePool→NodeClass and FIP identity chain. Advertising requires
Node Ready, Karpenter's valid private base-firewall contract, the shared ICMP
assignment, the exact shard-firewall policy and assignment, and the protected
CCM readiness label. A node that becomes NotReady loses the protected readiness
label and is withdrawn from public/private status, but CCM deliberately keeps
the shard firewall attached. This avoids a cloud firewall detach/reattach loop
while kubelet reachability recovers. Detachment is reserved for node deletion
or replacement and last-owner shard cleanup.

This controller contract assumes trusted cluster administrators. For
multi-tenancy, admission and RBAC must reserve the internal
`inspace.cloud/node-datapath` class, `Service.spec.externalIPs`, protected CCM
metadata, and Node-LB tolerations/selectors. NodeRestriction prevents a kubelet
from forging the protected labels; those labels are applied through the API
after registration and are never placed in kubelet bootstrap flags. The
`NoSchedule` taint alone is not a security boundary.

Every owned live datapath keeps its `(shard, protocol, port)` reservation until
that datapath is updated or deleted, so simultaneous port swaps and deleting
peers cannot create a transient duplicate frontend on one private node address.
The user Service must have a selector and explicit
`allocateLoadBalancerNodePorts: false`; unsupported frontends and source ranges
fail before static capacity is created. The generated
same-namespace `inlb-dp-<service-identity>` Service publishes private Node
InternalIPs as `ipMode: VIP`; the user Service publishes paired FIPs as
`ipMode: Proxy`. The identity is the first 52 lowercase hex characters of
SHA-256 over `namespace NUL name NUL Service-UID`, is repeated in the
`inspace.cloud/node-lb-service-id` label, and is bound by an exact controller
owner reference. CCM records
`service.inspace.cloud/node-lb-datapath-active-shard` before publishing any
private VIP. A new or edited Service first stages and verifies the exact child
spec while its VIP status is empty. CCM then persists a pending
aggregate-policy fence, updates the same shard firewall UUID in place, verifies
its exact policy and assignment, and only then publishes the private VIP and
new public Proxy status. Adding or
removing one member therefore expands or shrinks the aggregate policy while
preserving sibling NodePool, VM, FIP, private child, public status, and traffic
identity. Removing a member first commits and verifies the narrower aggregate
policy, then withdraws that Service's public/private status and child; siblings
remain active. InSpace DNAT therefore lands on Cilium's private frontend without
NodePorts or `externalIPs`, and no crash boundary makes a public rule reachable
before its exact private frontend is safe to publish.

The shard NodePool is the durable mutation anchor. It stores the shard firewall
identity, full SHA-256 applied membership/policy ledger, and pending
membership/policy fence. The CCM-owned `inspace.cloud/node-lb-state` finalizer
keeps this anchor alive until cloud cleanup is authoritatively complete.
After a timeout or controller restart, authoritative readback decides whether a
pending update reached the cloud; CCM permanently retains the issued fence and
never repeats an ambiguous rule update merely because time elapsed. It resumes
only after the pending policy is observable or explicit operator resolution.
A fresh shard attaches its aggregate firewall once while the node is not
publicly advertised, verifies assignment and Node recovery, and then enables the
protected readiness label and statuses. Migration first closes the old
functional child and removes its UID from the old ledger. It then retires the
old shard when unused and prepares replacement capacity and its firewall while
the Service remains detached; cutover is fail-closed and break-before-make.

A port or source-range edit uses the same closed restage fence: the functional
child and public status read back empty before the new member hash can enter the
aggregate ledger. The child remains empty through the in-place `PUT`, policy
promotion, and assignment readback, so an old wider rule cannot reach the
edited Service after a crash.

Firewall creation persists deterministic staged intent and a separate issued
marker before the paid POST. If that POST has no authoritative readback, CCM
keeps the NodePool or NodeClass finalizer and refuses every second create; no
finite run of empty list responses can prove that the original request did not
commit later. Reconciliation resumes only when the exact stable-name resource
becomes observable or an operator resolves the attempt after cloud-side proof.
Known-resource deletion still requires three absence observations at least 30
seconds apart, and visibility resets that evidence. Service finalization
requires the Service UID to be absent from the
applied shard membership ledger as well as three spaced authoritative absence
observations for its own exposure. The final Service and deleting NodePool
remain cleanup anchors: CCM withdraws the Service, deletes node capacity,
proves the aggregate firewall is unassigned, deletes that firewall, requires
three spaced absence reads, and only then removes both finalizers. NodePool
deletion uses foreground propagation so Kubernetes can terminate its
`blockOwnerDeletion` NodeClaims while the CCM state finalizer retains the
firewall ledger; background deletion would deadlock those two requirements.
If another actor starts background deletion, CCM safely reissues the exact
UID-fenced request as foreground only while managed NodeClaims remain; it never
re-adds `foregroundDeletion` after those direct dependents drain. The cluster
ICMP identity is persisted on the generated NodeClass. Its
`inspace.cloud/node-lb-cluster-state` finalizer is a separate durable ledger
anchor: external deletion first fails the cluster closed, drains every shard,
proves ICMP absence, and records a Service-side handoff before finalizer
release. Normal last-owner cleanup deletes the generated NodeClass only after
all managed NodePool, NodeClaim, and Node capacity is absent.

### Endpoint-local edge contract

`public-node-local` is an explicit branch of the user-facing
`inspace.cloud/node` class. It requires `externalTrafficPolicy: Local`, explicit
`allocateLoadBalancerNodePorts: false`, a non-empty selector, and the DNS-label
pool annotation `service.inspace.cloud/node-lb-pool`. Eligible Nodes must carry
the matching protected
`inspace.cloud.node-restriction.kubernetes.io/public-local-pool` label. They
must also be Ready, non-deleting, non-control-plane, not excluded from external
load balancers, and host a Ready, non-terminating EndpointSlice endpoint for
that exact Service. `publishNotReadyAddresses: true` is rejected because it can
make an unready backend appear Ready in EndpointSlice data.

This mode owns no capacity or address lifecycle. A Karpenter-backed Node must
resolve through the exact Node-to-NodeClaim-to-NodePool-to-NodeClass chain. Its
NodePool template carries the protected pool label and its NodeClass uses
`firewallProfile: public-node-local`. Karpenter normally synchronizes that
template label after registration; CCM independently proves the chain and
ensures the label is present before exposure. The NodeClass must reserve a
public IPv4 and use the exact configured private base-firewall UUID; CCM also
audits the VM's complete base-plus-Service assignment set before publication.
A non-Karpenter Node instead requires an administrator to apply the protected
label directly; a kubelet cannot self-apply that label. In both paths CCM still
verifies the exact providerID, VM, private address, and FIP before eligibility.
Karpenter or the administrator—not CCM—owns VM/FIP lifecycle. The administrator
is responsible for an equivalent default-deny base firewall on a manual node.
CCM publishes the sorted FIPs as public `ipMode: Proxy` status and owns one
deterministic per-Service TCP/UDP firewall. The firewall is attached to exactly
the eligible endpoint VMs and uses the Service's canonical IPv4
`loadBalancerSourceRanges`, or Any when omitted. The provider's NodeClass audit
permits only that exact class of additional firewall alongside the private base
firewall.

CCM also owns a same-namespace `inlb-dp-<service-identity>` child with the
exact parent owner reference, `loadBalancerClass: inspace.cloud/node-datapath`,
Local policy, no data-port NodePorts, and the same selector/ports. Kubernetes
still allocates one `healthCheckNodePort` for each Local LoadBalancer Service;
CCM does not publish that port in the InSpace firewall. The child publishes
eligible private Node InternalIPs with `ipMode: VIP`; the parent publishes the
paired public FIPs with `ipMode: Proxy` only after the private status and
firewall assignments read back exactly.

Readiness, endpoint, label, identity, conflict, or cloud-readback failure is
fail-closed: CCM detaches the Service firewall and requires authoritative
readback before shrinking either public or private status. First publication
keeps a durable assignment fence through activation and public-status
readback, then clears it last. Deleting the Service removes only the
deterministic firewall and finalizer; it must not move or delete a FIP or delete
user capacity. Every `(protocol, port)` claim is exclusive across the entire
named pool, independent of the current endpoint-node overlap. The lowest
lexicographic Service UID wins; CCM withdraws and detaches the loser and emits
`PublicNodeLocalPortConflict`. A Karpenter roll may change the published
address, so operators needing stable membership should use a static NodePool,
`expireAfter: Never`, disruption budgets, and short DNS TTLs.

### InSpace mutation outcome contract

The official InSpace API exposes no idempotency-key contract. Therefore an
HTTP error describes the response, not whether the mutation committed. This
rule applies to all 22 write methods in the shared client:

| Class | Client methods | Required controller behavior |
| --- | --- | --- |
| Resource creation | `CreateVM`, `CreateDisk`, `CreateFloatingIP`, `CreateFirewall`, `CreateLoadBalancer` | Persist immutable intent and an issued receipt before the POST. After that durability CAS, repeat the exact deterministic-name/ownership inventory: adopt one exact owned match, dispatch only from authoritative absence, and retain the receipt on a foreign, duplicate, or failed read. Never send a second POST while the first outcome is unresolved. |
| Relationship creation | `AttachDisk`, `AssignFloatingIP`, `AssignFirewallToVM`, `AddLoadBalancerTarget`, `AddLoadBalancerRule` | Fence the exact resource pair or rule before POST. Treat exact duplicate relationship rows as one set member, but reject malformed rows or the same resource on a different owner. |
| Deterministic replacement | `UpdateFloatingIP`, `UpdateFirewall` | Persist the exact desired payload/generation, issue once, then compare authoritative readback with both the applied and pending payload. A third state fails closed. |
| Relationship removal | `DetachDisk`, `UnassignFloatingIP`, `UnassignFirewallFromVM`, `RemoveLoadBalancerTarget`, `RemoveLoadBalancerRule` | Persist the exact stable pair/UUID and an issued receipt before dispatch. Once issued, never repeat the removal merely because the relationship remains visible; require exact authoritative absence or explicit operator resolution. |
| Resource deletion | `DeleteVM`, `DeleteDisk`, `DeleteFloatingIP`, `DeleteFirewall`, `DeleteLoadBalancer` | Delete only an exact durably owned UUID/address after persisting an issued receipt. Never replay an issued delete after any returned result; keep the finalizer or teardown receipt until repeated authoritative absence releases dependents and ownership state. |

The shared client never automatically replays POST, PUT, PATCH, or DELETE, and
blocks redirects for those methods. Every error returned after dispatch is
ambiguous until authoritative readback proves the exact result. This includes
every HTTP error status, transport failure, deadline/cancellation, response-read
failure, malformed 2xx body, and mutation redirect. `APIError.Retryable` is only
a scheduling hint; it is never proof that a write did not commit. A controller
may clear an additive or replacement receipt automatically only for a
positively identified local pre-dispatch block, or after a successful exact
read proves the intended commit. An HTTP 4xx plus an unchanged/absent read is
not terminal proof because the mutation may become visible later. For removals,
a fresh read that still shows the exact owned relationship or resource is only
evidence that cleanup remains unresolved; it is never authority for a second
dispatch. Only a positively identified local pre-dispatch block may reset an
issued receipt automatically.

A UUID or other handle in a mutation response is provisional evidence, not
ownership authority. Controllers promote only the canonical identity recovered
from a fresh exact ownership read; a valid-looking foreign response handle is
ignored while deterministic-name discovery finds the resource that actually
committed. Every controller repeats its mutation-target or create-absence proof
after its Kubernetes or status-store CAS and immediately before dispatch, so a
concurrent change during receipt persistence fails closed instead of crossing
the cloud boundary. The file-journal live probe applies the same rule after its
fsynced durability boundary.

Durable anchors are component-specific:

- fixed bootstrap uses the bounded `InSpaceCluster.status.createAttempts` and
  `status.deleteAttempts` ledgers, or the atomically locked cluster YAML status
  store for the standalone controller. Issued bootstrap removals are permanent
  no-replay locks until exact authoritative absence; VM absence is persisted
  and observed twice with a minimum interval;
- standard paid NLB and per-Service NodeLB operations use exact-UID Service
  annotations;
- shared NodeLB operations use their generated NodePool or NodeClass;
- CSI uses immutable namespace-scoped Lease receipts. Disk-delete and detach
  absence is stored in those Leases and completes only after three observations
  at least 30 seconds apart; visibility resets only the absence evidence.
  Attachment discovery exact-reads the union of every unfiltered location VM
  row and every configured-VPC member, so an outside-VPC attachment fails
  closed;
- Karpenter uses the NodeClaim create and removal fences plus the fixed, non-expiring
  `karpenter-inspace-firewall-mutations` Lease. That Lease stores independent
  per-firewall CAS receipts, so only one controller invocation can dispatch an
  assignment or detachment for a shared base firewall while unrelated
  firewalls may progress independently. Karpenter persists the issued receipt
  and terminal result; terminal destructive/removal state requires three fresh
  authoritative observations at least 30 seconds apart. A restart before the
  terminal write safely starts that observation sequence again.

Karpenter owns and removes only the exact private base-firewall relationship
persisted in its NodeClaim receipt. CCM exclusively owns the shared ICMP,
NodeLB shard, and per-Service firewall relationships. Fixed bootstrap is fully
Ready, with all control-plane relationship receipts materialized, before the
Karpenter controller starts; this is required because the target cluster and
its Lease coordinator do not exist during pre-cluster bootstrap.

An empty list is not sufficient to release an issued additive mutation: the
provider may have committed it but not exposed it through every read model yet.
When an issued operation remains unresolved, pause that controller and obtain
provider-side terminal no-commit proof before clearing only the exact receipt.

### Recovering a permanently fenced CCM mutation

A retained issued marker is a safety condition, not a retry timer. Pause the
CCM before operator recovery and save the complete Service, generated NodePool,
and generated NodeClass YAML. Audit InSpace in the configured location and
billing account using both the deterministic firewall name and every persisted
UUID. If the exact resource exists, do not clear state: resume CCM so it can
adopt, promote, or delete that resource normally.

Repeated empty list responses alone are not proof that an issued POST or PUT
cannot commit later. Clear a fence only after InSpace or provider support has
confirmed that the request reached a terminal no-commit result, or after the
exact resource was deleted and the original operation is known to be terminal.
For an ambiguous PUT, the observed cloud policy must exactly equal either the
persisted applied policy or pending policy; any third policy requires manual
cloud repair or support escalation before controller state is changed.

After that external proof, remove only the transaction annotations. For a
standard paid NLB Service, remove only
`service.inspace.cloud/public-nlb-mutation`. For a per-Service NodeLB, the
create receipts are `service.inspace.cloud/node-lb-pending-firewall-name`,
`service.inspace.cloud/node-lb-pending-firewall-started-at`,
`service.inspace.cloud/node-lb-pending-firewall-issued-token`, and
`service.inspace.cloud/node-lb-pending-firewall-issued-at`; the exact relation
receipt is the pair
`service.inspace.cloud/node-lb-firewall-relation-issued` and
`service.inspace.cloud/node-lb-firewall-relation-owner-uid`. After the required
provider-side terminal no-commit proof, remove both relation keys atomically
from the same exact Service, NodePool, or NodeClass owner; removing only one
leaves an intentionally fail-closed orphan receipt. For an
emergency withdrawal, retain the `node-lb-withdraw-firewall-*` ledger unless
provider-side proof covers every persisted firewall/VM pair. For a shard
NodePool the transaction annotations are the `node-lb-shard-firewall-pending-*`,
`node-lb-shard-firewall-issued-at`,
`node-lb-shard-firewall-create-absence-*`, and
`node-lb-shard-firewall-cleanup-observed-uuid` annotations. For the generated
NodeClass they are `node-lb-icmp-pending-firewall-*`,
and `node-lb-icmp-create-issued-at`. A Karpenter NodeClaim uses
`karpenter.inspace.cloud/create-fence` and
`karpenter.inspace.cloud/floating-ip-update-fence`; its shared base-firewall
coordinator is the `karpenter-inspace-firewall-mutations` Lease in the
Karpenter namespace. Do not edit any of these receipts while a VM,
base-firewall assignment/detachment, or FIP PATCH is unresolved. Never
remove the applied UUID/hash/ledger, ownership labels, or controller finalizers
during recovery. Resume the controller and let it perform its normal
authoritative readback and spaced cleanup proof. Blindly removing a finalizer
can orphan a billable resource.

Karpenter automatically decodes the v2 create-fence schema as conservative v3
state. Materialized v2 claims become observed base-firewall assignments;
reserved claims remain intent-only; issued claims remain issued/read-only and
cannot gain a new POST solely because the controller restarted. An issued v2
claim whose FIP PATCH outcome cannot be distinguished is also kept read-only.
No manual migration is required, but an already ambiguous v2 receipt may still
need the provider-side operator resolution described above.

Public exposure also retains the explicit, paid, TCP-only InSpace NLB path documented in the
[public Service example](charts/inspace-cloud-kube-modules/examples/service-public-nlb.yaml).
Public NLB Services use `externalTrafficPolicy: Local`; CCM watches
EndpointSlices and keeps targets limited to eligible Ready nodes with a Ready,
non-terminating local endpoint. InSpace does not probe the allocated
`healthCheckNodePort`, so node and endpoint events—not an NLB health check—drive
target convergence. Shared public-target eligibility excludes both
`node-role.kubernetes.io/control-plane` and legacy
`node-role.kubernetes.io/master` labels, including for `Cluster`. Kubernetes
defaults an omitted policy to `Cluster`; the CCM deliberately does not mutate
Service specs, so `Local` must be explicit.

Operators must reserve an inclusive 16-256-address RFC1918 range for Cilium LB
IPAM and exclude it from InSpace VM and NLB allocation. The InSpace API has no
range-reservation operation, so controllers detect collisions and fail closed
but cannot create the reservation. Treat the range as immutable after cluster
creation because changing it can reassign Service VIPs.

Cilium L2 Announcements is a beta feature and requires the VPC to accept ARP and
gratuitous ARP for VIPs not assigned to a VM NIC. Release acceptance must prove
that behavior before production use.

The workload chart's `global.inspace.controlPlaneVIP`, VPC UUID, and private
load-balancer range must exactly match bootstrap and every NodeClass. CCM uses
the VIP and range to reject public-NLB address collisions; Karpenter rejects a
NodeClass that differs before cloud validation or worker provisioning.

### Worker ownership and deletion

Every VM create request carries the configured VPC UUID. Karpenter additionally
requires the created VM UUID to appear exactly once in the network's
authoritative `vm_uuids` readback.

Workers are created with `reserve_public_ip=true`. InSpace initially assigns a
nameless floating IP while the VM's `public_ipv4` remains empty. Karpenter
assigns the prevalidated cloud firewall immediately after the VM POST and proves
its exact policy and sole assignment. It then discovers the VM's sole floating
IP, validates it, patches its deterministic name and billing account, and
requires exact readback.

Version 3 ownership records persist the deterministic floating-IP name but omit
`publicIPv4`; the live assignment remains authoritative. The returned NodeClaim
stores the exact name, address, and billing account as durable orphan-cleanup
identity. Deletion always dispatches the exact VM UUID first, proves core
Get/List/VPC absence, removes only the exact Floating IP, proves VM and
FIP-assignment absence again, and finally removes every stale firewall
assignment for the UUID. The shared firewall itself is not deleted with an
individual worker.

Karpenter VM creation also uses a durable one-POST fence. After its issue CAS,
fresh deterministic-name and ownership inventory either adopts one exact VM or
proves the absence needed to authorize POST. The SDK response UUID remains
provisional until canonical detail proves the complete v3 launch identity and
billing account and the configured VPC contains it exactly once. An independent
rollback CAS prevents a retry from racing successful adoption. The provider
finalizer tracks an unknown auto-FIP through the original ambiguity window,
including a pre-existing target/FIP association during adoption. An issued
ambiguous POST is never retried or auto-released from empty lists. Use the
issue-bound operator resolution protocol in the
[Karpenter provider runbook](modules/karpenter-provider/README.md#recover-an-unresolved-vm-create-fence);
never edit the opaque fence JSON or remove its finalizer manually.

Full-cluster acceptance binds the VM UUID to the Kubernetes Node provider ID,
requires its sole `InternalIP` to belong to the configured VPC, and requires the
CCM-published `ExternalIP` to equal the assigned floating IP.

## Credentials and safety

Copy [`.env.example`](.env.example) to `.env` for local credentials and set
its mode to `0600`. The real workspace `.env` is ignored by Git and excluded
from every Docker build context.

The following rules apply to every development and test workflow:

- Automated tests and smoke tests use loopback or in-memory fake APIs.
- Normal root tests unset InSpace credentials and remote-mutation gates.
- Live discovery is read-only and must be explicitly selected.
- The root live lifecycle probe uses a durable local journal, unique
  `inspace-e2e-*` names, and zero-residue audits before and after its mutation.
- Mutating requests to `api.inspace.cloud` are denied by default in the shared
  client. The root live-suite wrapper sets its mutation gates only after the
  billing-account confirmation succeeds. The former direct module lifecycle
  targets are retired because they could not survive process loss safely.
- API tokens, join tokens, private keys, generated kubeconfigs, state journals,
  and credential-bearing Helm values must never be committed or printed.
- The bootstrap-cache key is operator secret material even though it is not an
  API credential; keep `INSPACE_BOOTSTRAP_CACHE_KEY` and both persisted cache
  initialization files out of logs and source control.

## Local verification

Run the repository checks from the root:

```sh
make test
make smoke
make verify
make helm-verify
make images
make status
```

`make test` and `make smoke` cannot use local InSpace credentials. Smoke tests
exercise only fake-cloud lifecycles. `make verify` combines module tests, smoke
tests, vet, Helm verification, bootstrap-manifest checks, and static E2E
validation. Before opening a pull request, run the checks required by
[CONTRIBUTING.md](CONTRIBUTING.md).

## Isolated-account API lifecycle tests

The read-only audit and explicitly gated lifecycle suite use the root `.env`:

```sh
make live-audit
CONFIRM_INSPACE_LIVE_TEST="$INSPACE_BILLING_ACCOUNT_ID" make live-test
```

The default lifecycle suite performs a durable firewall create/delete
conformance check and a cross-location zero-leftover audit before and after the run. Never run
it against a production billing account or from a pull request.

The wrapper journals its direct firewall mutation in
`.e2e/live-suite/firewall-mutation.json` before dispatch and fsyncs both the
file and its parent directory. After that boundary, create re-lists the
deterministic name and either adopts one exact unassigned owned firewall or
dispatches only from authoritative absence; delete re-reads the exact UUID,
name, billing account, policy, and empty assignment set before dispatch. Its
random ownership token, billing scope, normalized policy hash, and eventual
UUID must all match authoritative readback before the firewall can be adopted.
The POST response UUID is diagnostic only and never becomes the cleanup anchor.
HTTP success, HTTP errors, timeouts, and interrupted response reads are all
treated as ambiguous. An issued POST or DELETE is never replayed. Delete
absence is persisted in the journal and completes only after three observations
at least 30 seconds apart; reappearance resets that evidence while retaining
the issued receipt, and restart resumes the persisted count.

If the wrapper reports a permanently unresolved receipt:

1. Stop every live-suite process. Remove `.e2e/live-suite/lock` only after
   proving that it is stale.
2. Keep the receipt. Compare its API URL, location, billing account, exact
   firewall name, UUID when present, and policy hash with repeated authoritative
   firewall-list reads.
3. For `create-issued`, rerun the suite when the exact resource becomes visible;
   it will adopt and clean up that resource without another POST. If the
   provider confirms that the request never committed, only an operator may
   archive the evidence and remove the receipt after a suitably spaced absence
   audit.
4. For `delete-issued`, never rerun DELETE through the harness. Rerun the suite
   after the original delete becomes visible; repeated exact absence will clear
   the receipt. If the resource remains, preserve the receipt while resolving
   it with the provider.

Never remove an issued receipt merely because one list response omits the
resource. The journal contains no API token, but it is operational evidence and
must not be committed.

Receipt replacement fsyncs the mode-0600 file before atomic rename and then
fsyncs its parent directory; receipt removal also fsyncs the parent. The
black-box contract covers committed and uncommitted HTTP 4xx/5xx responses and
transport disconnects for both POST and DELETE.

The old direct Go module lifecycle diagnostics are retired. They used
process-local cleanup for multi-resource VM, FIP, NLB, disk, and adapter
sequences, so a committed HTTP error or process loss could strand resources.
Use the guarded full-cluster E2E workflow below for component release
acceptance; its controllers persist their own cloud-mutation receipts.

## Full-cluster release acceptance

From a checkout matching an exact published release candidate, the destructive
release-acceptance suite proves the complete cluster lifecycle: three
stock-Ubuntu RKE2 control planes with embedded etcd, a bastion, and one
Karpenter worker, all on the configured AMD EPYC pool; Cilium native routing
and kube-proxy replacement; CCM node identity; public-IP egress and RKE2 join;
the default private bootstrap cache and its pinned TLS trust; an RWO CSI volume
that retains data through pod replacement; and a public TCP NLB response. The
default workflow finishes with an exact-ownership,
zero-leftover cloud audit.

```sh
export INSPACE_E2E_VERSION='<published-version>'
export CONFIRM_INSPACE_CLUSTER_E2E="$INSPACE_BILLING_ACCOUNT_ID"
make cluster-e2e
```

The default `all` workflow runs cluster initialization, acceptance tests, and
destruction in order. Maintainers can preserve and reuse a cluster while
debugging test-only changes:

```sh
make cluster-e2e-init
make cluster-e2e-test
make cluster-e2e-shell
make cluster-e2e-test
make cluster-e2e-destroy
```

`test`, `shell`, and `destroy` use `INSPACE_E2E_RUN_ID` when set, or the last
run persisted in the shared state volume otherwise. The interactive shell
reestablishes the private-API tunnel and exports `KUBECONFIG` for direct
`kubectl` debugging. Phase containers hold the state-volume lock for their
entire lifetime; `init`, `test`, and `shell` preserve the cluster instead of
destroying it on exit or failure. Their durable phase marker also prevents a
later default run from cleaning them implicitly; use the explicit destroy
target. A shell can attach after a late init failure once the kubeconfig and
pinned bastion access facts exist.

If the default workflow was explicitly retained with
`INSPACE_E2E_KEEP_RESOURCES=true`, its later destroy requires both the selected
run and explicit retained-cleanup authorization:

```sh
export INSPACE_E2E_RUN_ID='<persisted-run-id>'
export INSPACE_E2E_RECOVER_RETAINED=true
make cluster-e2e-destroy
```

The host entrypoint only builds and starts the pinned E2E runner image. The
Ansible controller, bastion-mediated private-node access, Helm, and Kubernetes
clients run inside that container; the host never runs the live-test toolchain.
See the [full-cluster E2E guide](test/e2e/README.md) for prerequisites, state
recovery, and the fail-closed cleanup contract.

## CI architecture

Current InSpace compute instances are x86-64, so image CI and releases build
`linux/amd64` by default. Native `linux/arm64` jobs remain available by
setting the repository variable `ENABLE_ARM64_IMAGES=true`; disabled ARM jobs
remain in the workflows for future instance support. The complete artifact and
promotion process is documented in [RELEASING.md](RELEASING.md).

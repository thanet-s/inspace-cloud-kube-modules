# Karpenter Provider for InSpace

This repository implements the InSpace provider for Karpenter `v1.14.0` and RKE2. It includes a production API adapter, `InSpaceNodeClass`, a 31-variant instance catalog, stock-Ubuntu bootstrap, NodeClass readiness reconciliation, and a runnable Karpenter controller command.

## Supported contract

- Location `bkk01`, Linux/amd64, on-demand capacity
- `intel-scalable` host pool `aac7dd66-f390-4edd-80c0-dd7cae49bd99`
- `amd-epyc` host pool `6976fdc8-4492-465b-bd16-9ad5f6b00b03`
- The original 24-shape matrix: `compute`, `general`, and `memory` families at
  1, 2, and 4 GiB/vCPU for CPU sizes `2, 4, 6, 8, 10, 12, 14, 16`
- Two additional single-core shapes, `is-general-1c-2g` and
  `is-memory-1c-4g`
- The `extra-memory` family at 8 GiB/vCPU for CPU sizes `1, 2, 4, 6, 8`;
  it stops at 8 vCPU because instances cannot exceed 64 GiB RAM
- Maximum 16 vCPU / 64 GiB across the catalog
- Ubuntu 24.04 and an exactly pinned RKE2 agent version
- Ephemeral root disks; persistent workload data belongs on RWO CSI volumes
- One immutable, inclusive 16-to-256-address RFC1918 Service VIP range reserved
  from worker NIC allocation

Variant names describe raw VM capacity, for example `is-general-1c-2g`, `is-memory-1c-4g`, `is-extra-memory-1c-8g`, and `is-extra-memory-8c-64g`. Allocatable disk reserves 8 GiB for Ubuntu/RKE2 plus a 4 GiB eviction threshold.

Every catalog shape advertises numeric `inspace.cloud/instance-cpu` (cores)
and `inspace.cloud/instance-memory` (MiB) labels. NodePool requirements can use
`Gt`, `Lt`, `Gte`, and `Lte`, for example `instance-cpu Gt ["2"]` or
`instance-memory Gte ["8192"]`. Each shape has separate `intel-scalable` and
`amd-epyc` offerings. Hardware class is selected only with the NodePool
`inspace.cloud/host-class` requirement; it is intentionally absent from
`InSpaceNodeClass`, so the same infrastructure/bootstrap policy can serve a
single-class or mixed-class NodePool. The selected offering is persisted in
the VM ownership record and returned on launched and rehydrated NodeClaims.
When a NodePool omits the host-class requirement, both offerings are eligible
and the provider uses a deterministic tie-break between their equal scheduling
weights. Specify the requirement whenever hardware identity matters.
NodeClass readiness validates both frozen class-to-pool UUID mappings and
reports them as `status.hostPoolUUIDs`.

Catalog offering prices use only the compute rates derived from the current
InSpace custom-VM calculator: `monthly compute THB = CPU cores × 60 + RAM GiB
× 30`, converted to hourly THB with 730 billing hours per month. Root-disk cost
is intentionally excluded from Karpenter's price score; disk size remains a
NodeClass capacity constraint. Intel and AMD offerings for the same VM shape
have the same price. Revalidate these frozen rates against InSpace before using
cost-based consolidation decisions in production.

`spec.rke2` is the required bootstrap contract; the legacy `spec.k3s` field is
not accepted. The RKE2 bootstrap schema has a distinct drift hash, including
the exact-VPC private-IP, verified-UFW, and bounded-agent-start contract, so
existing
K3s-backed NodeClaims are treated as drifted and replaced through Karpenter's
normal disruption controls after their NodeClasses are migrated.
The current immutable bootstrap schema is `stock-ubuntu-rke2-v11`; its bounded
local-hostname readback change makes workers rendered with older bootstrap
schemas eligible for normal Karpenter drift replacement.

`spec.rke2.skipOSUpgrade: true` is an explicit short-lived-test optimization.
It removes only the worker's one-time `apt-get upgrade -y`; mirror and resolver
setup, `apt-get update`, required package installation, and automatic-update
shutdown remain mandatory. Omitted or `false` keeps the production default.

`spec.bootstrapCache` makes the worker download path explicit. A cached
NodeClass sets `directDownload: false`, the bastion's canonical RFC1918
`address`, and the PEM public `caBundle` produced by control-plane bootstrap.
The provider derives `cache.<spec.clusterName>.inspace.internal:8443`, probes
that endpoint with the pinned CA before creating a billable VM, and binds the
stable hostname to the supplied address in worker `/etc/hosts`. Worker
cloud-init then downloads the RKE2 release assets from the cache and configures
RKE2's system-default registry to use it.

A direct NodeClass sets `directDownload: true` and must omit both `address` and
`caBundle`. It downloads RKE2 assets and system images from their upstream
HTTPS locations and installs no cache CA, host entry, or registry setting.
The cached-mode CA is an ECDSA P-256 certificate minted from the persisted real
cluster-initialization instant with an exact 15-calendar-year validity window.
Keep the NodeClass mode aligned with `InSpaceCluster.spec.bootstrapCache`; a
partially configured cache is rejected rather than silently falling back to
the public internet. The registry configuration contains no public-registry
mirror rules, so arbitrary workload images retain their original repositories
in either mode.

## Public IPv4 and firewall model

InSpace currently has no managed NAT gateway, so each worker must have exactly one provider-owned floating public IPv4 for internet egress. It is reserved in the initial VM create request so cloud-init has internet access from first boot. The guest NIC still exposes exactly one private RFC1918 address. The private address is the Kubernetes `InternalIP`; the CCM publishes the floating address only as `ExternalIP`. The managed base firewall blocks public ingress to the floating address.

`spec.firewallProfile` defaults to `private-worker`, which preserves the
exact-one-firewall rule. CCM-generated public load-balancer NodeClasses use
`public-node-load-balancer`: the base firewall remains private, while additional
firewalls are accepted only under two exact contracts:

- A Service firewall is named
  `inlb-<cluster-hash>-<Service-UID>-<policy-hash>` and contains only canonical
  explicit inbound TCP/UDP single-port rules. Its hash covers protocol, port,
  and canonical IPv4 source ranges; ICMP and outbound rules are forbidden.
- At most one cluster firewall is named
  `inlb-<cluster-ownership-hash>-icmp-<policy-hash>` and contains exactly one
  portless inbound ICMP-from-Any rule. InSpace has no ICMP type/code filter, so
  it permits all IPv4 ICMP from Any.

The cluster ICMP firewall may be absent during initial VM launch; CCM attaches
the shared firewall only after the authoritative Kubernetes identity exists and
does not advertise that node until it and all required Service firewalls are
visible. Foreign, unowned, malformed, duplicate cluster-ICMP, or hash-drifted
additional assignments fail the VM audit. Firewall descriptions are not
ownership authority because InSpace omits them from readback.

The provider uses a fail-closed sequence:

1. Validate that the supervisor VIP and both endpoints of the exact reserved
   Service VIP range are distinct usable host addresses—not network or
   broadcast addresses—inside the selected RFC1918 VPC.
2. Validate the intended default-deny firewall and reject any active Floating
   IP that already uses this NodeClaim's deterministic provider-owned name.
3. Persist a v3 VM ownership record containing the deterministic
   provider-owned Floating-IP name, but no address that is not yet known.
4. Create the VM with the NodeClass `network_uuid` and
   `reserve_public_ip=true`. InSpace assigns one initially nameless Floating IP
   to the new VM for immediate cloud-init egress; the VM's `public_ipv4` field
   must remain empty.
5. As the first post-POST mutation, assign the prevalidated firewall using the
   returned VM UUID. Require authoritative read-back of the exact base policy
   and assignment. Ordinary workers require exactly that one firewall. Public
   node-load-balancer workers require the base exactly once and permit only
   audited CCM Service firewalls plus at most one audited cluster ICMP
   firewall.
6. Read back the VM until its complete NodeClaim ownership/spec record, exact
   name, capacity, image, host pool, VPC, billing account, and one correctly
   sized primary root disk are persisted.
7. Read back that exact network until the VM UUID appears exactly once in its
   authoritative `vm_uuids` membership, and require exactly one usable
   RFC1918 private IPv4 inside that VPC; reject an address equal to the private
   RKE2 supervisor VIP or inside the reserved Service VIP range.
8. Discover exactly one enabled, non-virtual, non-deleted public Floating IP
   assigned to that owned VM UUID. Reject no assignment, multiple assignments,
   a foreign deterministic-name collision, or a conflicting name or billing
   account; v3 never calls the separate Floating-IP create operation.
9. Patch an acceptable nameless assignment with the deterministic name and
   NodeClass billing account, then require an exact name/account/assignment
   read-back before using its address.
10. Re-audit that no second, foreign, or unusable Floating IP is assigned to the
   worker.
11. Return the NodeClaim only after VPC attachment and both protections are
   confirmed.

Network membership and canonical VM read-back each have a 60-second bound,
10-second request bounds, exponential polling, and retries for transient read
failures or fields that are still absent. Any launch-identity value that is
already present but conflicts with the request fails immediately. Ambiguous VM
create responses, restarts before Floating-IP rename, and inconclusive PATCH
responses are recovered by reading the owned VM and its exact sole assignment;
the provider does not issue another VM or Floating-IP create request. A fresh
POST uses the preflight-validated firewall UUID for immediate protective
attachment before canonical VM convergence. Cancellation after the POST does
not cancel this bounded safety read-back. A valid UUID returned alongside any
error is used only as a protective-attachment anchor; canonical v3 ownership
is still required for adoption or deletion. A nil/UUID-less response is
recovered by deterministic reads without issuing a second POST, and the
firewall is attached as soon as one unique valid UUID becomes visible. An existing owned VM is instead
fully read and validated before any mutation. Conflicting policy or a foreign
firewall outside the effective profile fails closed without deleting that
established VM; if the VM has no base firewall and the intended assignment
cannot be restored, the canonically owned public VM is deleted rather than left
exposed. A fresh successful POST whose firewall
attachment or canonical ownership cannot be proven is rolled back. Cleanup
first tries to durably name and delete the exact auto-FIP; if that address
remains invisible, security takes priority and the fresh public VM is deleted
without guessing at a nameless FIP. Cleanup uncertainty is joined to the
launch error, and the firewall stays attached if VM deletion is uncertain. A temporary adoption
read-back failure is returned for reconciliation without destroying that VM. A
fresh or late-ambiguously-committed VM whose private address equals its
ownership-recorded supervisor VIP or falls inside its ownership-recorded
Service VIP range is unsafe and is rolled back. The same drift on an
established VM fails closed without destructive mutation; generic ownership
mismatches are never deleted. Delete removes the
named Floating IP before deleting the VM. One VM-detail 404 never authorizes
cleanup: an already-missing VM must be absent from both `GetVM` and `ListVMs`
in two consecutive bounded observations before its orphan floating IP or
firewall assignments are changed.
A later owned detail resumes the normal ownership-checked delete path; any
presence uncertainty fails without mutation. Create POSTs are never blindly
retried; read-before-create ownership records recover ambiguous responses.
The returned NodeClaim persists the exact Floating-IP name, address, and billing
account as a durable deletion identity. Only all three matching an authoritative
inventory row can authorize orphan cleanup after the VM is already absent;
an older v3 claim with only name/address may finish when two reads prove that
no overlapping FIP exists, but it cannot mutate an active address. Legacy
v1/v2 VM records retain their own address/account retry anchor.

`GetVM` and `ListVMs` repeat these checks through a bounded read-only snapshot.
VM list rows are only discovery and collision evidence: exact per-VM detail is
the ownership authority, including when the list omits descriptions. `ListVMs`
resolves detail with at most eight parallel reads, omits a row that became 404
after the snapshot, retries an incomplete detail when either view contains
Karpenter ownership evidence for the requested cluster (or cannot yet expose
the cluster), and fails closed if that evidence does not converge within the
read bound. Complete list and detail ownership records must agree exactly.
Definitively unmanaged descriptions and explicit records for another cluster
remain cluster-independent inventory and are ignored. A schema in the reserved
`karpenter.inspace.cloud/` namespace must be a deliberately supported version; an
unknown version fails closed instead of silently hiding a managed VM. Any other
read or list/detail identity uncertainty also fails closed. One firewall list,
one Floating-IP list, and one network read per unique VPC then detect a
lost/disabled address or an unauthorized second/public firewall,
membership drift, or a private-IP/supervisor-or-Service-VIP collision without
mutating resources.

New v3 ownership records persist the cloud VM/node name separately from the
NodeClaim ownership identity, the deterministic Floating-IP name, and the exact
host-pool UUID, vCPU count, and memory size used at launch. They deliberately
omit `publicIPv4`: the address does not exist when the record is written and is
always recovered from the exact live Floating-IP assignment. Established reads
compare canonical VM name, capacity, image, host pool, VPC, billing account,
and exactly one primary root disk against that record before reporting a worker
healthy. Complete established v1 and v2 records remain available for compatible
read and ownership-checked deletion. Both legacy schemas derive capacity from
the frozen 24-variant set, which intentionally excludes the two added
single-core shapes and the entire `extra-memory` family, and derive the pool
UUID from the frozen host-class mapping. A v1 record additionally uses the
NodeClaim name as its VM/node name. Partial or
contradictory exact fields fail closed; operators should recycle any legacy
worker whose identity cannot be derived.

`spec.networkUUID` and the literal VIP in `spec.rke2.server` must exactly match
the controller-wide `INSPACE_NETWORK_UUID` and `INSPACE_CONTROL_PLANE_VIP`.
This prevents a valid-looking NodeClass for another VPC or supervisor from
launching workers that cannot join this cluster. `spec.rke2.server` must be
`https://<RFC1918-VIP>:9345`: a literal private
supervisor virtual IPv4 inside the NodeClass VPC and outside pod CIDR
`10.42.0.0/16` and Service CIDR `10.43.0.0/16`. The VPC itself must be disjoint
from both fixed cluster CIDRs. DNS names, public addresses, and worker addresses are invalid.
NodeClass readiness proves the VIP belongs to the selected VPC before any cloud
mutation. Every create or adoption revalidates it and rejects a worker private
address collision. The 16-address pool plus a distinct supervisor VIP makes
`/27` the smallest usable VPC; `/28` through `/32` cannot satisfy the contract.

`spec.privateLoadBalancerPool.start` and `.stop` define an immutable, inclusive,
canonical RFC1918 range containing 16 through 256 addresses. Both endpoints
must be usable hosts inside `spec.networkUUID`; the range must exclude the RKE2
supervisor VIP, Cilium pod CIDR `10.42.0.0/16`, and Kubernetes Service CIDR
`10.43.0.0/16`. Every NodeClass must exactly equal the controller-wide
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_START` and
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP` values. This provider reserves and
audits the range; Cilium LB IPAM/L2 configuration is a separate cluster concern.

NodeClass readiness also verifies that its firewall:

- uses a VPC subnet that does not overlap Cilium native-routing pod CIDR
  `10.42.0.0/16`;
- has no public inbound rule, including host-scoped `/32` or `/128` rules;
- contains only TCP, UDP, and ICMP rules;
- allows all-port TCP, UDP, and ICMP traffic from prefixes covering both the
  NodeClass network subnet and Cilium native-routing pod CIDR `10.42.0.0/16`;
  and
- allows all-port TCP, UDP, and ICMP traffic to `any` endpoint for public-IP
  egress from the default-deny cloud firewall.

An exact-VPC-only firewall is not sufficient: packets routed between nodes
retain pod source addresses in `10.42.0.0/16`. The provider validates the
operator-managed rules and fails closed before allocating a floating IP or VM;
it never creates, broadens, or otherwise mutates firewall rules.

Public ingress to ordinary workers is always invalid. Administrative access
must traverse the private VPC through the dedicated bastion; direct public SSH
and NodePort access are not part of either worker profile. Public Node-LB nodes
accept only the CCM-audited Service TCP/UDP rules and shared cluster ICMP rule
described above.

The public profile validates cloud assignments; it is not Kubernetes tenant
isolation. In a multi-tenant cluster, admission and RBAC must reserve direct
`io.cilium/node` Services, `io.cilium.nodeipam/*` annotations,
`Service.spec.externalIPs`, and scheduling onto Node-LB nodes through their
taint/toleration or direct selectors. The generated `NoSchedule` taint is only
a placement guard.

Worker network policy relies on the validated InSpace cloud firewall. Generated bootstrap does not install or enable UFW. One `set -eu` orchestrator runs every bootstrap stage in order, executes `additionalUserData`, reapplies the required node tuning, then disables and verifies UFW before it can start RKE2. The RKE2 service also has an `ExecStartPre` verifier, so initial launch and later restarts fail unless `ufw status` is inactive and its unit is inactive and disabled (an absent unit is safe). It never flushes or rewrites iptables/nftables, which belong to Cilium and RKE2. The adapter replaces a single strict VPC-subnet placeholder with the exact API-reported prefix before VM creation. Bootstrap then requires exactly one guest address in that prefix and writes it as `node-ip`; it never chooses the default interface or mistakes the floating address for a NIC address. It does not set `node-external-ip` and has no external-address placeholder. The external CCM is authoritative: it reads the VM's private address and exact Floating-IP assignment from the InSpace API and publishes them as `InternalIP` and `ExternalIP`. InSpace service targets use the private node address. Deletion removes the Floating IP first, deletes the VM, and only then removes every stale firewall attachment for that exact VM UUID.

## RKE2 agent bootstrap

`cloud_init` is sent as an API-compatible JSON object. On stock Ubuntu 24.04 it:

- sets `/etc/hostname`, the active guest hostname, and RKE2 `node-name` to the
  same validated worker name;
- replaces any stale `127.0.1.1` host entry with that exact worker name and
  retries the exact `getent` readback within a fixed bound before package or
  resolver setup;
- disables active swap and idempotently comments persistent swap entries in `/etc/fstab`;
- configures TOT as the primary Ubuntu mirror and KKU as its request-failure fallback for both regular and security suites;
- replaces DHCP-provided DNS with static Google resolvers and stops and masks `systemd-resolved`;
- waits within one hard ten-minute package-preparation budget for floating-IP egress, then intentionally updates and, unless `spec.rke2.skipOSUpgrade` is explicitly true, upgrades the image before installing `curl`, CA certificates, `gzip`, `iproute2`, `procps`, and `tar`;
- after that one bootstrap package stage, persists `APT::Periodic` disablement and masks/stops `apt-daily`, `apt-daily-upgrade`, and `unattended-upgrades` systemd units so a Karpenter worker never starts an automatic package update later; this policy is reasserted after `additionalUserData`;
- persists and applies IPv4 forwarding plus the RKE2-recommended inotify instance/watch limits under `/etc/sysctl.d`;
- persists a high `nofile` PAM limit and applies `NOFILE`, unlimited process/memory-lock, and unlimited task limits directly to `rke2-agent.service`;
- downloads the exact RKE2 `rke2.linux-amd64.tar.gz` release and its `sha256sum-amd64.txt` asset with at most 60 attempts per asset;
- in cached mode, health-checks the private TLS endpoint first and downloads
  those assets from `cache.<cluster>.inspace.internal:8443`; direct mode uses
  the upstream GitHub release URL;
- verifies the tarball checksum and installed RKE2 version;
- configures the agent to join the stable TCP/9345 supervisor endpoint;
- enables the agent, starts it with `--no-block`, and waits at most 180 five-second checks for `active`, failing immediately on a failed service;
- configures `cloud-provider=external`, NodeClaim labels and taints;
- adds exactly one `karpenter.sh/unregistered:NoExecute` taint; and
- runs `additionalUserData` once via `cloud-init-per`, then re-disables and
  verifies UFW before starting RKE2.

Every VM create request includes Warren-compatible non-empty login fields. By
default the provider sends username `user` with a cryptographically random
32-character password generated immediately before the one VM create POST. The
provider never logs, returns, persists, or hashes that password. It is not an
operator credential. For controlled diagnostic access, configure both optional
NodeClass fields `sshUsername` and `sshPublicKey`; the latter must be exactly one
supported OpenSSH `authorized_keys` public-key line. Private keys are never
accepted or sent.

The RKE2 token is read from `spec.rke2.tokenSecretRef`. Because the NodeClass is cluster-scoped, the reference cannot choose an arbitrary namespace: it is fixed to Secret `inspace-rke2-agent-token`, key `token`, in `INSPACE_SECRET_NAMESPACE` (default `karpenter`). The resolver uses an uncached, resource-name-scoped GET and cannot select the separate `inspace-api` cloud credential Secret.

Worker cloud VM names, guest hostnames, and Kubernetes Node names are exactly
`<cluster>-karp-<NodePool>-<random>`. The provider derives this from the
NodeClaim name, which Karpenter generates as `<NodePool>-<random>`, and applies
the same value to the InSpace VM, the active guest hostname, and RKE2
`node-name`. It requires that prefix relationship and a combined DNS-1123
hostname no longer than 63 characters before any cloud mutation. NodeClaim
ownership and deletion remain bound to the original NodeClaim name; Node
registration binds through the canonical `inspace://<location>/<vm-uuid>`
provider ID.

## Run the controller

Install the upstream Karpenter CRDs, then install the InSpace CRD and controller resources. The controller manifest contains the Karpenter v1.14 core RBAC, provider RBAC, leader-election permissions, and fixed-control-plane scheduling rules for its own service account.

```sh
kubectl apply -f config/crd/bases/karpenter.inspace.cloud_inspacenodeclasses.yaml
kubectl apply -f config/controller/controller.yaml
```

Create two distinct Secrets in `karpenter`: `inspace-api` for the controller's cloud credential and `inspace-rke2-agent-token` for the disposable RKE2 join token. Never reuse the API credential as the join token.

The command at `cmd/controller` requires:

- `INSPACE_API_TOKEN`
- `INSPACE_CLUSTER_NAME`
- `INSPACE_DEFAULT_NODECLASS`
- `INSPACE_NETWORK_UUID`
- `INSPACE_CONTROL_PLANE_VIP`
- `INSPACE_PRIVATE_LOAD_BALANCER_POOL_START`
- `INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP`
- `INSPACE_ALLOW_REMOTE_MUTATIONS=true`

Optional settings include `INSPACE_API_BASE_URL`, `INSPACE_LOCATION`, and `INSPACE_SECRET_NAMESPACE`. The explicit mutation flag prevents an accidentally configured production process from starting with write access.

See `examples/` for NodeClasses and bounded NodePools. Replace all placeholder UUIDs and billing account IDs before applying them.

## Tests

Ordinary verification is fake-only and performs no network calls:

```sh
make test
make smoke
make verify
```

The real lifecycle test is separately gated and uses resource names beginning
with `inspace-e2e-`. It creates a VM with `reserve_public_ip=true`, discovers
and deterministically renames its exact auto-assigned Floating IP, verifies the
empty VM `public_ipv4` field and existing firewall, exercises get/list/delete,
audits Floating-IP-before-VM cleanup, and fails if a prefixed VM or Floating IP
remains:

```sh
INSPACE_RUN_LIVE_TESTS=true \
INSPACE_ALLOW_REMOTE_MUTATIONS=true \
make live-test
```

It additionally requires `INSPACE_API_TOKEN`, `INSPACE_BILLING_ACCOUNT_ID`, `INSPACE_NETWORK_UUID`, `INSPACE_CONTROL_PLANE_VIP`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_START`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP`, `INSPACE_FIREWALL_UUID`, and `INSPACE_AMD_HOST_POOL_UUID`. The live adapter lifecycle deliberately creates its worker on the `amd-epyc` class. The VPC, supervisor VIP, and Service range must satisfy the fixed pod/Service-CIDR constraints above. The supplied firewall must already satisfy the VPC/pod-CIDR TCP, UDP, and ICMP contract above with no public inbound rule; the live test performs a read-only preflight before creating resources. Normal `go test ./...` compiles this test but skips it before reading those values.

That smaller test covers the InSpace API lifecycle only. The separate
[full-cluster release acceptance test](../../test/e2e/README.md) deploys the
fixed RKE2 control plane, Cilium, CCM, CSI, and Karpenter from exact released
versions. Its host launcher invokes Docker only; provisioning, parallel waits,
validation, and cleanup run through Ansible inside the disposable runner image.
It proves one Ready worker has the persisted VM UUID in the configured VPC,
the matching provider ID, and one private `InternalIP` inside that VPC subnet;
then it schedules the RWO/TCP-NLB workload and requires zero owned resources
after teardown.

The local `replace github.com/thanet-s/inspace-cloud-kube-modules/modules/client => ../client` resolves the Kubernetes-independent shared API client inside this monorepo.

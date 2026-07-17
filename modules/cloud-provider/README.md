# cloud-provider-inspace

InSpace Cloud integration for Kubernetes/RKE2. This repository contains the
shared location-aware API client, an external cloud-controller-manager (CCM),
and the fixed three-server RKE2 bootstrap reconciler.

## Implemented

- VM, block disk, attach/detach, private network, stock VM image, firewall,
  floating IPv4, and TCP network-load-balancer API contracts.
- Canonical node provider IDs: `inspace://<location>/<vm-uuid>`.
- Kubernetes `InstancesV2`: private VM address as `InternalIP`, explicitly
  assigned floating IPv4 as `ExternalIP`, location as zone.
- Kubernetes `LoadBalancer` has two disjoint paths: private Services use
  Cilium LB-IPAM plus L2 announcements, while explicitly public TCP Services
  use deterministic InSpace NLB/FIP ownership.
- A reconciler that first creates one fixed Ubuntu 24.04 bastion
  (1 vCPU/2048 MiB/30 GiB), then creates exactly three Ubuntu 24.04 RKE2
  servers in deterministic slot order. Each server's restrictive firewall
  assignment is authoritatively proven before the next VM POST; already
  protected servers may continue booting in parallel. The API and RKE2
  registration use a caller-selected private VPC VIP; bootstrap creates no
  control-plane NLB.
- A cache-by-default bastion path. The cache listens only on the bastion's
  allocator-assigned private address as
  `cache.<metadata.name>.inspace.internal:8443`; it does not allocate another
  VIP. `spec.bootstrapCache.directDownload: true` explicitly disables it.
- Fixed control-plane VM, guest-hostname, and Kubernetes Node identities are
  `<metadata.name>-cp0`, `<metadata.name>-cp1`, and `<metadata.name>-cp2`.
  The bastion VM and guest hostname are `<metadata.name>-bastion`.
  `metadata.name` must be a lowercase DNS label of at most 55 characters.
- A per-node RKE2 static Pod running kube-vip v1.2.1 by immutable multiarch
  digest. It advertises only the control-plane VIP with ARP and leader
  election; Kubernetes Service handling is disabled. The Pod mounts the host
  RKE2 kubeconfig `/etc/rancher/rke2/rke2.yaml` at kube-vip's standard
  `/etc/kubernetes/admin.conf` path, maps `kubernetes` to `127.0.0.1`, and
  does not set `k8s_config_file`. Its `vip_nodename` comes from the downward
  API's `spec.nodeName`, so Lease ownership identifies an exact control-plane
  node rather than a mirror-Pod name. The container capability set drops
  `ALL` and adds exactly `NET_ADMIN` and `NET_RAW`.
- Pinned RKE2 release tarball installation verified against the matching
  official `sha256sum-amd64.txt` release asset.
- Pre-RKE2 Ubuntu preparation disables swap, configures TOT as the primary
  Ubuntu mirror with KKU as the request-failure fallback for both regular and
  security suites, binds the generated hostname to `127.0.1.1` with verified
  local resolution through bounded readback retry, installs static Google DNS
  while stopping and masking `systemd-resolved`, updates and upgrades packages
  within a hard ten-minute budget, then disables APT periodic updates and masks
  every `apt-daily*` unit plus `unattended-upgrades.service`. It also persists IPv4
  forwarding, RKE2 inotify values, PAM `nofile`, and matching
  `rke2-server.service` resource limits. Bastion cloud-init performs the same
  bounded one-time package update/upgrade and automatic-update shutdown before
  proving UFW inactive.

`spec.rke2.skipOSUpgrade: true` is an explicit optimization for short-lived
test clusters. It removes only the one-time `apt-get upgrade -y` step from all
three control planes and the bastion, including the default cache bastion. The
mirror rewrite, `apt-get update`, required package installation, and
automatic-update shutdown still run. Omit it or set it to `false` for the
production default.

- RKE2's packaged Cilium CNI in native-routing mode, with direct node routes,
  full kube-proxy replacement, LB-IPAM and L2 announcements. Public NodeLB
  application manifests use `loadBalancerClass: inspace.cloud/node`; CCM
  generates the separate private-VIP datapath Service.
- An operational continuous bootstrap CLI and a standard Kubernetes CCM
  command.

InSpace has no outbound NAT. Every bootstrap VM is therefore created with
`reserve_public_ip=true`. InSpace assigns one initially nameless floating IPv4;
that address provides internet egress to cloud-init from the VM's first boot.
The controller first attaches its already-created managed firewall and proves
the exact policy and VM assignment by authoritative readback before returning
from the create pass. On later passes it discovers the exact FIP assignment,
validates its account and private-address binding, patches its deterministic
cluster-prefixed name, and requires authoritative readback before adoption. The
guest NIC still has only its private RFC1918 address. RKE2 `node-ip` and
`advertise-address` are explicitly derived from the real VPC address, so the
VIP cannot become Kubernetes `InternalIP`; production cloud-init omits
`node-external-ip`, and the external CCM publishes the validated FIP as the
Kubernetes `ExternalIP`. The node firewall admits the exact VPC and pod CIDRs
but no public ingress. The separate bastion firewall defaults TCP/22 and
portless ICMP to Any; an explicit public IPv4 `/32` restricts both rules.
Guest UFW is not installed or configured by bootstrap;
if present, bootstrap must disable it and verify it inactive/disabled without
issuing raw iptables or nftables flush commands.

## Mutation safety

Remote API mutations are blocked unless
`INSPACE_ALLOW_REMOTE_MUTATIONS=true` is explicitly set. HTTP is accepted only
for literal loopback test servers; remote API URLs must be HTTPS. Every
cross-origin redirect is blocked so the `apikey` header cannot escape to
another host. The client does not automatically retry POST requests.
It also blocks redirects and automatic replay for PUT, PATCH, and DELETE.
Timeouts, HTTP 408/409/425/429/499 and 5xx responses, malformed success
responses, and transport errors are unknown commit outcomes; controller
readback, not the HTTP error class, decides convergence.

No credential belongs in Git, YAML, command-line flags, or logs. Supply it in
`INSPACE_API_TOKEN` (or legacy `INSPACE_API_KEY`) from a local `.env` file or a
Kubernetes Secret.

The CCM also requires `INSPACE_BILLING_ACCOUNT_ID` to be a positive decimal
integer at startup. This is an ownership invariant for node ExternalIP and
public load-balancer FIP validation, not an optional Service-only setting.

## Fixed control-plane controller

The target cluster does not exist yet, so the bootstrap controller runs from a
workstation or management host. It reads the `InSpaceCluster` YAML wire object
and reconciles safe, retryable passes. The fixed bastion is fully protected
before any control-plane creation. Missing control-plane VMs are created in
deterministic slot order with a hard creation bound of one. Each VM's
restrictive firewall assignment must be authoritatively visible before the
next VM POST; protected servers may continue booting in parallel, and
slot-ordered errors retain every successful VM for the next pass. Each server
must use exactly Ubuntu 24.04 with 2-16 vCPUs and 4096-65536 MiB memory.

Bootstrap persists bounded mutation ledgers in status. `status.createAttempts`
holds fourteen create/assignment/update slots: two firewall creates, four VM
creates, four exact firewall-to-VM assignments, and four floating-IP metadata
updates. `status.deleteAttempts` holds ten exact removal slots: four FIPs, four
VMs, and two firewalls. Intent and issue state are stored before the cloud
request. An issued operation is read/adopt-only across restart until exact
authoritative readback resolves it. The standalone command writes both maps
back to the cluster YAML with a file lock, compare-and-swap, atomic rename, and
readback; a process restart therefore cannot forget an ambiguous mutation.

After each status/file CAS, bootstrap repeats the exact create or mutation
authority immediately before the cloud request. For deterministic VM and
firewall creates, one exact owned name is adopted, only authoritative absence
permits POST, and a foreign, duplicate, or failed read retains the issued
receipt. A response UUID is provisional: only canonical detail, billing, shape,
and configured-VPC readback can promote it into the ledger. A foreign response
UUID is never used for protection or cleanup.

If an issued bootstrap entry remains unresolved, stop every bootstrap process
and save the complete cluster YAML before recovery. Query the exact
deterministic name and persisted UUID/address in the configured
location/account. If a create target or assignment exists, leave the
`createAttempts` entry intact so it can be adopted. If a removal target still
exists, leave the `deleteAttempts` entry intact; visibility never authorizes a
second destructive request. Clear only that exact key, including its
`issueID`, and only with provider-side terminal proof appropriate to the
operation. Never clear a whole map or start a second cluster config with the
same names to work around an issued entry.

`spec.bootstrapCache` is required and `directDownload` defaults to `false`.
Cached mode provisions the bastion with Docker from Docker's official Ubuntu
APT repository, pre-seeds the audited RKE2 release assets and an addon-aware
system-image inventory, and then exposes them through a private TLS, read-only
endpoint. The full inventory contains 34 images. If `spec.rke2.disable`
contains `rke2-ingress-nginx`, its webhook-certgen and ingress-controller
images are omitted, leaving 32 entries. The endpoint uses the bastion's
API-allocated RFC1918 address—never a manually selected cache VIP—and the
stable hostname `cache.<metadata.name>.inspace.internal` on TCP/8443.
Bootstrap writes that binding into each node's `/etc/hosts`, so it does not
depend on public DNS.

Cached initialization and reconciliation also require two persistent
controller values. `INSPACE_BOOTSTRAP_CACHE_KEY` is exactly 64 lowercase
hexadecimal characters encoding 32 random bytes.
`INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE` is captured from the real clock at the
actual first initialization and persisted in UTC RFC3339 whole-second form
(`YYYY-MM-DDTHH:MM:SSZ`); it must not be in the future. Together the inputs
deterministically derive ECDSA P-256 cluster cache CA and server certificates
whose validity starts at that persisted instant and ends exactly 15 calendar
years later. Treat the key as an operator secret,
preserve both values for the cluster lifecycle, and never put either in
`InSpaceCluster` YAML. Only the public CA is distributed to nodes. With
`directDownload: true`, the bastion remains required for private operator
access, but no cache is configured and neither value is required.

The TLS frontend accepts only `GET` and `HEAD`; the registry is read-only after
seeding and has deletion disabled. It is reachable only through the bastion's
private listener and VPC firewall rules. Do not publish TCP/8443 on the
bastion floating IP or through an NLB. This is a bounded, pre-seeded system
cache rather than a general-purpose registry or arbitrary-workload proxy.
Bootstrap retries both the writable seed-registry start and the final
read-only registry/NGINX recreation with bounded incremental backoff, allowing
at most nine Compose attempts for each startup.

`spec.endpoint.virtualIPv4` must be an unused host address inside the actual
InSpace VPC subnet. Bootstrap rejects network/broadcast/out-of-subnet values
and any same-VPC VM or load-balancer readback collision before kube-vip
can claim the address. InSpace exposes no private-address reservation API, so
the operator must reserve this VIP outside the controller and exclude it from
every VPC DHCP/IPAM allocation pool before the first reconcile. The collision
scan is a safety check, not a reservation mechanism.

`spec.network.privateLoadBalancerPool.start` and `.stop` define an inclusive,
canonical RFC1918 range of 16-256 addresses for Cilium private Services. The
v1alpha1 minimum of 16 avoids an operationally brittle pool with no practical
headroom, while the maximum of 256 bounds L2 lease and Kubernetes API-client
pressure. The range is immutable because changing it can reassign live Service
VIPs. It must consist only of usable hosts in the API-read VPC subnet and must
exclude the VPC network/broadcast addresses, control-plane VIP, pod CIDR and
Service CIDR. Bootstrap rejects any same-VPC VM or NLB collision and
rolls back a newly created bastion/control-plane VM that receives an address
inside it. InSpace exposes no range-reservation API, so operators must exclude
the entire range from VPC VM/NLB DHCP or IPAM before reconciliation.

Every RKE2 server receives the same deterministic Cilium pool and L2 policy
AddOn. Cilium API client limits are calculated from the inclusive range size:
`qps=max(10,ceil(addressCount/5))` and `burst=max(20,2*qps)`. The policy selects
Linux nodes and excludes nodes carrying the
`inspace.cloud/l2-announcement-disabled` label, allowing controlled drain and
lease migration without relying on interface names.

```sh
export INSPACE_API_TOKEN='...'
export INSPACE_RKE2_TOKEN='a-long-random-cluster-token'
# Generate and persist these once; reuse the exact values on every reconcile.
export INSPACE_BOOTSTRAP_CACHE_KEY='<64-lowercase-hex-characters>'
export INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE='<YYYY-MM-DDTHH:MM:SSZ>'
export INSPACE_ALLOW_REMOTE_MUTATIONS=true

go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --ssh-public-key-file "$HOME/.ssh/id_rsa.pub" \
  --ssh-username inspacee2e \
  --management-tcp-ports 22 \
  --until-ready --output=json
```

The SSH username/key and TCP/22 are required because every cluster has the
fixed bastion. Omitting `--management-cidr` defaults SSH and portless ICMP to
Any (`0.0.0.0/0`). Set one canonical public IPv4 `/32` to restrict both, and
reuse that exact value for reconcile and destroy. Private keys are never
accepted or copied. Other broad prefixes and all-port TCP/UDP rules are
rejected.
Control-plane FIPs have no public ingress; API and RKE2 registration use only
the private VIP. The real InSpace subnet is checked against the RKE2 pod and
service CIDRs before any mutation.

Use `--once` to perform exactly one reconciliation step. Control-plane display
names derive from `metadata.name`; deletion authority remains the versioned
owner/spec record whose owner hash derives from the resource namespace/name.
This makes a same-name VM from another namespace a fail-closed collision, not
an adoption candidate. An uncertain API response is resolved by listing and
validating the exact deterministic name and owner/spec record on the next loop,
not by blindly repeating the POST.

New control-plane owner/spec records use schema v8 because kube-vip's explicit
5/3/1-second election timing and 500-millisecond ARP cadence are part of their
immutable RKE2 cloud-init contract. Bastion records remain at v6.
Reconciliation does not adopt an older fixed VM into v8; use an explicit
destroy/recreate lifecycle. Owned teardown continues to recognize supported
older fixed-node schemas, including schema v7 control planes paired with the
unchanged v6 bastion.

New bootstrap FIPs are `<metadata.name>-bastion-ip` and
`<metadata.name>-cp0-ip` through `-cp2-ip`. The two firewall display names are
`<metadata.name>-bastion-<owner>` and `<metadata.name>-nodes-<owner>`; keeping
the namespace/name owner hash in firewall names preserves ownership even
though InSpace omits firewall descriptions from readback.

Reconciliation never migrates the legacy `rke2-<owner>-*` VM, FIP, or firewall
topology. It fails before mutation when those resources are present. Teardown
remains available for the released legacy topologies, including clusters whose
older resource name exceeds the current 55-character create limit. Teardown
selects exactly one coherent cluster-prefixed or legacy FIP/firewall naming
scheme and rejects any mix. Canonical VM detail, versioned owner/slot/spec
records, deterministic FIPs, and firewall policy/assignments must all validate.
Dual-bastion and mixed control-plane topologies are rejected.

Owned teardown is deterministic and fail-closed. Before its first mutation it
validates every deterministic VM/FIP name, assignment, billing account,
cluster-prefixed owner-qualified firewall name, exact firewall policy, and
firewall assignment.
Sparse VM list entries are canonicalized through the per-VM detail endpoint
before adoption or deletion.
InSpace accepts firewall descriptions on create but omits them from readback,
so an absent description is tolerated while any returned mismatch is rejected.
It unassigns and deletes all four owned FIPs before deleting the bastion and
three control-plane VMs, because InSpace VM deletion only leaves an automatic
FIP active and unassigned. Both managed firewalls are deleted only after their
assignments are absent:

Before every FIP unassign/delete, VM delete, and firewall delete, the controller
records the exact owned address, UUID, related UUID, deterministic slot, and
issued identity. Once a request is issued, neither a success response, HTTP
error, timeout, nor a still-visible object grants another dispatch. Only a
typed local pre-dispatch `ErrMutationBlocked` can return the receipt to intent.
The controller releases dependents only after two exact authoritative
absence/relationship-withdrawal observations separated in time. If the exact
resource or relationship reappears between those reads, only the absence
evidence is cleared; the issued no-replay lock remains.
Malformed VM-create rollback uses the same durable ledger, deletes the exact
unprotected VM once, proves its absence, then removes its exact auto-FIP before
atomically resetting the create/assignment/FIP slots for replacement. These
receipts have no TTL, survive controller reconstruction, and reject an unknown
UUID, wrong deterministic name, different firewall, or duplicate assignment.

```sh
go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --management-tcp-ports 22 \
  --delete --output=json
```

`infrastructureReady=true` means the bastion, three control-plane VMs, four
floating addresses, and both firewall assignments exist in the API. It does
**not** yet probe the cluster VIP from the controller host. The JSON result
reports `controlPlaneEndpoint`/`privateControlPlaneEndpoint` as
`https://<virtualIPv4>:6443`, `privateRegistrationEndpoint` as
`https://<virtualIPv4>:9345`, and the bastion UUID/public/private IPv4 plus
both firewall UUIDs. In cached mode it also reports
`bootstrapCacheAddress`, `bootstrapCacheEndpoint`, `bootstrapCacheRegistry`,
and the public `bootstrapCacheCABundle`; use the address and CA bundle in
cached `InSpaceNodeClass` resources. Direct mode omits those fields.
`maxParallelControlPlaneCreates: 1` is the hard CP creation bound. Missing VMs
are created in slot order, and each must receive authoritative restrictive
firewall protection before the next VM POST; their subsequent boots may still
overlap.

Control-plane slot 0 is the one-time RKE2 initializer. The controller creates
it only when no control-plane VM exists. If slot 0 is absent while slot 1 or 2
still exists, reconciliation fails closed instead of initializing a second
cluster. Recovering or replacing slot 0 requires an explicit manual lifecycle
that verifies the surviving etcd membership and chooses a state-aware RKE2
recovery/replacement procedure; automatic slot-0 replacement is intentionally
unsupported.

## External CCM

Build and deploy the CCM after the RKE2 API becomes available. The manifest has
RBAC, leader election, control-plane scheduling/tolerations, and all required
environment references:

```sh
kubectl -n kube-system create secret generic inspace-cloud-credentials \
  --from-env-file=./ccm-credentials.env
kubectl apply -f ./config/ccm/cloud-controller-manager.yaml
```

Replace all ConfigMap placeholders first. Its container image placeholder is
`ghcr.io/thanet-s/inspace-cloud-controller-manager:dev`; publish or load your built
image and change the tag before applying. CCM configuration requires
`INSPACE_CONTROL_PLANE_VIP`,
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_START` and
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP` so public-NLB allocation can reject
the RKE2 API VIP and addresses reserved for Cilium. The control-plane VIP and
pool must be canonical RFC1918 addresses outside the fixed pod CIDR
`10.42.0.0/16` and Service CIDR `10.43.0.0/16`, and the VIP must also be outside
the private load-balancer pool.

Private Cilium Service ownership is explicit:

```yaml
metadata:
  labels:
    inspace.cloud/load-balancer-scope: private
spec:
  type: LoadBalancer
  loadBalancerClass: io.cilium/l2-announcer
  externalTrafficPolicy: Cluster
```

An InSpace public NLB requires both markers and no `loadBalancerClass`:

```yaml
metadata:
  labels:
    inspace.cloud/load-balancer-scope: public
  annotations:
    service.beta.kubernetes.io/inspace-load-balancer-public: "true"
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
```

For `Local`, the CCM watches EndpointSlices and targets exactly the eligible
`Ready=True` nodes that host a Ready, non-terminating local endpoint for that
Service. EndpointSlice changes cover Pod scheduling, readiness, and
termination; Node add/delete, provider-ID, exclusion, disruption, and Ready
condition changes also trigger target reconciliation. InSpace does not probe
the Kubernetes `healthCheckNodePort`, so this is control-plane-driven health
filtering rather than an independent NLB data-plane health check. Public
Services may still use `Cluster`; unhealthy, deleting, excluded, or disrupting
nodes are filtered there as well. Nodes carrying either
`node-role.kubernetes.io/control-plane` or the legacy
`node-role.kubernetes.io/master` label are never public NLB targets in either
mode; adding or removing either role reconciles targets immediately. Kubernetes
defaults an omitted `externalTrafficPolicy` to `Cluster` before CCM observes the
Service, so set `Local` explicitly when local-endpoint targeting is required.
Private Cilium L2 Services must remain `externalTrafficPolicy: Cluster`.

The CCM can also own public Cilium node load balancers. Enable it with
`INSPACE_NODE_LOAD_BALANCER_ENABLED=true`, set
`INSPACE_NODE_LOAD_BALANCER_DEFAULT_NODE_CLASS` to the established worker
NodeClass that supplies the cluster/VPC/RKE2/cache contract, and optionally set
`INSPACE_NODE_LOAD_BALANCER_NODES_PER_SHARD` (default `1`). Karpenter must run
with `StaticCapacity=true`.

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

An omitted `service.inspace.cloud/node-lb-mode` means
`public-node-shared`. Shared Services pack onto an existing shard only when all
IPv4 `(protocol, port)` claims are free; otherwise CCM creates another shard.
Use `public-node-dedicated` for an isolated shard. Dedicated Services can set
`service.inspace.cloud/node-lb-cpu` and
`service.inspace.cloud/node-lb-memory`; the defaults are `1` and `2Gi`.
Explicit shapes enforce at least 1 CPU and 2 GiB, and the pair must exactly
match the finite provider catalog.

CCM never exposes application workers directly. It creates static, tainted AMD
EPYC NodePools with a 30 GiB root disk and a hardened NodeClass cloned from the
configured base. For every user Service it creates an exact-owned
same-namespace `inlb-dp-<service-identity>` Service with
`loadBalancerClass: inspace.cloud/node-datapath`. The identity is the first 52
lowercase hex characters of SHA-256 over
`namespace NUL name NUL Service-UID`; the child repeats it in the
`inspace.cloud/node-lb-service-id` label and has an exact controller owner
reference to that parent. CCM revalidates the complete rendered NodePool profile,
including its `NoSchedule` taint, and the exact
Node→NodeClaim→NodePool→NodeClass ownership chain before accepting a node. Only
healthy nodes with one authoritative FIP, Karpenter's valid private base
firewall, the shared cluster ICMP firewall, and the shard's exact aggregate
public firewall are eligible for the protected shard-ready label. Each Node-LB
VM has exactly the private base firewall and shared ICMP firewall, plus at most
one aggregate firewall for its shard. A Node that becomes NotReady loses the
protected readiness label and is withdrawn from Service status, but CCM retains
the aggregate firewall assignment while the node recovers. It detaches that
firewall only for node deletion or replacement and last-owner shard cleanup.
The generated Service publishes paired private Node InternalIPs with
`ipMode: VIP`; the user Service publishes the corresponding public FIPs with
`ipMode: Proxy`. InSpace DNAT rewrites the public destination to the private IP
before Cilium, so Cilium programs only the private frontend.
TCP and UDP are supported; SCTP and
`externalTrafficPolicy: Local` are rejected. The static NodePool limit permits
exactly one temporary surge node so Karpenter drift replacement can converge
while the steady-state count remains `nodesPerShard`.

Node-LB identity and readiness use
`inspace.cloud.node-restriction.kubernetes.io/node-lb`, `/cluster`, `/shard`,
and `/ready` labels, so the RKE2 NodeRestriction admission plugin is part of
the security boundary. That stops a kubelet from self-advertising; it does not
constrain a cluster administrator.
Multi-tenant clusters must use admission and RBAC to reserve the internal
`inspace.cloud/node-datapath` class, `Service.spec.externalIPs`, protected
provider annotations/finalizers, and
Node-LB tolerations/selectors. The generated `NoSchedule` taint is a placement
guard, not tenant isolation.

The user Service must have a selector and explicitly set
`allocateLoadBalancerNodePorts: false`; CCM does not mirror manually managed
EndpointSlices, and this dataplane consumes neither Kubernetes NodePorts nor
`externalIPs`.
`externalIPs`, `loadBalancerIP`, non-zero `nodePort` values, and non-IPv4
source ranges are rejected before CCM creates Karpenter capacity. A shard
migration is intentionally fail-closed and break-before-make: CCM first clears
and reads back the functional child VIP, removes the Service UID from the old
aggregate ledger, and retires the old shard when it has no other owner. It then
creates the replacement state anchor and capacity while the child remains
closed. The replacement child spec is read back with empty status, its exact
aggregate policy and assignment are proved, and only then does CCM record the
active shard and publish the new private VIP and public Proxy status.

Each shard owns one mutable firewall with the stable name
`inlb-<cluster-ownership-hash>-shard-<shard-hash>`. Policy changes never change
its name or UUID. Its rules are the canonical union of every member Service's
unique TCP/UDP `(protocol, port)` claims. Each rule uses that Service's exact
canonical IPv4 `loadBalancerSourceRanges`; an empty field means Any. Duplicate
`(protocol, port)` ownership is rejected by planning and fails closed if later
observed. The aggregate contains no ICMP or outbound rule.

CCM stores the applied membership/policy ledger, a separate full SHA-256
canonical policy hash, and any pending mutation fence on the shard NodePool. A
CCM finalizer makes that NodePool the durable state anchor through deletion. It
requests foreground NodePool deletion, allowing Kubernetes to terminate owned
NodeClaims while the CCM finalizer retains the ledger for final firewall
cleanup. Background deletion is not used because it cannot start dependent
garbage collection until that same state finalizer is released. If a user or
another controller already started background deletion, CCM reissues an exact
UID-fenced foreground delete only while managed NodeClaims remain. It does not
re-add `foregroundDeletion` after those direct dependents drain; the separate
capacity proof still waits for every managed Node and other finalizer. CCM
reads back that exact finalizer/spec before recording the shard in the owning
Service's `node-lb-shard-state-materialized` handoff. A missing or drifted
anchor can therefore never be downgraded to a fresh prospective assignment;
cleanup must first persist cloud-absence proof. It
updates the existing firewall with `PUT`, retaining provider UUIDs for unchanged
logical rules, and requires exact authoritative readback before activating a
new Service. CCM records paid-create authority before POST and repeats exact
deterministic-name absence or ownership after the owner CAS. Response UUIDs are
provisional until the unique stable-name resource passes canonical readback. If
a create response is ambiguous and no exact resource is observable, the state
finalizer remains and CCM permanently refuses a second create until the original
stable-name resource appears or an operator resolves the attempt after
cloud-side proof.
After an ambiguous update response or restart, cloud readback decides whether
the pending update was applied; CCM permanently retains the issued fence and
does not repeat the PUT on elapsed time. This prevents an older delayed request
from committing after a later policy generation. Progress resumes only when
the pending policy is observable or after explicit operator resolution.

Changing ports or `loadBalancerSourceRanges` uses a closed restage fence. CCM
first clears and reads back the functional child and public status, records the
new per-Service SHA-256 member policy while that child remains empty, updates
the aggregate in place, and proves the new ledger before reopening the private
VIP. The old, potentially wider rule therefore cannot reach the edited
frontend at any crash boundary.

All authorized Node-LB VMs also reuse one cluster-owned firewall named
`inlb-<cluster-ownership-hash>-icmp-<policy-hash>`. It contains exactly one
portless inbound ICMP-from-Any rule. `loadBalancerSourceRanges` therefore
restricts only the owning Service's TCP/UDP traffic and never restricts ping.
InSpace exposes no ICMP type/code filter, so the shared rule permits all IPv4
ICMP from Any.
CCM persists this shared identity on the generated NodeClass. The
`inspace.cloud/node-lb-cluster-state` finalizer keeps that ledger alive across
an external NodeClass deletion, so CCM first closes every frontend, drains all
managed shards, and proves ICMP-firewall absence before releasing the object.
The generated NodeClass and shared ICMP firewall are removed after the last
finalized Node-LB Service and all managed NodePool/NodeClaim/Node capacity are
absent. Every assignment is authoritatively verified before readiness.
Deterministic ownership, a permanent one-POST create fence, and spaced
known-resource absence readback cover create, replacement, crash recovery, and
deletion without relying on the firewall description that InSpace omits.
For a new shard, CCM attaches the aggregate firewall once while the node is not
publicly advertised, verifies the exact assignment and Node recovery, and then
enables the protected readiness label and status. Adding a non-conflicting
shared Service stages an exact child with empty status, expands the same
firewall in place, and then publishes only that Service; the sibling NodePool,
VM, FIP, firewall UUID, statuses, and traffic remain unchanged. Deletion first
shrinks and verifies the aggregate, then removes only the departing Service's
statuses and child. The last Service and deleting NodePool retain their
finalizers until capacity is gone and three spaced authoritative reads prove
the unassigned aggregate firewall is deleted. Cluster cleanup persists a
Service-side handoff before releasing the generated NodeClass finalizer, so a
restart cannot mistake a missing state object for proof of cloud absence.
Attaching the shared ICMP or shard firewall to a new surge/replacement VM keeps
already protected nodes and sibling Services published; the new VM remains
ineligible until a later authoritative readback. If an advertised VM loses an
assignment, only its affected shard is withdrawn before repair.

For the paid NLB path, if either public marker is removed, CCM deletes every deterministically owned
FIP/NLB before handing the Service to another implementation. Discovery and
deletion remain ownership-based even after markers change, preventing legacy
resources from leaking. Public FIP list/create/assignment responses must match
the deterministic name, billing account, active enabled non-virtual `public`
type, canonical global IPv4 and exact owned-NLB assignment before CCM reports
Service status. Before creating a public FIP, CCM also verifies that the owned
NLB's private address is neither the control-plane VIP nor an address in the
reserved Cilium pool. A collision triggers deterministic owned FIP/NLB cleanup
and fails the reconciliation.

For that paid NLB path, `Service.spec.loadBalancerSourceRanges` is rejected
because the InSpace NLB API exposes TCP port forwarding, not source-range
filtering. Use InSpace firewalls or in-cluster policy where appropriate. UDP
and SCTP Services are also rejected. The public Node-LB path above accepts
canonical IPv4 source ranges for the owning Service's TCP/UDP rules in the
shard aggregate only.

## Development and verification

Requires Go 1.26.5.

```sh
make test
make smoke
make vet
make build
```

All default tests use strict literal fixtures and loopback HTTP servers. They
make no request to InSpace and require no token.

Read-only discovery is separate and never enables mutation:

```sh
INSPACE_API_TOKEN='...' ./bin/inspace-discovery --location bkk01 --smoke
```

The isolated API lifecycle suite and the destructive
[full-cluster release acceptance test](../../test/e2e/README.md) are separate
from ordinary verification. The latter boots exactly three RKE2 servers,
checks embedded-etcd and CCM convergence, installs the released CSI and
Karpenter components, exercises an elastic worker/RWO volume/public TCP NLB,
and requires an exact zero-owned-resource cloud audit after teardown.

## Remaining production gaps

- The bootstrap binary consumes a YAML file; it does not yet watch the CRD,
  resolve Secret references through a Kubernetes management cluster, or use a
  Kubernetes finalizer. Lifecycle is explicit CLI reconciliation and owned
  `--delete` teardown.
- In-place control-plane machine image or shape updates are not implemented;
  changes require an explicitly managed replacement lifecycle.
- Automatic replacement of missing control-plane slot 0 is not implemented;
  use a manual, etcd-aware recovery lifecycle as described above.
- `infrastructureReady` is API-level only; RKE2 health and etcd membership need
  an authenticated readiness probe in the controller itself. The external
  release-acceptance suite performs those runtime checks separately.
- The InSpace firewall's unmatched-traffic/default-deny semantics still need a
  live conformance test before treating the managed policy as production
  isolation. The controller nevertheless validates the exact node and bastion
  policies, deterministic names, billing account, and assignments before every
  mutation; any non-empty description is also checked for drift.

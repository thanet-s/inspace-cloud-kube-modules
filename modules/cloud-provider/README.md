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
  servers in one bounded parallel batch. The API and RKE2 registration use a
  caller-selected private VPC VIP; bootstrap creates no control-plane NLB.
- A per-node RKE2 static Pod running kube-vip v1.2.1 by immutable multiarch
  digest. It advertises only the control-plane VIP with ARP and leader
  election; Kubernetes Service handling is disabled.
- Pinned RKE2 release tarball installation verified against the matching
  official `sha256sum-amd64.txt` release asset.
- RKE2's packaged Cilium CNI in native-routing mode, with direct node routes,
  full kube-proxy replacement, LB-IPAM and L2 announcements. Cilium Node IPAM
  is explicitly disabled and is never used for Service addressing.
- An operational continuous bootstrap CLI and a standard Kubernetes CCM
  command.

InSpace has no outbound NAT. The bootstrap flow therefore preallocates one
named floating IPv4 for every control-plane VM and the bastion, creates each
private-only VM, assigns its validated firewall, then assigns the address. The
guest NIC still has only its private RFC1918 address. RKE2 `node-ip` and
`advertise-address` are explicitly derived from the real VPC address, so the
VIP cannot become Kubernetes `InternalIP`; `node-external-ip` is each node's
egress floating address. The node firewall admits the exact VPC and pod CIDRs
but no public ingress. The separate bastion firewall admits only the operator
IPv4 `/32` on TCP/22. Guest UFW is not installed or configured by bootstrap;
if present, bootstrap must disable it and verify it inactive/disabled without
issuing raw iptables or nftables flush commands.

## Mutation safety

Remote API mutations are blocked unless
`INSPACE_ALLOW_REMOTE_MUTATIONS=true` is explicitly set. HTTP is accepted only
for literal loopback test servers; remote API URLs must be HTTPS. Every
cross-origin redirect is blocked so the `apikey` header cannot escape to
another host. The client does not automatically retry POST requests.

No credential belongs in Git, YAML, command-line flags, or logs. Supply it in
`INSPACE_API_TOKEN` (or legacy `INSPACE_API_KEY`) from a local `.env` file or a
Kubernetes Secret.

## Fixed control-plane controller

The target cluster does not exist yet, so the bootstrap controller runs from a
workstation or management host. It reads the `InSpaceCluster` YAML wire object
and reconciles safe, retryable passes. The fixed bastion is fully protected
before any control-plane creation. Missing control-plane VMs are then one hard
bounded batch: all three slots are launched concurrently, and slot-ordered
errors retain every successful VM for the next pass. Each server must use
exactly Ubuntu 24.04 with 2-16 vCPUs and 4096-65536 MiB memory.

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
export INSPACE_ALLOW_REMOTE_MUTATIONS=true

go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --ssh-public-key-file "$HOME/.ssh/id_rsa.pub" \
  --ssh-username inspacee2e \
  --management-cidr 203.0.113.10/32 \
  --management-tcp-ports 22 \
  --until-ready --output=json
```

The SSH username/key and exactly one public management `/32` TCP/22 are
required because every cluster has the fixed bastion. Private keys are never
accepted or copied. Broad public prefixes and all-port rules are rejected.
Control-plane FIPs have no public ingress; API and RKE2 registration use only
the private VIP. The real InSpace subnet is checked against the RKE2 pod and
service CIDRs before any mutation.

Use `--once` to perform exactly one reconciliation step. Ownership names are
derived from the resource namespace/name, so an uncertain API response is
resolved by listing and adopting the exact deterministic name on the next
loop, not by blindly repeating the POST.

Owned teardown is deterministic and fail-closed. Before its first mutation it
validates every deterministic VM/FIP name, assignment, billing account,
owner-derived firewall name, exact firewall policy, and firewall assignment.
Sparse VM list entries are canonicalized through the per-VM detail endpoint
before adoption or deletion.
InSpace accepts firewall descriptions on create but omits them from readback,
so an absent description is tolerated while any returned mismatch is rejected.
It then removes all four owned FIPs, deletes the bastion and three control-plane
VMs, and deletes both managed firewalls only after assignments are absent:

Before each owned VM deletion, the running controller records that exact VM
UUID and its expected managed-firewall UUID. It keeps the record across
retryable API or transport failures whose commit status is ambiguous, marks
those outcomes explicitly retryable, and retains it for five minutes after
DELETE returns. It removes the record after a proven local/non-retryable
rejection. This bounded transition tolerates delayed firewall-assignment
cleanup without
allowing an unknown UUID, another firewall, a duplicate assignment, or an
expired record to become deletion authority. A process restart forgets the
transition and therefore fails closed until the cloud assignment readback has
cleared.

```sh
go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --management-cidr 203.0.113.10/32 \
  --management-tcp-ports 22 \
  --delete --output=json
```

`infrastructureReady=true` means the bastion, three control-plane VMs, four
floating addresses, and both firewall assignments exist in the API. It does
**not** yet probe the cluster VIP from the controller host. The JSON result
reports `controlPlaneEndpoint`/`privateControlPlaneEndpoint` as
`https://<virtualIPv4>:6443`, `privateRegistrationEndpoint` as
`https://<virtualIPv4>:9345`, and the bastion UUID/public/private IPv4 plus
both firewall UUIDs. `maxParallelControlPlaneCreates: 3` is the hard CP
creation bound.

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
  externalTrafficPolicy: Cluster
```

If either public marker is removed, CCM deletes every deterministically owned
FIP/NLB before handing the Service to another implementation. Discovery and
deletion remain ownership-based even after markers change, preventing legacy
resources from leaking. Public FIP list/create/assignment responses must match
the deterministic name, billing account, active enabled non-virtual `public`
type, canonical global IPv4 and exact owned-NLB assignment before CCM reports
Service status. Before creating a public FIP, CCM also verifies that the owned
NLB's private address is neither the control-plane VIP nor an address in the
reserved Cilium pool. A collision triggers deterministic owned FIP/NLB cleanup
and fails the reconciliation.

`Service.spec.loadBalancerSourceRanges` is rejected because the InSpace NLB
API exposes TCP port forwarding, not source-range filtering. Use InSpace
firewalls or in-cluster policy where appropriate. UDP and SCTP Services are
also rejected.

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
  policies, owner-derived names, billing account, and assignments before every
  mutation; any non-empty description is also checked for drift.

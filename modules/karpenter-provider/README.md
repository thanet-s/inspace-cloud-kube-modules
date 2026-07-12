# Karpenter Provider for InSpace

This repository implements the InSpace provider for Karpenter `v1.14.0` and RKE2. It includes a production API adapter, `InSpaceNodeClass`, a 24-variant instance catalog, stock-Ubuntu bootstrap, NodeClass readiness reconciliation, and a runnable Karpenter controller command.

## Supported contract

- Location `bkk01`, Linux/amd64, on-demand capacity
- `intel-scalable` host pool `aac7dd66-f390-4edd-80c0-dd7cae49bd99`
- `amd-epyc` host pool `6976fdc8-4492-465b-bd16-9ad5f6b00b03`
- `compute`, `general`, and `memory` families at 1, 2, and 4 GiB/vCPU
- CPU sizes `2, 4, 6, 8, 10, 12, 14, 16`; maximum 16 vCPU / 64 GiB
- Ubuntu 24.04 and an exactly pinned RKE2 agent version
- Ephemeral root disks; persistent workload data belongs on RWO CSI volumes
- One immutable, inclusive 16-to-256-address RFC1918 Service VIP range reserved
  from worker NIC allocation

Variant names describe raw VM capacity, for example `is-compute-4c-4g`, `is-general-6c-12g`, and `is-memory-16c-64g`. Allocatable disk reserves 8 GiB for Ubuntu/RKE2 plus a 4 GiB eviction threshold.

Catalog prices are deterministic scheduling weights, not actual InSpace prices. A pricing source is still required before enabling cost-based consolidation decisions in production.

`spec.rke2` is the required bootstrap contract; the legacy `spec.k3s` field is
not accepted. The RKE2 bootstrap schema has a distinct drift hash, including
the exact-VPC private-IP, verified-UFW, and bounded-agent-start contract, so
existing
K3s-backed NodeClaims are treated as drifted and replaced through Karpenter's
normal disruption controls after their NodeClasses are migrated.

## Public IPv4 and firewall model

InSpace currently has no managed NAT gateway, so each worker must have exactly one provider-owned floating public IPv4 for internet egress. The guest NIC still exposes exactly one private RFC1918 address. The private address is the Kubernetes `InternalIP`; the CCM publishes the floating address only as `ExternalIP`. The floating address is not an ingress path.

The provider uses a fail-closed sequence:

1. Validate that the supervisor VIP and both endpoints of the exact reserved
   Service VIP range are distinct usable host addresses—not network or
   broadcast addresses—inside the selected RFC1918 VPC.
2. Allocate or recover a deterministically named, provider-owned Floating IP.
   It must be enabled, non-virtual, non-deleted, type `public`, and a public
   IPv4 address.
3. Create the VM with the NodeClass `network_uuid` and
   `reserve_public_ip=false`, avoiding an untracked implicit address.
4. Read back that exact network until the VM UUID appears exactly once in its
   authoritative `vm_uuids` membership.
5. Read back the VM until its complete NodeClaim ownership/spec record is
   persisted and it has exactly one usable RFC1918 private IPv4 inside that
   VPC; reject an address equal to the private RKE2 supervisor VIP or inside
   the reserved Service VIP range.
6. Audit all InSpace firewalls, assign the intended firewall, and require the
   worker to be attached exactly once to that firewall and no other.
7. Assign and read back the owned Floating IP.
8. Audit that no second or unusable Floating IP is assigned to the worker.
9. Return the NodeClaim only after VPC attachment and both protections are
   confirmed.

Network membership read-back has a 60-second total bound, 10-second request
bounds, exponential polling, and retries for transient read failures. A newly
created VM that cannot prove attachment or protection triggers detached,
bounded rollback of its floating IP and VM; cleanup failures are joined to the
launch error, and the firewall stays attached if VM deletion is uncertain. An
existing owned VM is discovered and validated before any new floating IP
mutation; a temporary adoption read-back failure is returned for reconciliation
without destroying that VM. A positively owned VM whose private address equals
its ownership-recorded supervisor VIP or falls inside its ownership-recorded
Service VIP range is unsafe and is rolled back, including a late ambiguous
commit; generic ownership mismatches are never deleted. Delete removes both
resources, including an orphan floating IP when the VM has already disappeared.
Create POSTs are never blindly retried; read-before-create ownership records
recover ambiguous responses.

`GetVM` and `ListVMs` repeat these checks through a bounded read-only snapshot.
One firewall list, one Floating-IP list, and one network read per unique VPC
detect a lost/disabled address, a second or public firewall, membership drift,
or a private-IP/supervisor-or-Service-VIP collision without mutating resources.

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

Public ingress to workers is always invalid. Administrative access must traverse
the private VPC through the dedicated bastion; workload traffic reaches private
targets through the TCP service path. Direct public SSH and NodePort access are
not part of the worker firewall contract.

Worker network policy relies on the validated InSpace cloud firewall. Generated bootstrap does not install or enable UFW. One `set -eu` orchestrator runs every bootstrap stage in order, executes `additionalUserData`, then disables and verifies UFW before it can start RKE2. The RKE2 service also has an `ExecStartPre` verifier, so initial launch and later restarts fail unless `ufw status` is inactive and its unit is inactive and disabled (an absent unit is safe). It never flushes or rewrites iptables/nftables, which belong to Cilium and RKE2. The adapter replaces a single strict VPC-subnet placeholder with the exact API-reported prefix before VM creation. Bootstrap then requires exactly one guest address in that prefix and writes it as `node-ip`; it never chooses the default interface or mistakes the floating address for a NIC address. A separate strict placeholder is replaced with the one allocated floating IPv4 for `node-external-ip`; unresolved or duplicate placeholders fail launch. The external CCM remains authoritative and must publish the same API-reported addresses as `InternalIP` and `ExternalIP`. InSpace service targets use the private node address. Deletion removes the Floating IP first, deletes the VM, and only then removes every stale firewall attachment for that exact VM UUID.

## RKE2 agent bootstrap

`cloud_init` is sent as an API-compatible JSON object. On stock Ubuntu 24.04 it:

- waits up to 60 attempts for `apt-get` to succeed after floating-IP egress exists, then installs `curl`, CA certificates, `gzip`, `iproute2`, and `tar`;
- downloads the exact RKE2 `rke2.linux-amd64.tar.gz` release and its `sha256sum-amd64.txt` asset with at most 60 attempts per asset;
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

The real lifecycle test is separately gated and uses resource names beginning with `inspace-e2e-`. It creates a named floating IP and VM, assigns the existing firewall, exercises get/list/delete, audits cleanup, and fails if a prefixed VM or floating IP remains:

```sh
INSPACE_RUN_LIVE_TESTS=true \
INSPACE_ALLOW_REMOTE_MUTATIONS=true \
make live-test
```

It additionally requires `INSPACE_API_TOKEN`, `INSPACE_BILLING_ACCOUNT_ID`, `INSPACE_NETWORK_UUID`, `INSPACE_CONTROL_PLANE_VIP`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_START`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP`, `INSPACE_FIREWALL_UUID`, and `INSPACE_INTEL_HOST_POOL_UUID`. The VPC, supervisor VIP, and Service range must satisfy the fixed pod/Service-CIDR constraints above. The supplied firewall must already satisfy the VPC/pod-CIDR TCP, UDP, and ICMP contract above with no public inbound rule; the live test performs a read-only preflight before creating resources. Normal `go test ./...` compiles this test but skips it before reading those values.

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

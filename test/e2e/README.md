# Full InSpace RKE2 cluster E2E

This is the destructive release-acceptance suite for the complete InSpace
stack. The host entrypoint is intentionally only a Docker launcher: Ansible,
Helm, kubectl, SSH, curl, provisioning, live assertions, and cleanup all run
inside a purpose-built Ubuntu 24.04 controller image. The destructive image
copies its bootstrap binary from the exact published CCM image tag; a separate
non-live target compiles local source for CI. The host needs no Go toolchain,
and nothing is installed or executed directly on it except Docker.

The test creates exactly three fixed RKE2 `v1.35.6+rke2r1` control-plane VMs.
The product bootstrap reconciler launches missing control-plane VMs with a
hard concurrency bound of three, and its result must report
`maxParallelControlPlaneCreates: 3`. Ansible binds the returned UUIDs to three
exact private VPC addresses and one egress FIP each, then uses at least three
forks plus the `free` strategy to wait for cloud-init, `rke2-server`, embedded
etcd, and the local API independently and in parallel through a bastion.

RKE2 uses Cilium in native-routing mode with the pod CIDR
`10.42.0.0/16`, and Cilium fully replaces kube-proxy. Acceptance requires the
Cilium ConfigMap, `auto-direct-node-routes`, live `cilium-dbg status --verbose`
on every control-plane and worker node, and the absence of kube-proxy
DaemonSets, pods, and host processes. The unused `rke2-ingress-nginx` addon is
disabled.

The API and registration listeners share the configured private kube-vip
address on TCP/6443 and TCP/9345. No bootstrap NLB or API endpoint FIP exists.
The suite pins kube-vip `v1.2.1` by digest, requires one static mirror pod per
control plane, one Lease holder, and exactly one VIP owner. It then removes the
leader's static manifest temporarily, proves ownership moves to a different
control plane without interrupting the API, and restores all three pods.

One controller-owned bastion is the sole inbound SSH endpoint. Control planes
and the Karpenter worker are reached only at private IPs through pinned SSH
host keys and `ProxyJump`; Kubernetes uses a container-local SSH forward to the
private VIP with that VIP as the TLS server name. The private registration VIP
is used by the `inspace-rke2-agent-token` Secret and worker bootstrap. Because
InSpace has no NAT service, all three control planes, the worker, and bastion
still receive one FIP for egress, but node FIPs are never used as management
endpoints. The worker proof binds Node/NodeClaim/provider ID to one exact VM,
authoritative VPC membership, private subnet containment, and its exact FIP.
Managed InSpace cloud firewalls are the only host firewalls; guest UFW must be
inactive and disabled or masked on the control planes, worker, and bastion.

The workload assertions cover a single-node `ReadWriteOnce` CSI disk,
VolumeAttachment, and persistence through pod replacement. They also create
two private Services with the same TCP port, private scope label,
`loadBalancerClass: io.cilium/l2-announcer`, and
`externalTrafficPolicy: Cluster`. Cilium LoadBalancer IPAM must allocate two
distinct VIPs inside the operator-reserved range, create one L2 announcement
Lease for each Service, and advertise both VIPs over the VPC while each returns
its own response marker. This proves same-port reuse comes from unique LB-IPAM
VIPs, not node addresses. Cilium Node IPAM and `io.cilium/node` are disabled and
unsupported.

The suite exercises private L2 lease-holder failover and requires reachability
to recover through ARP/gratuitous ARP. L2 Announcements remains a Cilium beta
feature; a passing run is also the required proof that the target InSpace VPC
accepts ARP for VIPs not assigned to a VM NIC. `externalTrafficPolicy: Local`
is deliberately unsupported because it is incompatible with this L2 mode.

One separate class-unset Service opts into the explicit paid, TCP-only InSpace
NLB using the public scope label and annotation. The suite proves the two
private Services own zero InSpace NLBs/FIPs, while the public Service owns
exactly one of each. It then removes the public opt-in, waits for that NLB/FIP
to be deleted and its status cleared, and verifies the transition left no
public cloud resource behind. UDP is not tested on the public path because the
InSpace NLB supports TCP only.

## Safety and cleanup

Use only a new, empty, isolated billing account. Before its first mutation the
suite captures every API-visible VM, firewall, floating IP, load balancer, and
disk and requires all five inventories to be empty. Cleanup must make the full
account inventory exactly equal that persisted baseline, in addition to its
deterministic ownership audit. A malformed or unidentifiable active API item
is fatal rather than silently ignored.

One exclusive lock covers the shared state volume, and an existing run ID can
never be reused for provisioning. A durable pre-mutation checkpoint allows a
missing journal to be classified as safe only before any remote call could
mutate state; once mutation may have started, missing or unreadable ownership
state preserves resources and fails closed. Explicit retention is persisted
independently of the journal and always wins over an old zero audit.

Cleanup runs in a separate Ansible playbook after both success and failure
(and on signals), unless resource retention was explicitly requested. Owner
removal is ordered:

1. all public/private workloads, Services, and the PVC;
2. pods, PV, and VolumeAttachments must disappear;
3. both private `cilium-l2announce-*` Leases must disappear and
   `CiliumLoadBalancerIPPool/inspace-private` must report zero used IPs;
4. NodePool, NodeClaims, worker Nodes, then NodeClass;
5. CSI/CCM/Karpenter-owned disks, workers, floating IPs, and service NLB must
   be absent before controller charts are removed;
6. bootstrap-owned control-plane VMs/FIPs, bastion/FIP, and both managed cloud
   firewalls; and
7. a deterministic final cloud audit must report exactly zero owned resources.

If Kubernetes owners may exist but the API or ownership journal is unusable,
cleanup preserves infrastructure and fails. That fail-closed behavior avoids
racing active CSI, CCM, or Karpenter controllers with raw cloud deletion.

State and the generated RKE2 token/kubeconfig live in a Docker volume named
`inspace-cloud-rke2-e2e-state` by default, never in the repository or image.
The `.env` file and SSH keys are mode-checked read-only bind mounts excluded
from the build context. The token file is not copied into Docker container
metadata. Only the SSH public key is submitted to InSpace.

Before a new run, the entrypoint automatically cleans an unfinished last run
with the same recorded published version and requires its final zero audit. If
the requested version differs, recover using the recorded version first. A run retained with
`INSPACE_E2E_KEEP_RESOURCES=true` is never removed implicitly. To clean one
explicitly retained run without starting another:

```sh
export INSPACE_E2E_RUN_ID='<persisted-run-id>'
export INSPACE_E2E_RECOVERY_ONLY=true
export INSPACE_E2E_RECOVER_RETAINED=true
./test/e2e/run.sh
```

## Run

Publish the exact release candidate first. Put the isolated account values in
the ignored, mode-`0600` root `.env`, then export the destructive confirmation
and released SemVer:

```sh
export INSPACE_E2E_VERSION='0.2.0-rc.1'
export CONFIRM_INSPACE_CLUSTER_E2E='<isolated-billing-account-id>'
./test/e2e/run.sh
```

Required `.env` values are `INSPACE_API_URL`, `INSPACE_API_TOKEN`,
`INSPACE_LOCATION`, `INSPACE_BILLING_ACCOUNT_ID`, `INSPACE_NETWORK_UUID`,
`INSPACE_CONTROL_PLANE_VIP`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_START`,
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP`, and
`INSPACE_INTEL_HOST_POOL_UUID`. The control-plane VIP must be one unused
RFC1918 address inside that VPC subnet. The inclusive private Service range
must contain 16-256 addresses, be excluded from InSpace VM and NLB allocation
before the run, and not contain that VIP; the current InSpace API cannot
reserve the range. Optional values include
`INSPACE_E2E_SSH_USERNAME`, `INSPACE_OS_NAME`, and `INSPACE_OS_VERSION`.

For an explicitly requested debugging session only:

```sh
export INSPACE_E2E_KEEP_RESOURCES=true
```

This continues to incur charges and intentionally skips automatic cleanup.
The state directory is printed by the container for manual recovery.

## Non-live verification

The following checks structure and fail-closed invariants without Docker or
cloud access:

```sh
python3 test/e2e/verify-static.py
```

Building the runner is also non-live; do not start it unless the isolated
billing-account confirmation is intentional:

```sh
docker build -f test/e2e/Dockerfile --target local-validation \
  -t inspace-cloud-rke2-e2e:local .
```

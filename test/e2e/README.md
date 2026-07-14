# Full InSpace RKE2 cluster E2E

This is the destructive release-acceptance suite for the complete InSpace
stack. The host entrypoint is intentionally only a Docker launcher: Ansible,
Helm, kubectl, SSH, curl, provisioning, live assertions, and cleanup all run
inside a purpose-built Ubuntu 26.04 controller image. The destructive image
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
disabled. The complete audited cache inventory has 34 images; this cluster
must seed exactly 32 because it omits the disabled addon's webhook-certgen and
ingress-controller images.

The API and registration listeners share the configured private kube-vip
address on TCP/6443 and TCP/9345. No bootstrap NLB or API endpoint FIP exists.
The suite pins kube-vip `v1.2.1` by digest, requires one static mirror pod per
control plane, one Lease holder, and exactly one VIP owner. Each generated
manifest and live mirror Pod must mount the host RKE2 kubeconfig
`/etc/rancher/rke2/rke2.yaml` at `/etc/kubernetes/admin.conf`, map
`kubernetes` to `127.0.0.1`, omit `k8s_config_file`, and derive
`vip_nodename` from the downward API's `spec.nodeName`. Lease-holder checks
must resolve that exact node name to one control-plane mirror Pod; a Pod-name
fallback is not accepted. Both the generated manifest and live Pod must drop
`ALL` Linux capabilities and add exactly `NET_ADMIN` and `NET_RAW`. The suite
then removes the leader's static manifest temporarily, proves ownership moves
to a different control plane without interrupting the API, and restores all
three pods.

One controller-owned bastion is the sole inbound SSH endpoint. Control planes
and the Karpenter worker are reached only at private IPs through pinned SSH
host keys and `ProxyJump`; Kubernetes uses a container-local SSH forward to the
private VIP with that VIP as the TLS server name. The private registration VIP
is used by the `inspace-rke2-agent-token` Secret and worker bootstrap. Because
InSpace has no NAT service, all three control planes, the worker, and bastion
still receive one FIP for egress, but node FIPs are never used as management
endpoints. VM creation uses `reserve=true`: InSpace creates one initially
nameless FIP already assigned to the VM while the VM detail's `public_ipv4`
remains empty. Each reconciler discovers that sole assignment by VM UUID,
PATCHes the deterministic owner name and billing account, and requires exact
authoritative readback before continuing. Karpenter persists ownership schema
`karpenter.inspace.cloud/v3` with the deterministic FIP name but no copied
`publicIPv4`; the FIP record is the address authority, and CCM must publish that
same address as the worker Node's sole `ExternalIP`. The worker proof binds
Node/NodeClaim/provider ID to one exact VM,
authoritative VPC membership, private subnet containment, the configured AMD
EPYC host pool, exactly one 100 GiB primary root disk, and its exact FIP. The
control planes, bastion, and Karpenter worker all use that exact AMD EPYC pool;
the worker NodePool selects it with an
`inspace.cloud/host-class In [amd-epyc]` requirement. The reusable NodeClass
validates both supported class-to-pool mappings, while the live Node and
NodeClaim must advertise `instance-cpu=2`, `instance-memory=4096` MiB, and the
resolved AMD host class. The E2E NodePool selects the `general` family and
requires `instance-cpu Gt ["1"]` without an instance-memory selector. This
excludes every 1-vCPU shape, while the pool limits and live Node/NodeClaim
assertions prove the selected worker is 2 vCPU / 4 GiB. The explicit family
requirement excludes every non-`general` shape, including `extra-memory`.
Before the final worker identity is journaled, the suite pulls immutable amd64
blobs directly from Docker Hub and GHCR. A recognized registry timeout triggers
a bounded blue/green retry: the failed worker is cordoned but its NodeClaim, VM,
and FIP remain allocated while Karpenter creates and proves a distinct FIP on a
new worker. Rejected FIPs are released only after one replacement passes both
registries; authentication, image, and other non-network failures stop without
rotating cloud resources. At most three workers overlap, and the NodePool is
restored to its normal one-worker limit after convergence.
The three control-plane cloud names, guest hostnames, and Kubernetes Node names
are live-proven as `<clusterResourceName>-cp0`, `-cp1`, and `-cp2`.
Each E2E control plane uses a 60 GiB root disk, and the E2E Karpenter NodeClass
uses a 100 GiB worker root disk.
The bastion cloud name and guest hostname are live-proven as
`<clusterResourceName>-bastion`. Bootstrap FIPs are
`<clusterResourceName>-bastion-ip` and `<clusterResourceName>-cp0-ip` through
`-cp2-ip`; firewalls are `<clusterResourceName>-bastion-<owner>` and
`<clusterResourceName>-nodes-<owner>`. The owner suffix keeps firewall identity
fail-closed even when InSpace omits descriptions from readback. Cluster
resource names are limited to 55 characters so the longest fixed `-bastion`
hostname remains a DNS label.
The worker cloud name, API hostname when returned, guest hostname, and
Kubernetes Node name are live-proven as
`<clusterResourceName>-karp-general-<Karpenter random suffix>` while its
separate `general-<random suffix>` NodeClaim remains the ownership identity.
The suite requires every control plane, worker, and bastion hostname to resolve
to `127.0.1.1` through its generated `/etc/hosts` entry after the bounded
bootstrap readback. Fixed-node ownership must be schema v6, and the Karpenter
worker must use bootstrap schema v11.
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
NLB using the public scope label and annotation with
`externalTrafficPolicy: Local`. Its target set must be exactly the Ready worker
that hosts the Ready local endpoint—never the three control-plane nodes. The
suite temporarily switches that Service to `externalTrafficPolicy: Cluster`,
requires exactly three Ready role-labeled control-plane nodes, and proves the
NLB still targets only the eligible Ready worker before restoring `Local` in an
unconditional cleanup block. Kubernetes defaults an omitted
`externalTrafficPolicy` to `Cluster`; the CCM preserves that API default and
does not mutate the Service spec, so users must request `Local` explicitly.
The suite also proves Node-event reconciliation by applying the standard
external-LB exclusion label and observing an empty target set, then removes
every serving replica and again requires zero targets before restoring the
replica and exact worker target. It proves the two private Services own zero
InSpace NLBs/FIPs, while the public Service owns exactly one of each. It then
removes only the public scope label (leaving the annotation and Service type
intact), waits for that NLB/FIP to be deleted and its status cleared, and
restores only the label to prove label-driven recreation. This directly
exercises CCM's provider-intent trigger for changes the generic Service
controller otherwise does not observe. UDP is not tested on the public path
because the InSpace NLB supports TCP only. After the final public-path check,
the suite deletes only this paid public Service and requires both its NLB and
FIP to be absent before it marks acceptance complete. The deployments, PVC,
private Services, cluster, and worker remain available to later checks or a
preserved phased run.

## Safety and cleanup

Use only a new, empty, isolated billing account. Before its first mutation the
suite captures every API-visible VM, firewall, floating IP, load balancer, and
disk and requires all five inventories to be empty. Cleanup must make the full
account inventory exactly equal that persisted baseline, in addition to its
deterministic ownership audit. A malformed or unidentifiable active API item
is fatal rather than silently ignored.

One exclusive lock covers the shared state volume for the full lifetime of
every phase container. An existing run ID can never be reused by the `init`
phase for new provisioning, but `test`, `shell`, and `destroy` deliberately
reuse an initialized run. A durable pre-mutation checkpoint allows a missing
journal to be classified as safe only before any remote call could mutate
state; once mutation may have started, missing or unreadable ownership state
preserves resources and fails closed. Explicit retention is persisted
independently of the journal and always wins over an old zero audit.

The default `all` phase runs `init-cluster.yml`, then `test.yml`, and finally
`destroy-cluster.yml`. It attempts destruction after completion or failure and
on signals unless resource retention was explicitly requested. The standalone
`init`, `test`, and `shell` phases instead preserve the cluster on success,
failure, and signals so a failed assertion can be inspected or rerun without
provisioning the cluster again. The `destroy` phase is the explicit cleanup
path for those preserved runs. A durable `phase-preserved` marker prevents a
later default `all` run from cleaning them implicitly. Owner removal is ordered:

1. all public/private workloads, Services, and the PVC;
2. pods, PV, and VolumeAttachments must disappear;
3. both private `cilium-l2announce-*` Leases must disappear and
   `CiliumLoadBalancerIPPool/inspace-private` must report zero used IPs;
4. NodePool, NodeClaims, worker Nodes, then NodeClass;
5. CSI/CCM/Karpenter-owned disks, workers, floating IPs, and service NLB must
   be absent before controller charts are removed; Karpenter deletes its named
   FIP before deleting the worker VM because VM deletion only leaves that FIP
   active and unassigned;
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

Before a default `all` run, the entrypoint cleans an unfinished non-phased run
with the same recorded published version and requires its final zero audit. It
refuses to clean a run carrying the durable phased-workflow marker. The
standalone `init` phase refuses to start while the last run remains unfinished;
use `test`, `shell`, or `destroy` for that run first. If the requested version
differs, select the version recorded in its state before destroying it. A run
retained with `INSPACE_E2E_KEEP_RESOURCES=true` is never removed implicitly.
To destroy an explicitly retained run, authorize that exact action:

```sh
export INSPACE_E2E_RUN_ID='<persisted-run-id>'
export INSPACE_E2E_RECOVER_RETAINED=true
make cluster-e2e-destroy
```

## Run

Publish the exact release candidate first. Put the isolated account values in
the ignored, mode-`0600` root `.env`, then export the destructive confirmation
and released SemVer:

```sh
export INSPACE_E2E_VERSION='<published-version>'
export CONFIRM_INSPACE_CLUSTER_E2E='<isolated-billing-account-id>'
make cluster-e2e
```

`make cluster-e2e` selects the default `all` phase, which initializes the
cluster, runs the acceptance tests, and destroys the cluster with a final zero
audit. The equivalent direct command is `./test/e2e/run.sh all`; omitting the
argument also selects `all`.

For development and test debugging, run the phases separately:

```sh
make cluster-e2e-init
make cluster-e2e-test
make cluster-e2e-shell
# Run kubectl commands inside the tunneled shell, then exit.
make cluster-e2e-test
make cluster-e2e-destroy
```

`init` creates a new run and preserves it. `test` reuses that initialized
cluster and preserves it whether the tests pass or fail, so test-only changes
can be exercised repeatedly. A successful `test` removes the paid public
Service/NLB/FIP after its acceptance checks while retaining the other test
resources; a later `test` recreates and revalidates that Service through the
normal manifest apply. `shell` reestablishes the private-API SSH tunnel,
exports the persisted kubeconfig, and opens an interactive environment where
commands such as `kubectl get nodes` work directly. Exiting the shell stops its
local tunnel but leaves the cluster running. Each phase container holds the
shared state-volume lock until it exits, so a shell blocks concurrent test or
destroy operations. Inspect or restart pods freely, but do not manually
delete/recreate the E2E Services or PVC: cleanup authority is bound to their
persisted UIDs. Use `cluster-e2e-destroy` followed by a new `init` when those
ownership objects must be replaced.

After a late `init` failure, `shell` can also attach when the ownership journal,
pinned bastion identity, and tunneled kubeconfig were already created. If the
failure happened before those access facts existed, the fail-closed option is
the explicit `destroy` phase.

The `test`, `shell`, and `destroy` phases select `INSPACE_E2E_RUN_ID` when it is
set; otherwise they select the run recorded in the state volume's
`last-run-id`. Set the variable explicitly when working with an initialized run
that is not the most recent one:

```sh
export INSPACE_E2E_RUN_ID='<persisted-run-id>'
make cluster-e2e-shell
```

Preserved phase runs continue to incur charges until `cluster-e2e-destroy`
completes.

The runner image is built and executed as `linux/amd64` by default, matching
the x86-64 AMD EPYC pool used by every E2E VM. A future ARM-backed test account
can opt in without changing the launcher:

```sh
export INSPACE_E2E_RUNNER_PLATFORM='linux/arm64'
```

Only `linux/amd64` and `linux/arm64` are accepted. The selected platform is
applied to both the Docker build and the Docker run.

Required `.env` values are `INSPACE_API_URL`, `INSPACE_API_TOKEN`,
`INSPACE_LOCATION`, `INSPACE_BILLING_ACCOUNT_ID`, `INSPACE_NETWORK_UUID`,
`INSPACE_CONTROL_PLANE_VIP`, `INSPACE_PRIVATE_LOAD_BALANCER_POOL_START`,
`INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP`, and
`INSPACE_AMD_HOST_POOL_UUID`. The AMD EPYC pool is used by the fixed control
planes, bastion, and Karpenter worker. The control-plane VIP must be one unused
RFC1918 address inside that VPC subnet. The inclusive private Service range
must contain 16-256 addresses, be excluded from InSpace VM and NLB allocation
before the run, and not contain that VIP; the current InSpace API cannot
reserve the range. Optional values include
`INSPACE_E2E_SSH_USERNAME`, `INSPACE_OS_NAME`, and `INSPACE_OS_VERSION`.

The default `all` workflow normally destroys its resources. To retain that
workflow's cluster explicitly after its test phase:

```sh
export INSPACE_E2E_KEEP_RESOURCES=true
make cluster-e2e
```

This marks the run as retained, continues to incur charges, and skips the
default automatic destroy. Later cleanup requires
`INSPACE_E2E_RECOVER_RETAINED=true` with `make cluster-e2e-destroy`, as shown
above. The standalone phase workflow already preserves its cluster and does
not require `INSPACE_E2E_KEEP_RESOURCES`.

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

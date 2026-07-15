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

Immediately after setting the static hostname, every control plane, worker,
and bastion removes any stale `127.0.1.1` mapping, writes exactly
`127.0.1.1 <generated-hostname>` to `/etc/hosts`, and retries the exact
`getent` readback within a fixed bound until that name resolves locally. This
bounded retry accounts for a short NSS readback delay after a successful file
append; package installation and resolver replacement do not begin until the
mapping is visible. Current fixed control-plane ownership records use schema
v7 because enabling Cilium Node IPAM changes their immutable RKE2 cloud-init;
bastion ownership remains v6. Karpenter's current immutable bootstrap drift
schema is `stock-ubuntu-rke2-v11`; this is separate from its cloud VM ownership
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
classes and cannot race the generic external CCM. Node IPAM is enabled for
CCM-owned shadow Services; the supported user contract is
`loadBalancerClass: inspace.cloud/node`, never raw `io.cilium/node`. The CCM
assigns shared Services by conflict-free `(protocol, port)` claims or gives
dedicated Services an isolated static Karpenter shard. Generated nodes use AMD
EPYC, a 30 GiB disk, a `NoSchedule` taint, and the private base firewall.
Per-Service public firewalls contain exact TCP/UDP rules only. One separately
owned cluster firewall containing a single portless inbound ICMP-from-Any rule
is reused by every authorized Node-LB VM. `loadBalancerSourceRanges` affects
only Service TCP/UDP rules and never restricts ping.

The Cilium readiness gate uses protected
`inspace.cloud.node-restriction.kubernetes.io/*` labels. CCM validates the full
rendered NodePool profile, including its taint, plus the exact
Node→NodeClaim→NodePool→NodeClass and FIP identity chain. Advertising requires
Node Ready, Karpenter's valid private base-firewall contract, the shared ICMP
assignment, and every active Service firewall assignment. A failure in those
authorization or assignment checks clears the ready label before returning.

This controller contract assumes trusted cluster administrators. For
multi-tenancy, admission and RBAC must reserve raw `io.cilium/node` Services,
`io.cilium.nodeipam/*` annotations, `Service.spec.externalIPs`, protected CCM
metadata, and Node-LB tolerations/selectors. NodeRestriction prevents a kubelet
from forging the protected labels; the `NoSchedule` taint alone is not a
security boundary.

Every owned live shadow keeps its `(shard, protocol, port)` reservation until
that shadow is updated or deleted, so simultaneous port swaps and deleting
peers cannot create a transient duplicate frontend on one public node address.
The user Service must have a selector and explicit
`allocateLoadBalancerNodePorts: false`; unsupported frontends and source ranges
fail before static capacity is created. Replacement capacity and the Cilium
shadow status must converge before CCM removes a previous shard or firewall.
Firewall creation persists a deterministic pre-POST intent. Ambiguous or
eventually consistent readback requires a five-minute grace period followed by
three absence observations at least 30 seconds apart; visibility resets that
evidence. Service finalization independently requires three spaced
authoritative absence observations, so a transient list omission cannot orphan
a billable firewall. The cluster ICMP identity is persisted on the generated
NodeClass and is deleted only after the last finalized Node-LB Service and all
managed NodePool, NodeClaim, and Node capacity are absent.

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
identity. Deletion unassigns and deletes that floating IP first, deletes the VM
only after FIP convergence, proves canonical VM absence, and finally removes
every stale firewall assignment for the exact VM UUID. The shared firewall
itself is not deleted with an individual worker.

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
- Live lifecycle tests are separate from normal tests, use unique
  `inspace-e2e-*` names, and clean up every resource they create.
- Mutating requests to `api.inspace.cloud` are denied by default in the shared
  client. Live module tests require both `INSPACE_RUN_LIVE_TESTS=true` and
  `INSPACE_ALLOW_REMOTE_MUTATIONS=true`; the root live-suite wrapper sets them
  only after its billing-account confirmation succeeds.
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

The lifecycle suite creates only resources named `inspace-e2e-*`, preserves
firewall protection when deletion is uncertain, and performs a zero-leftover
audit before and after the run. Every test VM uses the configured AMD EPYC
pool. The suite covers VM, firewall, floating-IP, TCP-NLB, block-disk, and real
Karpenter-adapter lifecycles. Never run it against a production billing account
or from a pull request.

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

# Ansible cluster lifecycle

`deploy/` is the operator-facing cluster lifecycle. It creates the fixed
bastion and RKE2 control plane, establishes private API access, installs the
released CCM/CSI/Karpenter charts, creates a default AMD EPYC worker
`InSpaceNodeClass` and `NodePool`, performs rolling operator configuration, and
destroys only the journaled cluster.

New v0.8.0 clusters enable Cilium Egress Gateway during immutable control-plane
bootstrap. After initialization, operators can apply
[`../charts/inspace-cloud-kube-modules/examples/egress-gateway-static.yaml`](../charts/inspace-cloud-kube-modules/examples/egress-gateway-static.yaml)
to maintain two tainted, egress-only Karpenter nodes for selected workloads.
Clusters bootstrapped by an older release require an explicit
destroy/recreate lifecycle to acquire this immutable Cilium setting.

The release E2E suite remains in `test/e2e/`. It deliberately has stricter
isolated-account assertions and is not the production inventory.

## Requirements

- macOS or Linux management host with Git, Docker, and an accessible
  `/var/run/docker.sock`
- Docker support for running `linux/amd64` images. The dependency-locked
  Ansible runner uses the management host's native Docker architecture; on
  Apple Silicon, only the released bootstrap controller uses Docker Desktop's
  x86 emulation because current InSpace VMs and controller images are x86-64
- one existing InSpace VPC, an unused private control-plane VIP, and a private
  Service VIP range of 16–256 addresses excluded from normal cloud allocation
- an exact released module version
- an SSH private/public key pair; private keys are used locally and never sent
  to InSpace, while the public key is supplied to VM creation
- `INSPACE_API_TOKEN` exported in the process environment

The launcher builds a local operator image from `deploy/Dockerfile` on first
use. Ubuntu, Docker CLI, Helm, Ansible Core and every Python package are
version-and-digest or exact-version locked; kubectl uses an exact version with
upstream checksum verification. The image is addressed by a fingerprint of
the committed deploy runner sources, so it is reused until runner code or its
dependency lock changes.

Inventory is never copied into that image. `deploy/run.sh` bind-mounts the
selected inventory read-only for every invocation, so editing configuration
does not rebuild the image. It also bind-mounts `deploy/.state/` read-write at
the same absolute path, the SSH key directory read-only at its same absolute
path, and the Docker socket for exact released bootstrap-controller execution.
The Docker build context excludes real inventories, SSH material and lifecycle
state.

Copy and edit the example without committing it:

```sh
cp deploy/inventory.example.yml deploy/inventory.yml
chmod 600 deploy/inventory.yml
export INSPACE_API_TOKEN='...'
```

By default, key paths in inventory must be absolute paths beneath
`$HOME/.ssh`. Set `INSPACE_DEPLOY_SSH_DIR` to the common parent directory when
the pair is stored elsewhere; that directory is mounted read-only at the same
absolute path. `INSPACE_DEPLOY_STATE_ROOT` can similarly relocate the durable
state root. A prebuilt image may be selected with
`INSPACE_DEPLOY_RUNNER_IMAGE`; the launcher never silently rebuilds an
explicitly selected image.

The real inventory, generated tokens, kubeconfig, host-key pins, bootstrap
ledger, and lifecycle journal are ignored by Git under `deploy/.state/`.
Back up that directory securely. Its `cluster.yaml` contains durable no-replay
receipts required for safe recovery and destroy.

## Bootstrap download and OS upgrade options

The inventory deliberately uses one setting for each cluster-wide bootstrap
choice:

| Inventory value | Default | Applies to |
| --- | --- | --- |
| `bootstrap_direct_download` | `false` | Bastion cache setup, control-plane downloads, and the generated Karpenter `InSpaceNodeClass` |
| `skip_os_upgrade` | `false` | Bastion, every fixed control-plane server, and every worker created from the generated Karpenter `InSpaceNodeClass` |

Cached mode (`bootstrap_direct_download: false`) is the normal path. The
bastion serves the private RKE2 asset and system-image cache, and both fixed
and elastic nodes use it. Direct mode keeps the bastion for private management
but makes every node use upstream download locations.

`skip_os_upgrade: true` is intended only for short-lived test clusters. It
skips the one-time `apt-get upgrade -y`, but still configures mirrors and DNS,
runs `apt-get update`, installs required packages, and disables later automatic
APT upgrades. Keep the production default `false` for both control-plane and
Karpenter nodes.

## Ubuntu release

`os_version` selects the Ubuntu release for the fixed control-plane servers,
the bastion (which follows them), and the generated Karpenter
`InSpaceNodeClass`. It must be exactly `"24.04"` or `"26.04"`; quote it in
inventory. `"26.04"` requires `modules_version` `1.1.0-rc.3` or later, because
earlier controllers accept only `24.04`, and preflight rejects the combination.
When `os_version` is omitted, a cluster that already has a persisted bootstrap
spec keeps the release it was built with, so `update` never replaces its
workers with another release and a resumed `init` still matches that spec; a
new cluster uses `"26.04"`. Setting a different release on an existing cluster
fails a resumed `init`. On `update` it changes only the NodeClass, so
Karpenter drift replaces the workers while the fixed control planes keep
their release.

## Cilium load-balancer settings

Two optional inventory values tune the bootstrap-owned `rke2-cilium`
HelmChartConfig. Omit both to keep Cilium's defaults and the unchanged
bootstrap spec. Either one requires a `modules_version` newer than
`1.1.0-rc.4`.

- `load_balancer_algorithm` sets Cilium's `loadBalancer.algorithm`: omitted
  (Cilium's default, `random`), `"random"`, or `"maglev"`. Maglev
  consistently hashes north-south Service traffic (Node-LB, NodePort, and
  LoadBalancer frontends): every node that considers the same backend set
  selects the same backend for a flow, and removing one backend remaps only its
  own flows. Cilium's default Maglev table size (16381, suited to about 160
  backends per Service) and its built-in cluster-wide hash seed are kept.
  In-cluster ClusterIP traffic uses socket-level load balancing and is not
  affected.
- `service_topology` (default `false`) sets Cilium's
  `loadBalancer.serviceTopology` when `true`.
  Cilium honors a Service's `trafficDistribution` (`PreferSameNode`,
  `PreferSameZone`, or `PreferClose`) only when it is enabled. That includes
  the `PreferSameNode` default that CCM gives every Node-LB datapath Service,
  which keeps traffic on the receiving LB node when a ready backend runs there
  (for example an ingress that tolerates the Node-LB taint) and falls back to
  every backend otherwise.

Both values are creation-time choices. They are written into the immutable
control-plane cloud-init and the on-disk HelmChartConfig, which `update` never
rewrites, and `InSpaceCluster` rejects any later change. `update` and every
other lifecycle command therefore refuse inventory values that differ from
the persisted bootstrap spec; changing them requires a new cluster.

After control-plane changes, `update` waits for the packaged `rke2-cilium`
chart Job and then requires every Cilium agent to report zero
`cilium_drift_checker_config_delta`. A non-zero value means an RKE2 upgrade
changed `cilium-config` without restarting that agent; `update` stops before
upgrading the cloud modules and names the affected agents so the operator can
review the change and restart them.

## One or three control-plane servers

Set `control_plane_replicas` to:

- `1` for a low-cost cluster. The API and embedded etcd have a single point of
  failure, but application workers still scale through Karpenter.
- `3` for embedded-etcd and control-plane HA.

Two is rejected. Replica count is immutable after creation; changing one to
three or three to one requires a complete, explicit destroy/recreate lifecycle.
Both layouts keep application workloads off the tainted fixed control plane
and start with zero Karpenter workers. The one-server layout pins CoreDNS to
one replica and disables its proportional autoscaler; otherwise a temporary
worker would receive a second CoreDNS Pod and could never become empty for
Karpenter consolidation.

## Commands

An explicit inventory path may be absolute or relative:

```sh
deploy/run.sh init "$PWD/deploy/inventory.yml"
deploy/run.sh status "$PWD/deploy/inventory.yml"
deploy/run.sh update "$PWD/deploy/inventory.yml"
deploy/run.sh tunnel "$PWD/deploy/inventory.yml"
```

`init` is resumable. It renders a desired spec separately and refuses any
bootstrap-spec drift before touching the persisted `cluster.yaml`; this avoids
erasing uncertain cloud-mutation receipts. Before its first cloud mutation it
also persists the bootstrap-controller version that must later resume or
destroy that ledger. Boolean fields omitted by the controller's canonical YAML
serialization are compared using their API default of `false`. It then:

1. generates and persists the RKE2 token and optional cache PKI seed;
2. runs the exact released bootstrap controller to API-level readiness;
3. binds its result to the deterministic FIPs;
4. pins bastion and private control-plane SSH host keys;
5. retrieves a kubeconfig whose endpoint is only the local bastion tunnel;
6. waits for the requested one or three Ready servers;
7. on a one-server topology, temporarily schedules only RKE2's packaged
   installation Jobs on cp0, restores both the control-plane and cloud-provider
   startup taints to their original state, and verifies zero workers before
   Karpenter exists; its bootstrap Helm configuration also keeps CoreDNS at
   one cp0 replica so an application worker can return to zero after use;
8. installs exact-version OCI charts and the default Karpenter resources.

InSpace's floating-IP pool has occasionally handed a bastion or control-plane
VM an address with no working SSH/internet path, hanging `init` on cloud-init
or SSH waits until they time out. Setting
`INSPACE_DEPLOY_INIT_AUTO_RECOVER=true` authorizes `init` to destroy and retry
the exact cluster named by the given inventory, unattended, once, if it does
not converge — the same class of advance authorization
`CONFIRM_CLUSTER_DESTROY` grants for a single explicit destroy, just given up
front instead of typed again mid-run. It is opt-in and defaults to `false`;
without it, a failed `init` stops and leaves the cluster for the operator to
inspect or destroy manually. `INSPACE_DEPLOY_INIT_RETRY_COOLDOWN_SECONDS`
(default `300`, max `3600`) sets the delay between the destroy and the retry,
giving the pool time to stop handing back the same just-freed address.

`update` does not replace fixed VMs or rewrite bootstrap cloud-init, and it is
the single command for both kinds of day-2 upgrade:

- **Cloud-module upgrade**: it refreshes the in-cluster API Secret, upgrades
  the CRD and workload OCI charts to `modules_version`, and reapplies the
  default Karpenter NodeClass/NodePool. Because the NodeClass identity changes
  whenever its rendered RKE2 version or image changes, Karpenter's built-in
  drift detection automatically replaces existing elastic workers with nodes
  running the new version, respecting NodePool disruption budgets — no manual
  worker action is required.
- **Control-plane RKE2 version upgrade**: when `rke2_version` in the inventory
  differs from the RKE2 version recorded in the deployment journal (the
  init-time version until the first upgrade) or from the kubelet version the
  running control plane reports, `update` downloads the exact upstream RKE2 release directly (bypassing the
  bastion bootstrap cache, which pins exactly one audited version per
  controller build), verifies its published checksum, and swaps the binary on
  one control-plane server at a time — stopping `rke2-server`, replacing
  `/usr/local/bin/rke2`, and restarting — waiting for that Node to be Ready and
  the cluster API to recover before moving to the next server. This is the
  same fail-closed one-at-a-time sequencing already used for
  `control_plane_extra_config` changes, so embedded-etcd quorum is preserved
  throughout (at most one of three servers is ever down). After every server
  runs the new release, `update` records it as `rke2Version` in `state.json`;
  `cluster.yaml` keeps the init-time version because it remains the bootstrap
  and destroy authority. Only `update` accepts an inventory `rke2_version`
  that differs from the recorded one. An RKE2 release candidate such as
  `v1.36.5-rc2+rke2r1` ships the GA kubelet, so its nodes report
  `v1.36.5+rke2r1`; the journal is what distinguishes the candidate from its
  GA release, and moving from the candidate to GA is an ordinary upgrade.

  A downgrade or a jump of more than one RKE2 minor version is refused unless
  the operator exports `INSPACE_CONFIRM_RKE2_VERSION_SKIP=<cluster-name>`,
  matching this project's typed-confirmation pattern for other destructive or
  unusual operations. A **cached-mode** cluster (`bootstrap_direct_download:
  false`) can only reach a version its bastion cache manifest supports; since
  that manifest is pinned per controller release (see
  [DEVELOPMENT.md](../DEVELOPMENT.md#bastion-bootstrap-cache)), an RKE2
  version bump on a cached cluster is normally paired with a
  `modules_version` bump to a release that pins the new version. A
  **direct-download** cluster (`bootstrap_direct_download: true`) can upgrade
  to any valid RKE2 release independently of `modules_version`.

`update` still puts `control_plane_extra_config` in RKE2's operator fragment
after any RKE2 binary upgrade, restarting at most one server at a time.
Topology, identity, control-plane taints, packaged-component disablement, CNI,
CIDR, token, data-directory, and registry keys remain blocked because the
bootstrap controller owns them; replica-count and machine-shape changes still
require the explicit destroy/recreate lifecycle. On a single-server cluster,
each RKE2 restart necessarily causes brief API downtime.

`tunnel` starts or reuses the SSH control connection and prints the local
kubeconfig path. The kubeconfig uses `127.0.0.1:16443` with the private VIP as
its TLS server name; it never exposes a control-plane FIP as a public API. The
launcher keeps this one container running and publishes its tunnel only on
host loopback. Repeating `tunnel` reuses it. `destroy` stops that tunnel
container before beginning the guarded teardown.

## Safe destroy

Destroy requires an exact typed confirmation:

```sh
export CONFIRM_CLUSTER_DESTROY=example-rke2
deploy/run.sh destroy "$PWD/deploy/inventory.yml"
```

The playbook fails closed when PVCs, PVs, or VolumeAttachments remain. Remove
application storage through Kubernetes first so CSI can detach and delete
disks safely. It deletes LoadBalancer Services while CCM can still reconcile,
deletes all NodePools and waits for every NodeClaim and non-control-plane node
to disappear, then removes NodeClasses and charts. Finally it runs the
bootstrap-controller version recorded at creation against the durable ledger.

VPCs, manually created floating IPs, and unrelated account resources are never
destroy targets. If the Kubernetes API or journal is unavailable, automated
destroy stops instead of bypassing CSI, CCM, Karpenter, or ownership checks.

## Limits

Fixed control-plane shape, image, bootstrap cache mode, network, VIP, and
replica-count updates are not in-place operations; the bootstrap controller
rejects immutable VM drift for those fields. RKE2 *version* is the one
exception: `update` performs an in-place, one-at-a-time control-plane binary
upgrade (see above) and elastic workers converge automatically through
Karpenter drift-replacement. `update` otherwise covers the allowlisted
operator RKE2 fragment and released cloud-module upgrades; machine shape and
replica-count replacement remain a planned, explicit destroy/recreate
lifecycle.

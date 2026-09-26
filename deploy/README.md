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

## Released image digests

Release tags are mutable, so the lifecycle never pulls a controller image by
tag. Before the first pull or cluster change, `init`, `update`, and `destroy`
run `scripts/resolve_release_images.py`. It reads the image-digest records
attached to the exact, immutable GitHub release, checks each record body
against the SHA-256 that GitHub reports for the asset, and then reads the
image index, its linux/amd64 manifest, and that manifest's config from
ghcr.io by digest. Every body must hash to the digest it was requested by, and
the config labels must name this repository and the exact version. Every call
is anonymous.

The bootstrap controller, which receives the InSpace API token and the RKE2
registration token, then runs as `image@sha256:<index digest>`. Helm installs
the CCM, CSI, and Karpenter workloads with `image.digest` set to the resolved
linux/amd64 manifest digest, which is also the digest the bootstrap cache
stores. The management host therefore needs HTTPS access to `api.github.com`,
`github.com`, and `ghcr.io`.

Release images also carry keyless build-provenance attestations. The runner
does not verify them automatically, because `gh attestation verify` needs a
GitHub token. To check one yourself:

```sh
gh attestation verify \
  oci://ghcr.io/thanet-s/inspace-cloud-controller-manager@sha256:<index digest> \
  --repo thanet-s/inspace-cloud-kube-modules
```

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

## Optional Gateway API

`gateway_api_enabled` (default `false`) enables Cilium's Gateway API
implementation and the `cilium` GatewayClass. Gateway API is served by Cilium
alone and needs no Traefik: `rke2-traefik` and `rke2-ingress-nginx` stay
disabled, the template also disables `rke2-traefik-crd` (its bundled Gateway
API CRDs would conflict), and `rke2-gateway-api-crd` is never disabled. It requires an `rke2_version`
that bundles Cilium 1.20 or newer (`v1.34.12+`, `v1.35.9+`, `v1.36.5+`, or
`v1.37.0+`; the audited `v1.36.5-rc2+rke2r1` qualifies) and preflight rejects
older releases. It is fixed at cluster creation: it is rendered only into
immutable control-plane bootstrap, a resumed `init` refuses a changed value,
and `update`, `status`, and `destroy` refuse an inventory that differs from
the persisted spec. Enabling it on an existing cluster requires a
destroy/recreate lifecycle.

Below RKE2 v1.37 the cluster installs the pinned Gateway API v1.6.1 standard
CRD bundle itself (the same version RKE2 v1.37 ships, including the upstream
`safe-upgrades` ValidatingAdmissionPolicy). The bundle is about 1.2 MB, too
large for cloud-init, and is never downloaded by a node. `init` prints it
offline from the exact bootstrap-controller image with
`inspace-cluster-controller --print-gateway-api-crds`, checks its SHA-256, and
copies it over SSH to `/var/lib/inspace/gateway-api-standard-install.yaml` on
every control plane. Each server waits up to 30 minutes for those exact bytes
before starting RKE2, then installs them as the RKE2 server manifest
`inspace-gateway-api-crds.yaml`, so Cilium sees the CRDs at its first start.
From v1.37 RKE2's default `rke2-gateway-api-crd` chart installs the same CRDs,
so nothing is printed, copied, or awaited. Before `update` rolls a cluster from
below v1.37 to v1.37 or later, it creates
`inspace-gateway-api-crds.yaml.skip` next to that manifest on every server.
RKE2 then stops re-applying the manifest without deleting anything, and its
chart adopts the existing CRDs with `takeOwnership`; Gateways and routes are
untouched. Never delete or disable that manifest: RKE2 deletes the resources
of a disabled manifest. `init` then requires `enable-gateway-api` in
`cilium-config` and an `Accepted` `cilium` GatewayClass. Expose a Gateway
through the paid public NLB with its `spec.infrastructure` labels and
annotations; see
[`../modules/cloud-provider/README.md`](../modules/cloud-provider/README.md#gateway-api).
`destroy` deletes every Gateway before the LoadBalancer Services, so Cilium
cannot recreate a Service that would receive a new paid NLB.

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

1. generates and persists the RKE2 server token, a separate RKE2 agent token
   (see [RKE2 join tokens](#rke2-join-tokens)), and the optional cache PKI
   seed;
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

- **Bootstrap cache refresh** (cached mode only; a no-op for
  `bootstrap_direct_download: true`): the bastion cache is read-only, is not a
  pull-through proxy, and was seeded once with the images of the release that
  built it. Cached nodes pull every RKE2 system image and every chart image
  (CCM, CSI and its sidecars, Karpenter) through it, and Karpenter workers
  download their RKE2 archive from it. So before `update` touches RKE2 or the
  charts, it runs the target `modules_version` controller image offline
  (`inspace-cluster-controller --print-bootstrap-cache-refresh`) to print that
  release's own cache seed contract, and adds exactly those entries on the
  bastion. When `update` moves RKE2 the list is the checksum-pinned RKE2
  archive and every image of the full seed; otherwise it is only the kube-vip,
  CSI sidecar, and module images. The bastion resolves each source to its
  linux/amd64 manifest digest (a digest-pinned source must return exactly the
  pinned bytes) and imports only missing tags, by that digest, with the same
  `skopeo` options as the build-time seed. It never deletes an entry and never
  overwrites a tag that holds another digest or an RKE2 archive with another
  checksum; either stops `update` before any change. The registry becomes
  writable only on the bastion's loopback while images are imported and is
  always restored to read-only; the private TLS endpoint stays GET/HEAD-only.
  Every entry is then read back through that endpoint, a write probe must be
  refused, and the whole step is bounded to 45 minutes. Each refresh adds to
  the cache's fixed 10 GB filesystem, which keeps a 1 GB reserve; a refresh
  that would cross it fails. The refresh also installs the current daily
  maintenance script, which keeps every refreshed RKE2 release instead of
  aging out all but the bootstrap one. Only a target release that supports
  `--print-bootstrap-cache-refresh` can update a cached cluster.
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
  running control plane reports, `update` downloads the exact upstream RKE2
  release archive onto each server directly from GitHub, verifies its
  published checksum, and swaps the binary on
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
  false`) still pulls the new release's system images from the bastion, so it
  can move only to the one RKE2 release its target `modules_version` pins
  (see [DEVELOPMENT.md](../DEVELOPMENT.md#bastion-bootstrap-cache)); the
  bootstrap cache refresh above adds that release first and refuses any other
  `rke2_version` before a server is touched. An RKE2 upgrade on a cached
  cluster is therefore paired with a `modules_version` that pins the new
  release, and a `modules_version` bump alone keeps the running RKE2 release.
  A **direct-download** cluster (`bootstrap_direct_download: true`) can upgrade
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

## RKE2 join tokens

RKE2 has two static join secrets. The server token (`rke2-token` in the state
directory) joins servers and also encrypts the cluster's bootstrap data. Anyone
holding it can fetch that data, including the CA and etcd keys, from the
supervisor on port 9345, which is equivalent to cluster-admin. The agent token
(`rke2-agent-token`) can join only agents.

A new cluster gets both. `init` generates each with `openssl rand -hex 32`,
stores it mode `0600`, and never logs it. Every control plane is rendered with
`token:` and `agent-token:`. Only the agent token goes into
`Secret/inspace-rke2-agent-token`, which Karpenter writes to every worker it
creates, including public Node-LB workers. The tokens use RKE2's short
format. The secure `K10<CA hash>::` form cannot be minted up front, because
the cluster CA does not exist until the first server starts.

A cluster created by an earlier release, or with a `modules_version` of
`1.1.0-rc.5` or older, has no `rke2-agent-token`. Its servers have no
`agent-token`, so `init` keeps putting the server token into the worker Secret.
Nothing changes for it automatically: an agent token is part of every
control-plane spec hash, so adding one later would stop `init` from adopting
the existing VMs. `destroy` never reads either token.

### Manual rotation

The steps below edit the servers directly. Afterwards, do not re-run `init`
for this cluster, because it re-applies the Secret from the original state
files. `update`, `status`, `tunnel`, and `destroy` never read the join tokens.
Rotate on one server at a time and wait for that Node to be Ready before you
continue.

To give a legacy cluster an agent token, or to rotate an existing one:

1. Generate a token: `umask 077; openssl rand -hex 32 >new-agent-token`.
2. On every control plane, write `agent-token: "<new token>"` to the mode
   `0600` file `/etc/rancher/rke2/config.yaml.d/50-agent-token.yaml`, then run
   `systemctl restart rke2-server`. RKE2 uses the last value it reads for a
   key, so this file overrides any `agent-token:` in
   `/etc/rancher/rke2/config.yaml`. Every server must use the same value.
3. Replace the Secret without putting the token on a command line:
   `kubectl -n kube-system create secret generic inspace-rke2-agent-token --from-file=token=new-agent-token --dry-run=client -o yaml | kubectl apply -f -`.
4. Replace every existing worker, one at a time, for example with
   `kubectl delete nodeclaim <name>`. Karpenter creates its replacement with
   the new token. A worker keeps its old token in
   `/etc/rancher/rke2/config.yaml` until it is replaced.

A legacy cluster's workers have held the server token, so rotate the server
token as well after the agent token is in place. On one server, run
`rke2 token rotate --token <old server token> --new-token <new server token>`.
Then set `token:` in `/etc/rancher/rke2/config.yaml` to the new value on every
server and restart them one at a time. Keep the new server token as securely
as the etcd snapshots, because RKE2 needs it to restore them. Leave the
state-directory `rke2-token` unchanged: it is the bootstrap ledger's record of
the original cloud-init, and `destroy` does not need it.

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

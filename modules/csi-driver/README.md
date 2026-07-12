# InSpace CSI driver

CSI v1.12 driver for InSpace block storage. The first release supports ext4
`SINGLE_NODE_WRITER`, which Kubernetes exposes as `ReadWriteOnce` (RWO).

The production controller uses the shared
`github.com/thanet-s/inspace-cloud-kube-modules/modules/client` client for disk
create/get/list/delete and VM disk attach/detach. The production node service
uses stable virtio by-id links, safe ext4 detection/formatting, mount conflict
inspection, bind mounts, and idempotent unmounts on Linux.

## Supported contract

| Area | Included | Deliberately excluded |
|---|---|---|
| Access | `SINGLE_NODE_WRITER` / RWO | RWX, ROX, every multi-node mode |
| Filesystem | ext4 mounted volumes | xfs, raw block |
| Controller | create, delete, validate, attach, detach | CSI snapshots, cloning, expansion |
| Node | stage, unstage, publish, unpublish, info, capabilities | stats, expansion |
| Placement | one configured InSpace location | cross-location attachment |

An RWO volume can move between workers only after detach from the old worker
finishes. A delete is refused while the disk is attached. It is also refused if
the InSpace disk has snapshots: the native delete API would delete those
snapshots too, so the driver fails safely instead.

Create is idempotent by `(location, CSI name)`. Because the native API does not
document an idempotency key, an ambiguous create or attach response is
reconciled with read-after-write discovery rather than a blind second mutation.
InSpace capacities are GiB, so CSI byte requests are rounded up to whole GiB.

## Identity and topology

PV volume handles are location-aware:

```text
inspace://bkk01/12345678-1234-1234-1234-123456789abc
```

The node derives the documented stable device link from the first 20
characters of the native disk UUID:

```text
/dev/disk/by-id/virtio-12345678-1234-1234-1
```

The node service reports its Kubernetes node name. For attach/detach, the
controller reads that Node's `spec.providerID` and requires an ID shaped like
`inspace://<location>/<vm-uuid>`. A direct canonical provider ID is also
accepted for diagnostics, but raw VM UUIDs and account-wide VM-name fallback
are rejected. A stale unpublish for a deleted Kubernetes Node is treated as an
idempotent no-op; it never detaches a different VM's disk. The driver never
identifies a node by a public or private IP address; public IPv4 egress does not
change CSI identity or topology.

Only `topology.inspace.cloud/location=<configured-location>` is accepted.
Unknown, empty, or conflicting topology segments are rejected.

## Controller and node modes

Production runs two separate binaries from the same image:

```text
--mode=controller   shared SDK + Kubernetes Node resolver
--mode=node         Linux device and mount adapter
```

Controller mode requires:

- `INSPACE_API_TOKEN`
- `INSPACE_ALLOW_REMOTE_MUTATIONS=true`
- `INSPACE_LOCATION` (for example `bkk01`)
- `INSPACE_BILLING_ACCOUNT_ID` for deterministic disk billing
- in-cluster ServiceAccount access to read Nodes

Node mode requires only `INSPACE_LOCATION` and `NODE_ID`. It does not read or
receive the InSpace API token. Its image must include `blkid`, `mkfs.ext4`,
`mount`, and `umount`, and it must run privileged with `/dev` and the RKE2
`/var/lib/kubelet` directory mounted as shown in `deploy/kubernetes/node.yaml`.

`--mode=all` is accepted only with `--development-fake`; it exists for local
protocol tests and never contacts InSpace or mounts the host.

The included runtime image installs `e2fsprogs` and `util-linux`, so all host
commands checked by node Probe are present. Build it from this repository with
`make image`, or from the monorepo root with:

```sh
docker build --platform=linux/amd64 -f modules/csi-driver/Dockerfile \
  -t inspace-csi-driver:dev .
```

## Tests

Go 1.26.5 is required. From this repository:

```sh
make verify
make smoke
```

The smoke test runs the complete fake gRPC lifecycle:

```text
Create -> Attach -> Stage -> Publish -> Unpublish -> Unstage -> Detach -> Delete
```

Unit tests cover idempotency, topology, capacity rounding, attachment ownership,
wrong-node detach safety, snapshot-protected delete, provider-ID resolution,
mount conflicts, service modes, Probe, and error-code normalization. They make
no network calls and do not modify the host.

An isolated-account disk lifecycle test is compiled only with the `live` build
tag and is additionally guarded by two explicit environment switches. It uses
resource names beginning with `inspace-e2e-` and always registers cleanup:

```sh
INSPACE_RUN_LIVE_TESTS=true \
INSPACE_ALLOW_REMOTE_MUTATIONS=true \
make live-test
```

Ordinary `make test`, `make smoke`, and `make verify` never compile or run that
live test. Never commit an API token.

The separate [full-cluster release acceptance test](../../test/e2e/README.md)
installs the released CSI controller and node DaemonSet into the real RKE2
cluster. It provisions and attaches one RWO volume to the Karpenter worker,
verifies the mounted marker through a pod replacement, then proves the
VolumeAttachment, PV, PVC, disk, and worker are absent after teardown.

## Kubernetes manifests

Files in `deploy/kubernetes` provide:

- a persistent, attach-required `CSIDriver`;
- a strict-topology RWO `StorageClass`;
- a controller Deployment with provisioner and attacher sidecars, scheduled on
  fixed RKE2 control-plane nodes;
- a privileged node DaemonSet with kubelet bidirectional mount propagation;
- controller RBAC, including read-only Node resolution.

Replace the example image tag before deployment. The controller Secret must be
created out of band with `api-token` and `billing-account-id` keys; no
credential is stored in this repository.

The current full-cluster test does not replace `csi-sanity`, upstream
Kubernetes storage conformance, node reboot/remount, forced VM deletion, or
destructive detach testing; run those before broadening the first-release RWO
contract. The local `replace` in `go.mod` points at the sibling shared SDK
module inside this monorepo.

# InSpace CSI driver

CSI v1.12 driver for InSpace block storage. The supported contract is ext4
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

## VM deletion safety

InSpace VM deletion can also delete every attached non-primary block volume.
Deleting a worker directly through the InSpace dashboard or API bypasses
Kubernetes, CSI detachment, and the Karpenter provider. That can permanently
delete the volumes and their data.

Terminate workers through Kubernetes/Karpenter and wait for each
`VolumeAttachment` to disappear. The Karpenter provider refuses its own VM
DELETE while any non-primary block volume remains in the VM's authoritative
storage inventory, then retries after CSI detaches every additional volume.
That guard cannot intercept an out-of-band dashboard or API deletion. Keep
independent backups for important data.

Create is idempotent by `(location, CSI name)`. The native API does not expose
idempotency keys, so the controller writes an immutable
`coordination.k8s.io/v1` Lease before each disk create, attach, detach, or
delete. Every returned HTTP error status, timeout, transport/read failure,
malformed success response, or controller restart is recovered only by
authoritative disk and VM-storage readback; the cloud mutation is never
dispatched a second time. After winning the Lease CAS, create re-lists the
unfiltered location inventory: one exact deterministic-name disk is adopted,
only exact absence permits POST, and a foreign, duplicate, or failed read keeps
the fence. The create response UUID is diagnostic only; the Lease receipt is
promoted solely from canonical deterministic-name readback after ownership,
shape, source, and Ready-state validation. Disk-delete and detach completion
require three separately persisted absence observations spaced by at least 30
seconds. Attach, detach, and delete also repeat exact disk, VM, VPC, and
attachment authority after the Lease CAS and immediately before dispatch. A
reappearing disk or attachment clears only that absence evidence. InSpace
capacities are GiB, so CSI byte requests are rounded up to whole GiB.

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
are rejected. Before every disk mutation, canonical detail reads must echo the
exact disk UUID and configured positive billing account; an omitted billing
field is rejected. Mutable CSI disks must also retain a non-empty display name,
`source_image_type: EMPTY`, no source image, and
`read_only_bootable: false`. Every authoritative VM-storage read rejects the
disk if it is marked as that VM's primary storage. These checks prevent a
manually constructed volume handle from importing or mutating a VM boot disk;
supported dynamically provisioned RWO disks are named, empty, and non-primary.
Target VM detail must likewise echo the provider UUID, billing account, and
`INSPACE_NETWORK_UUID`; the unfiltered VM inventory must contain that UUID
exactly once and the exact VPC must contain it exactly once.
Discovery lists never authorize a mutation by themselves. Attachment discovery
exact-reads the union of every location-wide VM row and every configured-VPC
member. A disk visible on a VM outside the configured VPC therefore blocks
delete and a second attach instead of being misclassified as unattached.
Missing or duplicate VM/VPC identity fails closed, and attachment mutations
are rejected when `INSPACE_NETWORK_UUID` is absent. If a Karpenter
`VolumeAttachment` outlives its Kubernetes Node, detach recovery requires a
typed Node `404`, the exact still-finalized deleting NodeClaim, its canonical
ProviderID and materialized create fence, zero current Nodes with that
ProviderID, and a complete v3 cloud VM identity that agrees on node name, guest
hostname, VM UUID, cluster, account, and VPC. The proof is repeated after the
detach Lease CAS immediately before dispatch. A clearly different current VM
is an idempotent no-op; static, legacy, partial, contradictory, or unavailable
identity fails retryably so external-attacher retains its finalizer. The driver
never identifies a node by a public or private IP address; public IPv4 egress
does not change CSI identity or topology.

Static and imported PV handles are unsupported. Disk shape and VM relationships
prevent a handle from targeting OS, image-backed, bootable, or primary storage,
but they do not prove which controller originally created an otherwise valid
named `EMPTY` non-primary disk in the same billing account. Treat cluster-wide
PV creation, CSI mutation-fence Lease access, and the controller's InSpace
credential as administrator privileges.

Only `topology.inspace.cloud/location=<configured-location>` is accepted.
Unknown, empty, or conflicting topology segments are rejected.
The paired Karpenter provider normalizes this CSI-owned key to its canonical
`inspace.cloud/location` catalog requirement. A bound RWO volume can therefore
request replacement capacity without an explicit CSI-topology requirement in
the NodePool.

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
- `INSPACE_NETWORK_UUID` (required for authoritative production attachment
  inventory) to bind every target VM to the cluster VPC
- in-cluster ServiceAccount access to read Nodes and manage the driver's
  mutation-fence Leases in its namespace
- read-only `get`/`list` access to Karpenter NodeClaims for deleted-Node detach
  recovery

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

The former direct disk lifecycle test is retired because process-local cleanup
cannot safely recover a committed HTTP error or process loss. Use the guarded
full-cluster release acceptance below. Ordinary `make test`, `make smoke`, and
`make verify` remain fake-only. Never commit an API token.

The separate [full-cluster release acceptance test](../../test/e2e/README.md)
installs the released CSI controller and node DaemonSet into the real RKE2
cluster. It provisions and attaches one RWO volume, verifies the mounted marker
through a Pod replacement, then requests deletion of the attached worker. The
test proves Karpenter keeps the VM while the non-primary disk is attached, CSI
detaches it, replacement capacity reattaches the same disk UUID, and the
persisted marker remains readable. Final teardown requires the
VolumeAttachment, PV, PVC, disk, and workers to be absent.

## Recover an unresolved mutation fence

An unresolved Lease is a safety lock, not a retry timer. The driver names it
`inspace-csi-<40-hex>` and includes that exact name in the CSI error. Do not
delete it merely because the cloud API currently returns an empty list: an
earlier request can still become visible later.

First pause the CSI controller and save every managed Lease:

```sh
kubectl -n <release-namespace> scale deployment/<csi-controller> --replicas=0
kubectl -n <release-namespace> get leases \
  -l storage.inspace.cloud/mutation-fence=true -o yaml \
  >inspace-csi-mutation-fences.before-recovery.yaml
```

Inspect the exact Lease named in the error. Its
`storage.inspace.cloud/fence-key`, `fence-intent`, `fence-attempt`, and optional
`fence-receipt` annotations bind the location, disk, VM, and operation. Audit
that exact identity through both `GetDisk`/`ListDisks` and every VM storage
list. If the intended state is visible, keep the Lease and resume the
controller so normal readback can complete it.

Remove one Lease only after InSpace support or equivalent independent evidence
proves the fenced request reached a terminal no-commit result. This includes
the deliberate crash window after Lease creation and before the cloud request;
the controller cannot distinguish that window from a lost response. Delete
only the exact saved UID, then resume the controller:

```sh
NAMESPACE=<release-namespace>
LEASE=<exact-lease-name>
LEASE_UID=$(kubectl -n "$NAMESPACE" get lease "$LEASE" -o jsonpath='{.metadata.uid}')
kubectl delete --raw="/apis/coordination.k8s.io/v1/namespaces/$NAMESPACE/leases/$LEASE" \
  -f - <<EOF
{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"$LEASE_UID"}}
EOF
kubectl -n <release-namespace> scale deployment/<csi-controller> --replicas=1
```

Never bulk-delete these Leases. An incorrect removal can duplicate a paid disk,
detach a disk from the wrong state transition, or race disk deletion.

## Kubernetes manifests

Files in `deploy/kubernetes` provide:

- a persistent, attach-required `CSIDriver`;
- a strict-topology RWO `StorageClass`;
- a controller Deployment with provisioner and attacher sidecars, scheduled on
  fixed RKE2 control-plane nodes;
- a privileged node DaemonSet with kubelet bidirectional mount propagation;
- controller RBAC, including read-only Node resolution and durable
  mutation-fence Lease management.

The standalone controller manifest gives both `csi-provisioner` and
`csi-attacher` a 600-second RPC timeout. This allows up to two minutes for
preflight reads and durable-fence acquisition. Immediately before any
CreateDisk, DeleteDisk, AttachDisk, or DetachDisk call, the driver requires
480 seconds to remain: five minutes for the shared client's mutation deadline,
two minutes for destructive recovery, and one minute for final readback and
Lease persistence. If less remains, the driver issues no cloud mutation and
exact-clears only that invocation's undispatched Lease. A shorter sidecar
deadline can cancel and strand the original no-replay Lease or cause
overlapping retries.

Replace the example image tag before deployment. The controller Secret must be
created out of band with `api-token` and `billing-account-id` keys; no
credential is stored in this repository.

The current full-cluster test does not replace `csi-sanity`, upstream
Kubernetes storage conformance, node reboot/remount, out-of-band dashboard/API
VM deletion, or destructive detach fault injection; run those before
broadening the supported RWO contract. The local `replace` in `go.mod` points
at the sibling shared SDK module inside this monorepo.

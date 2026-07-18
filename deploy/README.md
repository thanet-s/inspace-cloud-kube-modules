# Ansible cluster lifecycle

`deploy/` is the operator-facing cluster lifecycle. It creates the fixed
bastion and RKE2 control plane, establishes private API access, installs the
released CCM/CSI/Karpenter charts, creates a default AMD EPYC worker
`InSpaceNodeClass` and `NodePool`, performs rolling operator configuration, and
destroys only the journaled cluster.

The release E2E suite remains in `test/e2e/`. It deliberately has stricter
isolated-account assertions and is not the production inventory.

## Requirements

- macOS or Linux management host with `ansible-core 2.21`, Docker, Helm,
  kubectl, OpenSSH, OpenSSL, Python 3, and jq
- one existing InSpace VPC, an unused private control-plane VIP, and a private
  Service VIP range of 16–256 addresses excluded from normal cloud allocation
- an exact released module version
- an SSH private/public key pair; private keys are used locally and never sent
  to InSpace, while the public key is supplied to VM creation
- `INSPACE_API_TOKEN` exported in the process environment

Copy and edit the example without committing it:

```sh
cp deploy/inventory.example.yml deploy/inventory.yml
chmod 600 deploy/inventory.yml
export INSPACE_API_TOKEN='...'
```

The real inventory, generated tokens, kubeconfig, host-key pins, bootstrap
ledger, and lifecycle journal are ignored by Git under `deploy/.state/`.
Back up that directory securely. Its `cluster.yaml` contains durable no-replay
receipts required for safe recovery and destroy.

## One or three control-plane servers

Set `control_plane_replicas` to:

- `1` for a low-cost cluster. The API and embedded etcd have a single point of
  failure, but application workers still scale through Karpenter.
- `3` for embedded-etcd and control-plane HA.

Two is rejected. Replica count is immutable after creation; changing one to
three or three to one requires a complete, explicit destroy/recreate lifecycle.
Both layouts keep application workloads off the tainted fixed control plane
and start with zero Karpenter workers.

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
destroy that ledger. It then:

1. generates and persists the RKE2 token and optional cache PKI seed;
2. runs the exact released bootstrap controller to API-level readiness;
3. binds its result to the deterministic FIPs;
4. pins bastion and private control-plane SSH host keys;
5. retrieves a kubeconfig whose endpoint is only the local bastion tunnel;
6. waits for the requested one or three Ready servers;
7. installs exact-version OCI charts and the default Karpenter resources.

`update` does not replace fixed VMs or rewrite bootstrap cloud-init. It puts
`control_plane_extra_config` in RKE2's operator fragment and restarts at most
one server at a time, waiting for Node and API readiness before continuing.
Topology, identity, control-plane taints, packaged-component disablement, CNI,
CIDR, token, data-directory, and registry keys are blocked because the
bootstrap controller owns them. It then upgrades the CRD
and workload charts and reapplies the default NodeClass/NodePool. On a
single-server cluster, an RKE2 restart necessarily causes brief API downtime.

`tunnel` starts or reuses the SSH control connection and prints the local
kubeconfig path. The kubeconfig uses `127.0.0.1:16443` with the private VIP as
its TLS server name; it never exposes a control-plane FIP as a public API.

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

Fixed control-plane shape, image, RKE2 version, bootstrap cache mode, network,
VIP, and replica-count updates are not in-place operations. The bootstrap
controller rejects immutable VM drift. `update` is for the allowlisted
operator RKE2 fragment and released cloud-module upgrades; machine replacement
remains a planned, explicit lifecycle.

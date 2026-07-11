# Full InSpace cluster E2E

`run.sh` is the destructive release acceptance test. It is intentionally not
part of `go test`, pull-request CI, or the smaller API lifecycle suite.

The test uses the isolated account to create:

- exactly three 2-vCPU/4-GiB K3s control-plane VMs;
- one protected public IPv4 per VM and a TCP/6443 API NLB;
- CCM, CSI, and Karpenter from the released GHCR images/OCI charts;
- one bounded Karpenter worker;
- one RWO CSI disk; and
- one public TCP LoadBalancer Service.

It verifies embedded-etcd readiness, three fixed Ready control planes, CCM
provider IDs and InternalIP/ExternalIP, Karpenter registration, CSI attachment
and remount persistence, and the public TCP response marker.

Only `~/.ssh/id_rsa.pub` is submitted to InSpace. The private key never enters
the repository, API payload, state journal, container context, Kubernetes
Secret, or Helm release. Direct ingress is restricted to the runner's detected
public IPv4 `/32` on TCP 22, 6443, and the fixed E2E NodePort 30080.

## Run

Publish a release candidate first, then run from the repository root:

```sh
export INSPACE_E2E_VERSION=0.1.0-rc.1
export CONFIRM_INSPACE_CLUSTER_E2E="$INSPACE_BILLING_ACCOUNT_ID"
./test/e2e/run.sh
```

The root `.env` supplies the isolated InSpace token/account/network/pool values
and remains ignored with mode `0600`. Local state is written under `.e2e/` with
mode `0700`/`0600` and is ignored.

Cleanup runs for success, failure, SIGINT, and SIGTERM. It removes the Service,
PVC/disk, NodePool/worker, charts, control-plane FIPs/NLB/VMs, and finally the
managed firewall. It then audits deterministic ownership identities and fails
unless the count is zero. A VM with an uncertain delete keeps its firewall.

For an explicitly requested debugging session only:

```sh
export INSPACE_E2E_KEEP_RESOURCES=true
```

This deliberately disables automatic cleanup and continues to incur charges;
the state directory is printed for manual recovery. Never use it in CI.

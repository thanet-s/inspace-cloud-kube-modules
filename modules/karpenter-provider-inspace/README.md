# Karpenter Provider for InSpace

This repository implements the InSpace provider for Karpenter `v1.14.0` and K3s. It includes a production API adapter, `InSpaceNodeClass`, a 24-variant instance catalog, stock-Ubuntu bootstrap, NodeClass readiness reconciliation, and a runnable Karpenter controller command.

## Supported contract

- Location `bkk01`, Linux/amd64, on-demand capacity
- `intel-scalable` host pool `aac7dd66-f390-4edd-80c0-dd7cae49bd99`
- `amd-epyc` host pool `6976fdc8-4492-465b-bd16-9ad5f6b00b03`
- `compute`, `general`, and `memory` families at 1, 2, and 4 GiB/vCPU
- CPU sizes `2, 4, 6, 8, 10, 12, 14, 16`; maximum 16 vCPU / 64 GiB
- Ubuntu 24.04 and an exactly pinned K3s agent version
- Ephemeral root disks; persistent workload data belongs on RWO CSI volumes

Variant names describe raw VM capacity, for example `is-compute-4c-4g`, `is-general-6c-12g`, and `is-memory-16c-64g`. Allocatable disk reserves 8 GiB for Ubuntu/K3s plus a 4 GiB eviction threshold.

Catalog prices are deterministic scheduling weights, not actual InSpace prices. A pricing source is still required before enabling cost-based consolidation decisions in production.

## Public IPv4 and firewall model

InSpace currently has no managed NAT gateway, so each worker needs a floating public IPv4 for internet egress. The guest NIC still exposes only the private RFC1918 address.

The provider uses a fail-closed sequence:

1. Allocate or recover a deterministically named, provider-owned floating IP.
2. Create the VM with `reserve_public_ip=false`, avoiding an untracked implicit address.
3. Assign and read back the required InSpace firewall.
4. Assign and read back the owned floating IP.
5. Return the NodeClaim only after both protections are confirmed.

If protection fails, the adapter removes the VM and floating IP. Delete also removes both resources, including an orphan floating IP when the VM has already disappeared. Create POSTs are never blindly retried; read-before-create ownership records recover ambiguous responses.

NodeClass readiness verifies that its private network exists and that its firewall:

- has no inbound `any`, public all-port rule, or broad public prefix;
- allows all TCP and UDP ports from a prefix covering the NodeClass network subnet; and
- allows all outbound TCP and UDP traffic for node egress.

A public `/32` (or IPv6 `/128`) is accepted only on an explicit TCP/UDP port
range. The full-cluster E2E uses this narrowly for its operator source and
fixed TCP NodePort; public all-port access remains invalid.

Generated bootstrap also enables UFW with default-deny ingress and permits RFC1918 traffic only on the private interface. K3s detects and writes the RFC1918 `node-ip`; it never tries to discover a floating address from the guest NIC. Bootstrap contains exactly one strict external-IP placeholder, which the adapter replaces with its allocated floating IPv4 before VM creation; unresolved or duplicate placeholders fail launch. K3s therefore starts with `node-external-ip` set, while the external CCM remains authoritative and must publish the same API-reported address as `ExternalIP`. InSpace NLB targets must use the private node address, and NLB services are TCP-only. Deletion removes the floating IP first and keeps the cloud firewall attached until the VM has been deleted.

## Worker bootstrap

`cloud_init` is sent as an API-compatible JSON object. On stock Ubuntu 24.04 it:

- waits and retries `apt-get` until floating-IP egress exists, then installs `curl`, CA certificates, `iproute2`, and UFW;
- downloads the exact K3s release and its `sha256sum-amd64.txt` asset;
- verifies the checksum and installed K3s version;
- configures `cloud-provider=external`, NodeClaim labels and taints;
- adds exactly one `karpenter.sh/unregistered:NoExecute` taint; and
- runs `additionalUserData` once via `cloud-init-per`.

The K3s token is read from `tokenSecretRef`. Because the NodeClass is cluster-scoped, the reference cannot choose an arbitrary namespace: it is fixed to Secret `inspace-k3s-agent-token`, key `token`, in `INSPACE_SECRET_NAMESPACE` (default `karpenter`). The resolver uses an uncached, resource-name-scoped GET and cannot select the separate `inspace-api` cloud credential Secret.

## Run the controller

Install the upstream Karpenter CRDs, then install the InSpace CRD and controller resources. The controller manifest contains the Karpenter v1.14 core RBAC, provider RBAC, leader-election permissions, and fixed-control-plane scheduling rules for its own service account.

```sh
kubectl apply -f config/crd/bases/karpenter.inspace.cloud_inspacenodeclasses.yaml
kubectl apply -f config/controller/controller.yaml
```

Create two distinct Secrets in `karpenter`: `inspace-api` for the controller's cloud credential and `inspace-k3s-agent-token` for the disposable K3s join token. Never reuse the API credential as the join token.

The command at `cmd/controller` requires:

- `INSPACE_API_TOKEN`
- `INSPACE_CLUSTER_NAME`
- `INSPACE_DEFAULT_NODECLASS`
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

It additionally requires `INSPACE_API_TOKEN`, `INSPACE_BILLING_ACCOUNT_ID`, `INSPACE_NETWORK_UUID`, `INSPACE_FIREWALL_UUID`, and `INSPACE_INTEL_HOST_POOL_UUID`. Normal `go test ./...` compiles this test but skips it before reading those values.

This is an InSpace API resource-lifecycle test, not a full K3s node-join or workload scheduling test. Cluster-level conformance comes after the fixed control plane, CCM, and CSI components are deployed together.

The local `replace github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider-inspace => ../cloud-provider-inspace` resolves the shared SDK module inside this monorepo.

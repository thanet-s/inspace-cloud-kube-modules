# inspace-cloud-kube-modules

This monorepo contains three independently buildable Go modules:

| Module | Responsibility |
| --- | --- |
| `modules/cloud-provider` | Shared InSpace API client, external CCM, and fixed K3s control-plane/bootstrap controller |
| `modules/csi-driver` | RWO-only CSI controller and node plugin |
| `modules/karpenter-provider` | Karpenter `InSpaceNodeClass`, instance catalog, and elastic K3s worker lifecycle |

The repository root owns all source, tests, manifests, and E2E tooling.
`go.work` links the three modules for local development while their separate
`go.mod` files keep controller dependencies bounded.

## Network contract

InSpace does not provide shared outbound NAT for private-only VMs. Each
control-plane and Karpenter node therefore receives a floating public IPv4 for
internet egress. That address is not configured on the guest NIC: K3s uses the
NIC's RFC1918 address for node identity and cluster traffic, and separately
sets `node-external-ip` to the allocated floating address. The external CCM
reads that same assignment from the InSpace API and publishes it as
`NodeExternalIP`; it never tries to discover it from the NIC. InSpace NLB
targets also use private VM addresses. Every public VM must be assigned an
InSpace firewall before the controller considers it ready; unmatched public
inbound traffic is not part of the supported cluster contract.

## Safety contract

- Automated tests and smoke tests must use loopback/in-memory fake APIs.
- Live discovery is read-only and must be explicitly selected.
- Live lifecycle tests are separate from normal tests, require both
  `INSPACE_RUN_LIVE_TESTS=true` and `INSPACE_ALLOW_REMOTE_MUTATIONS=true`, use
  unique resource names, and clean up everything they create.
- Mutating requests are denied for `api.inspace.cloud` by default in the shared client.
- API tokens must never be committed, written to fixtures, or printed in logs.

Copy [`.env.example`](.env.example) to `.env` for local credentials. The real
workspace `.env` is ignored and should have mode `0600`.

## Commands

```sh
make test
make smoke
make helm-verify
make status
```

`make smoke` runs only fake-cloud lifecycle tests. It does not require an InSpace API token.

## Helm and releases

Production artifacts are published from SemVer tags as three multi-platform
GHCR images and two OCI Helm charts. Install the CRD chart first, then install
the workload chart into `kube-system`:

```sh
helm upgrade --install inspace-cloud-kube-modules-crds \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version "$VERSION"

helm upgrade --install inspace-cloud-kube-modules \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules \
  --version "$VERSION" \
  --namespace kube-system \
  --values values.yaml
```

The workload chart references one existing InSpace API Secret contract,
`inspace-cloud-credentials` with keys `api-token` and `billing-account-id`.
It never creates or copies this credential. Karpenter's K3s join credential is
kept separate as `inspace-k3s-agent-token` key `token`. See the
[`values` example](charts/inspace-cloud-kube-modules/examples/values.yaml),
the [chart guide](charts/inspace-cloud-kube-modules/README.md), and the
[release process](RELEASING.md).

The isolated-account lifecycle suite is deliberately separate. It creates
only resources named `inspace-e2e-*`, preserves firewall protection when a
delete is uncertain, and performs a zero-leftover audit before and after:

```sh
make live-audit
CONFIRM_INSPACE_LIVE_TEST="$INSPACE_BILLING_ACCOUNT_ID" make live-test
```

The root `.env` supplies local test-account values and is mode `0600`, ignored
by Git, and excluded from every Docker build context. The live suite covers API
resource lifecycles for VM/firewall/floating-IP/TCP-NLB/block-disk and the real
Karpenter adapter. It does not yet prove a three-server K3s boot, worker join,
in-guest internet access, CSI mount, or workload scheduling.

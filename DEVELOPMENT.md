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
audit before and after the run. It covers VM, firewall, floating-IP, TCP-NLB,
block-disk, and real Karpenter-adapter lifecycles. Never run it against a
production billing account or from a pull request.

## Full-cluster release acceptance

From a checkout matching an exact published release candidate, the destructive
release-acceptance suite proves the complete cluster lifecycle: three
stock-Ubuntu RKE2 control planes with embedded etcd, Cilium native routing and
kube-proxy replacement, CCM node identity, one Karpenter worker in the selected
VPC, public-IP egress and RKE2 join, an RWO CSI volume that retains data through
pod replacement, and a public TCP NLB response. It finishes with an
exact-ownership, zero-leftover cloud audit.

```sh
export INSPACE_E2E_VERSION='<published-version>'
export CONFIRM_INSPACE_CLUSTER_E2E="$INSPACE_BILLING_ACCOUNT_ID"
./test/e2e/run.sh
```

The host entrypoint only builds and starts the pinned E2E runner image. The
Ansible controller, bastion-mediated private-node access, Helm, and Kubernetes
clients run inside that container; the host never runs the live-test toolchain.
See the [full-cluster E2E guide](test/e2e/README.md) for prerequisites, state
recovery, and the fail-closed cleanup contract.

## CI architecture

Current InSpace Intel and AMD instances are x86-64, so image CI and releases
build `linux/amd64` by default. Native `linux/arm64` jobs remain available by
setting the repository variable `ENABLE_ARM64_IMAGES=true`; disabled ARM jobs
remain in the workflows for future instance support. The complete artifact and
promotion process is documented in [RELEASING.md](RELEASING.md).

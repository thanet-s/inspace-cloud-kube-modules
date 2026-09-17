# Release process

Releases are automated from annotated SemVer tags without `+build` metadata,
which Docker tags cannot preserve. The repository uses a single version for
the three controller images and both Helm charts.

1. Merge through `main` only after CI passes Go formatting, tests, vet,
   command builds, `govulncheck`, container builds, CRD integrity, Helm lint,
   and both namespace render paths.
2. Review dependency updates and release notes. Update chart defaults or CRDs
   in source before tagging; never patch a generated release artifact.
3. Create and push an annotated tag such as `v0.1.0` (or `v0.2.0-rc.1`).
4. The release workflow requires the tag target to be reachable from `main`
   and reruns the complete CI workflow against the tagged source.
5. It builds `linux/amd64` images by default, pushes versioned GHCR tags,
   attaches SBOM and keyless GitHub build-provenance attestations, and
   publishes and attests both OCI charts. Native `linux/arm64` builds remain
   available by setting the repository variable `ENABLE_ARM64_IMAGES=true`.
6. Only after every image and chart succeeds does the workflow create a draft,
   attach chart archives, `SHA256SUMS`, and immutable image-digest records,
   then publish the GitHub release. Repository release immutability prevents a
   published release or tag from being changed afterward.

Image builds are native on GitHub's `ubuntu-26.04` amd64 runner. When
`ENABLE_ARM64_IMAGES` is exactly `true`, the same CI and release workflows add
native `ubuntu-26.04-arm` jobs; the workflows never use QEMU. The manifest job
requires exactly the enabled platform set and its matching SBOM attestations
before publishing the version tag. Unset, `false`, and every value other than
exactly `true` mean amd64 only. Lightweight tag validation, CI Helm
verification, and final-release jobs use `ubuntu-slim` where the larger image
toolchain is unnecessary.

Stable releases support two deliberate paths. A direct stable release is
allowed only when no same-base `vX.Y.Z-rc*` tag exists; create the annotated
stable tag from `main`, and the complete release quality gate runs against that
tag. Once any same-base candidate exists, direct release is no longer allowed
and stable must promote the highest canonical candidate from the exact same
commit.

Before promoting a release candidate to stable:

1. Independently verify the immutable tag target, release checksums, OCI chart
   bytes, image platform indexes, SBOM attestations, and SLSA provenance.
2. From a clean checkout of that candidate tag, run `test/e2e/run.sh` against
   the exact published candidate in the isolated account. The launcher first
   builds a non-mutating verifier stage, validates the release's recorded OCI
   index digests, selects the unique `linux/amd64` child manifests, and then
   copies the bootstrap controller from the CCM child digest. The destructive
   runner therefore cannot mix local controller code or a mutable image tag
   with released charts or images. The launcher mechanically requires the
   current clean `HEAD` to equal the annotated `v$INSPACE_E2E_VERSION` tag for
   `all`, `init`, `test`, and `shell`, and requires that local tag object and
   peeled commit to equal the canonical GitHub tag. Before infrastructure
   creation, the verifier downloads the release `SHA256SUMS`, both chart
   archives, and the three immutable image-digest records. It requires each
   OCI chart pull to be byte-identical to its checksummed release archive,
   validates chart identity/source/revision metadata, verifies each GHCR version tag
   still resolves to its recorded index, and checks every selected linux/amd64
   image config's source/version/revision labels against the peeled commit.
   The runner binds that commit, all image digests, and both chart checksums,
   installs the locally verified chart archives, seeds product cache sources
   by platform digest, and checks live container-runtime image IDs. It must
   finish unattended and report zero owned cloud resources.

   Explicit `destroy` is exempt from checkout, GitHub, and GHCR access. It
   requires the preserved version-scoped runner and validates that runner
   against the durable artifact manifest and chart files in the run state.
   Never remove a release runner while its cluster remains: missing or
   mismatched teardown code fails closed and is not rebuilt from a newer
   checkout.
3. Create the stable annotated tag from the same tested commit, then repeat the
   artifact verification for the stable release. The release workflow finds the
   highest canonical same-base `vX.Y.Z-rc.N` tag and rejects the stable tag
   unless both peel to the same commit. A noncanonical ambiguous same-base RC
   tag or a different target fails before artifact publication.

Stable tags additionally update floating minor and `latest` image tags. A
major alias is published from v1 onward, but never as the ambiguous `:0` tag.
Prereleases publish only their exact prerelease version. Consumers should pin
an image digest or an exact chart version in production.

Versions are append-only even if a workflow fails after partially publishing
to GHCR. Never move or repush a failed version; fix the source and issue the
next prerelease such as `rc.2`. After a package is first created, verify all
three images and both `charts/*` packages are public before an anonymous RKE2
cluster attempts to pull them.

Published artifacts:

```text
ghcr.io/thanet-s/inspace-cloud-controller-manager:<version>
ghcr.io/thanet-s/inspace-csi-driver:<version>
ghcr.io/thanet-s/karpenter-provider-inspace:<version>
oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds
oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules
```

The release token is the workflow-scoped `GITHUB_TOKEN`; no long-lived
registry credential or InSpace API token is used by release automation.

## Known open issue: bastion/control-plane floating-IP allocation has no bad-address detection

`v0.9.0-rc.9` failed the live E2E test stage on a bad worker floating IP
(fixed by the bad-floating-IP cache and fast registration-timeout
controller). Validating that fix then hit an unrelated problem three
times in a row: the bastion VM was handed the exact same address
(`199.21.172.40`) on three consecutive live `all` runs (rc.10, rc.11,
rc.12), each time dropping its SSH session mid cloud-init wait
(`Connection ... closed`). Three-for-three on one address rules out
ordinary shared-pool bad luck and points at InSpace handing back the
most-recently-freed address rather than randomizing across the pool.

Bastion and control-plane floating IPs are auto-assigned as a side
effect of VM creation (`modules/cloud-provider/pkg/bootstrap`); the
bootstrap reconciler never calls `CreateFloatingIP` directly and has no
way to reject a specific address and ask for another. This differs from
worker nodes, where Karpenter's own NodeClaim lifecycle gives the
`BadFloatingIPStore` a signal to act on. No equivalent signal path
exists from the E2E harness's SSH-level observation into the Go
reconciler today.

`v0.9.0` was promoted from `v0.9.0-rc.13`, which passed a full live
`all` E2E run cleanly, after adding a cooldown delay before retrying a
failed init attempt (`INSPACE_E2E_INIT_RETRY_COOLDOWN_SECONDS`, default
300s) gave the pool enough time to stop handing back the same address.
That cooldown is a harness-level mitigation, not a fix: a real fix
needs bad-address detection and rejection in the production bootstrap
reconciler itself, deserving its own design pass rather than a rushed
change to its create-attempt fencing.

The real `deploy/` lifecycle (not just the E2E harness) hit the same
class of exposure: `deploy/playbooks/init-cluster.yml`'s control-plane
cloud-init wait had no retry at all, and `deploy/container-entrypoint.sh`
had no recovery path, so a bad bastion or control-plane address simply
failed the whole `init` run for an operator standing up a real cluster.
Both are now mitigated the same way as the E2E harness: the cloud-init
wait retries (`retries: 2`, `delay: 10`), and an opt-in
`INSPACE_DEPLOY_INIT_AUTO_RECOVER=true` lets `init` destroy and retry
the named cluster once, after a cooldown
(`INSPACE_DEPLOY_INIT_RETRY_COOLDOWN_SECONDS`, default 300s), if it does
not converge — see [deploy/README.md](deploy/README.md). It defaults to
`false` so existing fail-closed behavior is unchanged unless an operator
opts in; it still requires deriving the same `confirm_cluster_name` the
`destroy` playbook itself asserts against, so it can only ever destroy
the exact cluster `init` was just asked to create.

Both of those remain harness/operator-level mitigations layered on top of
the actual gap: the bootstrap reconciler itself
(`modules/cloud-provider/pkg/bootstrap`) has no `CreateFloatingIP` call to
reject an address against — `CreateVMRequest` has no field to request or
exclude one, so InSpace decides the address as a side effect of VM
creation with zero API-level control. There is also no signal path from
SSH/cloud-init-level observation into the Go reconciler: the bootstrap
process that provisions a cluster's VMs exits once cloud resources exist,
well before cloud-init or SSH even start, so it cannot itself learn that a
guest never came up. Detecting and rejecting a specific address inside
the reconciler's create-attempt fencing (intent/issued/rejected/
materialized phases, CAS-based drift detection, ambiguous-PATCH replay
protection) would need a real SSH-capable signal this component has never
had, and remains a large, correctness-sensitive change that deserves its
own design pass rather than a rushed addition to that state machine.

What `inspace-cluster-controller --until-ready` *can* do without that new
signal: once Reconcile reports the cluster Ready, it already knows every
bastion and control-plane VM's public floating IPv4
(`bootstrap.Result.BastionPublicIPv4`/`ControlPlanePublicIPv4`) from the
same API calls that provisioned them. It now probes TCP/22 on each one; if
any stays unreachable past `--floating-ip-reachability-timeout` (default
`5m`), it destroys the cluster and retries once with a fresh Reconcile
before accepting defeat and returning the original Ready result — see
[modules/cloud-provider/README.md](modules/cloud-provider/README.md). This
runs automatically for every caller of `--until-ready` (both `test/e2e`
and `deploy/`), ahead of and independently from the ansible-level
mitigations above, without needing SSH credentials or a real session:
a bare TCP connect only catches an address that never opens the port at
all, not one that completes a handshake and then drops a live session
mid-command (the exact rc.10–rc.12 signature), so the ansible-level
retries remain the layer that catches that narrower case. None of this
changes what "Ready" means for any caller that leaves the timeout at its
default or sets it to `0`.

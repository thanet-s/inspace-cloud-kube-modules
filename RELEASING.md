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
   unless both peel to the same commit. A missing RC, a noncanonical ambiguous
   same-base RC tag, or a different target fails before artifact publication.

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

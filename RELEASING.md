# Release process

Releases are automated from annotated SemVer tags. The repository uses a
single version for the three controller images and both Helm charts.

1. Merge through `main` only after CI passes Go formatting, tests, vet,
   command builds, `govulncheck`, container builds, CRD integrity, Helm lint,
   and both namespace render paths.
2. Review dependency updates and release notes. Update chart defaults or CRDs
   in source before tagging; never patch a generated release artifact.
3. Create and push an annotated tag such as `v0.1.0` (or `v0.2.0-rc.1`).
4. The release workflow requires the tag target to be reachable from `main`
   and reruns the complete CI workflow against the tagged source.
5. It builds `linux/amd64` and `linux/arm64` images, pushes versioned GHCR
   tags, attaches SBOM and keyless GitHub build-provenance attestations, and
   publishes and attests both OCI charts.
6. Only after every image and chart succeeds does the workflow create a draft,
   attach chart archives, `SHA256SUMS`, and immutable image-digest records,
   then publish the GitHub release. Repository release immutability prevents a
   published release or tag from being changed afterward.

Image builds are native on GitHub's `ubuntu-26.04` amd64 and
`ubuntu-26.04-arm` arm64 runners; the workflow does not use QEMU. The manifest
job combines the two platform digests into one multi-architecture tag only
after both builds succeed. Lightweight tag validation, CI Helm verification,
and final-release jobs use `ubuntu-slim` where the larger image toolchain is
unnecessary.

Before promoting a release candidate to stable:

1. Independently verify the immutable tag target, release checksums, OCI chart
   bytes, image platform indexes, SBOM attestations, and SLSA provenance.
2. From a clean checkout of that candidate tag, run `test/e2e/run.sh` against
   the exact published candidate in the isolated account. The runner is built
   from that checkout but copies the bootstrap controller from the candidate's
   published CCM image, so the destructive test cannot mix local controller
   code with released charts or images. It must finish unattended and report
   zero owned cloud resources.
3. Create the stable annotated tag from the same tested commit, then repeat the
   artifact verification for the stable release.

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

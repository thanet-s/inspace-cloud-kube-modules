# Release process

Releases are automated from signed or annotated SemVer tags. The repository
uses a single version for the three controller images and both Helm charts.

1. Merge through `main` only after CI passes Go formatting, tests, vet, CRD
   integrity, Helm lint, and both namespace render paths.
2. Review dependency updates and release notes. Update chart defaults or CRDs
   in source before tagging; never patch a generated release artifact.
3. Create and push a tag such as `v0.1.0` (or `v0.2.0-rc.1`).
4. The release workflow validates SemVer, builds `linux/amd64` and
   `linux/arm64` images, pushes versioned GHCR tags, attaches SBOM and GitHub
   build-provenance attestations, and publishes both OCI charts.
5. A GitHub release is created only after every image and chart succeeds. Its
   assets include the chart archives and `SHA256SUMS`.

Stable tags additionally update floating major, minor, and `latest` image
tags. Prereleases never update `latest`. Consumers should pin an image digest
or an exact chart version in production.

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

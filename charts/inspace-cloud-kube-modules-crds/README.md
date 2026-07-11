# InSpace Cloud Kubernetes CRDs

This chart installs the four unmodified Karpenter `v1.14.0` core CRDs and the
two CRDs owned by this repository. Install or upgrade it before the workload
chart. CRDs are ordinary templates in this dedicated chart, matching the
upstream Karpenter CRD-chart release model, so `helm upgrade` updates their
schemas instead of silently skipping them.

Do not uninstall this chart while custom resources exist. Helm would delete
the CRD objects and Kubernetes would consequently delete their custom
resources. For normal upgrades, keep the release installed and run
`helm upgrade --install`.

```sh
helm upgrade --install inspace-cloud-kube-modules-crds \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version 0.1.0
```

The Karpenter files are copied byte-for-byte from
`sigs.k8s.io/karpenter@v1.14.0/pkg/apis/crds`:

| File | SHA-256 |
| --- | --- |
| `autoscaling.x-k8s.io_capacitybuffers.yaml` | `66fd5680b902b38fb9657ad2b432196a06c42b37d078e53be2e39909200a6342` |
| `karpenter.sh_nodeclaims.yaml` | `712e207ad9da26b95717b82bff8bc89a2b5fc048309f97207e407788b426faf9` |
| `karpenter.sh_nodeoverlays.yaml` | `f65f0f3edd3afe96dc2b6b4fa648982dab557af077d7ab22e6ec26207b6465ed` |
| `karpenter.sh_nodepools.yaml` | `62990043212a239704c0195bbd37abd0fddad90a586f5b37dfb403a0a0aefe1e` |

Karpenter and this chart are licensed under Apache-2.0. Upstream attribution
is retained in the repository `NOTICE` file.

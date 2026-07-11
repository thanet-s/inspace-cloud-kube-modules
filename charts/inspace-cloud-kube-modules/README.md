# InSpace Cloud Kubernetes Modules Helm chart

This chart deploys the external cloud-controller-manager, the RWO CSI driver,
and the InSpace Karpenter provider. Install it into `kube-system`. Its CRDs are
published as a separate chart so CRD upgrades are explicit and happen before
controller upgrades.

## Secret contracts

The chart deliberately does not create the InSpace API Secret. All three
controllers refer to one existing Secret in the release namespace:

| Value | Default | Meaning |
| --- | --- | --- |
| `global.inspace.apiSecret.name` | `inspace-cloud-credentials` | Existing Secret name |
| `global.inspace.apiSecret.tokenKey` | `api-token` | InSpace API token key |
| `global.inspace.apiSecret.billingAccountIDKey` | `billing-account-id` | Decimal billing account ID key |

Karpenter's K3s join token is intentionally separate. The provider validates
the fixed `Secret/inspace-k3s-agent-token` key `token`; it cannot be pointed at
the cloud API credential. Prefer creating both Secrets outside Helm. Setting
`karpenter.agentTokenSecret.create=true` is provided for automation but stores
the agent token in Helm release data.

By default Karpenter runs in the Helm release namespace, so installing the
chart into `kube-system` needs exactly one cloud API Secret object. Set
`karpenter.namespace` to run it elsewhere and optionally set
`karpenter.createNamespace=true`; Kubernetes cannot use a Secret across
namespaces, so the same existing cloud API Secret contract must then also be
provisioned in that namespace. The chart never copies secret data.

## Install

```sh
export VERSION=0.1.0

helm upgrade --install inspace-cloud-kube-modules-crds \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version "$VERSION"

kubectl -n kube-system create secret generic inspace-cloud-credentials \
  --from-file=api-token=/secure/path/inspace-api-token \
  --from-file=billing-account-id=/secure/path/inspace-billing-account-id

kubectl -n kube-system create secret generic inspace-k3s-agent-token \
  --from-file=token=/secure/path/k3s-agent-token

helm upgrade --install inspace-cloud-kube-modules \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules \
  --version "$VERSION" \
  --namespace kube-system \
  --values values.yaml
```

Start from [`examples/values.yaml`](examples/values.yaml). Pin image digests in
production with each component's `image.digest` value; when set, the digest
takes precedence over `image.tag`.

The chart is licensed under Apache-2.0.

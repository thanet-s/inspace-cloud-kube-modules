# InSpace Cloud Kubernetes Modules

[![CI](https://github.com/thanet-s/inspace-cloud-kube-modules/actions/workflows/ci.yaml/badge.svg)](https://github.com/thanet-s/inspace-cloud-kube-modules/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/thanet-s/inspace-cloud-kube-modules?include_prereleases&sort=semver)](https://github.com/thanet-s/inspace-cloud-kube-modules/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Cloud integrations for running self-managed RKE2 clusters on
[InSpace Cloud](https://inspace.cloud/).

The project provides a fixed highly available control plane, native Kubernetes
cloud integration, block storage, and elastic Karpenter workers. It is designed
for clusters built directly on InSpace virtual machines rather than a managed
Kubernetes service.

> [!NOTE]
> Review the supported scope and test the release in an isolated account before
> production use.

## Highlights

- Three-node RKE2 control plane with embedded etcd and a dedicated bastion.
- Cilium native routing, eBPF masquerading, and full kube-proxy replacement.
- External cloud-controller-manager for node addresses and TCP load balancers.
- CSI driver for dynamically provisioned `ReadWriteOnce` block volumes.
- Karpenter provider for automatic RKE2 worker provisioning and termination.
- Fail-closed ownership checks and convergent cleanup for cloud resources.

## Components

| Component | Responsibility |
| --- | --- |
| [`modules/client`](modules/client) | Kubernetes-independent InSpace API client |
| [`modules/cloud-provider`](modules/cloud-provider) | External CCM and fixed RKE2 control-plane bootstrap |
| [`modules/csi-driver`](modules/csi-driver) | RWO block-volume CSI controller and node plugin |
| [`modules/karpenter-provider`](modules/karpenter-provider) | `InSpaceNodeClass`, instance catalog, and elastic worker lifecycle |

Each component is an independently buildable Go module linked locally by
`go.work`.

## Networking at a glance

- Node identity, RKE2 registration, and cluster traffic use private VPC addresses.
- Every VM receives a floating IPv4 for outbound internet access because InSpace
  does not provide shared NAT.
- Only the bastion accepts public ingress; the Kubernetes API uses a private
  kube-vip endpoint.
- Private `LoadBalancer` Services use Cilium LB IPAM and L2 Announcements.
- Public `LoadBalancer` Services use an explicit, optional, TCP-only InSpace NLB.
- InSpace firewalls enforce node policy; guest UFW is disabled.

The detailed networking, ownership, and cleanup invariants are documented in the
[development guide](DEVELOPMENT.md#network-and-node-contract).

## Getting started

1. Prepare an InSpace VPC, an unused private control-plane VIP, and a private
   Service VIP range excluded from VM and NLB allocation.
2. Bootstrap the bastion and three RKE2 servers using the
   [control-plane guide](modules/cloud-provider/README.md#fixed-control-plane-controller).
3. Create the API and RKE2 agent-token Secrets described in the
   [Helm chart guide](charts/inspace-cloud-kube-modules/README.md#secret-contracts).
4. Install the CRDs first, followed by the workload chart:

> [!IMPORTANT]
> For an existing installation that still uses
> `InSpaceNodeClass.spec.hostPoolSelector`, first add an explicit
> `inspace.cloud/host-class` requirement to every NodePool and verify it was
> stored while the old CRD/controller are still running. Then upgrade the CRD
> and workload chart. The new CRD prunes the removed selector; skipping this
> step makes both equal-priced classes eligible and no longer guarantees AMD.
> Fresh installations do not need this migration.

```sh
export VERSION='<release-version>'

helm upgrade --install inspace-cloud-kube-modules-crds \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules-crds \
  --version "$VERSION"

helm upgrade --install inspace-cloud-kube-modules \
  oci://ghcr.io/thanet-s/charts/inspace-cloud-kube-modules \
  --version "$VERSION" \
  --namespace kube-system \
  --values values.yaml
```

Start with the [example values](charts/inspace-cloud-kube-modules/examples/values.yaml)
and keep its VPC UUID, control-plane VIP, and private Service range identical to
the bootstrap and every `InSpaceNodeClass`.

## Supported scope

| Area | Current support |
| --- | --- |
| Node image | Ubuntu 24.04 |
| Architecture | `linux/amd64` |
| Kubernetes distribution | RKE2 |
| CNI | Cilium native routing |
| Persistent storage | Single-node `ReadWriteOnce` block volumes |
| Public load balancing | TCP through an InSpace NLB |
| Private load balancing | Cilium LB IPAM and L2 Announcements |

## Documentation

- [Helm installation and configuration](charts/inspace-cloud-kube-modules/README.md)
- [Control-plane bootstrap and CCM](modules/cloud-provider/README.md)
- [CSI driver](modules/csi-driver/README.md)
- [Karpenter provider](modules/karpenter-provider/README.md)
- [Development and testing](DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)
- [Release process](RELEASING.md)
- [Security policy](SECURITY.md)

## Development

Run the complete local verification suite with:

```sh
make verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for workspace setup, containerized Ansible
E2E testing, safety gates, and CI architecture.

## License

Licensed under the [Apache License 2.0](LICENSE).

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
- Private, bastion-backed bootstrap cache by default, with an explicit
  direct-download mode.
- Cilium native routing, eBPF masquerading, and full kube-proxy replacement.
- External cloud-controller-manager for node addresses, paid InSpace NLBs, and
  managed-shard or endpoint-local Cilium node load balancers.
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
- The bastion and explicitly requested public load-balancer capacity accept
  public ingress; the Kubernetes API uses a private kube-vip endpoint.
- By default the bastion also serves a private, read-only bootstrap cache at
  `cache.<cluster>.inspace.internal:8443`; it uses the bastion's allocated VPC
  address rather than another reserved VIP. Its ECDSA P-256 TLS material starts
  at the persisted real initialization time and is valid for exactly 15
  calendar years. The audited image seed follows the cluster's disabled RKE2
  addons instead of caching images used only by disabled components.
- Before package or Kubernetes setup, bootstrap binds each generated guest
  hostname to `127.0.1.1` and verifies local resolution with bounded readback
  retry, independently of DHCP and external DNS.
- Private `LoadBalancer` Services use Cilium LB IPAM and L2 Announcements.
- Public `LoadBalancer` Services can use an explicit TCP-only InSpace NLB,
  CCM-managed shards, or selected endpoint-local edge nodes.
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
the bootstrap and every `InSpaceNodeClass`. Cached clusters must also give each
NodeClass the bastion cache address and public CA produced by bootstrap. Set
`InSpaceCluster.spec.bootstrapCache.directDownload: true` and use the matching
direct NodeClass mode only when every node should download its RKE2 assets and
system images directly from the upstream hosts.

## Supported scope

| Area | Current support |
| --- | --- |
| Node image | Ubuntu 24.04 |
| Architecture | `linux/amd64` |
| Kubernetes distribution | RKE2 |
| CNI | Cilium native routing |
| Persistent storage | Single-node `ReadWriteOnce` block volumes |
| Public load balancing | TCP through an InSpace NLB; TCP/UDP through managed shards or selected endpoint-local nodes |
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

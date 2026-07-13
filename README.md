# inspace-cloud-kube-modules

This monorepo contains four independently buildable Go modules:

| Module | Responsibility |
| --- | --- |
| `modules/client` | Shared, Kubernetes-independent InSpace API client |
| `modules/cloud-provider` | External CCM and fixed RKE2 control-plane/bootstrap controller |
| `modules/csi-driver` | RWO-only CSI controller and node plugin |
| `modules/karpenter-provider` | Karpenter `InSpaceNodeClass`, instance catalog, and elastic RKE2 worker lifecycle |

For local setup, verification, and live-test workflows, see the
[development guide](DEVELOPMENT.md).

## Network contract

InSpace does not provide shared outbound NAT for private-only VMs. Every
control-plane, Karpenter worker, and bastion VM therefore receives one floating
public IPv4 for internet egress. A floating address is not configured on the
guest NIC: RKE2 uses the NIC's RFC1918 address for node identity and cluster
traffic, and separately sets `node-external-ip` to the allocated floating
address. The external CCM reads that same assignment from the InSpace API and
publishes it as `NodeExternalIP`; it never tries to discover it from the NIC.

Only the bastion accepts public ingress, restricted by the InSpace firewall to
TCP/22 from the operator's exact `/32`. Control-plane and worker floating IPs
are egress-only and their firewalls reject all public inbound rules. Ansible
reaches private node addresses through the bastion. Every VM must have its
intended InSpace firewall assigned and read back before it is considered ready.
The bootstrap-owned bastion is fixed to Ubuntu 24.04, 1 vCPU, 2 GiB RAM, and a
30 GiB root disk.

RKE2 uses its bundled Cilium chart in native-routing mode. Cilium installs
direct routes for the pod CIDR on the shared VPC, performs eBPF IPv4 masquerading
for internet egress, and fully replaces kube-proxy with eBPF service handling.
The fixed control-plane contract requires stock Ubuntu 24.04 with at least
2 vCPU and 4 GiB RAM, matching the tested RKE2/Cilium platform floor.
Its three VM names, guest hostnames, and Kubernetes Node names are exactly
`<InSpaceCluster metadata.name>-cp0`, `-cp1`, and `-cp2`.
Elastic worker VM names, guest hostnames, and Kubernetes Node names are exactly
`<clusterName>-karp-<NodePool name>-<Karpenter random suffix>`; the separate
NodeClaim identity remains the cloud ownership/deletion key.
Control planes and elastic workers disable swap, rewrite stock Ubuntu archive
endpoints to the Thailand mirror when present, and apply persistent Kubernetes
sysctl and RKE2 systemd limits before their RKE2 service starts.
Node firewalls are validated fail-closed for TCP, UDP, and ICMP coverage from
both the VPC subnet and native-routing pod CIDR, with matching outbound access.
A private kube-vip address inside the VPC is advertised by the control-plane
nodes with ARP leader election. It is the stable RKE2 API endpoint on TCP/6443
and registration endpoint on TCP/9345; bootstrap does not create a
control-plane NLB or public API endpoint.

Private workload `Service` load balancers use Cilium LoadBalancer IPAM and L2
Announcements by default. LB IPAM assigns a unique private VIP to each Service,
so multiple Services can use the same port without purchasing an InSpace NLB.
Private Services use `loadBalancerClass: io.cilium/l2-announcer` and
`inspace.cloud/load-balancer-scope: private`; Cilium advertises their VIPs by
ARP inside the VPC. Bootstrap sets `defaultLBServiceIPAM: none` so Cilium only
claims its explicit class and cannot race the generic external CCM. Cilium Node
IPAM remains disabled, and the `io.cilium/node` class is not supported. A
public InSpace NLB remains available only as an explicit, TCP-only paid option
with the public scope label and annotation documented in the chart examples.

The operator must reserve an inclusive 16-256-address RFC1918 range for Cilium
LB IPAM and exclude it from InSpace VM and NLB allocation. The current InSpace
API has no range-reservation operation, so the bootstrap and controllers
validate and fail closed on collisions but cannot create the reservation.
Treat the range as immutable after cluster creation: changing a live Cilium
pool can reassign Service VIPs. L2 Announcements is a Cilium beta feature and
requires the InSpace VPC to accept ARP and gratuitous ARP for VIPs not assigned
to a VM NIC; prove that behavior in release acceptance before production use.
The workload chart also requires `global.inspace.controlPlaneVIP`, matching the
bootstrap kube-vip address, so CCM can reject a public NLB private-address
collision with either that VIP or the Cilium pool. It passes the same VPC UUID,
control VIP, and pool to Karpenter, which rejects any NodeClass that differs
before cloud validation or worker provisioning.

Every VM create request carries the configured VPC UUID. Karpenter additionally
waits for the created VM UUID to appear exactly once in that network's
authoritative `vm_uuids` read-back before assigning the firewall and floating
IP. The full-cluster acceptance test also binds that UUID to the Kubernetes
Node provider ID and verifies its sole `InternalIP` is inside the same VPC
subnet.

## Helm and releases

Production artifacts are published from SemVer tags as three GHCR images and
two OCI Helm charts. Images target `linux/amd64` by default because current
InSpace Intel and AMD instances are x86-64. Install the CRD chart first, then
install the workload chart into `kube-system`:

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
It never creates or copies this credential. Karpenter's RKE2 join credential is
kept separate as `inspace-rke2-agent-token` key `token`. See the
[`values` example](charts/inspace-cloud-kube-modules/examples/values.yaml),
the [private L2 Service example](charts/inspace-cloud-kube-modules/examples/service-private-l2.yaml),
the [public NLB Service example](charts/inspace-cloud-kube-modules/examples/service-public-nlb.yaml),
the [chart guide](charts/inspace-cloud-kube-modules/README.md), and the
[release process](RELEASING.md).

# cloud-provider-inspace

InSpace Cloud integration for Kubernetes/K3s. This repository contains the
shared location-aware API client, an external cloud-controller-manager (CCM),
and the fixed three-server K3s bootstrap reconciler.

## Implemented

- VM, block disk, attach/detach, private network, stock VM image, firewall,
  floating IPv4, and TCP network-load-balancer API contracts.
- Canonical node provider IDs: `inspace://<location>/<vm-uuid>`.
- Kubernetes `InstancesV2`: private VM address as `InternalIP`, explicitly
  assigned floating IPv4 as `ExternalIP`, location as zone.
- Kubernetes `LoadBalancer`: TCP only, deterministic Service ownership names,
  private NLB by default, and an explicitly owned floating IPv4 when annotation
  `service.beta.kubernetes.io/inspace-load-balancer-public: "true"` is set.
- A reconciler that creates exactly three stock-Ubuntu K3s servers, a private
  TCP/6443 NLB, one firewall, and explicitly named floating IPv4 addresses.
- Pinned K3s release binary installation verified against the matching
  `sha256sum-amd64.txt` release asset.
- An operational continuous bootstrap CLI and a standard Kubernetes CCM
  command.

InSpace has no outbound NAT. The bootstrap flow therefore preallocates each
named floating IPv4, creates the private-only VM, assigns the validated
firewall, then assigns the address. The guest NIC still has only its private
RFC1918 address. K3s `node-ip`, `advertise-address`, and flannel interface are
derived from that private NIC; `node-external-ip` is the floating address.

## Mutation safety

Remote API mutations are blocked unless
`INSPACE_ALLOW_REMOTE_MUTATIONS=true` is explicitly set. HTTP is accepted only
for literal loopback test servers; remote API URLs must be HTTPS. Every
cross-origin redirect is blocked so the `apikey` header cannot escape to
another host. The client does not automatically retry POST requests.

No credential belongs in Git, YAML, command-line flags, or logs. Supply it in
`INSPACE_API_TOKEN` (or legacy `INSPACE_API_KEY`) from a local `.env` file or a
Kubernetes Secret.

## Fixed control-plane controller

The target cluster does not exist yet, so the bootstrap controller runs from a
workstation or management host. It reads the `InSpaceCluster` YAML wire object
and reconciles one safe step at a time:

```sh
export INSPACE_API_TOKEN='...'
export INSPACE_K3S_TOKEN='a-long-random-cluster-token'
export INSPACE_ALLOW_REMOTE_MUTATIONS=true

go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml
```

For guarded E2E/debug access, pass only an OpenSSH public key and one operator
IPv4 `/32`; the controller adds exactly the requested TCP ports to both the
InSpace firewall and guest UFW:

```sh
go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --ssh-public-key-file "$HOME/.ssh/id_rsa.pub" \
  --ssh-username inspacee2e \
  --management-cidr 203.0.113.10/32 \
  --management-tcp-ports 22,6443,30080 \
  --until-ready --output=json
```

Private keys are never accepted or copied. Broad public prefixes and
all-port public rules are rejected. The real InSpace subnet is also checked
against the K3s pod and service CIDRs before any mutation.

Use `--once` to perform exactly one reconciliation step. Ownership names are
derived from the resource namespace/name, so an uncertain API response is
resolved by listing and adopting the exact deterministic name on the next
loop, not by blindly repeating the POST.

Owned teardown is deterministic and fail-closed. It removes floating IPs and
the API NLB first, deletes VMs while their firewall remains attached, and
deletes the managed firewall only after assignments are absent:

```sh
go run ./cmd/inspace-cluster-controller \
  --cluster-config ./examples/inspacecluster.yaml \
  --delete --output=json
```

`infrastructureReady=true` means the three VMs, firewall, floating addresses,
and NLB targets exist in the API. It does **not** yet probe `/readyz` on K3s.
The reported control-plane endpoint uses `spec.endpoint.host`; point that DNS
name at `allocatedEndpointIPv4`. Both the NLB private IP and public IP are added
to the server certificate SANs before the first VM is created.
The JSON result also reports `privateControlPlaneEndpoint`; Karpenter workers
must use that private NLB endpoint instead of hairpinning through the public
floating address.

## External CCM

Build and deploy the CCM after the K3s API becomes available. The manifest has
RBAC, leader election, control-plane scheduling/tolerations, and all required
environment references:

```sh
kubectl -n kube-system create secret generic inspace-cloud-credentials \
  --from-env-file=./ccm-credentials.env
kubectl apply -f ./config/ccm/cloud-controller-manager.yaml
```

Replace all ConfigMap placeholders first. Its container image placeholder is
`ghcr.io/thanet-s/inspace-cloud-controller-manager:dev`; publish or load your built
image and change the tag before applying.

`Service.spec.loadBalancerSourceRanges` is rejected because the InSpace NLB
API exposes TCP port forwarding, not source-range filtering. Use InSpace
firewalls or in-cluster policy where appropriate. UDP and SCTP Services are
also rejected.

## Development and verification

Requires Go 1.26.5.

```sh
make test
make smoke
make vet
make build
```

All default tests use strict literal fixtures and loopback HTTP servers. They
make no request to InSpace and require no token.

Read-only discovery is separate and never enables mutation:

```sh
INSPACE_API_TOKEN='...' ./bin/inspace-discovery --location bkk01 --smoke
```

## Remaining production gaps

- The bootstrap binary consumes a YAML file; it does not yet watch the CRD or
  resolve the Secret references through a Kubernetes management cluster.
- Bootstrap deletion/finalizers and in-place machine updates are not
  implemented. It will not delete adopted infrastructure.
- `infrastructureReady` is API-level only; K3s health and etcd membership need
  an authenticated readiness probe.
- The InSpace firewall's unmatched-traffic/default-deny semantics still need a
  live conformance test before treating the managed policy as production
  isolation. The controller nevertheless rejects public inbound prefixes and
  refuses to assign a public IP unless the expected private-inbound and
  outbound-egress rules are present.
- Published container images and an end-to-end install test on the isolated
  test account are still required.

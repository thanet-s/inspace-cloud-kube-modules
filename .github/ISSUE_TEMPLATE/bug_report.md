---
name: Bug report
about: Report a problem with a released version or the local verification suite
title: "fix: "
labels: bug
---

**Do not include a live InSpace API token, RKE2/agent join token, kubeconfig,
SSH private key, or unredacted E2E state journal anywhere in this report.**
Suspected vulnerabilities or leaked credentials go through GitHub's
**Security → Report a vulnerability** private flow instead, per
[SECURITY.md](../../SECURITY.md).

## Component

Which module or area is affected?

- [ ] `modules/client`
- [ ] `modules/cloud-provider` (bootstrap / CCM)
- [ ] `modules/csi-driver`
- [ ] `modules/karpenter-provider`
- [ ] `charts/`
- [ ] `deploy/` (Ansible lifecycle)
- [ ] `test/e2e/`
- [ ] Other / not sure

## Version

- Module/chart version or commit SHA:
- RKE2 version (if relevant):
- Kubernetes distribution / topology (1 or 3 control planes):

## What happened

A clear description of the bug.

## What you expected

What you expected to happen instead.

## Steps to reproduce

Command(s) run, relevant `deploy/inventory.yml` fields (redact secrets), and
any Kubernetes manifests involved.

## Logs

Output of the relevant command, or `kubectl logs` / `kubectl describe` for the
affected controller. Redact IPs/tokens if this is a public repository issue
and you're unsure whether they're sensitive.

## Local verification

Does this reproduce with `make verify`, `make helm-verify`, or
`make deploy-verify` (see [DEVELOPMENT.md](../../DEVELOPMENT.md))? If so,
paste the failing output.

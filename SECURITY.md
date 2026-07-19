# Security policy

## Supported versions

Before `v1.0.0`, only the latest stable release receives security fixes.
Release candidates are supported only for acceptance testing. Starting with
`v1.0.0`, the latest minor release will receive security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or leaked credential.
Use GitHub's **Security → Report a vulnerability** private reporting flow for
this repository. Include affected versions, impact, reproduction steps, and any
suggested mitigation.

Never include a live InSpace API token, RKE2 join token, kubeconfig, SSH private
key, or unredacted E2E state journal in a report.

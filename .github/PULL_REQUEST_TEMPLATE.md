## What and why

<!-- What does this change, and what problem does it solve? Link an issue if one exists. -->

## Checks run locally

<!-- See CONTRIBUTING.md and DEVELOPMENT.md for the full command list. -->

- [ ] `make verify`
- [ ] `make images`
- [ ] `make helm-verify` (if `charts/` changed)
- [ ] `make deploy-verify` (if `deploy/` changed)
- [ ] `make e2e-static` (if `test/e2e/` changed)

## Scope check

- [ ] This PR does not run against a live InSpace account (the full-cluster
      E2E and API lifecycle tests are maintainer-operated only; see
      [CONTRIBUTING.md](../CONTRIBUTING.md))
- [ ] No generated kubeconfig, state journal, API token, join token, private
      key, or credential-bearing Helm values are committed
- [ ] Cloud ownership/cleanup changes stay fail-closed (no blind retry of a
      mutating POST/PUT/PATCH/DELETE); see the
      [InSpace mutation outcome contract](../DEVELOPMENT.md#inspace-mutation-outcome-contract)

## Notes for reviewers

<!-- Anything a reviewer should know: design tradeoffs, follow-ups, things you're unsure about. -->

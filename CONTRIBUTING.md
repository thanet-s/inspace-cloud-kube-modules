# Contributing

Contributions are licensed under Apache-2.0. By submitting a contribution, you
agree that it may be distributed under that license.

Before opening a pull request:

```sh
make verify
make images
```

Normal tests must not contact InSpace or read local credentials. API lifecycle
tests require their explicit two mutation gates. The full cluster E2E is a
maintainer-operated release acceptance test for the isolated billing account;
it must never run from pull requests.

Keep cloud ownership checks fail-closed, never blindly retry a mutating POST,
and ensure cleanup errors remain visible. Do not commit generated kubeconfigs,
state journals, API tokens, join tokens, private keys, or Helm values containing
credentials.

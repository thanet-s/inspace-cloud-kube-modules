# InSpace API client

This module contains the location-aware InSpace Cloud API client shared by the
cloud provider, CSI driver, and Karpenter provider. It deliberately has no
Kubernetes dependencies, so component dependency upgrades remain isolated.

Mutating requests to non-loopback endpoints are blocked unless a controller
explicitly enables them. Unit and smoke tests use the loopback-only fake API and
never contact a real InSpace account.

```sh
make test
make smoke
make verify
```

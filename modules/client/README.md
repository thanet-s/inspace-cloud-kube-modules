# InSpace API client

This module contains the location-aware InSpace Cloud API client shared by the
cloud provider, CSI driver, and Karpenter provider. It deliberately has no
Kubernetes dependencies, so component dependency upgrades remain isolated.

Mutating requests to non-loopback endpoints are blocked unless a controller
explicitly enables them. Unit and smoke tests use the loopback-only fake API and
never contact a real InSpace account.

The client sends each of its 22 mutation methods at most once. It does not
follow mutation redirects and it never converts `Retryable` into an automatic
replay. Any error
returned after dispatch—including every HTTP error status, timeout,
response-read failure, malformed success body, or caller cancellation—has an
unknown commit outcome until authoritative readback proves the exact resulting
state. Controllers must persist their own intent before the request and resolve
the result from reads. The InSpace API currently documents no idempotency-key
contract.

```sh
make test
make smoke
make verify
```

# CCM public-node-local: fail-static exposure and make-before-break transitions

Date: 2026-10-28. Base: `origin/main` d9d3c78. Branch: `fix/ccm-node-lb-fail-static`.

## 0. Incident and scope

On 2026-10-28 the `service.inspace.cloud/node-lb-pool` annotation of the public-node-local Service
`traefik-public` changed from `public-gateway` to `spe-relay-share`. `syncPublicNodeLocal` saw
`activePool != intent.Pool` and called `withdrawPublicNodeLocal` first
(`node_loadbalancer_local.go:111-117`). The withdrawal then looped for about 15 minutes on
"firewall relation mutation ... remains ambiguous; waiting for authoritative cloud readback"
(`node_loadbalancer_firewall_relation_fence.go:1241-1246`). All public sites were down.

Scope is the public-node-local path only. Production enters it through
`node_loadbalancer_aggregate_reconciler.go:24-56` (`sync`), which calls `syncPublicNodeLocal`.
The legacy shard path (`node_loadbalancer_reconciler.go:363-866`) is test-only and stays unchanged.
Aggregate (shared) mode is out of scope.

All paths below are relative to `modules/cloud-provider/pkg/cloudprovider/` unless they say otherwise.

## 1. Verified facts the design relies on

- The data path is the FIP, DNAT to the node private IP, then the per-Service InSpace firewall on the
  VM (the public gate, see the comment at `node_loadbalancer_local.go:1997-1999`), then Cilium. Cilium
  programs the child `inlb-dp-*` Service: ipMode VIP, eTP Local (`desiredPublicNodeLocalDatapath`,
  local.go:356-397; name from `nodeLoadBalancerDatapathName`, reconciler.go:3271). Parent status
  FIPs (ipMode Proxy) only feed DNS. All of this keeps working while the CCM is down.
- The Service firewall policy depends only on ports and source ranges (`desiredServiceFirewall`,
  reconciler.go:1994-2033). The node set and the pool do not change the policy. A pool switch
  therefore keeps the same firewall. A policy change needs a new firewall, because the name carries
  the hash.
- `failPublicNodeLocalClosed` (local.go:2019-2024) holds only on `inspace.IsTransient`. Every other
  cause runs `withdrawPublicNodeLocal` (local.go:1996-2017). That function detaches one VM per pass
  through `detachOwnedServiceFirewallsForFailure` (reconciler.go:958-1076). It then clears the parent
  status, the child status, and the activation and assignment annotations (local.go:1934-1956).
- Withdraw triggers in `syncPublicNodeLocal`: parse or invalid intent (76-87), firewall spec or
  activation inconsistency (99-110), pool or policy change (111-117), address or conflict errors
  (119-133; `publicNodeLocalAddresses` returns the first error of any node, including a VM audit
  error at 788-790), winner waiting (140-146), any change of the published set (148-155), zero
  nodes or a removed VIP (170-181), prepare waiting while active (184-191), and every fence, gate or
  readback error (199-299). The child datapath ensure step withdraws on absence, deletion, class
  drift and spec drift (local.go:433-493).
- Publication is only possible from an empty public status. `validatePublicNodeLocalAssignmentState`
  rejects a non-empty status before publication (local.go:1564-1566). The local pre-dispatch
  authority calls it (`authorizeServiceFirewallRelationPreDispatch`, fence.go:715-818, local branch).
  So today every node change must withdraw first.
- `auditPublicNodeLocalVMFirewalls` (local.go:890-970) runs `validateLivePublicNodeLocalServiceFirewall`
  (972-1077) for every other Service firewall on the VM. Any imperfect sibling, for example a missing
  Ready endpoint (1014-1016) or a pool mismatch (1001), fails the node for every Service.
- Timers: the relation receipt retires after `nodeLoadBalancerFirewallRelationRetireDelay` = 5m +
  30s (fence.go:236, shard_state.go:51, reconciler.go:90). An unassign needs two absence readbacks at
  least 30s apart (fence.go:186-230). The assignment intent times out at
  `nodeLoadBalancerPendingCreateTimeout` = 5m (reconciler.go:89; used at local.go:1067, 1464-1466,
  1606). That is earlier than the retire time, and the timeout is an error that fails closed. The
  result is a detach and assign loop.
- Every pending fence state is returned as an error (fence.go:1241-1248). `processNext` then calls
  `AddRateLimited` (reconciler.go:320-338) on `DefaultTypedControllerRateLimiter`
  (reconciler.go:198-201). Its per-item backoff grows to 1000s.
- `AssignFirewallToVM` turns a response body mismatch into an error after dispatch
  (`modules/client/firewall.go:94-128`). The fence records that as ambiguous (fence.go:1375).
- Port claims are exclusive per pool, and the lowest UID wins (local.go:1142-1161). A new Service
  with a lower UID can therefore take the port from a serving Service. Stale-exposure attribution
  uses `active-pool` and the child pool annotation (local.go:1205-1253).
- `cleanupPreviousFirewall` (reconciler.go:5012-5066) deletes every owned non-current firewall on
  each pass. `preparePublicNodeLocalFirewall` waits unless exactly one firewall is owned
  (local.go:343-352). `ensureFirewallMetadata` already records `node-lb-previous-firewall-uuid`
  (reconciler.go:3066-3118).

## 2. Design

### 2.1 Invariants

- I1 (fail-static). A Service that holds a persisted activation (`active-pool` is set) or a non-empty
  public status keeps its last known good exposure, unless one of the withdraw reasons in I2 is
  proven. Errors, ambiguity, timeouts and CCM downtime never remove exposure.
- I2 (verified intent only). Exposure is removed only for these reasons:
  - Whole Service: the Service is deleted, or the mode is no longer `public-node-local`
    (`cleanupPublicNodeLocal`, local.go:2026).
  - Whole Service: a verified port-conflict loss against another incumbent (see 2.5).
  - Whole Service: every published node is verified gone.
  - Per node: the Node object is absent or deleting; or the VM is exact not-found, `deleted`, or out
    of the configured VPC (the `false, nil` returns in `authorizePublicNodeLocalNode`, 646-666); or
    the NodeClaim or NodePool is absent or deleting; or the node pool label no longer matches.
  - Per node: no Ready local endpoint on that node for longer than
    `publicNodeLocalEndpointGoneGrace` (60s), while another published node keeps a Ready endpoint.
- I3 (make-before-break). In each pass, adds converge before any removal starts. An add runs in this
  order: child VIP, then firewall assign with readback, then parent FIP. A removal runs in this
  order: parent FIP, then firewall unassign with two spaced absence readbacks, then child VIP. A
  public FIP never reaches a node whose child VIP has gone while its firewall is still open.
- I4 (bounded fence). Every pending relation has a deadline that is known in advance. A pending
  state is a typed "wait" and not an error. It is requeued after a fixed delay, outside the
  exponential backoff. A relation that never converges is parked, so other relations can proceed.
- I5 (no zero window). A pool or policy transition publishes a union of the old and new exposure.
  Old exposure is removed only after the new exposure is fully converged and promoted.

### 2.2 Parent Service state machine

Annotations, on the parent unless stated:

| Key | Meaning |
|---|---|
| `service.inspace.cloud/public-node-local-active-pool` / `-active-policy` (existing) | What is serving (last known good). |
| `service.inspace.cloud/public-node-local-target-pool` / `-target-policy` (new) | A transition in progress. Both are set or both are empty. |
| `service.inspace.cloud/node-lb-previous-firewall-uuid` (existing) | The old-policy firewall. It stays until it is detached everywhere. |
| `service.inspace.cloud/public-node-local-assigning-*` and `node-lb-firewall-assigning-*` (existing) | The assignment intent. It now also covers incremental adds on an active Service. |
| `service.inspace.cloud/node-lb-firewall-relation-retired` (new) | The retirement counter of the relation fence (see 2.4). |
| Child: `service.inspace.cloud/public-node-local-target-pool` (new) | Lets peers attribute exposure to both pools. |

States:

```
Inactive --bootstrap (existing flow, local.go:119-304)--> Steady(active=A)
Steady(A) --node add/remove--> Steady(A)                       [incremental, Phase A]
Steady(A) --intent != A, admissible--> Union(active=A, target=B) [Phase B]
Steady(A) --intent != A, not admissible--> Steady(A) + Event TransitionRefused
Union(A,B) --all B nodes converged--> Promoted(active=B, previous-firewall or old-pool nodes remain)
Promoted --old nodes removed, previous firewall detached and deleted, child ports trimmed--> Steady(B)
Union(A,B) --intent back to A--> Steady(A)  (target cleared, target-only nodes pruned)
Union(A,B) --intent becomes C--> Steady(A) first, then Union(A,C)
any --Service deleted or mode off--> cleanupPublicNodeLocal (withdraw; the only full teardown)
```

In Phase A, `intent != active` holds Steady(A) with the Event `PublicNodeLocalTransitionPending`, so no
outage can occur before Phase B ships. The hold still converges nodes under the active identity (a pool
change runs the full incremental pass; a policy change removes gone nodes under the ledger firewall)
and requeues with the hold delay. Two exits exist before Phase B: a strict narrowing of the policy
(fewer ports, or source ranges that are a subset) only removes exposure and is applied promptly by
rebuilding, and the annotation `service.inspace.cloud/node-lb-allow-rebuild: "true"` permits the old
withdraw and rebuild for any pending change.

### 2.3 Held versus withdrawn

| Condition | Phase A behaviour |
|---|---|
| Transient provider error | Defer (existing `deferOnTransientProviderError`, reconciler.go:300-306) |
| Definite error, gate mismatch, readback ambiguity, assignment timeout, prepare waiting | Hold, plus the Event `PublicNodeLocalHolding` |
| Invalid annotation or reserved port while active | Hold the old exposure, plus an Event |
| Node unverified (audit, metadata or VM read failed) | Keep the node if published; never add it |
| Node verified gone or left the pool | Remove that node only (I3 order) |
| Endpoint gone on one node | Remove that node after 60s if another node has a Ready endpoint |
| Zero Ready endpoints Service-wide | Hold every published node, plus the Event `PublicNodeLocalNoReadyEndpoints` |
| Every published node verified gone | Full `withdrawPublicNodeLocal` |
| Child spec drift | Update the child spec in place (status is a subresource and survives) |
| Child absent, or class drift | Recreate the child and republish the VIPs; no firewall withdrawal |
| Not active and no public status (bootstrap) | Keep today's fail-closed behaviour; nothing is serving |

Zero-endpoint decision. Hold. With eTP Local and no local backend, Cilium drops the traffic, so
holding exposes nothing beyond intent. Withdrawing would add a multi-minute fence cycle and DNS churn
to the recovery of a rollout or a crash loop. When the pods return, a held edge serves at once. The
60s per-node grace covers a DaemonSet rolling restart. The grace is tracked in memory, so a CCM
restart only delays a removal and never speeds it up.

### 2.4 Bounding the fence

- The pending outcomes (fence.go:1241-1248) return `*nodeLoadBalancerFirewallRelationPendingError`.
  The message text stays the same, and the error carries `retryAfter`. For an unassign with a first
  absence, `retryAfter` is the time left until observed-at + delay. For an unconverged receipt, it is
  `min(nodeLoadBalancerRetry, retire-at - now)`. The worst case is the RetireDelay, 5m30s.
- `processNext` calls `AddAfter(key, retryAfter)` and `Forget(key)` for pending and holding errors.
  Other errors keep `AddRateLimited`, with the backoff capped at 60s.
- The local assignment intent timeout becomes `nodeLoadBalancerPublicNodeLocalAssignTimeout` =
  RetireDelay + 2×30s = 6m30s. When the intent expires and no relation receipt is issued, the intent
  is refreshed (new timestamp, current VM set). It is never failed.
- Way forward: each retirement of the same logical relation (operation, firewall, VM) increments
  `node-lb-firewall-relation-retired` (`<op>/<fw>/<vm>|<count>|<at>`). After 3 retirements, that
  relation is parked for 30 minutes. Asking for it returns `errNodeLoadBalancerFirewallRelationParked`
  without a dispatch, together with the Event `PublicNodeLocalFirewallRelationStuck`. The callers in
  the local path skip it and go on to the next VM. A convergence, or a different relation, resets
  the counter.

### 2.5 Port claims

Incumbency comes first. An incumbent is a Service whose `active-pool` (or `target-pool`) equals the
pool and whose child datapath ports prove the overlapping claim. An incumbent beats a newcomer.
Within the same class, the lowest UID wins (today's rule). A transition is refused up front if the
target pool's claims would lose (2.2).

## 3. Implementation plan

Conventions for every task:

- Write the failing test first, run it, and see it fail. Make the minimal change, run it again, and
  see it pass. Then run the whole package. Commit one task per commit.
- Run Go from `modules/cloud-provider` with `GOWORK=off`. Any Go 1.27 toolchain works, a container
  included.
- Focused run: `GOWORK=off go test ./pkg/cloudprovider/ -run '<Regex>' -count=1`.
- Gate after each task: `GOWORK=off go test ./pkg/cloudprovider/ -count=1` and
  `GOWORK=off go vet ./pkg/cloudprovider/`.
- Fixtures: `newPublishedPublicNodeLocalFixture` (transient_api_test.go:168),
  `publicNodeLocalTestService/Node/EndpointSliceLister` (local_test.go:914-980). Add a two-node
  variant, `newPublishedPublicNodeLocalFixtureN(t, n)`, in A6.

### Phase A: fail-static core (each task ships alone)

**A1. Capped rate limiter.**
Files: `node_loadbalancer_reconciler.go` (`newNodeLoadBalancerController` 198-201).
Test first: `TestNodeLoadBalancerRateLimiterCapsBackoffAt60s` in a new file
`node_loadbalancer_ratelimit_test.go`. It calls `When("k")` 40 times and asserts that every delay is
at most 60s and that the first delay is at least 5ms.
Change: add `newNodeLoadBalancerRateLimiter()`, which returns
`workqueue.NewTypedMaxOfRateLimiter(workqueue.NewTypedItemExponentialFailureRateLimiter[string](5*time.Millisecond, 60*time.Second), &workqueue.TypedBucketRateLimiter[string]{Limiter: rate.NewLimiter(rate.Limit(10), 100)})`.
Use it at line 199. Run: `-run TestNodeLoadBalancerRateLimiter`.

**A2. Typed pending fence result and fixed-delay requeue.**
Files: `node_loadbalancer_firewall_relation_fence.go` (reconcile 1018-1376, pending at 1241-1248),
`node_loadbalancer_reconciler.go` (`processNext` 320-338).
Test first, `TestNodeLoadBalancerFirewallRelationPendingIsTypedAndBounded`. Use the setup of
fence_test.go:516-581, with an omitted unassign. Assert
`errors.As(err, &*nodeLoadBalancerFirewallRelationPendingError)`, that the message still contains
"remains ambiguous", that `0 < retryAfter <= nodeLoadBalancerFirewallRelationRetireDelay`, and that
`retryAfter <= 30s` after the first absence. Second test,
`TestNodeLoadBalancerRequeueDelayForError`: it covers the helper
`nodeLoadBalancerRequeueDelay(err) (time.Duration, bool)` for pending, holding (added in A4),
transient (returns false) and plain errors (returns false).
Change: add the error type, which wraps the existing message. Return it from `outcomePending` and
`outcomePreDispatchProof`, and compute `retryAfter` from the fence timestamps. In `processNext`, when
the helper returns true, call `AddAfter` and then `Forget`. The PreDispatchProof message stays the
same (the test at fence_test.go:660 matches "spaced exact VM-absence").
Run: `-run 'TestNodeLoadBalancerFirewallRelation|TestNodeLoadBalancerRequeueDelay'`.

**A3. Timer order and expiry refresh.**
Files: `node_loadbalancer_local.go` (1067, 1464-1466, 1606), `node_loadbalancer_reconciler.go`
(constants 87-91).
Test first:
- `TestPublicNodeLocalAssignTimeoutExceedsRelationRetireDelay` asserts
  `nodeLoadBalancerPublicNodeLocalAssignTimeout >= nodeLoadBalancerFirewallRelationRetireDelay + 2*nodeLoadBalancerAbsenceConfirmationDelay`.
- `TestPublicNodeLocalExpiredAssignmentIntentRefreshesWithoutWithdraw` copies the local_test.go:488
  setup with `assign-at = now - 7m`. It asserts that `syncPublicNodeLocal` returns nil, that there is
  no unassign, that `assign-at` is refreshed, and that the loop then publishes.
Change: add the constant and use it in the three local sites. Keep `nodeLoadBalancerPendingCreateTimeout`
for firewall creates. In `ensurePublicNodeLocalAssignmentIntent`, when the intent is expired and
`annotationNodeLoadBalancerFirewallRelationIssued` is empty, rewrite AssignAt (and the VM set)
instead of returning the timeout error. If a receipt is issued, return a pending error.
Run: `-run 'TestPublicNodeLocal(AssignTimeout|ExpiredAssignment|FreshFence)'`.

**A4. Hold instead of withdraw.**
Files: `node_loadbalancer_local.go`.
Test first, `TestPublicNodeLocalDefiniteFailureHoldsPublishedState`, in
`node_loadbalancer_fail_static_test.go`. It is a table over `newPublishedPublicNodeLocalFixture`
with these cases: a definite `GetVM` error (`errors.New`); a definite `ListFirewalls` error; a
Services list error for the conflict check (a reactor); a drifted datapath read at a publication
gate (the reactor of transient_api_test.go:293-310, read 2 or later); an invalid pool annotation; a
pool annotation change; a port change. For each case it asserts:
- the parent `Status` and annotations are unchanged;
- the child status is unchanged;
- `len(api.unassignedFirewalls)` is unchanged;
- the error is not transient and satisfies `errors.As(*errPublicNodeLocalHolding)`;
- a Warning Event exists with reason `PublicNodeLocalHolding`, or `PublicNodeLocalTransitionPending`
  for the pool and port change cases.
Second test, `TestPublicNodeLocalUnpublishedFailureStillFailsClosed`: the local_test.go:433
scenario still unassigns.
Change:
1. Add `recordPublicNodeLocalHoldEvent(ctx, service, reason, cause)`. Copy the pattern of
   `recordNodeLoadBalancerReservedPortEvent` (1340-1370): the name is
   `service.Name + "." + shortHash(uid+"\x00"+reason+"\x00"+cause)`, and `AlreadyExists` maps to nil.
   It never writes Service annotations.
2. Add `errPublicNodeLocalHolding{cause}` and `holdOrFailPublicNodeLocal(ctx, service, cause)`. Order:
   (a) a transient cause defers, as before; (b) if `active-pool != ""` or the parent status is
   non-empty, emit the Event and return a holding error; (c) otherwise call today's
   `failPublicNodeLocalClosed`.
3. Replace the call sites at 84, 101, 106, 109, 121, 132, 186-190 and 199-298 with
   `holdOrFailPublicNodeLocal`.
4. At 111-117, when the Service is active and `intent.Pool != activePool` or
   `desiredFirewall.Hash != activePolicy`, emit `PublicNodeLocalTransitionPending` and return nil.
   Return before `ensurePublicNodeLocalDatapath` and `preparePublicNodeLocalFirewall`, so the child
   and the firewalls stay as they are. Requeue at resync.
5. At 140-146, when the Service is active and its own claim stands, hold. Withdraw only when it is
   not active.
6. Leave 148-155 and 170-181 as they are for now (A6 replaces them).
Update the existing test 271 (see §4). Run: `-run 'TestPublicNodeLocal(Definite|Unpublished|KeepsState|RejectsUnfenced)'`.

**A5. Node classification.**
Files: `node_loadbalancer_local.go` (`publicNodeLocalAddresses` 522-578, `authorizePublicNodeLocalNode`
624-792).
Test first, `TestPublicNodeLocalClassifyNodes`, a table:
- Ready node: goes to Ready.
- Node absent from the list but present in the published child status: goes to Gone.
- VM `Status: "Deleted"`: Gone.
- Valid empty VPC membership: Gone.
- Pool label changed (manual node): Gone (left the pool).
- `GetVM` definite error: Unverified.
- `InstanceMetadata` mismatch: Unverified.
- Authorized but no Ready endpoint: EndpointMissing.
Change: add `type publicNodeLocalNodeSet struct { Ready []nodeLoadBalancerAddress; Gone map[string]string; Unverified map[string]error; EndpointMissing map[string]nodeLoadBalancerAddress }`.
Add `classifyPublicNodeLocalNodes(ctx, service, intent) (publicNodeLocalNodeSet, bool, error)`. It
returns an error only for the Node list, the EndpointSlice lister and duplicate-IP failures. Split
`authorizePublicNodeLocalNode` into `authorizePublicNodeLocalNodeVerdict`, which returns
`(verdict, patched, err)`: each `return false, false, nil` becomes Gone or NotEligible, and each
error becomes Unverified. Keep the old signature as a wrapper, so the tests at local_test.go:362 and
732 do not change. `publicNodeLocalAddresses` becomes a wrapper that returns Ready plus the first
Unverified error. This keeps the bootstrap path and the validators byte-for-byte equal in behaviour.
Run: `-run 'TestPublicNodeLocal(Classify|Manual|Karpenter)'`.

**A6. Incremental node add and remove on an active Service.**
Files: a new file `node_loadbalancer_local_incremental.go`; `node_loadbalancer_local.go`
(`syncPublicNodeLocal` 119-304, staged audit 1045-1068); `node_loadbalancer_firewall_relation_fence.go`
(local branch of `authorizeServiceFirewallRelationPreDispatch`).
Tests first, in `node_loadbalancer_fail_static_test.go`, using
`newPublishedPublicNodeLocalFixtureN` and an injected `publicNodeLocalNow`:
- `TestPublicNodeLocalAddNodeKeepsExistingIPsPublished`. Add node 2 and its endpoint. After every
  pass: node 1's FIP is in the parent status, node 1's VIP is in the child status, and
  `unassignedFirewalls` is empty. At the end, both nodes are published and assigned, and the fence
  annotations are cleared. At every pass the step order holds: node 2's VIP appears before its
  assignment, and its FIP appears after the readback.
- `TestPublicNodeLocalRemoveNodeDetachesOnlyThatVM`. Two nodes; delete Node 2. Node 1 stays
  published in every pass. `unassignedFirewalls == [fw/vm2]`. Node 2's FIP leaves the parent status
  before the unassign. Node 2's VIP leaves the child status only after the second absence readback.
- `TestPublicNodeLocalEndpointGoneRemovesAfterGrace`. Node 2's endpoint goes away. At now+30s node 2
  is still published. At now+61s it is removed.
- `TestPublicNodeLocalZeroReadyEndpointsHoldsPublication`. All endpoints go away, and now passes the
  grace. Status, firewall and child stay unchanged across 10 passes, and the Event
  `PublicNodeLocalNoReadyEndpoints` exists.
- `TestPublicNodeLocalUnverifiedPublishedNodeIsHeld`. `GetVM` returns a definite error for VM 2.
  Node 2 stays published and node 3 is still added.
- `TestPublicNodeLocalAllPublishedNodesGoneWithdraws`. Every Node is deleted. The Service is fully
  withdrawn.
Change:
1. Turn `syncPublicNodeLocal` into a dispatcher. When `activePool == ""`, it runs the existing flow
   (lines 119-304, moved verbatim into `bootstrapPublicNodeLocal`). Otherwise it runs
   `convergeActivePublicNodeLocal`.
2. `convergeActivePublicNodeLocal` derives `published` from the child VIP status and the parent FIP
   status, and the assigned VMs from a fresh ListFirewalls. It computes:
   - `keep` = Ready + the published Unverified nodes + the published EndpointMissing nodes inside
     the grace (or all published nodes if Ready is empty);
   - `remove` = the published nodes proven Gone, or EndpointMissing past the grace while Ready is
     not empty, plus status entries and assigned VMs that match no existing Node.
   Then it runs one mutation per pass, in this order:
   1. Child VIP for the adds.
   2. Incremental assignment intent: `assign-vms` = the sorted VMs of `keep`.
   3. `assignPublicNodeLocalFirewallWithFence` for the missing VMs.
   4. Parent FIP union (`updatePublicNodeLocalStatusBound`).
   5. Clear the intent.
   6. Remove the parent FIPs of `remove`.
   7. `detachServiceFirewallFromOtherNodes(keep)`.
   8. Remove the child VIPs whose VM is no longer assigned (readback).
   9. Full withdraw only when `keep` is empty and every published node is Gone.
   It requeues after each mutation. Every error goes through `holdOrFailPublicNodeLocal`.
3. Add `validateActivePublicNodeLocalAssignState(ctx, current, intent, desired, fwUUID, vmUUID)`.
   It checks: intent and ledger unchanged; activation == (intent.Pool, desired.Hash); child spec
   matches; the VM's VIP is in the child status; the VM is in `assign-vms`; the fence is fresh; the
   VM is in a fresh Ready set. It allows a non-empty public status. In
   `authorizeServiceFirewallRelationPreDispatch`, call it instead of
   `validatePublicNodeLocalAssignmentState` when `active-pool` is set.
4. In `validateLivePublicNodeLocalServiceFirewall` (1045-1068), drop the
   `len(service.Status.LoadBalancer.Ingress) == 0` condition from `staged`, so an incremental add
   counts as staged.
5. Add `endpointGoneSince map[string]time.Time` (key: UID + "/" + node; guarded by a mutex) and
   `publicNodeLocalNow func() time.Time` to the controller.
Run: `-run 'TestPublicNodeLocal(AddNode|RemoveNode|EndpointGone|ZeroReady|Unverified|AllPublished|PublishedRestart|KeepsState)'`.

**A7. Per-node, per-Service audit isolation.**
Files: `node_loadbalancer_local.go` (`auditPublicNodeLocalVMFirewalls` 890-970,
`validateLivePublicNodeLocalServiceFirewall` 972-1077, call site 788).
Tests first:
- `TestPublicNodeLocalAuditIgnoresImperfectSiblingFirewall`. Reuse the Karpenter setup of
  local_test.go:732. A sibling Service firewall is assigned to the VM, but the sibling has no Ready
  endpoint. The subject is authorized, and the sibling key is enqueued.
- `TestPublicNodeLocalAuditStillRejectsForeignFirewall`. A non-cluster firewall is on the VM. The
  verdict is Unverified.
- `TestPublicNodeLocalAuditSkipsSubjectOwnFirewall`. The subject's own firewall has a stale ledger.
  The subject's own reconcile handles it, so it is not an audit error.
Change: pass `subject *corev1.Service`. Skip firewalls owned by `subject.UID`. A sibling ledger
failure becomes `klog.Warning` plus `c.queue.Add(siblingKey)` (when `c.queue` is not nil). It stays
fatal for: list errors, malformed rows, the base firewall checks (960-968), and
`ValidateNodeLoadBalancerServiceFirewall` failures (949-955).
Run: `-run 'TestPublicNodeLocal(Audit|Karpenter)'`.

**A8. Child datapath repair in place.**
Files: `node_loadbalancer_local.go` (`ensurePublicNodeLocalDatapath` 421-496).
Tests first:
- `TestPublicNodeLocalChildSpecDriftRepairsInPlace`. On a published fixture, set the child selector
  to `{app: stale}` and eTP to Cluster. One pass repairs the spec, the child status and the parent
  status are unchanged, and there is no unassign.
- `TestPublicNodeLocalMissingChildIsRecreatedWithoutWithdraw`. Delete the child. The child is
  recreated, the VIPs are republished within N passes, and the parent FIPs and the firewall
  assignment are unchanged throughout.
Change: when the Service is exposed:
- NotFound: create the child and requeue.
- DeletionTimestamp: requeue and do not withdraw.
- Class drift: delete with the UID precondition, then recreate, and emit an Event.
- Spec drift: `Update` the child in place.
Run: `-run 'TestPublicNodeLocal(Child|MissingChild|DriftCannot|DefiniteDatapath)'`.

**A9. Port-claim incumbency.**
Files: `node_loadbalancer_local.go` (`publicNodeLocalPortConflict` 1133-1199).
Test first: `TestPublicNodeLocalIncumbentKeepsPortAgainstLowerUIDNewcomer`. The incumbent
`z-service-uid` has `active-pool=edge` and a child with port 443. A newcomer, `a-service-uid`, uses
the same port. The incumbent gets loses=false and waiting=false. The newcomer gets loses=true.
Change: add `publicNodeLocalIncumbentInPool(ctx, svc, pool, ports)`. It is true when `active-pool`
(or `target-pool`) is the pool and the child ports overlap. At 1154, the other Service wins only
when it is an incumbent and this Service is not, or when both have the same incumbency and the other
UID is lower.
Run: `-run 'TestPublicNodeLocal(Incumbent|PortClaims|Malformed|Coexists)'`.

**A10. Park relations that never converge.**
Files: `node_loadbalancer_firewall_relation_fence.go` (retire branch 1090-1107, issue 1135-1203);
callers `detachServiceFirewallFromOtherNodes` (reconciler.go:4760-4810) and
`assignPublicNodeLocalFirewallWithFence` (local.go:1484-1531).
Test first: `TestNodeLoadBalancerFirewallRelationParksAfterThreeRetirements`. Use a clock and an
API that never applies the unassign. After 3 retire intervals, the 4th attempt returns
`errNodeLoadBalancerFirewallRelationParked`, `unassignCalls == 3`, and a different VM's relation
still issues. After 30m the parked relation issues again.
Change: maintain `node-lb-firewall-relation-retired` in the same owner commit as the retirement.
Clear it on convergence or when a different logical relation is issued. Callers `continue` on the
parked error.
Run: `-run 'TestNodeLoadBalancerFirewallRelation'`.

### Phase B: make-before-break pool and policy transition

**B1. Transition state helpers.**
Files: `node_loadbalancer_local.go` (constants 31-36) and a new file `node_loadbalancer_local_transition.go`.
Test first: `TestPublicNodeLocalTransitionState`, a table that maps annotations to the phases
Steady, Union, Promoted and Invalid (half-set target; target equal to active).
Change: add the constants and `publicNodeLocalTransition(service) (publicNodeLocalTransitionState, error)`.
Invalid goes to hold.

**B2. Refuse up front.**
Test first: `TestPublicNodeLocalPoolSwitchRefusedWhenTargetPoolPortTaken`. A is active in pool
`public-gateway`. B is an incumbent with 443 in `spe-relay-share`. A switches to `spe-relay-share`.
Assert: no target annotations, A's status unchanged, and the Event `PublicNodeLocalTransitionRefused`.
Change: add `publicNodeLocalTransitionAdmissible(ctx, service, targetIntent)`. It runs the A9
conflict check with this Service as a newcomer in the target pool and with the target ports.

**B3. Conflict attribution across both pools.**
Files: `publicNodeLocalStaleExposureBlocks` (1205-1253), `publicNodeLocalPortConflict`.
Test first: `TestPublicNodeLocalPeerInTransitionBlocksBothPools`. A peer has `active=X` and
`target=Y`, and its child target-pool is Y. A newcomer in X waits, and a newcomer in Y waits.
Change: the exposure pools are {active, target, child pool, child target pool}. The peer is
blocking in any of them.

**B4 and B5. Start the transition, then the union for a pool switch.**
Files: `syncPublicNodeLocal` (replace the A4 TransitionPending hold), `convergeActivePublicNodeLocal`,
`validateLivePublicNodeLocalServiceFirewall` (pool check at 1001 accepts active or target).
Test first: `TestPublicNodeLocalPoolSwitchMakeBeforeBreak`. Node a is in `public-gateway`
(published). Node b is in `spe-relay-share`. Change the pool annotation. After every pass:
- the parent status is not empty;
- every parent FIP's VM is assigned and has a child VIP.
In some pass, both FIPs are published together. At the end: only b is published,
`active-pool=spe-relay-share`, no target annotations, and VM a is unassigned.
Change: write `target-pool` and `target-policy` with a CAS through `updateExactParentService`. Set
the child target-pool. Then `keep` = the held active-pool set plus the target-pool Ready set, and
the A6 add pipeline runs over that union.

**B6. Promotion and cleanup.**
Test first: `TestPublicNodeLocalPromotionRequiresTargetConverged`. A target node is Ready but its
assignment is still pending, so there is no promotion and the old node stays.
Change: when every target-pool Ready node is assigned and published, use a CAS to set
`active-*=target-*`, delete `target-*`, and set the child pool to the target pool. From then on,
old-pool nodes are Gone (left the pool), and A6 removes them.

**B7. Policy change with a second firewall.**
Files: `preparePublicNodeLocalFirewall` (local.go:325-354), `cleanupPreviousFirewall`
(reconciler.go:5012-5066), `desiredPublicNodeLocalDatapath` (356-397),
`validateLivePublicNodeLocalServiceFirewall` (1005-1008).
Tests first:
- `TestPublicNodeLocalPortAddMakeBeforeBreak`: 443 becomes 443+8443. Port 443 stays in the child,
  and F1 stays assigned, until F2 is assigned to every keep VM. At the end, F1 is deleted and the
  child ports are {443, 8443}.
- `TestPublicNodeLocalPortRemovalClosesFirewallBeforeVIP`: 443+80 becomes 443. Port 80 stays in
  the child until F1's detach readback.
- `TestPublicNodeLocalSourceRangeChangeKeepsServing`.
Change:
1. Allow 2 owned firewalls (current and previous) while `target-policy` or `previous-firewall` is set.
2. `cleanupPreviousFirewall` skips the previous firewall while `target-policy` is set or while that
   firewall still has assignments. The detach is done by the A6 detach step, run per firewall.
3. Add `desiredPublicNodeLocalDatapathUnion(service, pool, existing)`. Its ports are the union of
   the existing child ports and the desired ports, keyed by protocol and port. On a name collision,
   the new port gets the name `t-<proto>-<port>`. Use it while `previous-firewall` is set. The source
   ranges are the union too.
4. The audit accepts `uuid == previous-firewall` together with `hash == active-policy`.
5. Promotion follows the rule of B6.
A combined pool and policy change uses the same tuple: F2 goes only to the target-pool VMs.

**B8. Bound the Service firewall create receipt.**
Files: `ensureServiceFirewall` (reconciler.go:2147-2158).
Test first: `TestServiceFirewallIssuedCreateRetiresAfterRetireDelay`. Before the delay, the receipt
is kept (the posterror_readback tests keep passing). After the RetireDelay and two absence readbacks
30s apart, the receipt is retired and the create is issued again once.
Change: reuse `recordFirewallAbsence` with the pending absent and checked annotations, gated on
`issuedAt + RetireDelay`.

**B9. Revert or retarget in the middle of a transition.**
Test first: `TestPublicNodeLocalTransitionRevertPrunesTargetOnly`. After the union, the pool goes
back to A. The target is cleared, only the target-only VMs are unassigned, and A's nodes are never
withdrawn. A third pool C first aborts the transition, then starts Union(A,C).

**B10. Crash and restart safety.**
Test first: `TestPublicNodeLocalTransitionResumesAfterRestartAtEveryStep`. For each step k of the
B5 and B7 scenarios, build a fresh controller (empty in-memory state) over the same kube and fake
API. Optionally inject one definite ListFirewalls error at step k. Assert the B5 invariants and the
final convergence.
Phase B gate: run the full package, run vet, and re-run `-run 'TestPublicNodeLocal|TestNodeLoadBalancerFirewallRelation'`.

## 4. Existing tests: what changes and why

| Test | Verdict |
|---|---|
| transient_api_test.go:271 `TestPublicNodeLocalDefiniteDatapathDriftWithdraws` | **Changes in A4.** Rename it to `...DriftAtGateHolds`. For reads 2 and later, expect a non-transient holding error, the parent status retained, and no unassign. Read 1 (repair) is unchanged. |
| transient_api_test.go:396 `TestNodeLoadBalancerFailClosedHelpersDeferOnTransientCause` | Unchanged. It covers the aggregate and legacy closers only. The local hold has its own test (A4). |
| transient_nth_test.go:62 `TestPublicNodeLocalKeepsStateOnNthTransientProviderCall` | Expectations unchanged. It guards A4 and A6, because hold writes no annotations. Extend n to 24, and add the definite twin `...OnNthDefiniteProviderCall` in A4. |
| local_test.go:141 `...StableUIDWinnerAcrossWholePool` | Unchanged. Neither Service is an incumbent (A9). |
| local_test.go:188 `...MalformedExposedPeerTemporarilyBlocksPort` | Unchanged at the function level. The new sync behaviour (an active winner holds) is in A4 step 5. |
| local_test.go:242 `...ManualNodeLifecycleUsesExistingFIP` | Unchanged. Mode off is verified intent, so cleanup still withdraws. Keep the tolerated message. |
| local_test.go:433 `...RejectsUnfencedPreexistingAssignment` | Unchanged. It is not active and has no public status, so it fails closed. It guards the hold criterion: a child VIP alone is not last known good. |
| local_test.go:488 `...FreshFenceResumesAssignmentAfterRestart` | Unchanged. Only the timeout constant grows (A3). |
| local_test.go:562 `...PublishedRestartClearsFreshAssignmentFence` | Unchanged. It now runs through `convergeActivePublicNodeLocal` and guards A6. |
| local_test.go:625 `...ResumesPartialMultiNodeAssignment` | Unchanged. The signature of `assignPublicNodeLocalFirewallWithFence` is kept. |
| local_test.go:694 `...DriftCannotMutateChildWhileAssignmentFenceIsUnresolved` | **Changes in A8.** Rename it to `...DriftRepairsChildInPlace`. Expect `changed=true`, a nil error, the selector repaired, and no unassign. A child spec update never widens the firewall gate. |
| firewall_relation_fence_test.go:516 `...TransientRemovalOmissionNeverReissues` | Assertions unchanged (still an error, still one DELETE). Add an `errors.As` pending assertion (A2). |
| firewall_relation_fence_test.go:583 `...UncommittedUnassignIsResentAfterRetireInterval` | Unchanged. One retirement does not park. Add the `errors.As` assertion. |
| firewall_relation_fence_test.go:968 `...EmergencyWithdrawalConcurrentControllersCASIssuesOnce` | Unchanged. The CAS and the single DELETE are unaffected. |
| posterror_readback_test.go (124, 194, 269, 337, 420, 528) | Unchanged. These are create and update receipts, and they retry inside the delay. B8 adds the test for after the delay. Fence_test.go:805 is the same. |

## 5. Risks and deliberate omissions

Risks:

- Holding on definite errors can keep serving a node whose security state later goes wrong, for
  example a foreign firewall added to the VM. Mitigations: such a node is never added, the condition
  is visible as an Event, and the operator can remove the node or set the mode off.
- The union phase temporarily exposes old ∪ new ports and the widest source ranges. The owner
  accepted this.
- Incumbency (A9) changes the conflict rule. A lower-UID newcomer no longer evicts a serving Service.
- The endpoint grace lives in memory. A CCM restart can only delay a removal.
- A parked relation can leave a firewall on a VM for 30 minutes. Its FIP has already left DNS.
- Retiring an ambiguous create (B8) can, after a very late commit, leave two firewalls with the same
  name. `ensureServiceFirewall` then errors with "multiple firewalls", which holds and shows an
  Event.
- Each pass does more provider reads, because every node is classified. Adds stay serial: one
  relation per Service at a time, about 10s per node.

Left out on purpose:

- Aggregate (shared) mode and the legacy shard path. They keep today's fail-closed behaviour.
- The standard NLB controller rate limiter (`loadbalancer_controller.go:69`).
- Service status conditions. Events only, so that hold never writes status.
- The `AssignFirewallToVM` body check (client/firewall.go:94-128). The bounded fence now absorbs it.
- DNS TTL tuning and metrics.

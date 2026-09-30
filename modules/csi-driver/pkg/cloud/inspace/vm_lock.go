package inspace

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

// lockVM serializes storage mutations that target one VM: InSpace accepts a
// single attach, detach, or resize request per VM while it is busy.
//
// A caller with a deadline may queue only for the part of the deadline that
// exceeds the mutation dispatch reserve. Waiting longer would hand it the lock
// with too little time left to dispatch, and would hold a sidecar worker for
// the whole timeout. When that budget ends first, lockVM fails with a
// retryable ErrUnavailable that does not wrap the parent context's error, so
// the caller retries later. A parent context that ends first returns its own
// error. Callers get the lock before creating any fence, so a failed wait
// leaves nothing behind.
//
// Once the lock is held, lockVM re-checks the reserve: the wait may have
// consumed it, or the caller may never have had it. The check looks only at
// the deadline, so a caller whose context was cancelled still reaches its own
// cleanup paths.
func (a *Adapter) lockVM(ctx context.Context, vmUUID string) (func(), error) {
	key := strings.ToLower(vmUUID)
	waitCtx := ctx
	if deadline, bounded := ctx.Deadline(); bounded {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithDeadline(ctx, deadline.Add(-minimumMutationDispatchReserve))
		defer cancel()
	}
	unlock, err := a.vmLocks.Lock(waitCtx, key)
	if err != nil {
		if parentErr := ctx.Err(); parentErr != nil {
			return nil, parentErr
		}
		return nil, fmt.Errorf(
			"%w: VM %s is busy with another storage mutation and the request has no time left to wait for it",
			cloud.ErrUnavailable, vmUUID,
		)
	}
	if err := dispatchReserveShortfall(ctx); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// dispatchReserveShortfall reports ErrUnavailable when ctx has a deadline with
// less than the mutation dispatch reserve left. Unbounded contexts pass.
func dispatchReserveShortfall(ctx context.Context) error {
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil
	}
	if remaining := time.Until(deadline); remaining < minimumMutationDispatchReserve {
		return fmt.Errorf(
			"%w: CSI mutation requires %.0fs of deadline reserve at dispatch; only %s remains",
			cloud.ErrUnavailable, minimumMutationDispatchReserve.Seconds(), remaining.Round(time.Millisecond),
		)
	}
	return nil
}

package provider

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

// fastRegistrationTimeout is only safe for a NodeClass that opts out of the
// one-time OS upgrade (RKE2.SkipOSUpgrade true), because that removes
// cloud-init's own up-to-10-minute package-preparation budget
// (pkg/bootstrap/cloudinit.go's package_deadline) from a healthy boot. With
// that budget removed, a healthy boot is bounded by the 5-minute
// internet-egress gate plus RKE2 install/registration, observed in practice
// at a few minutes total. This stays well above that observed time while
// being meaningfully tighter than Karpenter's fixed 15-minute default.
// Nodes that keep the OS upgrade are left entirely to Karpenter's own
// timeout; a legitimately slow package upgrade there can approach or exceed
// 15 minutes without anything being wrong.
const fastRegistrationTimeout = 9 * time.Minute

// FastRegistrationTimeoutController deletes a NodeClaim that never registers
// a Node well before Karpenter's own fixed 15-minute registration-liveness
// timeout, but only for NodeClasses with RKE2.SkipOSUpgrade true. It takes
// exactly the action Karpenter's own liveness controller would eventually
// take -- deleting the NodeClaim object, which the normal termination flow
// then carries through CloudProvider.Delete() -- just sooner. That means an
// existing BadFloatingIPStore record is populated exactly as it would be for
// the stock timeout, just with less time wasted first.
type FastRegistrationTimeoutController struct {
	kubeClient client.Client
	apiReader  client.Reader
	resolver   NodeClassResolver
	clock      func() time.Time
	timeout    time.Duration
}

func NewFastRegistrationTimeoutController(kubeClient client.Client, apiReader client.Reader, resolver NodeClassResolver) (*FastRegistrationTimeoutController, error) {
	if kubeClient == nil || apiReader == nil || resolver == nil {
		return nil, fmt.Errorf("Kubernetes client, uncached API reader, and NodeClass resolver are required for the fast registration-timeout controller")
	}
	return &FastRegistrationTimeoutController{
		kubeClient: kubeClient, apiReader: apiReader, resolver: resolver,
		clock: time.Now, timeout: fastRegistrationTimeout,
	}, nil
}

func (c *FastRegistrationTimeoutController) Name() string {
	return "inspace.nodeclaim.fast-registration-timeout"
}

func (c *FastRegistrationTimeoutController) Reconcile(ctx context.Context, nodeClaim *karpv1.NodeClaim) (reconcile.Result, error) {
	var exact karpv1.NodeClaim
	if err := c.apiReader.Get(ctx, types.NamespacedName{Name: nodeClaim.Name}, &exact); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if exact.UID != nodeClaim.UID || !exact.DeletionTimestamp.IsZero() {
		return reconcile.Result{}, nil
	}
	registered := exact.StatusConditions().Get(karpv1.ConditionTypeRegistered)
	if registered == nil || registered.IsTrue() || registered.LastTransitionTime.IsZero() {
		// A zero LastTransitionTime means the condition was just synthesized
		// as "AwaitingReconciliation" by StatusConditions() itself, not
		// actually observed -- Karpenter's own initialization controller
		// has not run yet. Treating that as infinitely overdue would delete
		// a NodeClaim the instant it is created.
		return reconcile.Result{}, nil
	}
	elapsed := c.clock().Sub(registered.LastTransitionTime.Time)
	if remaining := c.timeout - elapsed; remaining > 0 {
		return reconcile.Result{RequeueAfter: remaining}, nil
	}
	skip, err := c.nodeClassSkipsOSUpgrade(ctx, &exact)
	if err != nil || !skip {
		// Fail closed on any resolution error: leave the NodeClaim to
		// Karpenter's own stock timeout rather than guessing.
		return reconcile.Result{}, nil
	}
	if err := c.kubeClient.Delete(ctx, &exact); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	return reconcile.Result{}, nil
}

func (c *FastRegistrationTimeoutController) nodeClassSkipsOSUpgrade(ctx context.Context, nodeClaim *karpv1.NodeClaim) (bool, error) {
	ref := nodeClaim.Spec.NodeClassRef
	if ref == nil {
		return false, fmt.Errorf("NodeClaim %q has no NodeClassRef", nodeClaim.Name)
	}
	nodeClass, err := c.resolver.GetNodeClass(ctx, ref.Name)
	if err != nil {
		return false, err
	}
	return nodeClass.Spec.RKE2.SkipOSUpgrade, nil
}

func (c *FastRegistrationTimeoutController) Register(_ context.Context, m manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(m).
		Named(c.Name()).
		For(&karpv1.NodeClaim{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 5}).
		Complete(reconcile.AsReconciler(m.GetClient(), c))
}

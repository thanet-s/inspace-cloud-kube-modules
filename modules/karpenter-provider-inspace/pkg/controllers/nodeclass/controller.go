package nodeclass

import (
	"context"
	"fmt"
	"time"

	"github.com/awslabs/operatorpkg/status"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/cloud"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider-inspace/pkg/provider"
)

const retryAfter = time.Minute

type Controller struct {
	kubeClient  client.Client
	resolver    provider.NodeClassResolver
	validator   cloudapi.NodeClassValidator
	clusterName string
}

func NewController(kubeClient client.Client, resolver provider.NodeClassResolver, validator cloudapi.NodeClassValidator, clusterName string) (*Controller, error) {
	if kubeClient == nil || resolver == nil || validator == nil || clusterName == "" {
		return nil, fmt.Errorf("Kubernetes client, resolver, cloud validator, and cluster name are required")
	}
	return &Controller{kubeClient: kubeClient, resolver: resolver, validator: validator, clusterName: clusterName}, nil
}

func (c *Controller) Name() string { return "inspace.nodeclass.readiness" }

func (c *Controller) Reconcile(ctx context.Context, nodeClass *inspacev1.InSpaceNodeClass) (reconcile.Result, error) {
	stored := nodeClass.DeepCopy()
	requeue := false

	var readinessErr error
	if errs := nodeClass.Validate(); len(errs) != 0 {
		readinessErr = errs.ToAggregate()
	} else if nodeClass.Spec.ClusterName != c.clusterName {
		readinessErr = fmt.Errorf("NodeClass cluster %q does not match controller cluster %q", nodeClass.Spec.ClusterName, c.clusterName)
	} else if _, err := c.resolver.ResolveAgentToken(ctx, nodeClass); err != nil {
		readinessErr = err
		requeue = true
	} else {
		hostPoolUUID, _ := nodeClass.Spec.HostPoolSelector.UUID()
		if err := c.validator.ValidateNodeClass(ctx, nodeClass.Spec.Location, nodeClass.Spec.NetworkUUID, hostPoolUUID, nodeClass.Spec.FirewallUUID); err != nil {
			readinessErr = err
			requeue = true
		}
	}

	if readinessErr != nil {
		nodeClass.Status.HostPoolUUID = ""
		nodeClass.Status.FirewallUUID = ""
		nodeClass.Status.ObservedImageID = ""
		nodeClass.Status.ObservedSpecHash = ""
		nodeClass.Status.ObservedGeneration = 0
		nodeClass.Status.ObservedBillingAccountID = 0
		nodeClass.StatusConditions().SetFalse(status.ConditionReady, "NodeClassNotReady", readinessErr.Error())
	} else {
		hostPoolUUID, _ := nodeClass.Spec.HostPoolSelector.UUID()
		nodeClass.Status.HostPoolUUID = hostPoolUUID
		nodeClass.Status.FirewallUUID = nodeClass.Spec.FirewallUUID
		nodeClass.Status.ObservedImageID = nodeClass.Spec.ImageSelector.ID()
		nodeClass.Status.ObservedSpecHash = provider.NodeClassHash(nodeClass)
		nodeClass.Status.ObservedGeneration = nodeClass.Generation
		nodeClass.Status.ObservedBillingAccountID = nodeClass.Spec.BillingAccountID
		nodeClass.StatusConditions().SetTrueWithReason(status.ConditionReady, "NodeClassReady", "InSpace host pool and K3s token are ready")
	}

	if !equality.Semantic.DeepEqual(stored.Status, nodeClass.Status) {
		if err := c.kubeClient.Status().Patch(ctx, nodeClass, client.MergeFromWithOptions(stored, client.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, err
		}
	}
	if requeue {
		return reconcile.Result{RequeueAfter: retryAfter}, nil
	}
	return reconcile.Result{}, nil
}

func (c *Controller) Register(_ context.Context, m manager.Manager) error {
	return controllerruntime.NewControllerManagedBy(m).
		Named(c.Name()).
		For(&inspacev1.InSpaceNodeClass{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 5}).
		Complete(reconcile.AsReconciler(m.GetClient(), c))
}

// ReconcileByName is a small helper for focused tests and diagnostics.
func (c *Controller) ReconcileByName(ctx context.Context, name string) (reconcile.Result, error) {
	var nodeClass inspacev1.InSpaceNodeClass
	if err := c.kubeClient.Get(ctx, types.NamespacedName{Name: name}, &nodeClass); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	return c.Reconcile(ctx, &nodeClass)
}

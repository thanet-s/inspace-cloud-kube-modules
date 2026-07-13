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

	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	cloudapi "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/provider"
)

const retryAfter = time.Minute

type Controller struct {
	kubeClient              client.Client
	resolver                provider.NodeClassResolver
	validator               cloudapi.NodeClassValidator
	clusterName             string
	networkUUID             string
	controlPlaneVIP         string
	privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool
}

func NewController(kubeClient client.Client, resolver provider.NodeClassResolver, validator cloudapi.NodeClassValidator, clusterName, networkUUID, controlPlaneVIP string, privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool) (*Controller, error) {
	if kubeClient == nil || resolver == nil || validator == nil || clusterName == "" || networkUUID == "" || controlPlaneVIP == "" {
		return nil, fmt.Errorf("Kubernetes client, resolver, cloud validator, cluster name, network UUID, and control-plane VIP are required")
	}
	if err := inspacev1.ValidateNetworkUUID(networkUUID); err != nil {
		return nil, fmt.Errorf("controller network UUID: %w", err)
	}
	vip, err := inspacev1.ParseControlPlaneVIP(controlPlaneVIP)
	if err != nil {
		return nil, fmt.Errorf("controller control-plane VIP: %w", err)
	}
	if err := privateLoadBalancerPool.ValidateForSupervisor(vip); err != nil {
		return nil, fmt.Errorf("controller private load-balancer pool: %w", err)
	}
	return &Controller{
		kubeClient: kubeClient, resolver: resolver, validator: validator,
		clusterName: clusterName, networkUUID: networkUUID, controlPlaneVIP: vip.String(), privateLoadBalancerPool: privateLoadBalancerPool,
	}, nil
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
	} else if nodeClass.Spec.NetworkUUID != c.networkUUID {
		readinessErr = fmt.Errorf("NodeClass network %q does not match controller network %q", nodeClass.Spec.NetworkUUID, c.networkUUID)
	} else if controlPlaneVIP, _ := nodeClass.Spec.RKE2.ServerVIP(); controlPlaneVIP.String() != c.controlPlaneVIP {
		readinessErr = fmt.Errorf("NodeClass control-plane VIP %q does not match controller control-plane VIP %q", controlPlaneVIP, c.controlPlaneVIP)
	} else if nodeClass.Spec.PrivateLoadBalancerPool != c.privateLoadBalancerPool {
		readinessErr = fmt.Errorf("NodeClass private load-balancer pool %+v does not match controller pool %+v", nodeClass.Spec.PrivateLoadBalancerPool, c.privateLoadBalancerPool)
	} else if _, err := c.resolver.ResolveAgentToken(ctx, nodeClass); err != nil {
		readinessErr = err
		requeue = true
	} else {
		controlPlaneVIP, _ := nodeClass.Spec.RKE2.ServerVIP()
		for _, hostClass := range inspacev1.SupportedHostClasses() {
			hostPoolUUID, ok := inspacev1.HostPoolUUIDForClass(hostClass)
			if !ok {
				readinessErr = fmt.Errorf("provider has no host-pool UUID mapping for class %q", hostClass)
				break
			}
			if err := c.validator.ValidateNodeClass(ctx, nodeClass.Spec.Location, nodeClass.Spec.NetworkUUID, controlPlaneVIP.String(), nodeClass.Spec.PrivateLoadBalancerPool.Start, nodeClass.Spec.PrivateLoadBalancerPool.Stop, hostPoolUUID, nodeClass.Spec.FirewallUUID); err != nil {
				readinessErr = fmt.Errorf("validating %s host pool %s: %w", hostClass, hostPoolUUID, err)
				requeue = true
				break
			}
		}
	}

	if readinessErr != nil {
		nodeClass.Status.HostPoolUUIDs = nil
		nodeClass.Status.FirewallUUID = ""
		nodeClass.Status.ObservedImageID = ""
		nodeClass.Status.ObservedSpecHash = ""
		nodeClass.Status.ObservedGeneration = 0
		nodeClass.Status.ObservedBillingAccountID = 0
		nodeClass.StatusConditions().SetFalse(status.ConditionReady, "NodeClassNotReady", readinessErr.Error())
	} else {
		nodeClass.Status.HostPoolUUIDs = make([]string, 0, len(inspacev1.SupportedHostClasses()))
		for _, hostClass := range inspacev1.SupportedHostClasses() {
			hostPoolUUID, _ := inspacev1.HostPoolUUIDForClass(hostClass)
			nodeClass.Status.HostPoolUUIDs = append(nodeClass.Status.HostPoolUUIDs, hostPoolUUID)
		}
		nodeClass.Status.FirewallUUID = nodeClass.Spec.FirewallUUID
		nodeClass.Status.ObservedImageID = nodeClass.Spec.ImageSelector.ID()
		nodeClass.Status.ObservedSpecHash = provider.NodeClassHash(nodeClass)
		nodeClass.Status.ObservedGeneration = nodeClass.Generation
		nodeClass.Status.ObservedBillingAccountID = nodeClass.Spec.BillingAccountID
		nodeClass.StatusConditions().SetTrueWithReason(status.ConditionReady, "NodeClassReady", "Private RKE2 supervisor VIP and Service pool, InSpace VPC, Cilium native-routing firewall, Intel and AMD host pools, and RKE2 token are ready")
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

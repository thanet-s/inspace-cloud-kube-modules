package main

import (
	"fmt"
	"os"
	"strings"

	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/karpenter/pkg/cloudprovider/overlay"
	"sigs.k8s.io/karpenter/pkg/controllers"
	"sigs.k8s.io/karpenter/pkg/controllers/state"
	"sigs.k8s.io/karpenter/pkg/operator"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	buildversion "github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version"
	inspacev1 "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/apis/v1alpha1"
	inspacecloud "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/cloud/inspace"
	nodeclasscontroller "github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/controllers/nodeclass"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/karpenter-provider/pkg/provider"
)

const defaultAPIBaseURL = "https://api.inspace.cloud"

type settings struct {
	apiBaseURL              string
	apiToken                string
	clusterName             string
	defaultNodeClass        string
	secretNamespace         string
	location                string
	networkUUID             string
	controlPlaneVIP         string
	privateLoadBalancerPool inspacev1.PrivateLoadBalancerPool
	allowRemoteMutation     bool
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("karpenter-provider-inspace %s\n", operator.Version)
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "karpenter-provider-inspace: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadSettings()
	if err != nil {
		return err
	}
	if err := inspacev1.AddToScheme(kubescheme.Scheme); err != nil {
		return fmt.Errorf("registering InSpace API scheme: %w", err)
	}

	ctx, op := operator.NewOperator()
	apiClient, err := sdk.NewClient(sdk.Options{
		BaseURL:                   cfg.apiBaseURL,
		APIKey:                    cfg.apiToken,
		UserAgent:                 buildversion.UserAgent("karpenter-provider-inspace"),
		DangerouslyAllowMutations: cfg.allowRemoteMutation,
	})
	if err != nil {
		return fmt.Errorf("constructing InSpace API client: %w", err)
	}
	cloud, err := inspacecloud.New(apiClient)
	if err != nil {
		return err
	}
	// Use the uncached API reader so the dedicated Secret needs only an exact
	// resourceNames-scoped GET; controller-runtime must never list/watch all
	// Secrets into its shared cache.
	resolver, err := provider.NewKubernetesResolver(op.GetAPIReader(), cfg.secretNamespace)
	if err != nil {
		return err
	}
	undecorated, err := provider.New(cloud, resolver, provider.Options{
		ClusterName: cfg.clusterName, DefaultNodeClassName: cfg.defaultNodeClass, Location: cfg.location,
		NetworkUUID: cfg.networkUUID, ControlPlaneVIP: cfg.controlPlaneVIP, PrivateLoadBalancerPool: cfg.privateLoadBalancerPool,
	})
	if err != nil {
		return err
	}
	cloudProvider := overlay.Decorate(undecorated, op.GetClient(), op.InstanceTypeStore)
	clusterState := state.NewCluster(op.Clock, op.GetClient(), cloudProvider)
	nodeClassController, err := nodeclasscontroller.NewController(
		op.GetClient(), resolver, cloud, cfg.clusterName, cfg.networkUUID, cfg.controlPlaneVIP, cfg.privateLoadBalancerPool,
	)
	if err != nil {
		return err
	}
	allControllers := controllers.NewControllers(
		ctx, op.Manager, op.Clock, op.GetClient(), op.EventRecorder, cloudProvider,
		undecorated, clusterState, op.InstanceTypeStore,
	)
	allControllers = append(allControllers, nodeClassController)
	op.WithControllers(ctx, allControllers...).Start(ctx)
	return nil
}

func loadSettings() (settings, error) {
	cfg := settings{
		apiBaseURL:       envOr("INSPACE_API_BASE_URL", defaultAPIBaseURL),
		apiToken:         strings.TrimSpace(os.Getenv("INSPACE_API_TOKEN")),
		clusterName:      strings.TrimSpace(os.Getenv("INSPACE_CLUSTER_NAME")),
		defaultNodeClass: strings.TrimSpace(os.Getenv("INSPACE_DEFAULT_NODECLASS")),
		secretNamespace:  envOr("INSPACE_SECRET_NAMESPACE", "karpenter"),
		location:         envOr("INSPACE_LOCATION", inspacev1.LocationBangkok),
		networkUUID:      strings.TrimSpace(os.Getenv("INSPACE_NETWORK_UUID")),
		controlPlaneVIP:  strings.TrimSpace(os.Getenv("INSPACE_CONTROL_PLANE_VIP")),
		privateLoadBalancerPool: inspacev1.PrivateLoadBalancerPool{
			Start: strings.TrimSpace(os.Getenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_START")),
			Stop:  strings.TrimSpace(os.Getenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP")),
		},
	}
	if cfg.apiToken == "" || cfg.clusterName == "" || cfg.defaultNodeClass == "" || cfg.networkUUID == "" || cfg.controlPlaneVIP == "" {
		return settings{}, fmt.Errorf("INSPACE_API_TOKEN, INSPACE_CLUSTER_NAME, INSPACE_DEFAULT_NODECLASS, INSPACE_NETWORK_UUID, and INSPACE_CONTROL_PLANE_VIP are required")
	}
	if cfg.location != inspacev1.LocationBangkok {
		return settings{}, fmt.Errorf("INSPACE_LOCATION must be %q", inspacev1.LocationBangkok)
	}
	if err := inspacev1.ValidateNetworkUUID(cfg.networkUUID); err != nil {
		return settings{}, fmt.Errorf("INSPACE_NETWORK_UUID: %w", err)
	}
	controlPlaneVIP, err := inspacev1.ParseControlPlaneVIP(cfg.controlPlaneVIP)
	if err != nil {
		return settings{}, fmt.Errorf("INSPACE_CONTROL_PLANE_VIP: %w", err)
	}
	if err := cfg.privateLoadBalancerPool.ValidateForSupervisor(controlPlaneVIP); err != nil {
		return settings{}, fmt.Errorf("INSPACE_PRIVATE_LOAD_BALANCER_POOL_START/STOP: %w", err)
	}
	if strings.TrimSpace(os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS")) != "true" {
		return settings{}, fmt.Errorf("INSPACE_ALLOW_REMOTE_MUTATIONS=true is required to start the production controller")
	}
	cfg.allowRemoteMutation = true
	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

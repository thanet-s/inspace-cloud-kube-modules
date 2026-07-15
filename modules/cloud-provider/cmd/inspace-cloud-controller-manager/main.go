// Command inspace-cloud-controller-manager runs the standard Kubernetes cloud
// node, node lifecycle, and Service load-balancer controllers with the InSpace
// external cloud-provider implementation.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/wait"
	cloud "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudconfig "k8s.io/cloud-provider/app/config"
	"k8s.io/cloud-provider/names"
	"k8s.io/cloud-provider/options"
	"k8s.io/component-base/cli"
	cliflag "k8s.io/component-base/cli/flag"
	_ "k8s.io/component-base/logs/json/register"
	_ "k8s.io/component-base/metrics/prometheus/clientgo"
	_ "k8s.io/component-base/metrics/prometheus/version"
	"k8s.io/klog/v2"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	buildversion "github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version"
	inspaceprovider "github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/cloudprovider"
)

func main() {
	ccmOptions, err := options.NewCloudControllerManagerOptions()
	if err != nil {
		klog.Fatalf("initialize cloud controller manager options: %v", err)
	}
	flags := cliflag.NamedFlagSets{}
	command := app.NewCloudControllerManagerCommand(
		ccmOptions,
		initializeCloud,
		app.DefaultInitFuncConstructors,
		names.CCMControllerAliases(),
		flags,
		wait.NeverStop,
	)
	os.Exit(cli.Run(command))
}

func initializeCloud(config *cloudconfig.CompletedConfig) cloud.Interface {
	name := config.ComponentConfig.KubeCloudShared.CloudProvider.Name
	if name != inspaceprovider.ProviderName {
		klog.Fatalf("--cloud-provider must be %q, got %q", inspaceprovider.ProviderName, name)
	}
	apiKey := firstNonEmpty(os.Getenv("INSPACE_API_TOKEN"), os.Getenv("INSPACE_API_KEY"))
	if apiKey == "" {
		klog.Fatal("INSPACE_API_TOKEN is required")
	}
	baseURL := os.Getenv("INSPACE_API_URL")
	if baseURL == "" {
		baseURL = "https://api.inspace.cloud"
	}
	allowMutations, err := strconv.ParseBool(defaultValue(os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS"), "false"))
	if err != nil {
		klog.Fatalf("parse INSPACE_ALLOW_REMOTE_MUTATIONS: %v", err)
	}
	billingID, err := parseRequiredPositiveInt64("INSPACE_BILLING_ACCOUNT_ID")
	if err != nil {
		klog.Fatal(err)
	}
	nodeLoadBalancerEnabled, err := strconv.ParseBool(defaultValue(os.Getenv("INSPACE_NODE_LOAD_BALANCER_ENABLED"), "false"))
	if err != nil {
		klog.Fatalf("parse INSPACE_NODE_LOAD_BALANCER_ENABLED: %v", err)
	}
	nodesPerShard, err := parseInt32WithDefault("INSPACE_NODE_LOAD_BALANCER_NODES_PER_SHARD", 1)
	if err != nil {
		klog.Fatal(err)
	}
	api, err := inspace.NewClient(inspace.Options{
		BaseURL: baseURL, APIKey: apiKey, DangerouslyAllowMutations: allowMutations,
		UserAgent: buildversion.UserAgent("inspace-cloud-controller-manager"),
	})
	if err != nil {
		klog.Fatalf("initialize InSpace client: %v", err)
	}
	provider, err := inspaceprovider.New(api, inspaceprovider.Config{
		Location:                     os.Getenv("INSPACE_LOCATION"),
		Region:                       os.Getenv("INSPACE_REGION"),
		NetworkUUID:                  os.Getenv("INSPACE_NETWORK_UUID"),
		BillingAccountID:             billingID,
		ClusterID:                    os.Getenv("INSPACE_CLUSTER_ID"),
		ControlPlaneVIP:              os.Getenv("INSPACE_CONTROL_PLANE_VIP"),
		PrivateLoadBalancerPoolStart: os.Getenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_START"),
		PrivateLoadBalancerPoolStop:  os.Getenv("INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP"),
		NodeLoadBalancer: inspaceprovider.NodeLoadBalancerConfig{
			Enabled:          nodeLoadBalancerEnabled,
			DefaultNodeClass: os.Getenv("INSPACE_NODE_LOAD_BALANCER_DEFAULT_NODE_CLASS"),
			NodesPerShard:    nodesPerShard,
		},
	})
	if err != nil {
		klog.Fatalf("initialize InSpace cloud provider: %v", err)
	}
	if !allowMutations {
		klog.Warning("remote mutations are disabled; node metadata works but Service LoadBalancers cannot be changed")
	}
	return provider
}

func parseInt32WithDefault(name string, fallback int32) (int32, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return int32(parsed), nil
}

func parseRequiredPositiveInt64(name string) (int64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, fmt.Errorf("%s is required and must be a positive integer", name)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// Command inspace-cluster-controller continuously runs the idempotent fixed
// three-node control-plane reconciler from an InSpaceCluster YAML file.
// Kubernetes CRD watch wiring is a separate deployment increment; this binary
// is operational and uses the same wire object and safe reconciler.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/inspace"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	var once bool
	var interval time.Duration
	var version bool
	var untilReady bool
	var output string
	var sshPublicKeyFile string
	var sshUsername string
	var managementCIDR string
	var managementTCPPorts string
	var deleteOwned bool
	flag.StringVar(&configPath, "cluster-config", "", "path to an InSpaceCluster YAML file")
	flag.BoolVar(&once, "once", false, "perform one reconciliation and exit")
	flag.DurationVar(&interval, "interval", 20*time.Second, "minimum reconciliation interval")
	flag.BoolVar(&version, "version", false, "print version")
	flag.BoolVar(&untilReady, "until-ready", false, "reconcile until infrastructure is ready, then exit")
	flag.StringVar(&output, "output", "text", "result output format: text or json")
	flag.StringVar(&sshPublicKeyFile, "ssh-public-key-file", "", "path to one OpenSSH public key (never a private key)")
	flag.StringVar(&sshUsername, "ssh-username", "", "username created by InSpace for SSH access")
	flag.StringVar(&managementCIDR, "management-cidr", "", "single public IPv4 /32 allowed to reach management TCP ports")
	flag.StringVar(&managementTCPPorts, "management-tcp-ports", "", "comma-separated explicit TCP ports allowed from management-cidr")
	flag.BoolVar(&deleteOwned, "delete", false, "delete only this cluster's deterministically owned infrastructure, then exit")
	flag.Parse()
	if version {
		fmt.Println("inspace-cluster-controller dev")
		return nil
	}
	if configPath == "" {
		return errors.New("--cluster-config is required")
	}
	if once && untilReady {
		return errors.New("--once and --until-ready are mutually exclusive")
	}
	if output != "text" && output != "json" {
		return errors.New("--output must be text or json")
	}
	var sshPublicKey string
	if sshPublicKeyFile != "" {
		publicKeyData, readErr := os.ReadFile(sshPublicKeyFile)
		if readErr != nil {
			return fmt.Errorf("read SSH public key: %w", readErr)
		}
		sshPublicKey = strings.TrimSpace(string(publicKeyData))
	}
	ports, err := parseTCPPorts(managementTCPPorts)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read cluster config: %w", err)
	}
	var cluster v1alpha1.InSpaceCluster
	if err := yaml.UnmarshalStrict(data, &cluster); err != nil {
		return fmt.Errorf("decode cluster config: %w", err)
	}
	apiToken := firstNonEmpty(os.Getenv("INSPACE_API_TOKEN"), os.Getenv("INSPACE_API_KEY"))
	if apiToken == "" {
		return errors.New("INSPACE_API_TOKEN is required")
	}
	k3sToken := strings.TrimSpace(os.Getenv("INSPACE_K3S_TOKEN"))
	if !deleteOwned && k3sToken == "" {
		return errors.New("INSPACE_K3S_TOKEN is required")
	}
	allowMutations, err := strconv.ParseBool(defaultValue(os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS"), "false"))
	if err != nil {
		return fmt.Errorf("parse INSPACE_ALLOW_REMOTE_MUTATIONS: %w", err)
	}
	baseURL := defaultValue(os.Getenv("INSPACE_API_URL"), "https://api.inspace.cloud")
	api, err := inspace.NewClient(inspace.Options{
		BaseURL: baseURL, APIKey: apiToken, DangerouslyAllowMutations: allowMutations,
		UserAgent: "inspace-cluster-controller/dev",
	})
	if err != nil {
		return err
	}
	reconciler := &bootstrap.Reconciler{
		API: api, SSHUsername: sshUsername, SSHPublicKey: sshPublicKey,
		ManagementCIDR: managementCIDR, ManagementTCPPorts: ports,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	for {
		if deleteOwned {
			result, destroyErr := reconciler.Destroy(ctx, &cluster)
			if destroyErr != nil {
				if once || !isRetryable(destroyErr) {
					return destroyErr
				}
				fmt.Fprintf(os.Stderr, "transient destroy error; retrying: %v\n", destroyErr)
				if !waitFor(ctx, interval) {
					return nil
				}
				continue
			}
			if err := emitDestroyResult(os.Stdout, output, result); err != nil {
				return err
			}
			if once || result.Done {
				return nil
			}
			if !waitFor(ctx, interval) {
				return nil
			}
			continue
		}
		result, reconcileErr := reconciler.Reconcile(ctx, &cluster, k3sToken)
		if reconcileErr != nil {
			if once || !isRetryable(reconcileErr) {
				return reconcileErr
			}
			fmt.Fprintf(os.Stderr, "transient reconciliation error; retrying: %v\n", reconcileErr)
			if !waitFor(ctx, interval) {
				return nil
			}
			continue
		}
		if err := emitResult(os.Stdout, output, result); err != nil {
			return err
		}
		if once {
			return nil
		}
		if untilReady && result.Ready {
			return nil
		}
		wait := result.RequeueAfter
		if wait < interval {
			wait = interval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func emitDestroyResult(output *os.File, format string, result bootstrap.DestroyResult) error {
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	_, err := fmt.Fprintf(output, "destroyed=%t owner=%q remaining=%d message=%q\n", result.Done, result.Owner, len(result.Remaining), result.Message)
	return err
}

func emitResult(output *os.File, format string, result bootstrap.Result) error {
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	_, err := fmt.Fprintf(output, "infrastructureReady=%t controlPlaneVMs=%d endpoint=%q privateEndpoint=%q allocatedEndpointIPv4=%q owner=%q firewallUUID=%q apiLoadBalancerUUID=%q message=%q\n",
		result.Ready, len(result.ControlPlaneVMs), result.ControlPlaneEndpoint, result.PrivateControlPlaneEndpoint,
		result.AllocatedEndpointIPv4, result.Owner, result.FirewallUUID, result.APILoadBalancerUUID, result.Message)
	return err
}

func parseTCPPorts(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("parse management TCP port %q: %w", part, err)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func isRetryable(err error) bool {
	var apiErr *inspace.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Retryable
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func waitFor(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
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

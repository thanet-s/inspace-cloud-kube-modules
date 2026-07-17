// Command inspace-cluster-controller continuously runs the idempotent fixed
// three-node control-plane reconciler from an InSpaceCluster YAML file.
// Kubernetes CRD watch wiring is a separate deployment increment; this binary
// is operational and uses the same wire object and safe reconciler.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	buildversion "github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/pkg/bootstrap"
)

type infrastructureReconciler interface {
	Reconcile(context.Context, *v1alpha1.InSpaceCluster, string) (bootstrap.Result, error)
	Destroy(context.Context, *v1alpha1.InSpaceCluster) (bootstrap.DestroyResult, error)
}

type controllerLoopOptions struct {
	Once                  bool
	UntilReady            bool
	DeleteOwned           bool
	Interval              time.Duration
	IssuedVMCreateTimeout time.Duration
	OperationTimeout      time.Duration
	OutputFormat          string
	StandardOutput        io.Writer
	StandardError         io.Writer
}

// The shared HTTP client permits a synchronous VM create to run for up to five
// minutes. Keep an equally long post-timeout recovery window before a one-shot
// bootstrap exits, so a server-side create that finishes after the client
// disconnects can still be adopted and protected without replaying the POST.
const defaultIssuedVMCreateTimeout = 10 * time.Minute
const defaultOperationTimeout = 30 * time.Minute

var bootstrapCacheImageNames = []string{
	"inspace-cloud-controller-manager",
	"inspace-csi-driver",
	"karpenter-provider-inspace",
}

func parseBootstrapCacheImageDigests(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, fmt.Errorf("decode INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS: %w", err)
	}
	if len(values) != len(bootstrapCacheImageNames) {
		return nil, fmt.Errorf(
			"INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS must contain exactly %d module images",
			len(bootstrapCacheImageNames),
		)
	}
	for _, image := range bootstrapCacheImageNames {
		digest, ok := values[image]
		if !ok || len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
			return nil, fmt.Errorf(
				"INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS[%q] must be sha256:<64 lowercase hex>",
				image,
			)
		}
		for _, character := range digest[len("sha256:"):] {
			if !strings.ContainsRune("0123456789abcdef", character) {
				return nil, fmt.Errorf(
					"INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS[%q] must be sha256:<64 lowercase hex>",
					image,
				)
			}
		}
	}
	for image := range values {
		if !slices.Contains(bootstrapCacheImageNames, image) {
			return nil, fmt.Errorf(
				"INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS contains unknown module image %q",
				image,
			)
		}
	}
	return values, nil
}

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
	var issuedVMCreateTimeout time.Duration
	var operationTimeout time.Duration
	flag.StringVar(&configPath, "cluster-config", "", "path to an InSpaceCluster YAML file")
	flag.BoolVar(&once, "once", false, "perform one reconciliation and exit")
	flag.DurationVar(&interval, "interval", 20*time.Second, "minimum reconciliation interval")
	flag.BoolVar(&version, "version", false, "print version")
	flag.BoolVar(&untilReady, "until-ready", false, "reconcile until infrastructure is ready, then exit")
	flag.DurationVar(
		&issuedVMCreateTimeout,
		"issued-vm-create-timeout",
		defaultIssuedVMCreateTimeout,
		"maximum durable issue age for an authoritatively absent VM create in --until-ready mode",
	)
	flag.DurationVar(
		&operationTimeout,
		"operation-timeout",
		defaultOperationTimeout,
		"overall deadline for --until-ready or multi-pass --delete",
	)
	flag.StringVar(&output, "output", "text", "result output format: text or json")
	flag.StringVar(&sshPublicKeyFile, "ssh-public-key-file", "", "path to one OpenSSH public key (never a private key)")
	flag.StringVar(&sshUsername, "ssh-username", "", "required for creation: bastion SSH username created by InSpace")
	flag.StringVar(&managementCIDR, "management-cidr", bootstrap.DefaultManagementCIDR, "optional public IPv4 /32 allowed to reach the bastion; defaults to Any")
	flag.StringVar(&managementTCPPorts, "management-tcp-ports", "", "must be exactly 22 for bastion SSH")
	flag.BoolVar(&deleteOwned, "delete", false, "delete only this cluster's deterministically owned infrastructure, then exit")
	flag.Parse()
	if version {
		fmt.Printf("inspace-cluster-controller %s\n", buildversion.Version)
		return nil
	}
	if configPath == "" {
		return errors.New("--cluster-config is required")
	}
	if once && untilReady {
		return errors.New("--once and --until-ready are mutually exclusive")
	}
	if issuedVMCreateTimeout <= 0 {
		return errors.New("--issued-vm-create-timeout must be positive")
	}
	if operationTimeout <= 0 {
		return errors.New("--operation-timeout must be positive")
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
	rke2Token := strings.TrimSpace(os.Getenv("INSPACE_RKE2_TOKEN"))
	if !deleteOwned && rke2Token == "" {
		return errors.New("INSPACE_RKE2_TOKEN is required")
	}
	cacheKey, cacheNotBefore, err := loadBootstrapCacheSettings(&cluster, deleteOwned)
	if err != nil {
		return err
	}
	moduleImageDigests, err := parseBootstrapCacheImageDigests(os.Getenv("INSPACE_BOOTSTRAP_CACHE_IMAGE_DIGESTS"))
	if err != nil {
		return err
	}
	allowMutations, err := strconv.ParseBool(defaultValue(os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS"), "false"))
	if err != nil {
		return fmt.Errorf("parse INSPACE_ALLOW_REMOTE_MUTATIONS: %w", err)
	}
	baseURL := defaultValue(os.Getenv("INSPACE_API_URL"), "https://api.inspace.cloud")
	api, err := inspace.NewClient(inspace.Options{
		BaseURL: baseURL, APIKey: apiToken, DangerouslyAllowMutations: allowMutations,
		UserAgent: buildversion.UserAgent("inspace-cluster-controller"),
	})
	if err != nil {
		return err
	}
	reconciler := &bootstrap.Reconciler{
		API: api, SSHUsername: sshUsername, SSHPublicKey: sshPublicKey,
		StatusCompareAndSwap: newFileStatusCompareAndSwap(configPath),
		ManagementCIDR:       managementCIDR, ManagementTCPPorts: ports,
		BootstrapCacheKey: cacheKey, BootstrapCacheNotBefore: cacheNotBefore, ModuleVersion: buildversion.Version,
		ModuleImageDigests: moduleImageDigests,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runControllerLoop(ctx, reconciler, &cluster, rke2Token, controllerLoopOptions{
		Once: once, UntilReady: untilReady, DeleteOwned: deleteOwned,
		Interval: interval, IssuedVMCreateTimeout: issuedVMCreateTimeout, OperationTimeout: operationTimeout, OutputFormat: output,
		StandardOutput: os.Stdout, StandardError: os.Stderr,
	})
}

func runControllerLoop(ctx context.Context, reconciler infrastructureReconciler, cluster *v1alpha1.InSpaceCluster, rke2Token string, options controllerLoopOptions) error {
	loopCtx := ctx
	operationTimeout := options.OperationTimeout
	var lastOperationError error
	var lastProgress string
	boundedOperation := !options.Once && (options.UntilReady || options.DeleteOwned)
	if boundedOperation {
		if operationTimeout <= 0 {
			operationTimeout = defaultOperationTimeout
		}
		var cancel context.CancelFunc
		loopCtx, cancel = context.WithTimeout(ctx, operationTimeout)
		defer cancel()
	}
	operationDeadlineError := func() error {
		if boundedOperation && errors.Is(loopCtx.Err(), context.DeadlineExceeded) {
			operation := "bootstrap"
			if options.DeleteOwned {
				operation = "delete"
			}
			deadlineErr := fmt.Errorf("%s operation exceeded its %s deadline: %w", operation, operationTimeout, context.DeadlineExceeded)
			if lastOperationError != nil {
				return errors.Join(deadlineErr, fmt.Errorf("last unresolved cloud error: %w", lastOperationError))
			}
			if lastProgress != "" {
				return fmt.Errorf("%w; last progress: %s", deadlineErr, lastProgress)
			}
			return deadlineErr
		}
		return nil
	}

	for {
		if deadlineErr := operationDeadlineError(); deadlineErr != nil {
			return deadlineErr
		}
		if options.DeleteOwned {
			result, destroyErr := reconciler.Destroy(loopCtx, cluster)
			if destroyErr != nil {
				lastOperationError = destroyErr
			} else {
				lastOperationError = nil
				lastProgress = result.Message
			}
			if deadlineErr := operationDeadlineError(); deadlineErr != nil {
				return deadlineErr
			}
			if destroyErr != nil {
				if options.Once || !isRetryable(destroyErr) {
					return destroyErr
				}
				fmt.Fprintf(options.StandardError, "transient destroy error; retrying: %v\n", destroyErr)
				if !waitFor(loopCtx, options.Interval) {
					if deadlineErr := operationDeadlineError(); deadlineErr != nil {
						return deadlineErr
					}
					return nil
				}
				continue
			}
			if err := emitDestroyResult(options.StandardOutput, options.OutputFormat, result); err != nil {
				return err
			}
			if options.Once || result.Done {
				return nil
			}
			if !waitFor(loopCtx, options.Interval) {
				if deadlineErr := operationDeadlineError(); deadlineErr != nil {
					return deadlineErr
				}
				return nil
			}
			continue
		}
		result, reconcileErr := reconciler.Reconcile(loopCtx, cluster, rke2Token)
		if reconcileErr != nil {
			lastOperationError = reconcileErr
		} else {
			lastOperationError = nil
			lastProgress = result.Message
		}
		if deadlineErr := operationDeadlineError(); deadlineErr != nil {
			return deadlineErr
		}
		if reconcileErr != nil {
			if options.Once || !isRetryable(reconcileErr) {
				return reconcileErr
			}
			retryAfter := options.Interval
			if options.UntilReady {
				var absentCreate *bootstrap.IssuedVMCreateAbsentError
				if errors.As(reconcileErr, &absentCreate) {
					timeout := options.IssuedVMCreateTimeout
					if timeout <= 0 {
						timeout = defaultIssuedVMCreateTimeout
					}
					remaining := time.Until(absentCreate.IssuedAt.Add(timeout))
					if remaining <= 0 {
						return fmt.Errorf(
							"issued VM create %q exceeded its %s authoritative-absence deadline; refusing to replay: %w",
							absentCreate.ResourceName,
							timeout,
							reconcileErr,
						)
					}
					if retryAfter <= 0 || remaining < retryAfter {
						retryAfter = remaining
					}
				}
			}
			fmt.Fprintf(options.StandardError, "transient reconciliation error; retrying: %v\n", reconcileErr)
			if !waitFor(loopCtx, retryAfter) {
				if deadlineErr := operationDeadlineError(); deadlineErr != nil {
					return deadlineErr
				}
				return nil
			}
			continue
		}
		if err := emitResult(options.StandardOutput, options.OutputFormat, result); err != nil {
			return err
		}
		if options.Once {
			return nil
		}
		if options.UntilReady && result.Ready {
			return nil
		}
		wait := result.RequeueAfter
		if wait < options.Interval {
			wait = options.Interval
		}
		timer := time.NewTimer(wait)
		select {
		case <-loopCtx.Done():
			timer.Stop()
			if deadlineErr := operationDeadlineError(); deadlineErr != nil {
				return deadlineErr
			}
			return nil
		case <-timer.C:
		}
	}
}

func emitDestroyResult(output io.Writer, format string, result bootstrap.DestroyResult) error {
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	_, err := fmt.Fprintf(output, "destroyed=%t owner=%q remaining=%d message=%q\n", result.Done, result.Owner, len(result.Remaining), result.Message)
	return err
}

func emitResult(output io.Writer, format string, result bootstrap.Result) error {
	if format == "json" {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	_, err := fmt.Fprintf(output, "infrastructureReady=%t controlPlaneVMs=%d endpoint=%q privateEndpoint=%q privateRegistrationEndpoint=%q owner=%q firewallUUID=%q bastionFirewallUUID=%q bastionVMUUID=%q bastionPublicIPv4=%q bastionPrivateIPv4=%q bootstrapCacheEndpoint=%q bootstrapCacheRegistry=%q bootstrapCacheAddress=%q message=%q\n",
		result.Ready, len(result.ControlPlaneVMs), result.ControlPlaneEndpoint, result.PrivateControlPlaneEndpoint,
		result.PrivateRegistrationEndpoint, result.Owner, result.FirewallUUID, result.BastionFirewallUUID,
		result.BastionVMUUID, result.BastionPublicIPv4, result.BastionPrivateIPv4,
		result.BootstrapCacheEndpoint, result.BootstrapCacheRegistry, result.BootstrapCacheAddress, result.Message)
	return err
}

func loadBootstrapCacheSettings(cluster *v1alpha1.InSpaceCluster, deleting bool) ([]byte, time.Time, error) {
	if deleting || cluster.Spec.BootstrapCache.DirectDownload {
		return nil, time.Time{}, nil
	}
	rawKey := strings.TrimSpace(os.Getenv("INSPACE_BOOTSTRAP_CACHE_KEY"))
	if len(rawKey) != 64 || strings.ToLower(rawKey) != rawKey {
		return nil, time.Time{}, errors.New("INSPACE_BOOTSTRAP_CACHE_KEY must be exactly 64 lowercase hexadecimal characters in cached mode")
	}
	key, err := hex.DecodeString(rawKey)
	if err != nil || len(key) != 32 {
		return nil, time.Time{}, errors.New("INSPACE_BOOTSTRAP_CACHE_KEY must encode exactly 32 bytes")
	}
	rawNotBefore := strings.TrimSpace(os.Getenv("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE"))
	notBefore, err := time.Parse(time.RFC3339, rawNotBefore)
	if err != nil || notBefore.Location() != time.UTC || notBefore.Format(time.RFC3339) != rawNotBefore {
		return nil, time.Time{}, errors.New("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE must be the persisted UTC RFC3339 cluster-initialization time")
	}
	now := time.Now().UTC()
	if notBefore.After(now) {
		return nil, time.Time{}, errors.New("INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE must not be in the future")
	}
	if !now.Before(notBefore.AddDate(15, 0, 0)) {
		return nil, time.Time{}, errors.New("the persisted bootstrap cache certificate lifetime has expired")
	}
	return key, notBefore, nil
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
	if errors.Is(err, bootstrap.ErrRetryableAmbiguousVMDelete) || errors.Is(err, bootstrap.ErrCreateAttemptPending) {
		return true
	}
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

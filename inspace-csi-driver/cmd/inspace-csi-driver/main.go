package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/cloud"
	cloudfake "github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/cloud/fake"
	cloudinspace "github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/cloud/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/driver"
	"github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/host"
	hostfake "github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/host/fake"
	hostlinux "github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/host/linux"
)

func main() {
	endpoint := flag.String("endpoint", "unix:///csi/csi.sock", "CSI Unix socket endpoint")
	location := flag.String("location", os.Getenv("INSPACE_LOCATION"), "InSpace location slug")
	mode := flag.String("mode", "controller", "service mode: controller or node (all is development-fake only)")
	nodeID := flag.String("node-id", os.Getenv("NODE_ID"), "Kubernetes node name or InSpace provider ID (node mode)")
	apiBaseURL := flag.String("api-base-url", envOr("INSPACE_API_BASE_URL", "https://api.inspace.cloud"), "InSpace API base URL")
	billingAccountID := flag.Int64("billing-account-id", envInt64("INSPACE_BILLING_ACCOUNT_ID"), "InSpace billing account ID (required for global tokens)")
	developmentFake := flag.Bool("development-fake", false, "use in-memory adapters; NEVER use for real workloads")
	flag.Parse()

	driverMode := driver.Mode(strings.ToLower(strings.TrimSpace(*mode)))
	var provider cloud.Interface
	var mounter host.Mounter
	if *developmentFake {
		if driverMode == driver.ModeController || driverMode == driver.ModeAll {
			provider = cloudfake.New()
		}
		if driverMode == driver.ModeNode || driverMode == driver.ModeAll {
			mounter = hostfake.New()
		}
	} else {
		switch driverMode {
		case driver.ModeController:
			token := strings.TrimSpace(os.Getenv("INSPACE_API_TOKEN"))
			if token == "" {
				log.Fatal("controller mode requires INSPACE_API_TOKEN")
			}
			if !envTrue("INSPACE_ALLOW_REMOTE_MUTATIONS") {
				log.Fatal("controller mode requires INSPACE_ALLOW_REMOTE_MUTATIONS=true")
			}
			client, err := sdk.NewClient(sdk.Options{
				BaseURL: *apiBaseURL, APIKey: token, UserAgent: "inspace-csi-driver/0.1.0",
				DangerouslyAllowMutations: true,
			})
			if err != nil {
				log.Fatalf("configure InSpace API: %v", err)
			}
			resolver, err := cloudinspace.NewInClusterNodeResolver()
			if err != nil {
				log.Fatalf("configure Kubernetes node resolver: %v", err)
			}
			provider, err = cloudinspace.New(client, resolver, cloudinspace.Config{
				Location: *location, BillingAccountID: *billingAccountID,
			})
			if err != nil {
				log.Fatalf("configure cloud adapter: %v", err)
			}
		case driver.ModeNode:
			if strings.TrimSpace(*nodeID) == "" {
				log.Fatal("node mode requires --node-id or NODE_ID")
			}
			var err error
			mounter, err = hostlinux.New()
			if err != nil {
				log.Fatalf("configure Linux mounter: %v", err)
			}
		case driver.ModeAll:
			log.Fatal("mode all is allowed only with --development-fake")
		default:
			log.Fatalf("unsupported mode %q", *mode)
		}
	}
	d, err := driver.New(driver.Config{Mode: driverMode, Location: *location, NodeID: *nodeID}, provider, mounter)
	if err != nil {
		log.Fatalf("configure driver: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := d.Serve(ctx, *endpoint); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envTrue(name string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(name)))
	return err == nil && value
}

func envInt64(name string) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		log.Fatalf("%s must be a non-negative integer", name)
	}
	return parsed
}

//go:build live

package inspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	sdk "github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
	"github.com/thanet-s/inspace-cloud-kube-modules/inspace-csi-driver/pkg/cloud"
)

func TestLiveDiskLifecycle(t *testing.T) {
	if os.Getenv("INSPACE_RUN_LIVE_TESTS") != "true" || os.Getenv("INSPACE_ALLOW_REMOTE_MUTATIONS") != "true" {
		t.Skip("live mutations require both INSPACE_RUN_LIVE_TESTS=true and INSPACE_ALLOW_REMOTE_MUTATIONS=true")
	}
	token := strings.TrimSpace(os.Getenv("INSPACE_API_TOKEN"))
	location := strings.TrimSpace(os.Getenv("INSPACE_LOCATION"))
	if token == "" || location == "" {
		t.Fatal("INSPACE_API_TOKEN and INSPACE_LOCATION are required")
	}
	baseURL := strings.TrimSpace(os.Getenv("INSPACE_API_BASE_URL"))
	if baseURL == "" {
		baseURL = "https://api.inspace.cloud"
	}
	billingID, err := strconv.ParseInt(defaultString(os.Getenv("INSPACE_BILLING_ACCOUNT_ID"), "0"), 10, 64)
	if err != nil || billingID < 0 {
		t.Fatal("INSPACE_BILLING_ACCOUNT_ID must be a non-negative integer")
	}
	client, err := sdk.NewClient(sdk.Options{
		BaseURL: baseURL, APIKey: token, UserAgent: "inspace-csi-live-test/0.1.0",
		DangerouslyAllowMutations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New(client, nil, Config{Location: location, BillingAccountID: billingID})
	if err != nil {
		t.Fatal(err)
	}
	name := "inspace-e2e-csi-" + time.Now().UTC().Format("20060102t150405") + "-" + randomSuffix(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	volume, err := adapter.EnsureVolume(ctx, cloud.VolumeSpec{Name: name, Location: location, CapacityBytes: gib})
	if err != nil {
		t.Fatal(err)
	}
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if err := adapter.DeleteVolume(cleanupCtx, location, volume.ID); err != nil && !errorsIsNotFound(err) {
			t.Errorf("cleanup live disk %s: %v", volume.ID, err)
		}
	})
	got, err := adapter.GetVolume(ctx, location, volume.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != name || got.CapacityBytes < gib {
		t.Fatalf("live disk mismatch: %#v", got)
	}
	if err := adapter.DeleteVolume(ctx, location, volume.ID); err != nil {
		t.Fatal(err)
	}
	deleted = true
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	value := make([]byte, 4)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func errorsIsNotFound(err error) bool {
	return err == cloud.ErrNotFound || sdk.IsNotFound(err)
}

package bootstrap

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
)

// legacyV9DirectHash is the direct control-plane rendering without a separate
// agent token. Clusters created before the agent token existed keep exactly
// these bytes, so their spec hashes, adoption, and destroy authority are
// unchanged.
const legacyV9DirectHash = "d0e02293426fc7c175413a8ea922c58b2d22b3f9653db444f2a379f3a4dca1f0"

func agentTokenRKE2Config(t *testing.T, input CloudInitInput) string {
	t.Helper()
	raw, err := RenderCloudInitJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	return decodeWriteFiles(t, raw)["/var/lib/inspace/rke2-config"]
}

func TestRenderCloudInitSetsSeparateAgentTokenOnEveryControlPlane(t *testing.T) {
	for _, initialize := range []bool{true, false} {
		input := cacheContractControlPlaneInput()
		input.Initialize = initialize
		input.ServerAddress = "10.20.30.10"
		input.RKE2Token = "unit-server-token"
		input.RKE2AgentToken = "unit-agent-token"
		config := agentTokenRKE2Config(t, input)
		if !strings.Contains(config, "token: \"unit-server-token\"\nagent-token: \"unit-agent-token\"\n") {
			t.Fatalf("initialize=%t: control-plane RKE2 config lacks both server and agent tokens:\n%s", initialize, config)
		}
		if strings.Count(config, "agent-token:") != 1 || strings.Count(config, "unit-agent-token") != 1 {
			t.Fatalf("initialize=%t: control-plane RKE2 config must set the agent token exactly once:\n%s", initialize, config)
		}
	}
}

func TestRenderCloudInitWithoutAgentTokenKeepsLegacyBytes(t *testing.T) {
	input := cacheContractControlPlaneInput()
	input.RKE2AgentToken = ""
	raw, err := RenderCloudInitJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(decodeWriteFiles(t, raw)["/var/lib/inspace/rke2-config"], "agent-token") {
		t.Fatal("legacy rendering without an agent token must not set agent-token")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(raw))); got != legacyV9DirectHash {
		t.Fatalf("legacy control-plane cloud-init hash=%s, want %s; existing clusters would lose adoption", got, legacyV9DirectHash)
	}
}

func TestRenderCloudInitRejectsAgentTokenEqualToServerToken(t *testing.T) {
	input := cacheContractControlPlaneInput()
	input.RKE2AgentToken = input.RKE2Token
	if _, err := RenderCloudInitJSON(input); err == nil || !strings.Contains(err.Error(), "agent token must differ") {
		t.Fatalf("expected agent/server token reuse rejection, got %v", err)
	}
}

func TestReconcilerRendersConfiguredAgentTokenIntoControlPlaneSpec(t *testing.T) {
	cluster := testCluster()
	network := &inspace.Network{UUID: cluster.Spec.Network.UUID, Subnet: "10.20.30.0/24"}
	withoutAgent := &Reconciler{SSHUsername: "ops", SSHPublicKey: "ssh-ed25519 AAAA"}
	withAgent := &Reconciler{SSHUsername: "ops", SSHPublicKey: "ssh-ed25519 AAAA", RKE2AgentToken: "unit-agent-token"}
	for slot := 0; slot < ControlPlaneReplicas; slot++ {
		legacy, err := withoutAgent.desiredControlPlaneVMRequest(cluster, network, "owner", slot, cluster.Spec.Endpoint.VirtualIPv4, "unit-server-token", nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(decodeWriteFiles(t, legacy.CloudInit)["/var/lib/inspace/rke2-config"], "agent-token") {
			t.Fatalf("slot %d: reconciler without an agent token must keep the legacy config", slot)
		}
		desired, err := withAgent.desiredControlPlaneVMRequest(cluster, network, "owner", slot, cluster.Spec.Endpoint.VirtualIPv4, "unit-server-token", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(decodeWriteFiles(t, desired.CloudInit)["/var/lib/inspace/rke2-config"], "agent-token: \"unit-agent-token\"\n") {
			t.Fatalf("slot %d: control-plane spec lacks the configured agent token", slot)
		}
		if desired.Description == legacy.Description || !strings.HasPrefix(desired.Description, "inspace-rke2-cp/v9 owner=owner slot=") {
			t.Fatalf("slot %d: agent token must stay inside the v9 spec hash, got %q", slot, desired.Description)
		}
	}
}

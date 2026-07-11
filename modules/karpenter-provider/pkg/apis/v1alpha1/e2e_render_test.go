package v1alpha1

import (
	"os"
	"strings"
	"testing"
)

func TestClusterE2ERendersWorkerSSHAccess(t *testing.T) {
	data, err := os.ReadFile("../../../../../test/e2e/run.sh")
	if err != nil {
		t.Fatalf("read cluster E2E: %v", err)
	}
	script := string(data)
	for _, expected := range []string{
		`sshUsername: $ssh_user`,
		`sshPublicKey: "$configured_public_key"`,
		`ufw allow proto tcp from $management_cidr to any port 22`,
		`wait_until 600 "SSH on Karpenter worker" ssh_ready "$worker_public_ip"`,
		`wait_until 600 "worker cloud-init, Ubuntu 24.04, and K3s agent" k3s_agent_ready "$worker_public_ip"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("cluster E2E does not render %q into its worker NodeClass", expected)
		}
	}
}

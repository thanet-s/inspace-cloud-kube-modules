package bootstrap

import (
	"strings"
	"testing"
)

// Workers are agents. Their only RKE2 credential is the agent join token from
// the dedicated Secret; they must never be configured with a server token,
// an agent-token server option, or any other token-bearing key that would let
// root on a worker read server bootstrap data from the supervisor.
func TestWorkerConfigCarriesOnlyTheAgentJoinToken(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "agent-join-token",
		RKE2Version: "v1.36.5+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	rke2Config := writeFileContent(t, doc, "/etc/rancher/rke2/config.yaml")
	var tokenLines []string
	for _, line := range strings.Split(rke2Config, "\n") {
		key, _, _ := strings.Cut(line, ":")
		if strings.Contains(strings.ToLower(key), "token") {
			tokenLines = append(tokenLines, line)
		}
	}
	if len(tokenLines) != 1 || tokenLines[0] != `token: "agent-join-token"` {
		t.Fatalf("worker RKE2 config token keys = %q, want only the agent join token", tokenLines)
	}
	if strings.Count(data, "agent-join-token") != 0 {
		t.Fatal("agent join token leaked outside the base64 worker config file")
	}
	for _, file := range doc.WriteFiles {
		if file.Path == "/etc/rancher/rke2/config.yaml" && (file.Permissions != "0600" || file.Owner != "root:root") {
			t.Fatalf("worker RKE2 config mode=%s owner=%s, want 0600 root:root", file.Permissions, file.Owner)
		}
	}
}

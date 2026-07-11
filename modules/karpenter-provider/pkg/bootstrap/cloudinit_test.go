package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

func TestRenderIncludesExactlyOneRegistrationTaint(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName:   "worker-1",
		Server:     "https://api.test.example:6443",
		Token:      "secret-token",
		K3sVersion: "v1.35.6+k3s1",
		Labels:     map[string]string{"example.com/workload": "true"},
		Taints: []corev1.Taint{
			karpv1.UnregisteredNoExecuteTaint,
			{Key: "example.com/bootstrap", Value: "true", Effect: corev1.TaintEffectNoSchedule},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatalf("cloud-init is not a JSON object: %v\n%s", err, data)
	}
	if _, ok := parsed["package_update"]; ok {
		t.Fatal("package_update must not race floating-IP assignment")
	}
	if _, ok := parsed["packages"]; ok {
		t.Fatal("cloud-init packages module must not race floating-IP assignment")
	}
	doc, contents := decodedDocument(t, data)
	decoded := strings.Join(contents, "\n")
	rendered := decoded + "\n" + strings.Join(doc.RunCmd, "\n")
	for _, file := range doc.WriteFiles {
		rendered += "\n" + file.Path
	}
	if count := strings.Count(decoded, "karpenter.sh/unregistered:NoExecute"); count != 1 {
		t.Fatalf("expected one registration taint, found %d\n%s", count, data)
	}
	if count := strings.Count(decoded, ExternalIPv4Placeholder); count != 1 {
		t.Fatalf("expected one external IPv4 placeholder, found %d", count)
	}
	if len(doc.RunCmd) != 6 {
		t.Fatalf("runcmd = %#v, want six string commands", doc.RunCmd)
	}
	for _, file := range doc.WriteFiles {
		if file.Encoding != "b64" {
			t.Fatalf("write_files entry %q encoding = %q, want b64", file.Path, file.Encoding)
		}
	}
	if strings.Contains(data, "secret-token") {
		t.Fatal("raw cloud-init JSON must not expose decoded file contents")
	}
	resolved, err := ResolveExternalIPv4(data, "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	_, resolvedContents := decodedDocument(t, resolved)
	resolvedDecoded := strings.Join(resolvedContents, "\n")
	if strings.Contains(resolvedDecoded, ExternalIPv4Placeholder) || !strings.Contains(resolvedDecoded, `node-external-ip: "203.0.113.10"`) {
		t.Fatalf("external IPv4 was not resolved in K3s config: %s", resolved)
	}
	for _, expected := range []string{"cloud-provider=external", "k3s-agent.service", "example.com/workload=true", "sha256sum-amd64.txt", "v1.35.6+k3s1", "10-private-node-ip.yaml", "default deny incoming", "192.168.0.0/16", "waiting for floating-IP egress", "attempt $attempt", "--retry-all-errors"} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("cloud-init is missing %q", expected)
		}
	}
}

func TestResolveExternalIPv4RequiresExactlyOnePlaceholder(t *testing.T) {
	for _, input := range []string{
		`{"write_files":[]}`,
		`{"value":"__INSPACE_FLOATING_IPV4____INSPACE_FLOATING_IPV4__"}`,
		`{"write_files":[{"path":"/bad","encoding":"plain","content":"__INSPACE_FLOATING_IPV4__"}]}`,
		`{"write_files":[{"path":"/config","encoding":"b64","content":"X19JTlNQQUNFX0ZMT0FUSU5HX0lQVjRfXw=="}],"runcmd":["echo __INSPACE_FLOATING_IPV4__"]}`,
	} {
		if _, err := ResolveExternalIPv4(input, "203.0.113.10"); err == nil {
			t.Fatalf("expected strict placeholder validation for %s", input)
		}
	}
}

func TestAdditionalScriptUsesCloudInitOnceSemaphore(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://api.test.example:6443", Token: "secret-token",
		K3sVersion: "v1.35.6+k3s1", AdditionalScript: "touch /opt/ran",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, contents := decodedDocument(t, data)
	decoded := strings.Join(contents, "\n")
	for _, expected := range []string{"cloud-init-per", "inspace-additional-user-data", "touch /opt/ran"} {
		if !strings.Contains(decoded, expected) && !strings.Contains(strings.Join(mustDocument(t, data).RunCmd, "\n"), expected) {
			t.Fatalf("cloud-init is missing %q: %s", expected, data)
		}
	}
}

func decodedDocument(t *testing.T, data string) (document, []string) {
	t.Helper()
	doc := mustDocument(t, data)
	contents := make([]string, 0, len(doc.WriteFiles))
	for _, file := range doc.WriteFiles {
		content, err := decodeWriteFile(file)
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, content)
	}
	return doc, contents
}

func mustDocument(t *testing.T, data string) document {
	t.Helper()
	var doc document
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("decode cloud-init document: %v", err)
	}
	return doc
}

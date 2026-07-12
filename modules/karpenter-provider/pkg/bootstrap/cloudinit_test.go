package bootstrap

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	karpv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

func TestRenderIncludesExactlyOneRegistrationTaint(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName:    "worker-1",
		Server:      "https://10.0.0.10:9345",
		Token:       "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
		Labels:      map[string]string{"example.com/workload": "true"},
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
	if count := strings.Count(decoded, VPCSubnetPlaceholder); count != 1 {
		t.Fatalf("expected one VPC subnet placeholder, found %d", count)
	}
	if len(doc.RunCmd) != 1 || doc.RunCmd[0] != "/usr/local/sbin/inspace-bootstrap-rke2-agent" {
		t.Fatalf("runcmd = %#v, want one fail-fast orchestrator", doc.RunCmd)
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
		t.Fatalf("external IPv4 was not resolved in RKE2 config: %s", resolved)
	}
	resolved, err = ResolveVPCSubnet(resolved, "10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, resolvedContents = decodedDocument(t, resolved)
	resolvedDecoded = strings.Join(resolvedContents, "\n")
	if strings.Contains(resolvedDecoded, VPCSubnetPlaceholder) || !strings.Contains(resolvedDecoded, "vpc_subnet='10.0.0.0/24'") {
		t.Fatalf("VPC subnet was not resolved in private-IP detector: %s", resolved)
	}
	for _, expected := range []string{
		"cloud-provider=external",
		`server: "https://10.0.0.10:9345"`,
		"rke2-agent.service",
		"[ -f /usr/local/lib/systemd/system/rke2-agent.service ]",
		"example.com/workload=true",
		"rke2.linux-amd64.tar.gz",
		"sha256sum-amd64.txt",
		"v1.35.6+rke2r1",
		"/etc/rancher/rke2/config.yaml",
		`ip -o -4 addr show to "$vpc_subnet" scope global`,
		`[ "$(printf '%s\n' "$vpc_identities" | awk 'NF { count++ } END { print count + 0 }')" -eq 1 ]`,
		"ufw --force disable",
		"systemctl disable --now ufw.service",
		"systemctl start --no-block rke2-agent.service",
		`[ "$attempt" -ge 180 ]`,
		"waiting for floating-IP egress",
		"attempt $attempt",
		"--retry-all-errors",
	} {
		if !strings.Contains(rendered, expected) {
			t.Errorf("cloud-init is missing %q", expected)
		}
	}
	if strings.Contains(strings.ToLower(rendered), "k3s") {
		t.Fatalf("RKE2 bootstrap retained a K3s artifact:\n%s", rendered)
	}
	if SchemaVersion != "stock-ubuntu-rke2-v3" {
		t.Fatalf("bootstrap schema = %q, want exact-VPC/firewall/startup drift version v3", SchemaVersion)
	}
}

func TestRenderedShellScriptsHaveValidSyntax(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1", AdditionalScript: "touch /opt/ran",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, contents := decodedDocument(t, data)
	checked := 0
	for i, content := range contents {
		if !strings.HasPrefix(content, "#!/bin/sh\n") {
			continue
		}
		command := exec.Command("sh", "-n")
		command.Stdin = strings.NewReader(content)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("write_files[%d] shell syntax: %v\n%s", i, err, output)
		}
		checked++
	}
	if checked != 8 {
		t.Fatalf("syntax-checked %d shell scripts, want eight; runcmd=%#v", checked, doc.RunCmd)
	}
}

func TestRenderedHostFirewallAndRetryContracts(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	disableHostFirewall := writeFileContent(t, doc, "/usr/local/sbin/inspace-disable-host-firewall")
	for _, want := range []string{
		"if command -v ufw >/dev/null 2>&1; then",
		"ufw --force disable",
		`LC_ALL=C ufw status | grep -Fq "Status: inactive"`,
		"systemctl list-unit-files ufw.service --no-legend",
		"systemctl disable --now ufw.service",
		"systemctl is-active --quiet ufw.service",
		"systemctl is-enabled ufw.service",
	} {
		if !strings.Contains(disableHostFirewall, want) {
			t.Errorf("host-firewall disable script is missing %q\n%s", want, disableHostFirewall)
		}
	}
	for _, forbidden := range []string{"ufw --force enable", "ufw allow", "ufw route", "iptables", "nft"} {
		if strings.Contains(disableHostFirewall, forbidden) {
			t.Errorf("host-firewall disable script must not contain %q\n%s", forbidden, disableHostFirewall)
		}
	}

	stubDir := t.TempDir()
	commandLog := filepath.Join(stubDir, "commands.log")
	writeExecutable(t, filepath.Join(stubDir, "ufw"), `#!/bin/sh
printf 'ufw %s\n' "$*" >> "$COMMAND_LOG"
if [ "$*" = "status" ]; then printf 'Status: inactive\n'; fi
`)
	writeExecutable(t, filepath.Join(stubDir, "systemctl"), `#!/bin/sh
printf 'systemctl %s\n' "$*" >> "$COMMAND_LOG"
case "$*" in
  "list-unit-files ufw.service --no-legend") printf 'ufw.service enabled\n' ;;
  "is-active --quiet ufw.service") exit 3 ;;
  "is-enabled ufw.service") printf 'disabled\n'; exit 1 ;;
esac
`)
	command := exec.Command("sh")
	command.Stdin = strings.NewReader(disableHostFirewall)
	command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "COMMAND_LOG="+commandLog)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("rendered host-firewall disable failed with command stubs: %v\n%s", err, output)
	}
	gotCommands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	wantCommands := "ufw --force disable\nsystemctl list-unit-files ufw.service --no-legend\nsystemctl disable --now ufw.service\nufw status\nsystemctl list-unit-files ufw.service --no-legend\nsystemctl is-active --quiet ufw.service\nsystemctl is-enabled ufw.service\n"
	if string(gotCommands) != wantCommands {
		t.Fatalf("executed host-firewall commands differ\ngot:\n%s\nwant:\n%s", gotCommands, wantCommands)
	}

	writeExecutable(t, filepath.Join(stubDir, "systemctl"), `#!/bin/sh
case "$*" in
  "list-unit-files ufw.service --no-legend") printf 'ufw.service enabled\n' ;;
  "disable --now ufw.service") exit 1 ;;
esac
`)
	command = exec.Command("sh")
	command.Stdin = strings.NewReader(disableHostFirewall)
	command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "COMMAND_LOG="+commandLog)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("host-firewall script swallowed systemctl disable failure\n%s", output)
	}

	writeExecutable(t, filepath.Join(stubDir, "systemctl"), "#!/bin/sh\nexit 0\n")
	command = exec.Command("sh")
	command.Stdin = strings.NewReader(disableHostFirewall)
	command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "COMMAND_LOG="+commandLog)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("host-firewall script rejected an absent ufw.service unit: %v\n%s", err, output)
	}

	prerequisites := writeFileContent(t, doc, "/usr/local/sbin/inspace-install-prerequisites")
	if strings.Contains(prerequisites, "ufw") {
		t.Fatalf("prerequisite installer must not install or configure UFW\n%s", prerequisites)
	}
	for _, want := range []string{
		`while [ "$attempt" -lt 60 ]; do`,
		`echo "package installation failed after $attempt attempts" >&2`,
		"exit 1",
	} {
		if !strings.Contains(prerequisites, want) {
			t.Errorf("prerequisite installer is missing retry bound %q\n%s", want, prerequisites)
		}
	}
	installer := writeFileContent(t, doc, "/usr/local/sbin/inspace-install-rke2")
	for _, want := range []string{
		`while [ "$attempt" -lt 60 ]; do`,
		`echo "download of $url failed after $attempt attempts" >&2`,
		"return 1",
	} {
		if !strings.Contains(installer, want) {
			t.Errorf("RKE2 installer is missing download retry bound %q\n%s", want, installer)
		}
	}
}

func TestRenderedAgentStartIsBoundedAndFailFast(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	startAgent := writeFileContent(t, mustDocument(t, data), "/usr/local/sbin/inspace-start-rke2-agent")
	for _, want := range []string{
		"systemctl enable rke2-agent.service",
		"systemctl start --no-block rke2-agent.service",
		"until systemctl is-active --quiet rke2-agent.service",
		"systemctl is-failed --quiet rke2-agent.service",
		`[ "$attempt" -ge 180 ]`,
	} {
		if !strings.Contains(startAgent, want) {
			t.Errorf("agent start script is missing %q\n%s", want, startAgent)
		}
	}
	if strings.Contains(startAgent, "enable --now") {
		t.Fatalf("agent start script retained unbounded enable --now\n%s", startAgent)
	}

	stubDir := t.TempDir()
	activeCounter := filepath.Join(stubDir, "active.count")
	sleepCounter := filepath.Join(stubDir, "sleep.count")
	writeExecutable(t, filepath.Join(stubDir, "systemctl"), `#!/bin/sh
case "$*" in
  "is-active --quiet rke2-agent.service")
    count=0
    if [ -f "$ACTIVE_COUNTER" ]; then count="$(cat "$ACTIVE_COUNTER")"; fi
    count=$((count + 1))
    echo "$count" > "$ACTIVE_COUNTER"
    if [ "$count" -ge 3 ]; then exit 0; fi
    exit 3
    ;;
  "is-failed --quiet rke2-agent.service") exit 1 ;;
esac
exit 0
`)
	writeCounterStub(t, filepath.Join(stubDir, "sleep"), "SLEEP_COUNTER", false)
	command := exec.Command("sh")
	command.Stdin = strings.NewReader(startAgent)
	command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "ACTIVE_COUNTER="+activeCounter, "SLEEP_COUNTER="+sleepCounter)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bounded agent start failed: %v\n%s", err, output)
	}
	if got := readCounter(t, activeCounter); got != 3 {
		t.Fatalf("agent active checks = %d, want 3", got)
	}
	if got := readCounter(t, sleepCounter); got != 2 {
		t.Fatalf("agent wait sleeps = %d, want 2", got)
	}

	writeExecutable(t, filepath.Join(stubDir, "systemctl"), `#!/bin/sh
case "$*" in
  "is-active --quiet rke2-agent.service") exit 3 ;;
  "is-failed --quiet rke2-agent.service") exit 0 ;;
esac
exit 0
`)
	command = exec.Command("sh")
	command.Stdin = strings.NewReader(startAgent)
	command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "ACTIVE_COUNTER="+activeCounter, "SLEEP_COUNTER="+sleepCounter)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("agent start ignored failed service state\n%s", output)
	}
}

func TestBootstrapOrchestratorIsFailFastAndDisablesFirewallAfterAdditionalData(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1", AdditionalScript: "ufw --force enable",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	orchestrator := writeFileContent(t, doc, "/usr/local/sbin/inspace-bootstrap-rke2-agent")
	dropIn := writeFileContent(t, doc, "/etc/systemd/system/rke2-agent.service.d/10-inspace-private-ip.conf")
	if !strings.Contains(dropIn, "ExecStartPre=/usr/local/sbin/inspace-verify-host-firewall") {
		t.Fatalf("RKE2 service lacks host-firewall pre-start gate\n%s", dropIn)
	}
	additionalIndex := strings.Index(orchestrator, "cloud-init-per once inspace-additional-user-data")
	disableIndex := strings.Index(orchestrator, "/usr/local/sbin/inspace-disable-host-firewall")
	verifyIndex := strings.Index(orchestrator, "/usr/local/sbin/inspace-verify-host-firewall")
	startIndex := strings.Index(orchestrator, "/usr/local/sbin/inspace-start-rke2-agent")
	if additionalIndex < 0 || disableIndex <= additionalIndex || verifyIndex <= disableIndex || startIndex <= verifyIndex {
		t.Fatalf("unsafe orchestrator order\n%s", orchestrator)
	}

	stubDir := t.TempDir()
	commandLog := filepath.Join(stubDir, "orchestrator.log")
	stub := `#!/bin/sh
name="$(basename "$0")"
printf '%s\n' "$name" >> "$COMMAND_LOG"
if [ "$name" = "${FAIL_STEP:-}" ]; then exit 1; fi
exit 0
`
	for _, name := range []string{
		"inspace-install-prerequisites", "inspace-install-rke2", "inspace-detect-private-ip",
		"inspace-additional-user-data", "inspace-disable-host-firewall", "inspace-verify-host-firewall", "inspace-start-rke2-agent", "cloud-init-per",
	} {
		writeExecutable(t, filepath.Join(stubDir, name), stub)
	}
	harness := strings.ReplaceAll(orchestrator, "/usr/local/sbin/", stubDir+"/")
	run := func(failStep string) (string, error) {
		t.Helper()
		if err := os.WriteFile(commandLog, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("sh")
		command.Stdin = strings.NewReader(harness)
		command.Env = append(os.Environ(), "PATH="+stubDir+":"+os.Getenv("PATH"), "COMMAND_LOG="+commandLog, "FAIL_STEP="+failStep)
		_, err := command.CombinedOutput()
		log, readErr := os.ReadFile(commandLog)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return string(log), err
	}

	log, err := run("inspace-verify-host-firewall")
	if err == nil {
		t.Fatal("orchestrator ignored firewall verification failure")
	}
	if strings.Contains(log, "inspace-start-rke2-agent") {
		t.Fatalf("agent start ran after firewall verification failure\n%s", log)
	}
	wantBeforeFailure := "inspace-install-prerequisites\ninspace-install-rke2\ninspace-detect-private-ip\ncloud-init-per\ninspace-disable-host-firewall\ninspace-verify-host-firewall\n"
	if log != wantBeforeFailure {
		t.Fatalf("failure order differs\ngot:\n%swant:\n%s", log, wantBeforeFailure)
	}

	log, err = run("inspace-install-prerequisites")
	if err == nil || log != "inspace-install-prerequisites\n" {
		t.Fatalf("prerequisite failure did not stop orchestrator: err=%v log=%q", err, log)
	}
}

func TestRenderedRetryLoopsStopAfterSixtyAttempts(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	stubDir := t.TempDir()
	aptCounter := filepath.Join(stubDir, "apt.count")
	sleepCounter := filepath.Join(stubDir, "apt-sleep.count")
	writeCounterStub(t, filepath.Join(stubDir, "apt-get"), "APT_COUNTER", true)
	writeCounterStub(t, filepath.Join(stubDir, "sleep"), "SLEEP_COUNTER", false)
	prerequisites := writeFileContent(t, doc, "/usr/local/sbin/inspace-install-prerequisites")
	command := exec.Command("sh")
	command.Stdin = strings.NewReader(prerequisites)
	command.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"APT_COUNTER="+aptCounter,
		"SLEEP_COUNTER="+sleepCounter,
	)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("prerequisite retry loop unexpectedly succeeded\n%s", output)
	}
	if got := readCounter(t, aptCounter); got != 60 {
		t.Fatalf("apt attempts = %d, want 60", got)
	}
	if got := readCounter(t, sleepCounter); got != 59 {
		t.Fatalf("apt retry sleeps = %d, want 59", got)
	}

	curlCounter := filepath.Join(stubDir, "curl.count")
	sleepCounter = filepath.Join(stubDir, "curl-sleep.count")
	writeCounterStub(t, filepath.Join(stubDir, "curl"), "CURL_COUNTER", true)
	installer := writeFileContent(t, doc, "/usr/local/sbin/inspace-install-rke2")
	functionStart := strings.Index(installer, "download_asset() {")
	if functionStart < 0 {
		t.Fatalf("could not isolate download_asset from rendered installer\n%s", installer)
	}
	functionEnd := strings.Index(installer[functionStart:], "\ndownload_asset ")
	if functionEnd < 0 {
		t.Fatalf("could not isolate download_asset from rendered installer\n%s", installer)
	}
	functionEnd += functionStart
	downloadHarness := "#!/bin/sh\nset -eu\n" + installer[functionStart:functionEnd] + `
download_asset "https://example.invalid/rke2.tar.gz" "$DOWNLOAD_OUTPUT"
`
	command = exec.Command("sh")
	command.Stdin = strings.NewReader(downloadHarness)
	command.Env = append(os.Environ(),
		"PATH="+stubDir+":"+os.Getenv("PATH"),
		"CURL_COUNTER="+curlCounter,
		"SLEEP_COUNTER="+sleepCounter,
		"DOWNLOAD_OUTPUT="+filepath.Join(stubDir, "download"),
	)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("download retry loop unexpectedly succeeded\n%s", output)
	}
	if got := readCounter(t, curlCounter); got != 60 {
		t.Fatalf("curl attempts = %d, want 60", got)
	}
	if got := readCounter(t, sleepCounter); got != 59 {
		t.Fatalf("download retry sleeps = %d, want 59", got)
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

func TestResolveVPCSubnetRequiresExactlyOneSafePlaceholder(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveVPCSubnet(data, "10.0.0.17/24")
	if err != nil {
		t.Fatal(err)
	}
	_, contents := decodedDocument(t, resolved)
	decoded := strings.Join(contents, "\n")
	if strings.Contains(decoded, VPCSubnetPlaceholder) || !strings.Contains(decoded, "vpc_subnet='10.0.0.0/24'") {
		t.Fatalf("resolved VPC subnet is not canonical and exact\n%s", decoded)
	}
	for _, subnet := range []string{"", "203.0.113.0/24", "10.42.0.0/16", "10.43.0.0/16", "10.0.0.0/28", "10.0.0.0/31", "10.0.0.10/32", "fd00::/64"} {
		if _, err := ResolveVPCSubnet(data, subnet); err == nil {
			t.Fatalf("unsafe VPC subnet %q was accepted", subnet)
		}
	}
	for _, input := range []string{
		`{"write_files":[]}`,
		`{"value":"__INSPACE_VPC_SUBNET____INSPACE_VPC_SUBNET__"}`,
		`{"write_files":[{"path":"/bad","encoding":"plain","content":"__INSPACE_VPC_SUBNET__"}]}`,
	} {
		if _, err := ResolveVPCSubnet(input, "10.0.0.0/24"); err == nil {
			t.Fatalf("expected strict VPC placeholder validation for %s", input)
		}
	}
}

func TestRenderRequiresExactRKE2ReleaseAndSupervisorEndpoint(t *testing.T) {
	base := Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1",
	}
	for name, mutate := range map[string]func(*Config){
		"legacy K3s release": func(config *Config) { config.RKE2Version = "v1.35.6+k3s1" },
		"release channel":    func(config *Config) { config.RKE2Version = "stable" },
		"Kubernetes API":     func(config *Config) { config.Server = "https://api.test.example:6443" },
		"insecure endpoint":  func(config *Config) { config.Server = "http://api.test.example:9345" },
		"DNS endpoint":       func(config *Config) { config.Server = "https://registration.example:9345" },
		"public endpoint":    func(config *Config) { config.Server = "https://203.0.113.10:9345" },
		"pod-CIDR endpoint":  func(config *Config) { config.Server = "https://10.42.0.10:9345" },
		"Service endpoint":   func(config *Config) { config.Server = "https://10.43.0.10:9345" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := RenderCloudInit(config); err == nil {
				t.Fatal("expected RKE2 bootstrap contract validation error")
			}
		})
	}
}

func TestAdditionalScriptUsesCloudInitOnceSemaphore(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.35.6+rke2r1", AdditionalScript: "touch /opt/ran",
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

func writeFileContent(t *testing.T, doc document, path string) string {
	t.Helper()
	for _, file := range doc.WriteFiles {
		if file.Path != path {
			continue
		}
		content, err := decodeWriteFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	t.Fatalf("cloud-init is missing write_files path %s", path)
	return ""
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeCounterStub(t *testing.T, path, counterEnvironment string, fail bool) {
	t.Helper()
	exitStatus := "0"
	if fail {
		exitStatus = "1"
	}
	writeExecutable(t, path, `#!/bin/sh
counter_file="${`+counterEnvironment+`:?}"
count=0
if [ -f "$counter_file" ]; then
  count="$(cat "$counter_file")"
fi
echo $((count + 1)) > "$counter_file"
exit `+exitStatus+`
`)
}

func readCounter(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustDocument(t *testing.T, data string) document {
	t.Helper()
	var doc document
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("decode cloud-init document: %v", err)
	}
	return doc
}

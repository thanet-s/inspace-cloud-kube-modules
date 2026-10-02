package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hostSandbox rewrites the absolute host paths used by a rendered snippet to a
// temporary directory and stubs usermod, so the snippet's real shell logic runs
// without touching the test machine.
type hostSandbox struct {
	t    *testing.T
	root string
}

func newHostSandbox(t *testing.T, osRelease, passwd string) *hostSandbox {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc/default", "etc/apt/sources.list.d", "var/lib/inspace", "bin", "stub"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", osRelease, 0o644)
	write("etc/passwd", passwd, 0o644)
	write("etc/adduser.conf", "# adduser defaults\nDSHELL=/bin/sh\n", 0o644)
	write("bin/bash", "#!/bin/sh\n", 0o755)
	write("var/lib/inspace/ubuntu.sources", ubuntuAPTSourcesTemplate, 0o644)
	// usermod --shell SHELL ACCOUNT rewrites field 7 of the sandbox passwd.
	write("stub/usermod", `#!/bin/sh
set -eu
[ "$1" = --shell ]
awk -F: -v OFS=: -v shell="$2" -v account="$3" '$1 == account { $7 = shell } { print }' "$SANDBOX/etc/passwd" >"$SANDBOX/etc/passwd.new"
mv "$SANDBOX/etc/passwd.new" "$SANDBOX/etc/passwd"
`, 0o755)
	return &hostSandbox{t: t, root: root}
}

func (s *hostSandbox) run(script string) (string, error) {
	s.t.Helper()
	for _, path := range []string{
		"/etc/os-release", "/etc/passwd", "/etc/default/useradd", "/etc/adduser.conf",
		"/etc/apt/sources.list.d/ubuntu.sources", "/var/lib/inspace/ubuntu.sources",
	} {
		for _, prefix := range []string{" ", ">", "'", `"`} {
			script = strings.ReplaceAll(script, prefix+path, prefix+s.root+path)
		}
	}
	// /bin/bash is also the shell value written to passwd and defaults, so only
	// its existence check is redirected.
	script = strings.ReplaceAll(script, "test -x /bin/bash", "test -x "+s.root+"/bin/bash")
	command := exec.Command("sh", "-c", "set -eu\n"+script)
	command.Env = append(os.Environ(), "PATH="+filepath.Join(s.root, "stub")+":"+os.Getenv("PATH"), "SANDBOX="+s.root)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (s *hostSandbox) read(path string) string {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.root, path))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(data)
}

const sandboxPasswd = `root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ubuntu:x:1000:1000::/home/ubuntu:/bin/sh
operator:x:1001:1001::/home/operator:/usr/bin/dash
alice:x:1002:1002::/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
`

func TestUbuntuSourcesTemplateHasNoHardcodedRelease(t *testing.T) {
	if strings.Contains(ubuntuAPTSourcesTemplate, "noble") || strings.Contains(ubuntuAPTSourcesTemplate, "resolute") {
		t.Fatalf("Ubuntu sources hardcode a release codename:\n%s", ubuntuAPTSourcesTemplate)
	}
	if got := strings.Count(ubuntuAPTSourcesTemplate, "@UBUNTU_CODENAME@"); got != 4 {
		t.Fatalf("Ubuntu sources contain %d codename placeholders, want 4", got)
	}
}

func TestUbuntuSourcesFollowTheBootedRelease(t *testing.T) {
	for _, codename := range []string{"noble", "resolute"} {
		t.Run(codename, func(t *testing.T) {
			sandbox := newHostSandbox(t, "VERSION_CODENAME="+codename+"\n", sandboxPasswd)
			if output, err := sandbox.run(ubuntuSourcesInstallCommands()); err != nil {
				t.Fatalf("sources install failed: %v\n%s", err, output)
			}
			sources := sandbox.read("etc/apt/sources.list.d/ubuntu.sources")
			for _, want := range []string{
				"Suites: " + codename + " " + codename + "-updates " + codename + "-backports",
				"Suites: " + codename + "-security",
			} {
				if !strings.Contains(sources, want) {
					t.Fatalf("installed sources lack %q:\n%s", want, sources)
				}
			}
			if strings.Contains(sources, "@UBUNTU_CODENAME@") {
				t.Fatalf("installed sources kept a placeholder:\n%s", sources)
			}
		})
	}
}

func TestUbuntuSourcesRejectUnsupportedRelease(t *testing.T) {
	sandbox := newHostSandbox(t, "VERSION_CODENAME=jammy\n", sandboxPasswd)
	output, err := sandbox.run(ubuntuSourcesInstallCommands())
	if err == nil || !strings.Contains(output, "unsupported Ubuntu release") {
		t.Fatalf("jammy sources install err=%v output=%q, want unsupported-release failure", err, output)
	}
}

func TestBashBecomesTheLoginShellForInteractiveAccounts(t *testing.T) {
	sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
	if output, err := sandbox.run(bashLoginShellCommands()); err != nil {
		t.Fatalf("login shell setup failed: %v\n%s", err, output)
	}
	shells := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(sandbox.read("etc/passwd")), "\n") {
		fields := strings.Split(line, ":")
		shells[fields[0]] = fields[6]
	}
	for account, want := range map[string]string{
		"root": "/bin/bash", "ubuntu": "/bin/bash", "operator": "/bin/bash", "alice": "/bin/bash",
		"daemon": "/usr/sbin/nologin", "nobody": "/bin/sh",
	} {
		if shells[account] != want {
			t.Errorf("%s shell = %q, want %q", account, shells[account], want)
		}
	}
	if got := sandbox.read("etc/default/useradd"); !strings.Contains(got, "SHELL=/bin/bash\n") {
		t.Errorf("useradd default shell not bash:\n%s", got)
	}
	if got := sandbox.read("etc/adduser.conf"); !strings.Contains(got, "DSHELL=/bin/bash\n") || strings.Contains(got, "DSHELL=/bin/sh") {
		t.Errorf("adduser default shell not bash:\n%s", got)
	}
	// Re-running is idempotent.
	if output, err := sandbox.run(bashLoginShellCommands()); err != nil {
		t.Fatalf("second login shell setup failed: %v\n%s", err, output)
	}
}

// stub replaces a sandbox command with a script that runs before the real one.
func (s *hostSandbox) stub(name, body string) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.root, "stub", name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		s.t.Fatal(err)
	}
}

// The snippets are embedded mid-script, so a failed postcondition must stop
// the whole script under set -e rather than only set the snippet's status.
const continuationMarker = "\necho continued-after-failed-postcondition\n"

func TestUbuntuSourcesPostconditionStopsTheScript(t *testing.T) {
	sandbox := newHostSandbox(t, "VERSION_CODENAME=noble\n", sandboxPasswd)
	// A sed that copies its input verbatim leaves every placeholder behind.
	sandbox.stub("sed", "shift\nexec cat \"$@\"\n")
	output, err := sandbox.run(ubuntuSourcesInstallCommands() + continuationMarker)
	if err == nil || strings.Contains(output, "continued-after-failed-postcondition") {
		t.Fatalf("sources install with a surviving placeholder err=%v output=%q, want the script to stop", err, output)
	}
}

func TestBashLoginShellPostconditionStopsTheScript(t *testing.T) {
	sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
	// A usermod that reports success without changing passwd leaves sh logins.
	sandbox.stub("usermod", "exit 0\n")
	output, err := sandbox.run(bashLoginShellCommands() + continuationMarker)
	if err == nil || strings.Contains(output, "continued-after-failed-postcondition") {
		t.Fatalf("login shell setup with unchanged sh logins err=%v output=%q, want the script to stop", err, output)
	}
}

func TestWorkerHostScriptsHaveNoNegatedAssertions(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.36.5+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	scripts := []string{ubuntuSourcesInstallCommands(), bashLoginShellCommands()}
	for _, file := range doc.WriteFiles {
		content, err := decodeWriteFile(file)
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, content)
	}
	// set -e ignores the status of a command negated with !, so such a line
	// can never fail the script it guards.
	for _, script := range scripts {
		for _, line := range strings.Split(script, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "! ") {
				t.Errorf("script asserts with a negated command that set -e ignores: %q", line)
			}
		}
	}
}

func TestWorkerHostPreparationSetsUbuntuSourcesAndBashLoginShell(t *testing.T) {
	data, err := RenderCloudInit(Config{
		NodeName: "worker-1", Server: "https://10.0.0.10:9345", Token: "secret-token",
		RKE2Version: "v1.36.5+rke2r1",
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := mustDocument(t, data)
	prepare := writeFileContent(t, doc, "/usr/local/sbin/inspace-prepare-kubernetes-node")
	for _, want := range []string{ubuntuSourcesInstallCommands(), bashLoginShellCommands()} {
		if !strings.Contains(prepare, strings.TrimSpace(want)) {
			t.Errorf("worker host preparation lacks:\n%s", want)
		}
	}
	if strings.Contains(prepare, "install -m 0644 /var/lib/inspace/ubuntu.sources") {
		t.Error("worker host preparation still installs the sources template verbatim")
	}
	if got := writeFileContent(t, doc, "/var/lib/inspace/ubuntu.sources"); got != ubuntuAPTSourcesTemplate {
		t.Errorf("worker sources template differs:\n%s", got)
	}
}

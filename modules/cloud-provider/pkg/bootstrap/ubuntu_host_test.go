package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostSandbox rewrites the absolute host paths used by a rendered snippet to a
// temporary directory and stubs usermod, so the snippet's real shell logic runs
// without touching the test machine.
type hostSandbox struct {
	t    *testing.T
	root string
	env  []string
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
	write("var/lib/inspace/ubuntu.sources", ubuntuAPTSourcesConfig, 0o644)
	write("var/lib/inspace/static-resolv.conf", staticGoogleResolverConfig, 0o644)
	// systemctl reports systemd-resolved masked, and active only when the test
	// sets SANDBOX_RESOLVED_ACTIVE=1.
	write("stub/systemctl", `#!/bin/sh
case "$1" in
  is-enabled) echo masked ;;
  is-active) [ "${SANDBOX_RESOLVED_ACTIVE:-0}" = 1 ] ;;
esac
`, 0o755)
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
		"/etc/resolv.conf", "/var/lib/inspace/static-resolv.conf",
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
	command.Env = append(command.Env, s.env...)
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
	if strings.Contains(ubuntuAPTSourcesConfig, "noble") || strings.Contains(ubuntuAPTSourcesConfig, "resolute") {
		t.Fatalf("Ubuntu sources hardcode a release codename:\n%s", ubuntuAPTSourcesConfig)
	}
	if got := strings.Count(ubuntuAPTSourcesConfig, "@UBUNTU_CODENAME@"); got != 4 {
		t.Fatalf("Ubuntu sources contain %d codename placeholders, want 4", got)
	}
}

func TestUbuntuSourcesFollowTheBootedRelease(t *testing.T) {
	for _, codename := range []string{"noble", "resolute"} {
		t.Run(codename, func(t *testing.T) {
			sandbox := newHostSandbox(t, "VERSION_CODENAME="+codename+"\n", sandboxPasswd)
			if output, err := sandbox.run(renderUbuntuSourcesInstallCommands()); err != nil {
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
	output, err := sandbox.run(renderUbuntuSourcesInstallCommands())
	if err == nil || !strings.Contains(output, "unsupported Ubuntu release") {
		t.Fatalf("jammy sources install err=%v output=%q, want unsupported-release failure", err, output)
	}
}

func TestBashBecomesTheLoginShellForInteractiveAccounts(t *testing.T) {
	sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
	if output, err := sandbox.run(renderBashLoginShellCommands()); err != nil {
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
	if output, err := sandbox.run(renderBashLoginShellCommands()); err != nil {
		t.Fatalf("second login shell setup failed: %v\n%s", err, output)
	}
}

func TestEveryBootstrapScriptSetsUbuntuSourcesAndBashLoginShell(t *testing.T) {
	scripts := map[string]string{}
	controlPlane, err := RenderCloudInitJSON(CloudInitInput{
		NodeName: "cp-1", NodeExternalIPv4: "203.0.113.11", PrivateSubnet: "10.20.30.0/24", VirtualIPv4: "10.20.30.10",
		RKE2Version: "v1.36.4+rke2r1", RKE2Token: "token", ServerAddress: "10.20.30.10",
		PodCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
		PrivateLoadBalancerPoolStart: "10.20.30.200", PrivateLoadBalancerPoolStop: "10.20.30.239",
		TLSSubjectAltNames: []string{"10.20.30.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scripts["control-plane"] = decodeWriteFiles(t, controlPlane)["/usr/local/sbin/inspace-bootstrap-rke2"]
	bastion, err := RenderBastionCloudInitJSON("unit-bastion")
	if err != nil {
		t.Fatal(err)
	}
	scripts["bastion"] = decodeWriteFiles(t, bastion)["/usr/local/sbin/inspace-bootstrap-bastion"]
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS([]byte("0123456789abcdef0123456789abcdef"), "default/unit:4d7ca80d", hostname, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cacheBastion, err := RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
		NodeName: "unit-bastion", PrivateSubnet: "10.20.30.0/24", CacheHostname: hostname,
		RKE2Version: bootstrapCacheRKE2Version, ModuleVersion: "0.3.1-rc.2",
		CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	scripts["cache-bastion"] = decodeWriteFiles(t, cacheBastion)["/usr/local/sbin/inspace-bootstrap-cache-bastion"]
	for name, script := range scripts {
		if script == "" {
			t.Fatalf("%s bootstrap script missing", name)
		}
		for _, want := range []string{renderUbuntuSourcesInstallCommands(), renderBashLoginShellCommands()} {
			if !strings.Contains(script, strings.TrimSpace(want)) {
				t.Errorf("%s bootstrap script lacks:\n%s", name, want)
			}
		}
		if strings.Contains(script, "install -m 0644 /var/lib/inspace/ubuntu.sources") {
			t.Errorf("%s bootstrap script still installs the sources template verbatim", name)
		}
	}
}

func (s *hostSandbox) stub(name, content string) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.root, "stub", name), []byte(content), 0o755); err != nil {
		s.t.Fatal(err)
	}
}

// renderedStaticResolverCommands extracts the exact rendered static-resolver
// block (from removing /etc/resolv.conf through the systemd-resolved checks).
func renderedStaticResolverCommands(t *testing.T) string {
	t.Helper()
	rendered := renderUbuntuRepositoryAndResolverCommands("unit-bastion")
	start := strings.Index(rendered, "rm -f /etc/resolv.conf\n")
	end := strings.Index(rendered, "grep -Fqx 'http://mirror1.totbb.net/ubuntu/")
	if start < 0 || end <= start {
		t.Fatalf("static resolver block not found in:\n%s", rendered)
	}
	return rendered[start:end]
}

// POSIX shells never apply set -e to a command prefixed with "!", so every
// negative host assertion must fail the script explicitly. Each case forces
// the asserted condition to be violated and requires that the rendered
// snippet stops the script: the command after it (as in the real bootstrap
// script, where more setup always follows) must never run.
func TestNegativeHostAssertionsFailTheBootstrapScript(t *testing.T) {
	const continued = "echo bootstrap-continued-after-assertion\n"
	requireStopped := func(t *testing.T, output string, err error, message string) {
		t.Helper()
		if err == nil || strings.Contains(output, "bootstrap-continued-after-assertion") || !strings.Contains(output, message) {
			t.Fatalf("violated assertion did not stop the script: err=%v output=%q, want %q", err, output, message)
		}
	}
	t.Run("leftover Ubuntu codename placeholder", func(t *testing.T) {
		sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
		// A sed that copies its input unchanged leaves every placeholder.
		sandbox.stub("sed", "#!/bin/sh\nshift\ncat \"$@\"\n")
		output, err := sandbox.run(renderUbuntuSourcesInstallCommands() + continued)
		requireStopped(t, output, err, "@UBUNTU_CODENAME@ placeholder")
	})
	t.Run("sh login shell left behind", func(t *testing.T) {
		sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
		// A usermod that changes nothing leaves /bin/sh and dash accounts.
		sandbox.stub("usermod", "#!/bin/sh\nexit 0\n")
		output, err := sandbox.run(renderBashLoginShellCommands() + continued)
		requireStopped(t, output, err, "still uses /bin/sh or dash")
	})
	t.Run("systemd-resolved still active", func(t *testing.T) {
		sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
		sandbox.env = []string{"SANDBOX_RESOLVED_ACTIVE=1"}
		output, err := sandbox.run(renderedStaticResolverCommands(t) + continued)
		requireStopped(t, output, err, "systemd-resolved.service is still active")
	})
	t.Run("systemd-resolved inactive", func(t *testing.T) {
		sandbox := newHostSandbox(t, "VERSION_CODENAME=resolute\n", sandboxPasswd)
		if output, err := sandbox.run(renderedStaticResolverCommands(t)); err != nil {
			t.Fatalf("static resolver setup failed: %v\n%s", err, output)
		}
		if got := sandbox.read("etc/resolv.conf"); got != staticGoogleResolverConfig {
			t.Fatalf("static resolver file = %q", got)
		}
	})
}

func TestBootstrapScriptsHaveNoBangPrefixedAssertions(t *testing.T) {
	hostname := "cache.unit.inspace.internal"
	material, err := deriveCacheTLS([]byte("0123456789abcdef0123456789abcdef"), "default/unit:4d7ca80d", hostname, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cachedControlPlane := cacheContractControlPlaneInput()
	cachedControlPlane.BootstrapCache = &NodeCacheConfig{Address: "10.20.30.21", Hostname: hostname, CABundle: material.CACertificate}
	rendered := map[string]func() (string, error){
		"control-plane":        func() (string, error) { return RenderCloudInitJSON(cacheContractControlPlaneInput()) },
		"cached control-plane": func() (string, error) { return RenderCloudInitJSON(cachedControlPlane) },
		"bastion":              func() (string, error) { return RenderBastionCloudInitJSON("unit-bastion") },
		"cache-bastion": func() (string, error) {
			return RenderCacheBastionCloudInitJSON(CacheBastionCloudInitInput{
				NodeName: "unit-bastion", PrivateSubnet: "10.20.30.0/24", CacheHostname: hostname,
				RKE2Version: bootstrapCacheRKE2Version, ModuleVersion: "0.3.1-rc.2",
				CACertificate: material.CACertificate, ServerCertificate: material.ServerCertificate, ServerPrivateKey: material.ServerPrivateKey,
			})
		},
	}
	for name, render := range rendered {
		raw, err := render()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for path, content := range decodeWriteFiles(t, raw) {
			for number, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "! ") {
					t.Errorf("%s %s line %d is a \"!\" assertion that set -e ignores: %q", name, path, number+1, line)
				}
			}
		}
	}
}

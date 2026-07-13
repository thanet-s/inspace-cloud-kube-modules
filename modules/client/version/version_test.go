package version

import "testing"

func TestUserAgentIncludesBuildVersion(t *testing.T) {
	previous := Version
	Version = "0.2.0-test"
	t.Cleanup(func() { Version = previous })

	if got, want := UserAgent("inspace-test"), "inspace-test/0.2.0-test"; got != want {
		t.Fatalf("UserAgent() = %q, want %q", got, want)
	}
}

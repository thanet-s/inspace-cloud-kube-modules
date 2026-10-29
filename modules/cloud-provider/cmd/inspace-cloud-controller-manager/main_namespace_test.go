package main

import "testing"

func TestParseCCMNamespaceEnv(t *testing.T) {
	const name = "INSPACE_CCM_NAMESPACE"
	for _, test := range []struct{ value, want string }{
		{value: " kube-system ", want: "kube-system"},
		{value: "inspace", want: "inspace"},
		{value: "   ", want: ""},
		{value: "", want: ""},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv(name, test.value)
			if got := parseCCMNamespace(); got != test.want {
				t.Fatalf("parseCCMNamespace() = %q, want %q", got, test.want)
			}
		})
	}
}

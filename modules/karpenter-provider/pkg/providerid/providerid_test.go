package providerid

import "testing"

func TestRoundTrip(t *testing.T) {
	want := ID{Location: "bkk01", VMUUID: "11111111-1111-4111-8111-111111111111"}
	value := New(want.Location, want.VMUUID)
	got, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if value != "inspace://bkk01/11111111-1111-4111-8111-111111111111" {
		t.Fatalf("unexpected provider ID %q", value)
	}
}

func TestRejectsMalformedProviderID(t *testing.T) {
	for _, value := range []string{"", "aws://bkk01/id", "inspace:///id", "inspace://bkk01/a/b"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}

package providerid

import "testing"

func TestRoundTrip(t *testing.T) {
	value, err := New("bkk01", "AAC7DD66-F390-4EDD-80C0-DD7CAE49BD99")
	if err != nil {
		t.Fatal(err)
	}
	if value != "inspace://bkk01/aac7dd66-f390-4edd-80c0-dd7cae49bd99" {
		t.Fatalf("New() = %q", value)
	}
	id, err := Parse(value)
	if err != nil || id.Location != "bkk01" || id.String() != value {
		t.Fatalf("Parse() = %#v, %v", id, err)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, value := range []string{"aws://bkk01/id", "inspace://bkk01/not-a-uuid", "inspace://BKK01/aac7dd66-f390-4edd-80c0-dd7cae49bd99"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}

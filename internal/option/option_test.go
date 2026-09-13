package option

import "testing"

func TestFirstString(t *testing.T) {
	if got := FirstString(nil); got != "" {
		t.Fatalf("FirstString(nil) = %q", got)
	}
	if got := FirstString([]string{"first", "second"}); got != "first" {
		t.Fatalf("FirstString(...) = %q", got)
	}
}

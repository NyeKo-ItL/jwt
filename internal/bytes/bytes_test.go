package bytes

import "testing"

func TestLeftPad(t *testing.T) {
	if got := LeftPad([]byte{1, 2, 3}, 2); len(got) != 3 {
		t.Fatalf("no-op path: len = %d, want 3", len(got))
	}

	got := LeftPad([]byte{9}, 4)
	if len(got) != 4 || got[0] != 0 || got[3] != 9 {
		t.Fatalf("pad path: %v", got)
	}
}

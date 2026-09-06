package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAudienceMarshal(t *testing.T) {
	cases := []struct {
		in   Audience
		want string
	}{
		{Audience{"one"}, `"one"`},
		{Audience{"a", "b"}, `["a","b"]`},
		{Audience{}, `[]`},
	}
	for _, c := range cases {
		got, err := json.Marshal(c.in)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", c.in, err)
		}
		if string(got) != c.want {
			t.Fatalf("Marshal(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestAudienceUnmarshal(t *testing.T) {
	cases := []struct {
		in      string
		want    Audience
		wantErr bool
	}{
		{`"x"`, Audience{"x"}, false},
		{`["x","y"]`, Audience{"x", "y"}, false},
		{`  "x"  `, Audience{"x"}, false},
		{`null`, nil, false},
		{``, nil, false},
		{`123`, nil, true},
		{`[1,2]`, nil, true},
		{`{`, nil, true},
	}
	for _, c := range cases {
		var got Audience
		err := got.UnmarshalJSON([]byte(c.in))
		if c.wantErr {
			if err == nil {
				t.Fatalf("UnmarshalJSON(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("UnmarshalJSON(%q): %v", c.in, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("UnmarshalJSON(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("UnmarshalJSON(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestAudienceHas(t *testing.T) {
	a := Audience{"a", "b"}
	if !a.Has("a") || !a.Has("b") {
		t.Fatal("Has missed a present value")
	}
	if a.Has("c") {
		t.Fatal("Has reported an absent value")
	}
}

func TestNumericDateMarshal(t *testing.T) {
	n := NewNumericDate(time.Unix(1609459200, 0))
	got, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1609459200" {
		t.Fatalf("Marshal = %s, want 1609459200", got)
	}
}

func TestNumericDateUnmarshal(t *testing.T) {
	cases := []struct {
		in       string
		wantUnix int64
		wantErr  bool
		noChange bool
	}{
		{`1609459200`, 1609459200, false, false},
		{`"1609459200"`, 1609459200, false, false},
		{`1609459200.0`, 1609459200, false, false},
		{`null`, 0, false, true},
		{``, 0, false, true},
		{`"abc"`, 0, true, false},
		{`true`, 0, true, false},
	}
	for _, c := range cases {
		var n NumericDate
		err := n.UnmarshalJSON([]byte(c.in))
		if c.wantErr {
			if err == nil {
				t.Fatalf("UnmarshalJSON(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("UnmarshalJSON(%q): %v", c.in, err)
		}
		if c.noChange {
			if !n.Time.IsZero() {
				t.Fatalf("UnmarshalJSON(%q) changed a zero value to %v", c.in, n.Time)
			}
			continue
		}
		if n.Time.Unix() != c.wantUnix {
			t.Fatalf("UnmarshalJSON(%q) = %d, want %d", c.in, n.Time.Unix(), c.wantUnix)
		}
	}
}

func TestNumericDateFractional(t *testing.T) {
	var n NumericDate
	if err := n.UnmarshalJSON([]byte("1.5")); err != nil {
		t.Fatal(err)
	}
	if n.Time.Nanosecond() != 500_000_000 {
		t.Fatalf("fractional seconds lost: %d ns", n.Time.Nanosecond())
	}
}

type demoCustom struct {
	Role  string `json:"role,omitempty"`
	Level int    `json:"level,omitempty"`
}

func TestClaimsFlattenRoundTrip(t *testing.T) {
	in := Claims[demoCustom]{
		RegisteredClaims: RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "subject",
			Audience:  Audience{"a", "b"},
			ExpiresAt: NewNumericDate(time.Unix(2000, 0)),
			ID:        "jti-1",
		},
		Custom: demoCustom{Role: "admin", Level: 3},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(raw, &flat); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"iss", "sub", "aud", "exp", "jti", "role", "level"} {
		if _, ok := flat[key]; !ok {
			t.Fatalf("flattened object missing %q: %s", key, raw)
		}
	}
	if flat["role"] != "admin" || flat["iss"] != "issuer" {
		t.Fatalf("unexpected flattened values: %s", raw)
	}

	var out Claims[demoCustom]
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Issuer != in.Issuer || out.ID != in.ID || out.Custom != in.Custom {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
	if !out.ExpiresAt.Time.Equal(in.ExpiresAt.Time) {
		t.Fatalf("exp round trip mismatch: %v vs %v", out.ExpiresAt, in.ExpiresAt)
	}
}

func TestClaimsRegisteredWinsOnConflict(t *testing.T) {
	type conflicting struct {
		Iss string `json:"iss"`
	}
	in := Claims[conflicting]{
		RegisteredClaims: RegisteredClaims{Issuer: "real"},
		Custom:           conflicting{Iss: "fake"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(raw, &flat); err != nil {
		t.Fatal(err)
	}
	if flat["iss"] != "real" {
		t.Fatalf("iss = %v, want registered value to win", flat["iss"])
	}
}

func TestClaimsMarshalErrorsOnBadCustom(t *testing.T) {
	// A channel cannot be JSON-marshaled.
	_, err := json.Marshal(Claims[chan int]{Custom: make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error for un-marshalable custom payload")
	}
}

func TestConfirmationJSON(t *testing.T) {
	rc := RegisteredClaims{Confirmation: &Confirmation{JWKThumbprint: "abc"}}
	raw, err := json.Marshal(rc)
	if err != nil {
		t.Fatal(err)
	}
	var out RegisteredClaims
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Confirmation == nil || out.Confirmation.JWKThumbprint != "abc" {
		t.Fatalf("cnf round trip failed: %s", raw)
	}
}

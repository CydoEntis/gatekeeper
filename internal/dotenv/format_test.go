package dotenv

import (
	"bytes"
	"fmt"
	"testing"
)

// TestMarshalRoundTrips is the property that makes export-then-import safe: every
// value that goes out must come back byte-for-byte.
func TestMarshalRoundTrips(t *testing.T) {
	values := []string{
		"simple",
		"",
		"a b",
		"  padded  ",
		"it's",
		`say "hi"`,
		`back\slash`,
		"line1\nline2",
		"tab\there",
		"carriage\rreturn",
		"$HOME",
		"${VAR}",
		"$(command)",
		"`backticks`",
		"pass#word",
		"#leading",
		"trailing #",
		"emoji 🔐",
		"café",
		"a=b",
		"-",
		"123",
		"postgres://u:p@h:5432/db?sslmode=require",
		"-----BEGIN KEY-----\nAAAA\n-----END KEY-----",
	}

	pairs := make([]Pair, 0, len(values))
	for i, v := range values {
		pairs = append(pairs, Pair{Key: fmt.Sprintf("K%02d", i), Value: v})
	}

	data := Marshal(pairs)

	got, err := Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("re-parsing marshalled output failed: %v\n--- file ---\n%s", err, data)
	}
	if len(got) != len(pairs) {
		t.Fatalf("round trip produced %d pairs, want %d\n--- file ---\n%s", len(got), len(pairs), data)
	}

	back := make(map[string]string, len(got))
	for _, p := range got {
		back[p.Key] = p.Value
	}
	for _, p := range pairs {
		if back[p.Key] != p.Value {
			t.Errorf("%s round-tripped to %q, want %q\n--- file ---\n%s",
				p.Key, back[p.Key], p.Value, data)
		}
	}
}

// TestMarshalSortsKeys keeps exported files stable and diffable.
func TestMarshalSortsKeys(t *testing.T) {
	got := string(Marshal([]Pair{{Key: "B", Value: "2"}, {Key: "A", Value: "1"}, {Key: "C", Value: "3"}}))
	want := "A=1\nB=2\nC=3\n"
	if got != want {
		t.Errorf("Marshal = %q, want %q", got, want)
	}
}

func TestMarshalEmptyValueIsQuoted(t *testing.T) {
	// A bare `KEY=` and `KEY=""` both parse to the empty string, but quoting makes
	// the intent visible to a human reading the file.
	if got := string(Marshal([]Pair{{Key: "A"}})); got != "A=\"\"\n" {
		t.Errorf("Marshal = %q, want %q", got, "A=\"\"\n")
	}
}

// TestQuoteEscapesDollarSigns documents a deliberate choice: exported files are
// safe to hand to other dotenv tooling that *does* expand variables.
func TestQuoteEscapesDollarSigns(t *testing.T) {
	if got := Quote("$HOME"); got != `"\$HOME"` {
		t.Errorf("Quote($HOME) = %q, want %q", got, `"\$HOME"`)
	}
	// And it still round-trips through our own parser.
	pairs, err := Parse(bytes.NewReader(Marshal([]Pair{{Key: "A", Value: "$HOME"}})))
	if err != nil {
		t.Fatal(err)
	}
	if pairs[0].Value != "$HOME" {
		t.Errorf("value = %q, want $HOME", pairs[0].Value)
	}
}

func TestQuoteLeavesSafeValuesAlone(t *testing.T) {
	for _, v := range []string{"simple", "postgres://u:p@h/db", "123", "-", "a_b-c.d", "café"} {
		if got := Quote(v); got != v {
			t.Errorf("Quote(%q) = %q, want it unchanged", v, got)
		}
	}
}

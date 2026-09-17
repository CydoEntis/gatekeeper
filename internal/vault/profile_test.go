package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestInvalidUTF8IsRefusedNotRewritten is the regression test for a bug the
// round-trip fuzzer found within seconds of being run.
//
// encoding/json does not reject invalid UTF-8; it replaces each bad byte with the
// Unicode replacement character. So a value containing one byte that is not valid
// UTF-8 — which is what a Windows-1252 `.env` produces for an accented
// character — was accepted, stored, and returned *different*. A credential that
// quietly changes is worse than one that is refused, because nothing tells you.
func TestInvalidUTF8IsRefusedNotRewritten(t *testing.T) {
	profile := Profile{
		Format:    FormatVersion,
		Name:      "demo",
		Revision:  1,
		Variables: map[string]string{"PASSWORD": "pa\x86ss"},
	}

	err := profile.Validate()
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err = %v, want ErrInvalidValue", err)
	}
	// The message has to name the likely cause, or the user has no idea what to do.
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("the error does not explain the problem: %v", err)
	}
	if !strings.Contains(err.Error(), "PASSWORD") {
		t.Errorf("the error does not name the variable: %v", err)
	}

	// And the value really is what would have been rewritten.
	if rewritten := string([]byte("pa\x86ss")); !strings.Contains(rewritten, "\uFFFD") {
		encoded, marshalErr := encodeProfile(Profile{
			Format: FormatVersion, Name: "demo", Revision: 1,
			Variables: map[string]string{"PASSWORD": "pa\x86ss"},
		})
		if marshalErr == nil && bytes.Contains(encoded, []byte("\x86")) {
			t.Error("the bad byte survived encoding, so this test proves nothing")
		}
	}
}

// TestValidUTF8IsStillAccepted keeps the new rule from becoming over-broad.
func TestValidUTF8IsStillAccepted(t *testing.T) {
	for _, value := range []string{"plain", "café", "🔐", "日本語", "emoji and accents: 🔐 café"} {
		profile := Profile{
			Format:    FormatVersion,
			Name:      "demo",
			Revision:  1,
			Variables: map[string]string{"V": value},
		}
		if err := profile.Validate(); err != nil {
			t.Errorf("valid UTF-8 %q was refused: %v", value, err)
		}
	}
}

// FuzzDecodeProfile exercises the decoder that reads attacker-influenced bytes.
//
// A profile is decrypted ciphertext, which is to say bytes this project did not
// write: a tampered vault, a hand-edited file, or a profile produced by a future
// version. The decoder must survive all of it.
//
// The invariant is narrow and absolute: **DecodeProfile never panics**. Any error
// is an acceptable outcome, because the decoder is allowed to refuse anything it
// does not understand. A panic is not.
//
// Run the seed corpus as an ordinary test, or fuzz for a while:
//
//	go test ./internal/vault/ -run Fuzz
//	go test ./internal/vault/ -fuzz FuzzDecodeProfile -fuzztime 30s
func FuzzDecodeProfile(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"format":1}`,
		`{"format":1,"name":"demo","variables":{}}`,
		`{"format":1,"name":"demo","variables":{"A":"1"}}`,
		`{"format":2,"name":"demo","variables":{}}`,
		`{"format":1,"name":"demo","variables":{"A":"1","A":"2"}}`,
		`{"format":1,"name":"demo","variables":{"1BAD":"x"}}`,
		`{"format":1,"name":"demo","variables":{"A":"a\u0000b"}}`,
		`{"format":1,"name":"../escape","variables":{}}`,
		`{"format":1,"name":"demo","unknown":true}`,
		`{"format":1,"name":"demo","variables":{}}{"format":1}`,
		`{"format":1,"flags":{"A":{"note":"n","at":"2026-09-17T00:00:00Z"}}}`,
		`[1,2,3]`,
		`null`,
		"\x00\xff\xfe",
		"",
		strings.Repeat("[", 4096),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		profile, err := DecodeProfile(bytes.NewReader(raw))
		if err != nil {
			// Refusing is a valid outcome. What matters is *how* it refused: an
			// error must never be accompanied by a half-decoded profile, because
			// a caller that ignored the error would then act on invented data.
			if profile.Name != "" || len(profile.Variables) != 0 {
				t.Fatalf("returned a profile alongside an error: %+v (err %v)", profile, err)
			}
			return
		}

		// Anything that decoded must also pass validation, since the decoder
		// promises to enforce the rules rather than returning them for checking.
		if err := profile.Validate(); err != nil {
			t.Fatalf("decoded a profile that fails validation: %v", err)
		}

		// And a decoded profile must be safe to inspect without panicking.
		_ = profile.Summary()
	})
}

// FuzzRoundTrip is the property that makes export-then-import trustworthy.
//
// Anything the parser accepts must survive being written back out and read again,
// with every value unchanged. This catches the class of bug where a value parses
// one way and renders another — a secret that quietly comes back different, or
// not at all.
func FuzzRoundTrip(f *testing.F) {
	f.Add("A=1\n", "A")
	f.Add("A=\"a b\"\n", "A")
	f.Add("A=\"line1\\nline2\"\n", "A")
	f.Add("A=pass#word\n", "A")
	f.Add("A=\n", "A")

	f.Fuzz(func(t *testing.T, key, value string) {
		if !ValidVariableName(key) {
			t.Skip("not a valid variable name; nothing to round-trip")
		}

		original := Profile{
			Format:    FormatVersion,
			Name:      "demo",
			Revision:  1,
			Variables: map[string]string{key: value},
		}
		if err := original.Validate(); err != nil {
			// Values this project refuses (a NUL byte, say) are not round-trip
			// candidates; the refusal itself is covered elsewhere.
			t.Skip("value is rejected by validation; nothing to round-trip")
		}

		encoded, err := encodeProfile(original)
		if err != nil {
			t.Fatalf("marshalling a validated profile failed: %v", err)
		}

		decoded, err := DecodeProfile(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("re-decoding our own output failed: %v\n%q", err, encoded)
		}

		if got := decoded.Variables[key]; got != value {
			t.Fatalf("value changed in the round trip: %q became %q", value, got)
		}
	})
}

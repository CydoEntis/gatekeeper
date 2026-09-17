package envelope

import (
	"bytes"
	"errors"
	"testing"
)

const (
	// Deliberately not a real key length, so that a secret scanner — including
	// this project's own — cannot mistake the fixture for the real thing.
	boxSecret     = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ"
	boxPassphrase = "correct horse battery staple"
)

func TestPassphraseBoxRoundTrip(t *testing.T) {
	sealed, err := (PassphraseBox{}).Seal(boxPassphrase, boxSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The whole point: the plaintext must not survive sealing.
	if bytes.Contains(sealed, []byte(boxSecret)) {
		t.Fatal("sealed output contains the plaintext")
	}
	if bytes.Contains(sealed, []byte("AGE-SECRET-KEY")) {
		t.Fatal("sealed output contains the private key prefix")
	}

	// Armored, so it survives being pasted or copied by a text-mode tool.
	if !bytes.HasPrefix(sealed, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatalf("sealed output is not armored; got %q", firstLineOf(sealed))
	}

	got, err := (PassphraseBox{}).Open(boxPassphrase, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != boxSecret {
		t.Fatalf("open = %q, want %q", got, boxSecret)
	}
}

// TestPassphraseBoxSurvivesLineEndingConversion checks the reason the identity
// file is armored rather than binary.
//
// Git for Windows defaults to core.autocrlf=true, and plenty of other tools
// rewrite line endings. On raw ciphertext that silently corrupts the file; on
// armor it is harmless.
func TestPassphraseBoxSurvivesLineEndingConversion(t *testing.T) {
	sealed, err := (PassphraseBox{}).Seal(boxPassphrase, boxSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	crlf := bytes.ReplaceAll(sealed, []byte("\n"), []byte("\r\n"))
	if bytes.Equal(crlf, sealed) {
		t.Skip("no line endings to convert")
	}

	got, err := (PassphraseBox{}).Open(boxPassphrase, crlf)
	if err != nil {
		t.Fatalf("open after CRLF conversion: %v", err)
	}
	if got != boxSecret {
		t.Fatalf("open after CRLF conversion = %q, want %q", got, boxSecret)
	}
}

func TestPassphraseBoxRejectsWrongPassphrase(t *testing.T) {
	sealed, err := (PassphraseBox{}).Seal(boxPassphrase, boxSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, wrong := range []string{"wrong passphrase entirely", "", "correct horse battery stapl"} {
		if _, err := (PassphraseBox{}).Open(wrong, sealed); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("Open(%q) err = %v, want ErrWrongPassphrase", wrong, err)
		}
	}
}

func TestPassphraseBoxRejectsTamperedAndTruncatedInput(t *testing.T) {
	sealed, err := (PassphraseBox{}).Seal(boxPassphrase, boxSecret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Flip a bit inside the first line of base64, past the armor header.
	tampered := append([]byte(nil), sealed...)
	i := bytes.IndexByte(tampered, '\n') + 5
	tampered[i] ^= 0x01

	truncated := sealed[:len(sealed)/2]

	for name, input := range map[string][]byte{
		"tampered":  tampered,
		"truncated": truncated,
		"empty":     {},
		"garbage":   []byte("not an age file at all"),
	} {
		if _, err := (PassphraseBox{}).Open(boxPassphrase, input); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want ErrWrongPassphrase", name, err)
		}
	}
}

func TestPassphraseBoxRefusesToSealWithNoPassphrase(t *testing.T) {
	if _, err := (PassphraseBox{}).Seal("", boxSecret); err == nil {
		t.Fatal("sealed with an empty passphrase")
	}
}

func firstLineOf(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

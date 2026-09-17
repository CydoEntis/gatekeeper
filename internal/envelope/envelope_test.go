package envelope

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

// sealTo encrypts plaintext to a fresh identity and returns the ciphertext and
// the identity that can open it.
func sealTo(t *testing.T, plaintext []byte) ([]byte, age.Identity) {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return sealed.Bytes(), identity
}

func readAll(r io.Reader) error {
	_, err := io.ReadAll(r)
	return err
}

// TestDecryptEnforcesThePayloadLimit is the regression test for a limit that was
// documented but not applied.
//
// The old code wrapped the payload in io.LimitReader, whose whole behaviour is to
// truncate silently. An oversize profile therefore failed later, in the JSON
// decoder, with a message about an unterminated object and no hint that size was
// the problem. A limit that is not enforced is not a limit.
func TestDecryptEnforcesThePayloadLimit(t *testing.T) {
	plaintext := bytes.Repeat([]byte("A"), 4096)
	sealed, identity := sealTo(t, plaintext)

	err := Age{MaxPlaintext: 1024}.Decrypt(bytes.NewReader(sealed), []age.Identity{identity}, readAll)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Errorf("the error does not say what the limit was: %v", err)
	}
}

// TestDecryptAllowsAPayloadAtTheLimit checks the bound is not off by one in the
// direction that would reject a legitimate profile.
func TestDecryptAllowsAPayloadAtTheLimit(t *testing.T) {
	plaintext := bytes.Repeat([]byte("A"), 1024)
	sealed, identity := sealTo(t, plaintext)

	var got []byte
	err := Age{MaxPlaintext: 1024}.Decrypt(bytes.NewReader(sealed), []age.Identity{identity}, func(r io.Reader) error {
		var err error
		got, err = io.ReadAll(r)
		return err
	})
	if err != nil {
		t.Fatalf("a payload exactly at the limit was refused: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip returned %d bytes, want %d", len(got), len(plaintext))
	}
}

// TestDecryptUsesTheDefaultLimitWhenUnset checks the zero value means "use the
// default", not "no limit" — the dangerous reading.
func TestDecryptUsesTheDefaultLimitWhenUnset(t *testing.T) {
	plaintext := bytes.Repeat([]byte("A"), DefaultMaxPlaintext+10)
	sealed, identity := sealTo(t, plaintext)

	err := Age{}.Decrypt(bytes.NewReader(sealed), []age.Identity{identity}, readAll)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}

// TestDecryptRefusesWithNoIdentity keeps the fail-closed behaviour.
func TestDecryptRefusesWithNoIdentity(t *testing.T) {
	sealed, _ := sealTo(t, []byte("x"))

	if err := (Age{}).Decrypt(bytes.NewReader(sealed), nil, readAll); !errors.Is(err, ErrNotDecryptable) {
		t.Fatalf("err = %v, want ErrNotDecryptable", err)
	}
}

package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// ErrWrongPassphrase is returned when a sealed secret cannot be opened.
//
// Unlike ErrNotDecryptable, distinguishing this from corruption is acceptable
// here: there is exactly one passphrase for a local file, so the message tells
// an attacker nothing they could not learn by trying once.
var ErrWrongPassphrase = errors.New("wrong passphrase, or the sealed file is damaged")

// MaxSealedPlaintext bounds a sealed secret. A private identity is one short
// line, so anything larger is not one.
const MaxSealedPlaintext = 64 << 10

// PassphraseBox seals a small text secret under a passphrase.
//
// This is how the private identity is protected at rest. It is deliberately not
// part of Envelope: a passphrase is a different kind of recipient, and callers
// that only deal with profiles should not have to know it exists.
//
// The output is ASCII armored on purpose. The identity file is the one artifact
// a user may move by hand, paste into a password manager, or copy through a
// text-mode tool — and armor cannot be mangled by line-ending conversion the way
// raw ciphertext can. The standard `age -d` command reads it directly.
type PassphraseBox struct{}

// Seal encrypts plaintext under passphrase and returns an armored age file.
func (PassphraseBox) Seal(passphrase string, plaintext string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("refusing to seal with an empty passphrase")
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("prepare passphrase encryption: %w", err)
	}

	var buf bytes.Buffer
	armored := armor.NewWriter(&buf)

	w, err := age.Encrypt(armored, recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt sealed secret: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return nil, fmt.Errorf("encrypt sealed secret: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("encrypt sealed secret: %w", err)
	}
	// The armor writer is closed last: it emits the trailing footer, and closing
	// it earlier would truncate the file.
	if err := armored.Close(); err != nil {
		return nil, fmt.Errorf("armor sealed secret: %w", err)
	}
	return buf.Bytes(), nil
}

// Open decrypts a sealed secret.
//
// Every failure returns ErrWrongPassphrase. The upstream age error is dropped
// rather than wrapped, because a wrong passphrase and a corrupted file are not
// worth distinguishing to the caller and the upstream text can quote bytes.
func (PassphraseBox) Open(passphrase string, sealed []byte) (string, error) {
	if passphrase == "" {
		return "", ErrWrongPassphrase
	}

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return "", ErrWrongPassphrase
	}

	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(sealed)), identity)
	if err != nil {
		return "", ErrWrongPassphrase
	}

	plaintext, err := io.ReadAll(io.LimitReader(r, MaxSealedPlaintext+1))
	if err != nil {
		return "", ErrWrongPassphrase
	}
	if len(plaintext) > MaxSealedPlaintext {
		return "", fmt.Errorf("sealed secret is larger than %d bytes", MaxSealedPlaintext)
	}
	return strings.TrimSpace(string(plaintext)), nil
}

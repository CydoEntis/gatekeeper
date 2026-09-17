// Package envelope is the only place in Gatekeeper that knows how secrets are
// encrypted. Nothing above it sees a cipher, a nonce, a KDF, or a key format.
//
// There is deliberately no cryptography in this file: every primitive belongs
// to filippo.io/age. If you ever find yourself wanting to add a nonce or a
// "simple" scheme here, stop -- that is the bug.
package envelope

import (
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// ErrNotDecryptable is returned for every decryption failure.
//
// Wrong identity, truncated file, and tampered ciphertext are deliberately
// indistinguishable. The upstream age error can quote payload bytes, and
// telling an attacker *which* failure occurred is itself a leak.
var ErrNotDecryptable = errors.New("ciphertext is not decryptable by this identity")

// ErrBadIdentity is returned when a private key cannot be parsed. The upstream
// error is dropped rather than wrapped because it echoes the key material.
var ErrBadIdentity = errors.New("identity is not a valid age identity")

// ErrPayloadTooLarge reports a decrypted payload beyond the configured limit.
//
// Encrypted input is unbounded by nature, so the limit is what stops a hostile
// file from exhausting memory. Exceeding it is a failure, not a truncation.
var ErrPayloadTooLarge = errors.New("decrypted payload is larger than the limit")

// DefaultMaxPlaintext bounds how much a profile may expand to. A profile is
// kilobytes at most; the limit exists so a hostile file cannot exhaust memory.
const DefaultMaxPlaintext = 1 << 20 // 1 MiB

// Envelope is deliberately callback-shaped.
//
// A []byte API would quietly encourage callers to hold a second plaintext copy
// and to return it up the stack. This shape makes the plaintext lifetime
// obvious and confines it to the callback.
type Envelope interface {
	Encrypt(dst io.Writer, recipients []age.Recipient, writePlaintext func(io.Writer) error) error
	Decrypt(src io.Reader, identities []age.Identity, readPlaintext func(io.Reader) error) error
}

// Age is the real implementation.
type Age struct {
	MaxPlaintext int64
}

func (a Age) Encrypt(dst io.Writer, recipients []age.Recipient, writePlaintext func(io.Writer) error) error {
	// Fail closed. Encrypting to nobody would write a profile that no identity
	// on earth can open -- silent, permanent data loss.
	if len(recipients) == 0 {
		return errors.New("refusing to encrypt: no recipients")
	}

	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := writePlaintext(w); err != nil {
		return fmt.Errorf("encrypt plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return nil
}

func (a Age) Decrypt(src io.Reader, identities []age.Identity, readPlaintext func(io.Reader) error) error {
	if len(identities) == 0 {
		return ErrNotDecryptable
	}

	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return ErrNotDecryptable
	}

	max := a.MaxPlaintext
	if max <= 0 {
		max = DefaultMaxPlaintext
	}

	// A LimitedReader rather than a bare LimitReader, because the limit has to be
	// *enforced* and not merely applied. A LimitReader would hand the caller a
	// silently truncated payload, which then fails somewhere else with a message
	// about the wrong thing — an unterminated JSON object, say — and no hint that
	// the real problem was size.
	limited := &io.LimitedReader{R: r, N: max + 1}
	if err := readPlaintext(limited); err != nil {
		return err
	}
	if limited.N <= 0 {
		return fmt.Errorf("%w: more than %d bytes", ErrPayloadTooLarge, max)
	}
	return nil
}

// GenerateIdentity returns a fresh X25519 private key and its public recipient.
func GenerateIdentity() (private string, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("generate identity: %w", err)
	}
	return id.String(), id.Recipient().String(), nil
}

// ParseIdentity turns a private key string into a usable identity.
func ParseIdentity(s string) (age.Identity, error) {
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		// Not wrapped on purpose: see ErrBadIdentity.
		return nil, ErrBadIdentity
	}
	return id, nil
}

// ParseRecipient turns a public key string into a usable recipient.
//
// Public keys are not secret, so wrapping the upstream error is safe here and
// makes a typo'd key diagnosable.
func ParseRecipient(s string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("parse recipient: %w", err)
	}
	return r, nil
}

// RecipientOf derives the public recipient belonging to a private identity
// string.
//
// This exists so callers can recover the public half from a stored key without
// reaching into age's concrete types, and without the private half ever being
// returned alongside it.
func RecipientOf(private string) (string, error) {
	id, err := age.ParseX25519Identity(private)
	if err != nil {
		// Not wrapped, for the same reason as ParseIdentity.
		return "", ErrBadIdentity
	}
	return id.Recipient().String(), nil
}

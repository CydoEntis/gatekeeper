package vault

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"gatekeeper/internal/envelope"
	"gatekeeper/internal/platform"
)

// newTestVault returns a vault encrypted to a fresh throwaway identity, plus the
// directory it lives in.
//
// It builds the FileVault directly rather than through Open so these tests
// exercise the storage layer on its own, with no manifest or devices file in the
// way.
func newTestVault(t *testing.T) (*FileVault, string) {
	t.Helper()

	private, recipientText, err := envelope.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	recipient, err := envelope.ParseRecipient(recipientText)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	identity, err := envelope.ParseIdentity(private)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}

	dir := t.TempDir()
	return &FileVault{
		Dir:        dir,
		Envelope:   envelope.Age{},
		Recipients: []age.Recipient{recipient},
		Identities: []age.Identity{identity},
	}, dir
}

// TestUnauthorizedIdentityCannotReadAProfile is the property that makes the
// recipient model meaningful: holding the ciphertext is not enough.
//
// It is checked at the vault rather than the envelope because FileVault.Read is
// what a caller actually reaches, and it is the layer that maps a failure onto an
// error the CLI can act on.
func TestUnauthorizedIdentityCannotReadAProfile(t *testing.T) {
	ctx := context.Background()
	v, dir := newTestVault(t)

	if _, err := v.Create(ctx, "demo", map[string]string{"DEMO_SECRET": "value"}); err != nil {
		t.Fatalf("create profile: %v", err)
	}

	attackerPrivate, _, err := envelope.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate attacker identity: %v", err)
	}
	attacker, err := envelope.ParseIdentity(attackerPrivate)
	if err != nil {
		t.Fatalf("parse attacker identity: %v", err)
	}

	// Same directory, same ciphertext, different key: no read access.
	attackerVault := &FileVault{
		Dir:        dir,
		Envelope:   envelope.Age{},
		Identities: []age.Identity{attacker},
	}
	if _, err := attackerVault.Read(ctx, "demo"); !errors.Is(err, envelope.ErrNotDecryptable) {
		t.Fatalf("unauthorized read err = %v, want ErrNotDecryptable", err)
	}
}

// failingEnvelope always refuses to encrypt, which stops a write after the temp
// file has been created but before it is renamed into place.
//
// This is the only way to reach the cleanup path. On a *successful* write there
// is never a leftover regardless of whether the deferred removal runs, because
// ReplaceFile renames the temp file onto the destination. So a test that writes
// successfully and then looks for temp files cannot fail: it proves nothing.
type failingEnvelope struct{}

// errEncryptRefused is the injected failure. It is deliberately unexported:
// nothing outside this test should be able to construct this condition.
var errEncryptRefused = errors.New("encryption refused by test double")

func (failingEnvelope) Encrypt(_ io.Writer, _ []age.Recipient, _ func(io.Writer) error) error {
	return errEncryptRefused
}

func (failingEnvelope) Decrypt(_ io.Reader, _ []age.Identity, _ func(io.Reader) error) error {
	return envelope.ErrNotDecryptable
}

// TestAFailedWriteLeavesNoTemporaryFileBehind covers the cleanup half of the
// atomic write in writeAtomic.
//
// The temp file is removed by a deferred call, so a bug here leaks silently: the
// failure is reported correctly and the user retries, while the profiles
// directory slowly fills with orphaned ciphertext that nothing reads or deletes.
// Only a deliberate look at the directory catches it.
func TestAFailedWriteLeavesNoTemporaryFileBehind(t *testing.T) {
	ctx := context.Background()
	v, dir := newTestVault(t)
	v.Envelope = failingEnvelope{}

	_, err := v.Create(ctx, "demo", map[string]string{"DEMO_SECRET": "value"})
	if !errors.Is(err, errEncryptRefused) {
		t.Fatalf("err = %v, want the injected encryption failure", err)
	}

	profilesDir := filepath.Join(dir, ProfilesDir)
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		// The directory must still exist -- writeAtomic creates it before it can
		// fail -- so a read error here is a real problem, not an acceptable
		// "nothing was written" outcome.
		t.Fatalf("read profiles directory: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), platform.TempFilePrefix) {
			t.Errorf("temporary file left behind after a failed write: %s", e.Name())
		}
	}
	// A failed create must not leave a profile behind either.
	if len(entries) != 0 {
		t.Errorf("failed write left %d entries in the profiles directory", len(entries))
	}
}

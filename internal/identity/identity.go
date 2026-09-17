// Package identity owns key generation, local identity storage, and the rules
// that protect a private key.
//
// Two properties matter more than anything else here:
//
//  1. A private identity is written to the per-user configuration directory,
//     never inside a vault. If a key ever lands in a synchronized directory,
//     every encrypted file in it -- including every revision in its history --
//     becomes readable.
//  2. The identity file is encrypted at rest under a passphrase. That is what
//     replaces full-disk encryption, and it is also what protects the key if the
//     key file itself is copied or backed up somewhere careless.
//
// This package never imports age. All cryptography goes through internal/envelope,
// which is the only package that knows what a cipher is.
package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"gatekeeper/internal/envelope"
	"gatekeeper/internal/platform"
)

// Passphrase length policy.
//
// The minimum is enforced; the warning threshold is not. Refusing outright below
// 20 characters would push people toward writing the passphrase down, which is
// worse than a slightly short one.
const (
	MinPassphraseLen  = 12
	WarnPassphraseLen = 20
)

// Names of the things this package owns.
const (
	// identitiesDirName is the directory under the per-user config directory that
	// holds private keys, one file per vault.
	identitiesDirName = "identities"

	// identityFileExt is the extension of a private identity file.
	//
	// It carries weight beyond tidiness: the commit guard treats this extension as
	// a reason to stop, because a passphrase-encrypted key has no readable content
	// to detect. The two must agree, which is why this is named.
	identityFileExt = ".key"
)

var (
	// ErrNotFound reports that no local identity exists for a vault.
	ErrNotFound = errors.New("no local identity for this vault")
	// ErrExists reports that an identity already exists and will not be replaced.
	ErrExists = errors.New("an identity already exists for this vault")
	// ErrWeakPassphrase reports a passphrase below the enforced minimum.
	ErrWeakPassphrase = errors.New("passphrase is too short")
	// ErrWrongPassphrase reports a failed unlock.
	ErrWrongPassphrase = envelope.ErrWrongPassphrase
)

// Identity is one key pair.
//
// In v0.1 a single identity is shared by all of a user's machines. That is a
// policy choice, not a limitation: profiles are encrypted to a list of
// recipients, so issuing one identity per machine later is additive.
type Identity struct {
	VaultID   string
	Private   string // AGE-SECRET-KEY-1...
	Recipient string // age1...
}

// Generate creates a fresh identity for a vault.
func Generate(vaultID string) (Identity, error) {
	private, recipient, err := envelope.GenerateIdentity()
	if err != nil {
		return Identity{}, err
	}
	return Identity{VaultID: vaultID, Private: private, Recipient: recipient}, nil
}

// ValidatePassphrase enforces the minimum length.
func ValidatePassphrase(passphrase string) error {
	if n := utf8.RuneCountInString(passphrase); n < MinPassphraseLen {
		return fmt.Errorf("%w: %d characters given, %d required", ErrWeakPassphrase, n, MinPassphraseLen)
	}
	return nil
}

// PassphraseIsWeak reports whether a passphrase should draw a warning.
//
// The test is length alone. Estimating the entropy of a human-chosen string is
// guesswork, and length is the property that actually matters against an offline
// attack.
func PassphraseIsWeak(passphrase string) bool {
	return utf8.RuneCountInString(passphrase) < WarnPassphraseLen
}

// Path returns where a vault's private identity lives.
//
// The directory is keyed by vault ID, so several vaults -- a personal one and a
// work one -- coexist without colliding and without sharing a key.
func Path(vaultID string) (string, error) {
	dir, err := platform.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, identitiesDirName, vaultID+identityFileExt), nil
}

// Dir returns the directory holding all local identities.
func Dir() (string, error) {
	dir, err := platform.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, identitiesDirName), nil
}

// Save writes a private identity, encrypted under a passphrase, and refuses to
// replace an existing one.
//
// The file is an ASCII-armored age file, not a raw key. Two consequences are
// worth knowing: the standard `age` command still reads it (`age -d key >
// raw.key`), and it survives being pasted into a password manager or copied by a
// tool that rewrites line endings.
//
// Writing goes through a temporary file in the same directory and an atomic
// replace, so an interrupted save cannot leave a half-written key that would look
// like a wrong passphrase forever after.
func Save(id Identity, passphrase string) (string, error) {
	path, err := Path(id.VaultID)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%w: %s", ErrExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect identity path: %w", err)
	}
	return write(id, passphrase)
}

// ChangePassphrase re-encrypts a vault's identity under a new passphrase.
//
// The old passphrase is required and verified, so this cannot be used to lock
// someone out of a vault they cannot already open. The new key file is written
// and atomically swapped in, so an interruption leaves the old passphrase
// working rather than leaving no working passphrase at all.
func ChangePassphrase(vaultID, oldPassphrase, newPassphrase string) (string, error) {
	if oldPassphrase == newPassphrase {
		return "", errors.New("the new passphrase is the same as the current one")
	}

	// Unlocking first is what makes the old passphrase authoritative rather than
	// decorative.
	id, err := Load(vaultID, oldPassphrase)
	if err != nil {
		return "", err
	}
	return Rewrite(id, newPassphrase)
}

// Rewrite replaces a vault's identity, encrypted under a new passphrase.
//
// This is how the passphrase is changed: unlock with the old one, write with the
// new one. It is the only function that overwrites a key file, and it exists so
// that changing a passphrase never requires deleting the key first — which would
// leave the vault unopenable if anything went wrong in between.
func Rewrite(id Identity, passphrase string) (string, error) {
	return write(id, passphrase)
}

// write seals an identity and installs it atomically.
func write(id Identity, passphrase string) (string, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return "", err
	}

	path, err := Path(id.VaultID)
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, platform.PrivateDirMode); err != nil {
		return "", fmt.Errorf("create identity directory: %w", err)
	}

	sealed, err := (envelope.PassphraseBox{}).Seal(passphrase, id.Private+"\n")
	if err != nil {
		return "", err
	}

	// The temporary file holds ciphertext, so a leftover from a crash is not a
	// plaintext exposure.
	tmp, err := os.CreateTemp(dir, platform.TempFilePrefix+"identity-*")
	if err != nil {
		return "", fmt.Errorf("create temporary identity: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(platform.PrivateFileMode); err != nil {
		return "", fmt.Errorf("set identity permissions: %w", err)
	}
	if _, err := tmp.Write(sealed); err != nil {
		return "", fmt.Errorf("write identity: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("flush identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close identity: %w", err)
	}

	if err := platform.ReplaceFile(tmpName, path); err != nil {
		return "", fmt.Errorf("install identity: %w", err)
	}
	if err := platform.SyncDir(dir); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads and unlocks a vault's private identity.
//
// It refuses to use a key other local users could read, because a world-readable
// identity is not protected at all and the failure would otherwise be silent.
func Load(vaultID string, passphrase string) (Identity, error) {
	if passphrase == "" {
		return Identity{}, ErrWrongPassphrase
	}

	path, err := Path(vaultID)
	if err != nil {
		return Identity{}, err
	}

	// The permission check happens inside ReadPrivateFile, against the open
	// descriptor, so an unsafe key is refused before its bytes are used -- and
	// there is no window between the check and the read for the file to be
	// swapped underneath us.
	sealed, err := platform.ReadPrivateFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Identity{}, fmt.Errorf("%w (looked for %s)", ErrNotFound, path)
		}
		return Identity{}, err
	}

	private, err := (envelope.PassphraseBox{}).Open(passphrase, sealed)
	if err != nil {
		return Identity{}, err
	}

	recipient, err := envelope.RecipientOf(private)
	if err != nil {
		return Identity{}, fmt.Errorf("identity at %s: %w", path, err)
	}
	return Identity{VaultID: vaultID, Private: private, Recipient: recipient}, nil
}

// Exists reports whether a vault already has a local identity.
func Exists(vaultID string) bool {
	path, err := Path(vaultID)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// ReadRawPrivateKey reads a raw age private key from an explicit path.
//
// This is the *recovery* form. The offline recovery identity is deliberately not
// passphrase-encrypted, because it is meant to survive on paper or removable
// media, where a passphrase would only add one more way to lose it.
//
// The permission check is still applied: a recovery key left world-readable is
// the same problem as any other exposed key.
func ReadRawPrivateKey(path string) (string, error) {
	sealed, err := platform.ReadPrivateFile(path)
	if err != nil {
		return "", fmt.Errorf("read identity: %w", err)
	}

	private := strings.TrimSpace(string(sealed))
	if _, err := envelope.RecipientOf(private); err != nil {
		return "", fmt.Errorf("%s is not a usable age private key: %w", path, err)
	}
	return private, nil
}

// WriteRecovery writes the offline recovery identity to an explicit destination.
//
// This is the one place Gatekeeper emits a raw private key, and it is
// deliberately not encrypted: the destination is paper or removable media, and a
// passphrase on a printed key adds nothing while adding a way to lose it.
//
// It is also the documented backstop for a forgotten passphrase, which is why
// init refuses to run at all when nothing could receive it.
func WriteRecovery(path string, private string) error {
	if path == "" {
		return errors.New("no recovery destination given")
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, platform.PrivateFileMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		}
		return fmt.Errorf("create recovery file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(strings.TrimSpace(private) + "\n"); err != nil {
		return fmt.Errorf("write recovery file: %w", err)
	}
	return f.Sync()
}

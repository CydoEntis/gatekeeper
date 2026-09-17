package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gatekeeper/internal/platform"
)

// Names of the files that make up a vault directory.
const (
	ManifestFile = "manifest.json"
	DevicesFile  = "devices.json"
	ProfilesDir  = "profiles"
	// ProfileFileExt is the extension of an encrypted profile. It is exported
	// because the Git adapter has to tell profiles from metadata when it builds a
	// commit message.
	ProfileFileExt = ".age"
)

// Manifest is plaintext metadata. It holds no secrets, and is safe to commit.
type Manifest struct {
	Format    int       `json:"format"`
	VaultID   string    `json:"vault_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Device is one authorized recipient, as public information.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Recipient string    `json:"recipient"`
	AddedAt   time.Time `json:"added_at"`
}

// Devices is the recipient set.
//
// In v0.1 this holds exactly one device entry, shared by all of the user's
// machines, plus the offline recovery recipient. The list shape is deliberate:
// moving to one identity per machine later means adding entries and
// re-encrypting, with no format change.
type Devices struct {
	Format            int      `json:"format"`
	Revision          int      `json:"revision"`
	Devices           []Device `json:"devices"`
	RecoveryRecipient string   `json:"recovery_recipient"`
}

// vaultGitignore is written into every vault.
//
// The private identity lives outside the vault by design, so this is defence in
// depth rather than the primary control: it is what stops a stray copy, a
// plaintext export, or a half-written temp file from being committed by
// `git add -A` in a moment of inattention.
//
// The temp pattern is built from platform.TempFilePrefix rather than written out,
// because those two must agree. A temp file the ignore rules miss is an encrypted
// fragment committed by accident, and the mistake would be invisible.
var vaultGitignore = `# Written by Gatekeeper. Private keys must never be committed.
*.key
identities/
` + platform.TempFilePrefix + `*
.env
.env.*
!.env.example
`

// GitignoreFile is the vault's own ignore rules.
const GitignoreFile = ".gitignore"

// WriteGitignore writes the vault ignore rules if they are not already present.
//
// It never overwrites, so a user who has customised the file keeps their version.
func WriteGitignore(dir string) error {
	path := filepath.Join(dir, GitignoreFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.WriteFile(path, []byte(vaultGitignore), platform.PrivateFileMode); err != nil {
		return fmt.Errorf("write vault .gitignore: %w", err)
	}
	return nil
}

// ErrNotVault reports a directory that does not look like a vault.
var ErrNotVault = errors.New("directory is not a Gatekeeper vault")

// ReadManifest loads and validates a vault's manifest.
func ReadManifest(dir string) (Manifest, error) {
	encoded, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, fmt.Errorf("%w: no %s in %s", ErrNotVault, ManifestFile, dir)
		}
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}

	var m Manifest
	if err := strictUnmarshal(encoded, &m); err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if m.Format != FormatVersion {
		return Manifest{}, fmt.Errorf("%w: manifest format %d", ErrUnsupportedFormat, m.Format)
	}
	return m, nil
}

// ReadDevices loads the recipient set.
func ReadDevices(dir string) (Devices, error) {
	encoded, err := os.ReadFile(filepath.Join(dir, DevicesFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Devices{}, fmt.Errorf("%w: no %s in %s", ErrNotVault, DevicesFile, dir)
		}
		return Devices{}, fmt.Errorf("read devices: %w", err)
	}

	var d Devices
	if err := strictUnmarshal(encoded, &d); err != nil {
		return Devices{}, fmt.Errorf("read devices: %w", err)
	}
	if d.Format != FormatVersion {
		return Devices{}, fmt.Errorf("%w: devices format %d", ErrUnsupportedFormat, d.Format)
	}
	if len(d.Devices) == 0 {
		// A recipient set with nobody in it cannot decrypt anything. Fail closed
		// rather than reporting an empty but "valid" vault.
		return Devices{}, errors.New("devices file lists no recipients")
	}
	return d, nil
}

// WriteManifest persists the vault's plaintext metadata atomically, so a crash
// cannot leave a vault with a half-written manifest.
func WriteManifest(dir string, m Manifest) error {
	return writeJSONAtomic(dir, ManifestFile, m)
}

// WriteDevices persists the recipient set atomically.
//
// The atomicity matters more here than anywhere else in the vault: a partially
// written recipient list is a vault whose holders are ambiguous, and the next
// write would encrypt to whatever survived.
func WriteDevices(dir string, d Devices) error {
	return writeJSONAtomic(dir, DevicesFile, d)
}

// writeJSONAtomic encodes v and installs it with a temp-file-and-rename, so the
// destination is either the old file or the new one and never a mixture.
func writeJSONAtomic(dir, name string, v any) error {
	payload, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, platform.TempFilePrefix+"*.json")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(platform.PrivateFileMode); err != nil {
		return fmt.Errorf("set temp permissions: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("write temp %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush temp %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp %s: %w", name, err)
	}
	if err := platform.ReplaceFile(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("replace %s: %w", name, err)
	}
	return platform.SyncDir(dir)
}

// strictUnmarshal rejects unknown fields, duplicate keys, and trailing content.
//
// The duplicate-key check matters here for the same reason it matters for an
// encrypted profile, and rather more: `devices.json` is what decides who can read
// the vault, and encoding/json silently keeps the *last* of two identical keys. A
// file that says two different things about a recipient should be refused rather
// than resolved by position.
func strictUnmarshal(encoded []byte, v any) error {
	if err := rejectDuplicateKeys(encoded); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return ErrTrailingContent
	}
	return nil
}

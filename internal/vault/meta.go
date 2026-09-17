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
const vaultGitignore = `# Written by Gatekeeper. Private keys must never be committed.
*.key
identities/
*.tmp
.tmp-*
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
	if err := os.WriteFile(path, []byte(vaultGitignore), 0o600); err != nil {
		return fmt.Errorf("write vault .gitignore: %w", err)
	}
	return nil
}

// ErrNotVault reports a directory that does not look like a vault.
var ErrNotVault = errors.New("directory is not an Gatekeeper vault")

// ReadManifest loads and validates a vault's manifest.
func ReadManifest(dir string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, fmt.Errorf("%w: no %s in %s", ErrNotVault, ManifestFile, dir)
		}
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}

	var m Manifest
	if err := strictUnmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if m.Format != FormatVersion {
		return Manifest{}, fmt.Errorf("%w: manifest format %d", ErrUnsupportedFormat, m.Format)
	}
	return m, nil
}

// ReadDevices loads the recipient set.
func ReadDevices(dir string) (Devices, error) {
	data, err := os.ReadFile(filepath.Join(dir, DevicesFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Devices{}, fmt.Errorf("%w: no %s in %s", ErrNotVault, DevicesFile, dir)
		}
		return Devices{}, fmt.Errorf("read devices: %w", err)
	}

	var d Devices
	if err := strictUnmarshal(data, &d); err != nil {
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

// WriteManifest and WriteDevices persist metadata atomically, so a crash cannot
// leave a vault with a half-written manifest.
func WriteManifest(dir string, m Manifest) error {
	return writeJSONAtomic(dir, ManifestFile, m)
}

func WriteDevices(dir string, d Devices) error {
	return writeJSONAtomic(dir, DevicesFile, d)
}

func writeJSONAtomic(dir, name string, v any) error {
	payload, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dir, ".tmp-*.json")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
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

// strictUnmarshal rejects unknown fields and trailing content, matching the
// decoding rules applied to encrypted profiles.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return ErrTrailingContent
	}
	return nil
}

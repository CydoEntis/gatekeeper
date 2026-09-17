package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"gatekeeper/internal/envelope"
	"gatekeeper/internal/platform"
)

// ChangeFunc mutates a decrypted profile in place. It runs inside the vault's
// read-modify-encrypt-write cycle, so a caller can never accidentally persist
// plaintext or skip the atomic replacement.
type ChangeFunc func(p *Profile) error

// Vault is the deepest module in the design. It owns validation, encrypted
// persistence, revisions, recipient selection, and atomic writes.
type Vault interface {
	List(ctx context.Context) ([]Summary, error)
	Read(ctx context.Context, name string) (Profile, error)
	Create(ctx context.Context, name string, vars map[string]string) (Summary, error)
	Change(ctx context.Context, name string, fn ChangeFunc) (Summary, error)
}

// FileVault stores one age-encrypted JSON file per profile.
//
// Every dependency is injected. The vault never reaches for a global
// recipient, a global identity, or the wall clock -- which is what makes the
// crash-injection tests in Phase 3 possible at all.
type FileVault struct {
	Dir        string
	Envelope   envelope.Envelope
	Recipients []age.Recipient
	Identities []age.Identity
	Now        func() time.Time
	NewID      func() (string, error)
}

// profilesDir is where encrypted profiles live, kept apart from the plaintext
// metadata so a vault directory listing does not mix the two.
func (v *FileVault) profilesDir() string {
	return filepath.Join(v.Dir, ProfilesDir)
}

func (v *FileVault) path(name string) string {
	return filepath.Join(v.profilesDir(), name+ProfileFileExt)
}

func (v *FileVault) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

func (v *FileVault) newID() (string, error) {
	if v.NewID != nil {
		return v.NewID()
	}
	return NewID()
}

// List returns profile names and revisions without decrypting any value.
//
// It currently reads each profile to obtain the revision. When listing becomes
// hot, the revision can move into plaintext metadata -- but note that
// ARCHITECTURE.md 3.3 already accepts profile-name metadata, not revision
// metadata, so that would be a deliberate change.
func (v *FileVault) List(ctx context.Context) ([]Summary, error) {
	entries, err := os.ReadDir(v.profilesDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list profiles: %w", err)
	}

	var out []Summary
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ProfileFileExt {
			continue
		}
		name := e.Name()[:len(e.Name())-len(ProfileFileExt)]
		p, err := v.Read(ctx, name)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Summary())
	}
	return out, nil
}

// Read decrypts and validates one profile.
func (v *FileVault) Read(ctx context.Context, name string) (Profile, error) {
	if !profileNameRE.MatchString(name) {
		return Profile{}, InvalidProfileName(name)
	}

	f, err := os.Open(v.path(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Profile{}, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return Profile{}, fmt.Errorf("open profile: %w", err)
	}
	defer f.Close()

	var p Profile
	err = v.Envelope.Decrypt(f, v.Identities, func(r io.Reader) error {
		decoded, err := DecodeProfile(r)
		if err != nil {
			return err
		}
		p = decoded
		return nil
	})
	if err != nil {
		return Profile{}, fmt.Errorf("read profile %q: %w", name, err)
	}

	// The filename is the one piece of profile metadata that is not encrypted.
	// If it disagrees with the payload, one of the two has been tampered with.
	if p.Name != name {
		return Profile{}, fmt.Errorf("%w: file says %q, payload says %q", ErrNameMismatch, name, p.Name)
	}
	return p, nil
}

// Create writes a new profile and refuses to overwrite an existing one.
func (v *FileVault) Create(ctx context.Context, name string, vars map[string]string) (Summary, error) {
	if !profileNameRE.MatchString(name) {
		return Summary{}, InvalidProfileName(name)
	}
	if _, err := os.Stat(v.path(name)); err == nil {
		return Summary{}, fmt.Errorf("%w: %s", ErrAlreadyExists, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Summary{}, fmt.Errorf("stat profile: %w", err)
	}

	if vars == nil {
		vars = map[string]string{}
	}
	id, err := v.newID()
	if err != nil {
		return Summary{}, fmt.Errorf("generate profile id: %w", err)
	}
	p := Profile{
		Format:    FormatVersion,
		ID:        id,
		Name:      name,
		Revision:  1,
		UpdatedAt: v.now().UTC(),
		Variables: vars,
	}
	if err := p.Validate(); err != nil {
		return Summary{}, err
	}
	if err := v.writeAtomic(p); err != nil {
		return Summary{}, err
	}
	return p.Summary(), nil
}

// Change centralizes read-modify-encrypt-write so no caller can bypass atomic
// persistence or the revision bump.
func (v *FileVault) Change(ctx context.Context, name string, fn ChangeFunc) (Summary, error) {
	p, err := v.Read(ctx, name)
	if err != nil {
		return Summary{}, err
	}

	if err := fn(&p); err != nil {
		return Summary{}, err
	}

	p.Revision++
	p.UpdatedAt = v.now().UTC()
	if p.Variables == nil {
		p.Variables = map[string]string{}
	}
	if err := p.Validate(); err != nil {
		return Summary{}, err
	}
	if err := v.writeAtomic(p); err != nil {
		return Summary{}, err
	}
	return p.Summary(), nil
}

// writeAtomic follows ARCHITECTURE.md 4.4 exactly:
//
//	encrypt to an unpredictable temp file in the same directory -> flush ->
//	close -> restrictive permissions -> atomic replace -> sync the directory.
//
// The temp file lives in the same directory on purpose: a cross-volume rename
// is a copy, which is not atomic and can leave a half-written profile.
func (v *FileVault) writeAtomic(p Profile) error {
	dir := v.profilesDir()
	// Ensure the directory exists, so a FileVault constructed directly -- as the
	// spike and the tests do -- behaves the same as one built by Open.
	if err := os.MkdirAll(dir, platform.PrivateDirMode); err != nil {
		return fmt.Errorf("create profiles directory: %w", err)
	}

	// The temp file lives in the same directory as the destination on purpose: a
	// cross-volume rename is a copy, which is not atomic and can leave a
	// half-written profile.
	tmp, err := os.CreateTemp(dir, platform.TempFilePrefix+"*.age")
	if err != nil {
		return fmt.Errorf("create temp profile: %w", err)
	}
	tmpName := tmp.Name()

	// Best-effort cleanup. After a successful rename this is a harmless no-op.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// Plaintext never touches this file, but the ciphertext is still restricted
	// so a partially written profile is not readable by other local users.
	if err := tmp.Chmod(platform.PrivateFileMode); err != nil {
		return fmt.Errorf("set temp permissions: %w", err)
	}

	// The only plaintext copy is the in-memory payload handed to the envelope
	// callback. It is never written anywhere except through the cipher.
	payload, err := encodeProfile(p)
	if err != nil {
		return err
	}

	if err := v.Envelope.Encrypt(tmp, v.Recipients, func(w io.Writer) error {
		_, err := w.Write(payload)
		return err
	}); err != nil {
		return err
	}

	// Flush before rename: without this, a crash can leave the new name
	// pointing at unwritten data.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush temp profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp profile: %w", err)
	}

	if err := platform.ReplaceFile(tmpName, v.path(p.Name)); err != nil {
		return fmt.Errorf("replace profile: %w", err)
	}
	return platform.SyncDir(dir)
}

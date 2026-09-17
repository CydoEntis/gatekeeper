package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gatekeeper/internal/identity"
	"gatekeeper/internal/localconfig"
	"gatekeeper/internal/vault"
)

// UseVault records dir as this machine's default vault.
//
// This is the missing half of moving to a second machine. `init` records a
// default, but init cannot run against a vault that already exists — so before
// this existed, a new machine had no way to stop passing --vault on every single
// command, and the error message pointed at init, which would refuse.
//
// The directory is verified to be a real vault first, so a typo cannot silently
// become the default.
func (a App) UseVault(ctx context.Context, dir string) (vault.Manifest, error) {
	if err := ctx.Err(); err != nil {
		return vault.Manifest{}, err
	}
	if dir == "" {
		return vault.Manifest{}, fmt.Errorf("%w: no vault directory given", ErrUsage)
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return vault.Manifest{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}

	manifest, err := vault.ReadManifest(abs)
	if err != nil {
		return vault.Manifest{}, err
	}

	cfg, err := localconfig.Load()
	if err != nil {
		return vault.Manifest{}, err
	}
	cfg.DefaultVault = abs
	if err := localconfig.Save(cfg); err != nil {
		return vault.Manifest{}, err
	}

	return manifest, nil
}

// VaultRef identifies a vault and how to unlock it.
//
// Passed per call rather than held on App, so one App serves a personal vault and
// a work vault without either being able to reach the other's key.
type VaultRef struct {
	Dir string
	// Passphrase unlocks the local identity. This is the everyday path.
	Passphrase string
	// Identity is a raw age private key supplied directly, bypassing the local
	// identity entirely. This is the recovery path: the offline recovery key is
	// not passphrase-encrypted, and using it is how access is restored when the
	// local identity is gone or the passphrase is forgotten.
	Identity string
}

// open unlocks a vault and returns it ready for use.
//
// The order matters. The manifest supplies the vault id, and the vault id selects
// which local identity is loaded. That indirection is what lets two vaults coexist
// on one machine without sharing a key — and it is what `Identity` bypasses when
// the local identity is exactly what has been lost.
func (a App) open(ref VaultRef) (*vault.FileVault, error) {
	if ref.Dir == "" {
		return nil, fmt.Errorf("%w: no vault directory selected", ErrUsage)
	}

	manifest, err := vault.ReadManifest(ref.Dir)
	if err != nil {
		return nil, err
	}

	private := ref.Identity
	if private == "" {
		id, err := identity.Load(manifest.VaultID, ref.Passphrase)
		if err != nil {
			return nil, err
		}
		private = id.Private
	}

	// A key that is not a recipient fails later, at decryption, with the same
	// indistinguishable error as any other unusable key. That is deliberate: it
	// avoids turning this into an oracle for which keys a vault accepts.
	return vault.Open(ref.Dir, private)
}

// SetRequest stores one variable in one profile.
type SetRequest struct {
	Profile string
	Key     string
	// Value is supplied by the caller. This layer never reads it from an
	// argument, because an argument is visible in shell history and in the
	// process list.
	Value string
}

// ChangeResult reports a mutation without revealing any value.
type ChangeResult struct {
	Profile   string
	Revision  int
	Variables []string
	// Created reports that the profile did not exist and was created by this
	// call. With `gk profile create` deferred, `set` is what makes a profile
	// exist at all.
	Created bool
}

// Set stores a value, creating the profile if it does not exist.
func (a App) Set(ctx context.Context, ref VaultRef, req SetRequest) (ChangeResult, error) {
	if err := ctx.Err(); err != nil {
		return ChangeResult{}, err
	}

	// Name checks are pure string work and happen before the vault is unlocked,
	// so a typo costs the user nothing.
	if !vault.ValidProfileName(req.Profile) {
		return ChangeResult{}, fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, req.Profile)
	}
	if !vault.ValidVariableName(req.Key) {
		return ChangeResult{}, fmt.Errorf("%w: variable name %q", vault.ErrInvalidName, req.Key)
	}

	v, err := a.open(ref)
	if err != nil {
		return ChangeResult{}, err
	}

	created := false
	if _, err := v.Read(ctx, req.Profile); err != nil {
		if !errors.Is(err, vault.ErrNotFound) {
			return ChangeResult{}, err
		}
		created = true
	}

	var summary vault.Summary
	if created {
		summary, err = v.Create(ctx, req.Profile, map[string]string{req.Key: req.Value})
	} else {
		summary, err = v.Change(ctx, req.Profile, func(p *vault.Profile) error {
			p.Variables[req.Key] = req.Value
			return nil
		})
	}
	if err != nil {
		return ChangeResult{}, err
	}

	return ChangeResult{
		Profile:   summary.Name,
		Revision:  summary.Revision,
		Variables: summary.Vars,
		Created:   created,
	}, nil
}

// Profiles names every profile in the vault.
//
// It returns names, variable counts and revisions — never a value. Note that it
// currently decrypts each profile to read its revision. Moving the revision into
// plaintext metadata would avoid that, but ARCHITECTURE.md 3.3 accepts only
// profile-name metadata, so that would be a deliberate change rather than an
// optimisation.
func (a App) Profiles(ctx context.Context, ref VaultRef) ([]vault.Summary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := a.open(ref)
	if err != nil {
		return nil, err
	}
	return v.List(ctx)
}

// List names the variables in one profile. It never returns a value.
func (a App) List(ctx context.Context, ref VaultRef, profile string) (vault.Summary, error) {
	if err := ctx.Err(); err != nil {
		return vault.Summary{}, err
	}
	if !vault.ValidProfileName(profile) {
		return vault.Summary{}, fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, profile)
	}

	v, err := a.open(ref)
	if err != nil {
		return vault.Summary{}, err
	}
	p, err := v.Read(ctx, profile)
	if err != nil {
		return vault.Summary{}, err
	}
	return p.Summary(), nil
}

// ProfileEnvironment is a profile's variables, ready to inject into a child
// process.
//
// It carries secrets, so it deliberately has no usable default formatting. A
// stray `%v` in a log line, a debug print, or an error that wrapped it would
// otherwise print every value at once — the exact disclosure the rest of this
// package works to prevent.
type ProfileEnvironment map[string]string

// String redacts.
//
// This exists so that the convenient thing to write (printing the value) is also
// the safe thing.
func (e ProfileEnvironment) String() string {
	return fmt.Sprintf("Environment(%d variables, redacted)", len(e))
}

// Environment decrypts one profile for injection into a child process.
//
// The result leaves this layer by design — it has to, to reach a child process —
// but nothing in the command layer prints it.
func (a App) Environment(ctx context.Context, ref VaultRef, profile string) (ProfileEnvironment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !vault.ValidProfileName(profile) {
		return nil, fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, profile)
	}

	v, err := a.open(ref)
	if err != nil {
		return nil, err
	}
	p, err := v.Read(ctx, profile)
	if err != nil {
		return nil, err
	}

	env := make(ProfileEnvironment, len(p.Variables))
	for key, value := range p.Variables {
		env[key] = value
	}
	return env, nil
}

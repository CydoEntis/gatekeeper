// Package app holds the use cases shared by the CLI and any future entry point.
//
// Command handlers parse input and render output; they do not contain vault or
// cryptography logic. Keeping that boundary means a later MCP or UI adapter
// cannot bypass the safety rules by reaching past this layer.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gatekeeper/internal/identity"
	"gatekeeper/internal/localconfig"
	"gatekeeper/internal/vault"
)

var (
	// ErrUsage reports a request that is malformed before any work happens.
	ErrUsage = errors.New("invalid request")
	// ErrAlreadyInitialized reports a directory that already holds a vault.
	ErrAlreadyInitialized = errors.New("vault is already initialized")
	// ErrRecoveryUndeliverable reports that the recovery identity has nowhere to
	// go, which makes initialization unsafe to perform at all.
	ErrRecoveryUndeliverable = errors.New("recovery identity cannot be delivered")
)

// App is the use-case surface.
//
// Time and ID generation are injected so tests are deterministic -- the same
// reason the vault takes them. Nothing here constructs a global dependency.
type App struct {
	Now   func() time.Time
	NewID func() (string, error)
}

// New returns an App wired to the real clock and a random ID source.
func New() App {
	return App{Now: time.Now, NewID: vault.NewID}
}

// InitRequest describes an initialization.
type InitRequest struct {
	// VaultDir is where the synchronized vault will live.
	VaultDir string
	// Name labels the vault itself, such as "personal" or "work".
	Name string
	// DeviceName labels the recipient identity. In v0.1 a single identity is
	// shared across the user's machines, so this names the key rather than a
	// specific computer.
	DeviceName string
	// RecoveryOut is an explicit path for the offline recovery identity.
	RecoveryOut string
	// Passphrase encrypts the private identity at rest. It is supplied by the
	// caller rather than prompted for here, so the application layer performs no
	// terminal I/O and can be tested without one.
	Passphrase string
	// PassphraseWeak reports that the caller already determined the passphrase is
	// short enough to warn about. The warning is emitted by the caller because it
	// is presentation.
	PassphraseWeak bool
	// RecoveryPrintable reports whether standard output is an interactive
	// terminal. When it is not, and no RecoveryOut is given, initialization is
	// refused rather than printing a private key into a pipe or a log.
	RecoveryPrintable bool
	// SetDefault records this vault as the machine-local default.
	SetDefault bool
}

// InitResult reports what initialization created.
type InitResult struct {
	VaultDir          string
	VaultID           string
	Name              string
	DeviceName        string
	DeviceRecipient   string
	RecoveryRecipient string
	IdentityPath      string
	RecoveryWrittenTo string

	// RecoveryIdentity is a private key.
	//
	// It is populated ONLY when the caller has established that standard output
	// is a terminal. It must be written to that terminal once and never logged,
	// recorded, or included in an error.
	RecoveryIdentity string
}

// Init creates a vault, a device identity, and an offline recovery identity.
//
// The ordering here is the whole safety argument:
//
//  1. Preconditions are checked before anything is created, so a refusal costs
//     nothing and leaves no debris.
//  2. The private identity is written OUTSIDE the vault directory.
//  3. If any later step fails, what was created is removed, so a failed init
//     never leaves a vault whose key is missing or a key whose vault is missing.
//  4. The recovery identity is delivered last, and if it cannot be delivered the
//     whole operation is undone -- a vault with a lost recovery key is one
//     stolen laptop away from being unrecoverable.
func (a App) Init(ctx context.Context, req InitRequest) (InitResult, error) {
	if err := ctx.Err(); err != nil {
		return InitResult{}, err
	}
	if req.VaultDir == "" {
		return InitResult{}, fmt.Errorf("%w: no vault directory given", ErrUsage)
	}

	dir, err := filepath.Abs(req.VaultDir)
	if err != nil {
		return InitResult{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if req.Name == "" {
		req.Name = "personal"
	}
	if req.DeviceName == "" {
		req.DeviceName = req.Name
	}

	// --- Preconditions, before anything exists -------------------------------

	if _, err := os.Stat(filepath.Join(dir, vault.ManifestFile)); err == nil {
		// Refuse rather than overwrite. Re-initializing would issue a new
		// identity and orphan every profile encrypted to the old one.
		return InitResult{}, fmt.Errorf("%w: %s", ErrAlreadyInitialized, dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitResult{}, fmt.Errorf("inspect vault directory: %w", err)
	}

	if req.RecoveryOut == "" && !req.RecoveryPrintable {
		return InitResult{}, fmt.Errorf(
			"%w: standard output is not a terminal, so the recovery identity would be "+
				"captured by a pipe, file, or log instead of being seen once. "+
				"Pass --recovery-out PATH to write it somewhere you control", ErrRecoveryUndeliverable)
	}

	// The passphrase is checked before anything is created, for the same reason:
	// a refusal must cost nothing and leave no debris behind.
	if err := identity.ValidatePassphrase(req.Passphrase); err != nil {
		return InitResult{}, err
	}

	// --- Generate -------------------------------------------------------------

	vaultID, err := a.NewID()
	if err != nil {
		return InitResult{}, fmt.Errorf("generate vault id: %w", err)
	}
	device, err := identity.Generate(vaultID)
	if err != nil {
		return InitResult{}, fmt.Errorf("generate device identity: %w", err)
	}
	recovery, err := identity.Generate(vaultID)
	if err != nil {
		return InitResult{}, fmt.Errorf("generate recovery identity: %w", err)
	}

	// --- Create, with undo on any failure ------------------------------------

	// The private identity goes to the per-user config directory, deliberately
	// NOT into dir, and is encrypted under the passphrase. This is
	// ARCHITECTURE.md invariant #1, plus the control that replaces full-disk
	// encryption.
	identityPath, err := identity.Save(device, req.Passphrase)
	if err != nil {
		return InitResult{}, err
	}

	undo := func() {
		// Only ever removes things this function just created.
		_ = os.Remove(identityPath)
		_ = os.Remove(filepath.Join(dir, vault.ManifestFile))
		_ = os.Remove(filepath.Join(dir, vault.DevicesFile))
		_ = os.Remove(filepath.Join(dir, vault.GitignoreFile))
		_ = os.Remove(filepath.Join(dir, vault.ProfilesDir))
		_ = os.Remove(dir) // succeeds only when empty
	}

	if err := os.MkdirAll(filepath.Join(dir, vault.ProfilesDir), 0o700); err != nil {
		undo()
		return InitResult{}, fmt.Errorf("create vault directory: %w", err)
	}

	now := a.Now().UTC()
	manifest := vault.Manifest{
		Format:    vault.FormatVersion,
		VaultID:   vaultID,
		Name:      req.Name,
		CreatedAt: now,
	}
	devices := vault.Devices{
		Format:   vault.FormatVersion,
		Revision: 1,
		Devices: []vault.Device{{
			ID:        vaultID,
			Name:      req.DeviceName,
			Recipient: device.Recipient,
			AddedAt:   now,
		}},
		RecoveryRecipient: recovery.Recipient,
	}

	if err := vault.WriteManifest(dir, manifest); err != nil {
		undo()
		return InitResult{}, err
	}
	if err := vault.WriteDevices(dir, devices); err != nil {
		undo()
		return InitResult{}, err
	}
	if err := vault.WriteGitignore(dir); err != nil {
		undo()
		return InitResult{}, err
	}

	result := InitResult{
		VaultDir:          dir,
		VaultID:           vaultID,
		Name:              req.Name,
		DeviceName:        req.DeviceName,
		DeviceRecipient:   device.Recipient,
		RecoveryRecipient: recovery.Recipient,
		IdentityPath:      identityPath,
	}

	// --- Deliver the recovery identity ---------------------------------------

	if req.RecoveryOut != "" {
		if err := identity.WriteRecovery(req.RecoveryOut, recovery.Private); err != nil {
			undo()
			return InitResult{}, err
		}
		result.RecoveryWrittenTo = req.RecoveryOut
	} else {
		result.RecoveryIdentity = recovery.Private
	}

	if req.SetDefault {
		cfg, err := localconfig.Load()
		if err != nil {
			undo()
			return InitResult{}, err
		}
		cfg.DefaultVault = dir
		if err := localconfig.Save(cfg); err != nil {
			undo()
			return InitResult{}, err
		}
	}

	return result, nil
}

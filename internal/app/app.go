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
	"gatekeeper/internal/platform"
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

// DefaultVaultName labels a vault when the caller does not name one.
const DefaultVaultName = "personal"

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
	req = normalizeInitRequest(req)
	dir, err := validateInitRequest(req)
	if err != nil {
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

	// The private identity goes to the per-user config directory, deliberately NOT
	// into dir, and is encrypted under the passphrase. This is ARCHITECTURE.md
	// invariant #1, plus the control that replaces full-disk encryption.
	identityPath, err := identity.Save(device, req.Passphrase)
	if err != nil {
		return InitResult{}, err
	}
	undo := removeInitArtifacts(dir, identityPath)

	// From here every failure undoes what has been created, so a failed init can
	// never leave a vault whose key is missing or a key whose vault is missing.
	if err := installVault(dir, req, vaultID, device, recovery, a.Now().UTC()); err != nil {
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

	if err := deliverRecovery(&result, req, recovery); err != nil {
		undo()
		return InitResult{}, err
	}

	if req.SetDefault {
		if err := recordDefaultVault(dir); err != nil {
			undo()
			return InitResult{}, err
		}
	}

	return result, nil
}

// normalizeInitRequest fills in the labels a caller may leave unset.
func normalizeInitRequest(req InitRequest) InitRequest {
	if req.Name == "" {
		req.Name = DefaultVaultName
	}
	if req.DeviceName == "" {
		req.DeviceName = req.Name
	}
	return req
}

// validateInitRequest refuses anything that must not proceed, and returns the
// absolute vault directory.
//
// Every check here happens before the first file is created. That ordering is the
// point: a refusal must cost the user nothing and leave no debris behind, and the
// simplest way to guarantee it is to refuse while nothing exists yet.
func validateInitRequest(req InitRequest) (string, error) {
	if req.VaultDir == "" {
		return "", fmt.Errorf("%w: no vault directory given", ErrUsage)
	}

	dir, err := filepath.Abs(req.VaultDir)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUsage, err)
	}

	// Refuse rather than overwrite: re-initializing would issue a new identity and
	// orphan every profile encrypted to the old one.
	switch _, err := os.Stat(filepath.Join(dir, vault.ManifestFile)); {
	case err == nil:
		return "", fmt.Errorf("%w: %s", ErrAlreadyInitialized, dir)
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("inspect vault directory: %w", err)
	}

	if req.RecoveryOut == "" && !req.RecoveryPrintable {
		return "", fmt.Errorf(
			"%w: standard output is not a terminal, so the recovery identity would be "+
				"captured by a pipe, file, or log instead of being seen once. "+
				"Pass --recovery-out PATH to write it somewhere you control", ErrRecoveryUndeliverable)
	}

	return dir, identity.ValidatePassphrase(req.Passphrase)
}

// removeInitArtifacts returns the undo for a partially created vault.
//
// It only ever removes what Init itself just created. The final Remove succeeds
// only when the directory is empty, so a vault directory that already held
// unrelated files is left alone rather than emptied.
func removeInitArtifacts(dir, identityPath string) func() {
	return func() {
		_ = os.Remove(identityPath)
		_ = os.Remove(filepath.Join(dir, vault.ManifestFile))
		_ = os.Remove(filepath.Join(dir, vault.DevicesFile))
		_ = os.Remove(filepath.Join(dir, vault.GitignoreFile))
		_ = os.Remove(filepath.Join(dir, vault.ProfilesDir))
		_ = os.Remove(dir)
	}
}

// installVault writes the vault directory: the profiles directory, then the
// public metadata. Nothing here is secret.
func installVault(dir string, req InitRequest, vaultID string, device, recovery identity.Identity, now time.Time) error {
	if err := os.MkdirAll(filepath.Join(dir, vault.ProfilesDir), platform.PrivateDirMode); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	// Every profile is encrypted to both recipients, so losing every machine is
	// survivable as long as the recovery key survives.
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
	manifest := vault.Manifest{
		Format:    vault.FormatVersion,
		VaultID:   vaultID,
		Name:      req.Name,
		CreatedAt: now,
	}

	if err := vault.WriteManifest(dir, manifest); err != nil {
		return err
	}
	if err := vault.WriteDevices(dir, devices); err != nil {
		return err
	}
	return vault.WriteGitignore(dir)
}

// deliverRecovery hands the offline recovery identity to the user, exactly once.
//
// It is the only private key Gatekeeper emits, and where it goes is the caller's
// decision: an explicit file, or a terminal. It is never stored locally, because
// a recovery key that lives only on the machine it is meant to recover is not a
// recovery key.
func deliverRecovery(result *InitResult, req InitRequest, recovery identity.Identity) error {
	if req.RecoveryOut != "" {
		if err := identity.WriteRecovery(req.RecoveryOut, recovery.Private); err != nil {
			return err
		}
		result.RecoveryWrittenTo = req.RecoveryOut
		return nil
	}
	result.RecoveryIdentity = recovery.Private
	return nil
}

// recordDefaultVault makes dir the vault later commands use without being told.
func recordDefaultVault(dir string) error {
	cfg, err := localconfig.Load()
	if err != nil {
		return err
	}
	cfg.DefaultVault = dir
	return localconfig.Save(cfg)
}

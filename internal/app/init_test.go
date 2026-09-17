package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gatekeeper/internal/envelope"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/vault"
)

// testPassphrase stands in for a user's passphrase. It is long enough to pass the
// enforced minimum and the warning threshold, so tests exercise the normal path
// rather than tripping a policy check by accident.
const testPassphrase = "correct horse battery staple"

// isolateConfigRedirects the per-user configuration directory into a temporary
// directory, so tests never touch the real one and never see the developer's own
// identities.
//
// Both variables are set because the platform module deliberately uses a
// different source on Windows (%LOCALAPPDATA%) than everywhere else
// (os.UserConfigDir, which reads XDG_CONFIG_HOME).
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("APPDATA", dir)
	return dir
}

func mustInit(t *testing.T, vaultDir string) InitResult {
	t.Helper()
	res, err := New().Init(context.Background(), InitRequest{
		VaultDir:          vaultDir,
		Passphrase:        testPassphrase,
		RecoveryPrintable: true,
		SetDefault:        true,
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return res
}

// TestIdentityFileIsEncryptedAtRest is the test that proves the passphrase does
// something. If the identity file on disk held the private key in the clear, a
// stolen machine, a copied backup, or a careless sync of the config directory
// would hand over every secret the vault has ever held.
func TestIdentityFileIsEncryptedAtRest(t *testing.T) {
	isolateConfig(t)
	res := mustInit(t, filepath.Join(t.TempDir(), "vault"))

	raw, err := os.ReadFile(res.IdentityPath)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}

	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("the identity file contains a raw private key")
	}
	// Armored on purpose: it survives being pasted into a password manager or
	// copied by a tool that rewrites line endings.
	if !strings.HasPrefix(string(raw), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("identity file is not an armored age file; first line: %q", firstLineOf(raw))
	}

	// The private key really is present, just sealed -- so the check above is not
	// passing merely because nothing was written.
	loaded, err := identity.Load(res.VaultID, testPassphrase)
	if err != nil {
		t.Fatalf("load with the correct passphrase: %v", err)
	}
	if !strings.HasPrefix(loaded.Private, "AGE-SECRET-KEY-") {
		t.Fatal("the unlocked identity is not a private key")
	}
	if strings.Contains(string(raw), loaded.Private) {
		t.Fatal("the identity file contains the private key it is meant to protect")
	}
}

// TestCorrectPassphraseUnlocks checks the stored identity round-trips and is the
// one the vault was built around.
func TestCorrectPassphraseUnlocks(t *testing.T) {
	isolateConfig(t)
	res := mustInit(t, filepath.Join(t.TempDir(), "vault"))

	loaded, err := identity.Load(res.VaultID, testPassphrase)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Recipient != res.DeviceRecipient {
		t.Errorf("unlocked recipient = %q, want %q", loaded.Recipient, res.DeviceRecipient)
	}
	if loaded.VaultID != res.VaultID {
		t.Errorf("unlocked vault id = %q, want %q", loaded.VaultID, res.VaultID)
	}
}

// TestWrongPassphraseIsRefused checks a bad unlock fails cleanly and says so,
// rather than returning a garbage identity or a confusing parse error.
func TestWrongPassphraseIsRefused(t *testing.T) {
	isolateConfig(t)
	res := mustInit(t, filepath.Join(t.TempDir(), "vault"))

	for _, attempt := range []string{"not the right passphrase at all", ""} {
		if _, err := identity.Load(res.VaultID, attempt); !errors.Is(err, identity.ErrWrongPassphrase) {
			t.Errorf("Load(%q) err = %v, want ErrWrongPassphrase", attempt, err)
		}
	}
}

// TestWeakPassphraseIsRefusedBeforeAnythingIsCreated checks the policy is a
// precondition, so a refusal leaves no vault and no identity behind.
func TestWeakPassphraseIsRefusedBeforeAnythingIsCreated(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	_, err := New().Init(context.Background(), InitRequest{
		VaultDir:          vaultDir,
		Passphrase:        "short",
		RecoveryPrintable: true,
	})
	if !errors.Is(err, identity.ErrWeakPassphrase) {
		t.Fatalf("err = %v, want ErrWeakPassphrase", err)
	}
	if _, err := os.Stat(vaultDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused passphrase still created the vault directory")
	}

	idDir, err := identity.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(idDir); err == nil && len(entries) != 0 {
		t.Errorf("a refused passphrase left %d identity file(s) behind", len(entries))
	}
}

func firstLineOf(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// TestInitPutsIdentityOutsideVault is the load-bearing security test.
//
// ARCHITECTURE.md invariant #1: a private identity must never enter the
// synchronized vault directory. If it does, every revision in the Git history
// becomes readable, forever.
func TestInitPutsIdentityOutsideVault(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	res := mustInit(t, vaultDir)

	// The identity is somewhere else entirely.
	if strings.HasPrefix(res.IdentityPath, res.VaultDir+string(os.PathSeparator)) {
		t.Fatalf("identity %s is inside the vault %s", res.IdentityPath, res.VaultDir)
	}
	if _, err := os.Stat(res.IdentityPath); err != nil {
		t.Fatalf("identity was not written: %v", err)
	}

	// No file anywhere under the vault contains key material.
	assertNoKeyMaterial(t, res.VaultDir)

	// The vault is a vault, and its metadata is readable and public.
	manifest, err := vault.ReadManifest(res.VaultDir)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if manifest.VaultID != res.VaultID {
		t.Errorf("manifest vault id = %q, want %q", manifest.VaultID, res.VaultID)
	}

	devices, err := vault.ReadDevices(res.VaultDir)
	if err != nil {
		t.Fatalf("read devices: %v", err)
	}
	if len(devices.Devices) != 1 {
		t.Fatalf("recipients = %d, want 1 in v0.1", len(devices.Devices))
	}
	if devices.Devices[0].Recipient != res.DeviceRecipient {
		t.Error("device recipient does not match the generated identity")
	}
	if devices.RecoveryRecipient == "" || devices.RecoveryRecipient == devices.Devices[0].Recipient {
		t.Error("recovery recipient must exist and be a different key")
	}

	// Public metadata must not contain the private key either.
	raw, err := os.ReadFile(filepath.Join(res.VaultDir, vault.DevicesFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Error("devices.json contains private key material")
	}
}

// TestInitRefusesToOverwriteVault covers the Phase 4 acceptance criterion that
// re-running init cannot clobber an existing vault or identity.
//
// Overwriting would issue a new identity and silently orphan every profile
// already encrypted to the old one.
func TestInitRefusesToOverwriteVault(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	first := mustInit(t, vaultDir)

	_, err := New().Init(context.Background(), InitRequest{
		VaultDir:          vaultDir,
		Passphrase:        testPassphrase,
		RecoveryPrintable: true,
	})
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init error = %v, want ErrAlreadyInitialized", err)
	}

	// The original vault and identity are untouched.
	devices, err := vault.ReadDevices(vaultDir)
	if err != nil {
		t.Fatalf("read devices after refused init: %v", err)
	}
	if devices.Devices[0].Recipient != first.DeviceRecipient {
		t.Error("refused init modified the existing recipient set")
	}
	if !identity.Exists(first.VaultID) {
		t.Error("refused init removed the original identity")
	}
}

// TestInitRefusesWithoutARecoveryDestination covers the criterion that a
// redirected standard output cannot capture a recovery identity.
//
// This is checked as a precondition, so a refusal happens before anything is
// created -- a vault whose recovery key went into a CI log is a vault that is
// one lost laptop from being unrecoverable.
func TestInitRefusesWithoutARecoveryDestination(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	_, err := New().Init(context.Background(), InitRequest{
		VaultDir:          vaultDir,
		Passphrase:        testPassphrase,
		RecoveryPrintable: false, // stdout is not a terminal
		RecoveryOut:       "",
	})
	if !errors.Is(err, ErrRecoveryUndeliverable) {
		t.Fatalf("error = %v, want ErrRecoveryUndeliverable", err)
	}

	// Nothing was created. A refusal must cost nothing.
	if _, err := os.Stat(vaultDir); !errors.Is(err, os.ErrNotExist) {
		t.Error("refused init created the vault directory")
	}
	idDir, err := identity.Dir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(idDir)
	if err == nil && len(entries) != 0 {
		t.Errorf("refused init left %d identity file(s) behind", len(entries))
	}
}

// TestInitWritesRecoveryToFile checks the explicit-destination path.
func TestInitWritesRecoveryToFile(t *testing.T) {
	isolateConfig(t)
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	recoveryPath := filepath.Join(base, "recovery.key")

	res, err := New().Init(context.Background(), InitRequest{
		VaultDir:          vaultDir,
		Passphrase:        testPassphrase,
		RecoveryOut:       recoveryPath,
		RecoveryPrintable: false, // a file destination makes printing unnecessary
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if res.RecoveryIdentity != "" {
		t.Error("recovery identity was returned for printing even though a file was given")
	}
	if res.RecoveryWrittenTo != recoveryPath {
		t.Errorf("RecoveryWrittenTo = %q, want %q", res.RecoveryWrittenTo, recoveryPath)
	}

	raw, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatalf("read recovery file: %v", err)
	}
	key := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(key, "AGE-SECRET-KEY-") {
		t.Errorf("recovery file does not contain an age identity: %q", key)
	}
	if key == res.DeviceRecipient {
		t.Error("recovery file contains the device recipient, not the recovery key")
	}

	// And the recovery key is still not in the vault.
	if strings.Contains(readTree(t, vaultDir), key) {
		t.Error("recovery key was written inside the vault directory")
	}

	// Refuse to overwrite an existing recovery file.
	if _, err := New().Init(context.Background(), InitRequest{
		VaultDir:          filepath.Join(base, "vault2"),
		Passphrase:        testPassphrase,
		RecoveryOut:       recoveryPath,
		RecoveryPrintable: false,
	}); err == nil {
		t.Error("init overwrote an existing recovery file")
	}
}

// TestInitUndoesEverythingOnFailure checks the rollback path.
//
// The identity is written before the vault, because the vault is useless without
// it. That ordering means a later failure must remove the identity again, or a
// retry would find a key for a vault that does not exist.
func TestInitUndoesEverythingOnFailure(t *testing.T) {
	isolateConfig(t)
	base := t.TempDir()

	// A file where a directory needs to be, so creating the vault must fail.
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := New().Init(context.Background(), InitRequest{
		VaultDir:          filepath.Join(blocker, "vault"),
		Passphrase:        testPassphrase,
		RecoveryPrintable: true,
	})
	if err == nil {
		t.Fatal("init succeeded where the vault directory could not be created")
	}

	idDir, err := identity.Dir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(idDir)
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".key") {
				t.Errorf("failed init left identity %s behind", e.Name())
			}
		}
	}
}

// TestRecoveryIdentityIsUsable checks that the recovery key is a real key and
// not merely a string that looks like one.
func TestRecoveryIdentityIsUsable(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	res := mustInit(t, vaultDir)
	if res.RecoveryIdentity == "" {
		t.Fatal("no recovery identity was returned")
	}

	// It parses as an age identity, and it is a genuinely different key from the
	// device identity -- otherwise "recovery" would be a second copy of the same
	// secret and would not survive losing the device key.
	recoveryRecipient, err := envelope.RecipientOf(res.RecoveryIdentity)
	if err != nil {
		t.Fatalf("recovery identity does not parse as an age key: %v", err)
	}
	if recoveryRecipient == res.DeviceRecipient {
		t.Fatal("recovery identity is the same key as the device identity")
	}
	if recoveryRecipient != res.RecoveryRecipient {
		t.Errorf("recovery recipient = %q, but derived %q", res.RecoveryRecipient, recoveryRecipient)
	}
}

// assertNoKeyMaterial fails if any file under dir contains an age private key.
func assertNoKeyMaterial(t *testing.T, dir string) {
	t.Helper()
	tree := readTree(t, dir)
	if strings.Contains(tree, "AGE-SECRET-KEY") {
		t.Errorf("private key material found under %s", dir)
	}
}

// readTree concatenates every regular file under dir.
func readTree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b.Write(data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return b.String()
}

// TestIdentityPermissionsAreCheckedOnPosix verifies that a world-readable key is
// refused rather than silently used.
//
// Skipped on Windows, where mode bits do not exist and the platform module
// checks the key's location instead.
func TestIdentityPermissionsAreCheckedOnPosix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not available on Windows")
	}
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	res := mustInit(t, vaultDir)

	// Loosen the key, then confirm loading refuses it.
	if err := os.Chmod(res.IdentityPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(res.VaultID, testPassphrase); err == nil {
		t.Fatal("a world-readable identity was loaded without complaint")
	}
}

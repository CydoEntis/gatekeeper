package cli

import (
	"strings"
	"testing"
)

const newTestPassphrase = "a completely different passphrase"

// TestPasswdChangesThePassphrase is the acceptance test: the old passphrase stops
// working and the new one starts.
func TestPasswdChangesThePassphrase(t *testing.T) {
	v := newTestVault(t)
	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "DEMO_SECRET="+testCanary+"\n")); code != ExitOK {
		t.Fatalf("seeding: %s", stderr)
	}

	newPass := passphraseFileWith(t, newTestPassphrase, 0o600)
	code, stdout, stderr := v.run(t, "passwd", "--new-passphrase-file", newPass)
	if code != ExitOK {
		t.Fatalf("passwd exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Passphrase changed") {
		t.Errorf("output: %q", stdout)
	}
	if strings.Contains(stdout+stderr, newTestPassphrase) || strings.Contains(stdout+stderr, testPassphrase) {
		t.Error("a passphrase was echoed into the output")
	}

	// The old passphrase is now wrong.
	code, _, _ = runArgs(t, "list", "demo", "--vault", v.dir, "--passphrase-file", v.passFile)
	if code != ExitLocked {
		t.Errorf("the old passphrase still works; exit = %d", code)
	}

	// The new one works, and the data is intact.
	code, stdout, stderr = runArgs(t, "list", "demo", "--vault", v.dir, "--passphrase-file", newPass)
	if code != ExitOK {
		t.Fatalf("the new passphrase did not work: exit %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "DEMO_SECRET") {
		t.Errorf("listing after the change: %q", stdout)
	}
}

// TestPasswdNeedsTheCurrentPassphrase checks this cannot be used to take over a
// vault you cannot already open.
func TestPasswdNeedsTheCurrentPassphrase(t *testing.T) {
	v := newTestVault(t)

	wrong := passphraseFileWith(t, "not the current passphrase", 0o600)
	newPass := passphraseFileWith(t, newTestPassphrase, 0o600)

	code, _, stderr := runArgs(t, "passwd",
		"--vault", v.dir,
		"--passphrase-file", wrong,
		"--new-passphrase-file", newPass,
	)
	if code != ExitLocked {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitLocked, stderr)
	}

	// And the original passphrase still works: a refused change must not have
	// half-applied.
	code, _, stderr = runArgs(t, "list", "demo", "--vault", v.dir, "--passphrase-file", v.passFile)
	if code == ExitLocked {
		t.Fatalf("a refused change broke the original passphrase: %s", stderr)
	}
}

// TestPasswdRefusesTheSamePassphrase checks the obvious no-op is reported rather
// than silently rewriting the key file.
func TestPasswdRefusesTheSamePassphrase(t *testing.T) {
	v := newTestVault(t)

	code, _, stderr := v.run(t, "passwd", "--new-passphrase-file", v.passFile)
	if code == ExitOK {
		t.Fatal("changing to the same passphrase was accepted")
	}
	if !strings.Contains(stderr, "same as the current one") {
		t.Errorf("error is not explanatory: %s", stderr)
	}
}

// TestPasswdRefusesAWeakReplacement checks the length policy applies here too,
// and applies before anything is written.
func TestPasswdRefusesAWeakReplacement(t *testing.T) {
	v := newTestVault(t)

	weak := passphraseFileWith(t, "short", 0o600)
	code, _, stderr := v.run(t, "passwd", "--new-passphrase-file", weak)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitUsage, stderr)
	}

	// The original still works.
	if code, _, _ := runArgs(t, "list", "demo", "--vault", v.dir, "--passphrase-file", v.passFile); code == ExitLocked {
		t.Error("a refused change broke the original passphrase")
	}
}

// TestPasswdExplainsTheRecoveryKey checks the unhelpful case is caught before
// prompting for anything.
func TestPasswdExplainsTheRecoveryKey(t *testing.T) {
	v := newTestVault(t)

	code, _, stderr := runArgs(t, "passwd", "--vault", v.dir, "--identity", v.recovery)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "recovery key has no passphrase") {
		t.Errorf("error does not explain itself: %s", stderr)
	}
}

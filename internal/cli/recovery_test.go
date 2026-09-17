package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecoveryKeyRestoresAccessWithNoLocalIdentity is the acceptance test for the
// definition of done: "the recovery identity restores access without any device".
//
// It has to be exercised through the real command layer. The cryptography was
// already proven by a unit test, but proving the *cipher works* is not the same as
// proving a person can get their secrets back — and for a while that gap was real:
// there was no way to hand a recovery key to `gk` at all.
func TestRecoveryKeyRestoresAccessWithNoLocalIdentity(t *testing.T) {
	v := newTestVault(t)
	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "DEMO_SECRET="+testCanary+"\n")); code != ExitOK {
		t.Fatalf("import: %s", stderr)
	}

	// Lose the machine: the local identity is gone, and so is the passphrase for
	// it, in the sense that neither is available any more.
	identityPath := findIdentityFile(t)
	if identityPath == "" {
		t.Fatal("could not find the local identity to remove")
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}

	// The everyday path is now closed.
	if code, _, _ := v.run(t, "list", "demo"); code == ExitOK {
		t.Fatal("list succeeded with no local identity present")
	}

	// The recovery key opens it, with no passphrase.
	code, stdout, stderr := runArgs(t, "list", "demo", "--vault", v.dir, "--identity", v.recovery)
	if code != ExitOK {
		t.Fatalf("list with the recovery key exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "DEMO_SECRET") {
		t.Errorf("the recovered listing is missing the variable: %q", stdout)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Error("listing through the recovery key disclosed a value")
	}

	// And the values really come back, not just the names.
	restored := filepath.Join(t.TempDir(), "restored.env")
	code, _, stderr = runArgs(t, "export", "demo", "--output", restored, "--vault", v.dir, "--identity", v.recovery)
	if code != ExitOK {
		t.Fatalf("export with the recovery key exited %d; stderr: %s", code, stderr)
	}
	data, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), testCanary) {
		t.Errorf("the recovery key did not recover the value:\n%s", data)
	}
}

// TestIdentityFlagRejectsAWorldReadableKey keeps the recovery path to the same
// standard as every other secret file.
func TestIdentityFlagRejectsAWorldReadableKey(t *testing.T) {
	v := newTestVault(t)

	if err := os.Chmod(v.recovery, 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runArgs(t, "list", "demo", "--vault", v.dir, "--identity", v.recovery)
	if code != ExitPermission {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitPermission, stderr)
	}
	if strings.Contains(stdout+stderr, "AGE-SECRET-KEY") {
		t.Error("the refusal echoed key material")
	}
}

// TestIdentityFlagRejectsSomethingThatIsNotAKey checks a wrong file fails with a
// clear message rather than a confusing decryption error later.
func TestIdentityFlagRejectsSomethingThatIsNotAKey(t *testing.T) {
	v := newTestVault(t)

	notAKey := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notAKey, []byte("this is not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runArgs(t, "list", "demo", "--vault", v.dir, "--identity", notAKey)
	if code == ExitOK {
		t.Fatal("a file that is not a key was accepted")
	}
	if !strings.Contains(stderr, "not a usable age private key") {
		t.Errorf("error is not explanatory: %s", stderr)
	}
}

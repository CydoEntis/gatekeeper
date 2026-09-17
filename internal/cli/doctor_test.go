package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDoctor executes doctor with only the vault flag.
//
// `doctor` deliberately has no --passphrase-file flag — it does not need the
// passphrase, which is the point — so the usual test helper does not apply.
func (v testVault) runDoctor(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{}, args...)
	full = append(full, "--vault", v.dir)
	return runArgs(t, full...)
}

// TestDoctorPassesOnAHealthyVault checks the diagnostic is quiet when everything
// is in order, so that a failure means something.
func TestDoctorPassesOnAHealthyVault(t *testing.T) {
	v := newTestVault(t)

	code, stdout, stderr := v.runDoctor(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d; stderr: %s\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "Everything checks out") {
		t.Errorf("doctor output:\n%s", stdout)
	}
	for _, want := range []string{
		"vault readable",
		"recipients readable",
		"identity present",
		"identity protected",
		"no key material in the vault",
		"vault has ignore rules",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("doctor did not report %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout+stderr, "AGE-SECRET-KEY") {
		t.Error("doctor printed key material")
	}
}

// TestDoctorStillWorksWithoutThePassphrase is the property that makes it useful:
// it must run in the situation where the vault will not open.
func TestDoctorStillWorksWithoutThePassphrase(t *testing.T) {
	v := newTestVault(t)

	// No --passphrase-file, and standard input is not a terminal.
	withNonTerminalStdin(t)
	code, stdout, stderr := runArgs(t, "doctor", "--vault", v.dir)
	if code != ExitOK {
		t.Fatalf("doctor exit = %d; stderr: %s\n%s", code, stderr, stdout)
	}
}

// TestDoctorReportsAMissingIdentity checks a broken state is actually reported,
// rather than passing because the checks are shallow.
func TestDoctorReportsAMissingIdentity(t *testing.T) {
	v := newTestVault(t)

	// Remove the identity, leaving a vault nobody can open.
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(v.passFile), "..", "**", "*.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Walk to find the identity rather than guessing the config layout.
	identityPath := findIdentityFile(t)
	if identityPath == "" {
		t.Fatalf("could not find the identity file (glob gave %v)", matches)
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := v.runDoctor(t, "doctor")
	if code == ExitOK {
		t.Fatalf("doctor passed with no identity:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "identity present") {
		t.Errorf("doctor did not report the missing identity:\n%s", stdout)
	}
	if !strings.Contains(stderr, "check(s) failed") {
		t.Errorf("stderr does not summarise the failures: %s", stderr)
	}
}

// TestDoctorPreCommitRefusesSecrets is the guardrail that exists for the mistake
// the threat model calls dominant.
func TestDoctorPreCommitRefusesSecrets(t *testing.T) {
	dir := t.TempDir()
	// A dotenv file and an identity-shaped file, as a careless `git add -A` would
	// sweep up.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.key"), []byte("opaque\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runArgs(t, "doctor", "--pre-commit", "--path", dir)
	if code != ExitPermission {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitPermission, stderr)
	}
	if !strings.Contains(stderr, ".env") || !strings.Contains(stderr, "deploy.key") {
		t.Errorf("the refusal does not list every finding:\n%s", stderr)
	}
	// A hook must not print the offending contents.
	if strings.Contains(stdout+stderr, "SECRET=value") {
		t.Error("the refusal printed the contents of a secret file")
	}
	// And it must say what to do about a key that already leaked.
	if !strings.Contains(stderr, "rotated") {
		t.Errorf("the refusal does not mention rotation: %s", stderr)
	}
}

func TestDoctorPreCommitPassesACleanDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.example"), []byte("A=\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runArgs(t, "doctor", "--pre-commit", "--path", dir)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "No secrets found") {
		t.Errorf("output: %s", stdout)
	}
}

// findIdentityFile locates the identity written under the isolated config
// directory.
func findIdentityFile(t *testing.T) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(os.Getenv("XDG_CONFIG_HOME"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(path, ".key") {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

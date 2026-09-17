package cli

import (
	"bytes"
	"gatekeeper/internal/platform"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testPassphrase = "correct horse battery staple"

// isolateConfig points the per-user configuration directory at a temporary
// directory so tests never read or write the developer's real identities.
func isolateConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("APPDATA", dir)
}

// passphraseFileWith writes a passphrase to a file with an explicit mode.
//
// The explicit Chmod matters: os.WriteFile is subject to the process umask, so
// asking for 0600 can silently produce something else.
func passphraseFileWith(t *testing.T, passphrase string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase.txt")
	if err := os.WriteFile(path, []byte(passphrase+"\n"), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

func passphraseFile(t *testing.T) string {
	t.Helper()
	return passphraseFileWith(t, testPassphrase, platform.PrivateFileMode)
}

// withNonTerminalStdin detaches standard input from the terminal so a test that
// expects a refusal is deterministic.
//
// This is not cosmetic. Running `go test` from a terminal leaves the test process
// with that terminal on stdin, so a passphrase prompt would block forever waiting
// for someone to type. /dev/null (NUL on Windows) is a character device that is
// not a terminal, which is exactly the case worth exercising.
func withNonTerminalStdin(t *testing.T) {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	previous := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = previous
		f.Close()
	})
}

// TestInitRefusesToLeakRecoveryToNonTerminal is the command-level version of the
// Phase 4 criterion: redirected standard output cannot capture a recovery
// identity.
//
// Under `go test`, stdout is not a terminal, which is exactly the condition being
// tested. The command must refuse, explain how to proceed, and print no key
// material on either stream.
func TestInitRefusesToLeakRecoveryToNonTerminal(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{
		"init", "--vault", vaultDir, "--passphrase-file", passphraseFile(t),
	}, &stdout, &stderr)

	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitUsage, stderr.String())
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "AGE-SECRET-KEY") {
		t.Fatal("private key material reached a non-terminal destination")
	}
	// The refusal has to be actionable, not just safe.
	if !strings.Contains(stderr.String(), "recovery-out") {
		t.Errorf("refusal does not say how to proceed: %s", stderr.String())
	}
}

// TestInitRefusesWithoutAPassphraseSource checks that a passphrase is never
// invented, defaulted, or read from somewhere unsafe.
//
// There is deliberately no environment-variable fallback: every child process
// inherits the environment, so an exported passphrase would be handed to every
// program `gk run` starts.
func TestInitRefusesWithoutAPassphraseSource(t *testing.T) {
	isolateConfig(t)
	base := t.TempDir()
	withNonTerminalStdin(t)

	for _, env := range []string{"GK_PASSPHRASE", "ENVSAFE_PASSPHRASE", "PASSPHRASE"} {
		t.Setenv(env, testPassphrase)
	}

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{
		"init", "--vault", filepath.Join(base, "vault"),
		"--recovery-out", filepath.Join(base, "recovery.key"),
	}, &stdout, &stderr)

	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitUsage, stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "AGE-SECRET-KEY") {
		t.Fatal("private key material was printed")
	}
	if !strings.Contains(stderr.String(), "passphrase-file") {
		t.Errorf("refusal does not say how to supply a passphrase: %s", stderr.String())
	}
	// An environment variable must not have been silently accepted.
	if _, err := os.Stat(filepath.Join(base, "vault")); !os.IsNotExist(err) {
		t.Error("init proceeded using an environment-variable passphrase")
	}
}

// TestInitRejectsAWorldReadablePassphraseFile checks the permission rule, which
// exists because a passphrase in a readable file defeats the encryption it
// protects.
func TestInitRejectsAWorldReadablePassphraseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not available on Windows")
	}
	isolateConfig(t)
	base := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{
		"init",
		"--vault", filepath.Join(base, "vault"),
		"--recovery-out", filepath.Join(base, "recovery.key"),
		"--passphrase-file", passphraseFileWith(t, testPassphrase, 0o644),
	}, &stdout, &stderr)

	if code != ExitPermission {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, ExitPermission, stderr.String())
	}
	if !strings.Contains(stderr.String(), "readable by others") {
		t.Errorf("error does not explain the problem: %s", stderr.String())
	}
}

// TestShortPassphraseWarnsButProceeds pins the policy: the minimum is enforced,
// the warning threshold is not. Refusing a 14-character passphrase would push
// people toward writing it down, which is worse than a slightly short one.
func TestShortPassphraseWarnsButProceeds(t *testing.T) {
	isolateConfig(t)
	base := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{
		"init",
		"--vault", filepath.Join(base, "vault"),
		"--recovery-out", filepath.Join(base, "recovery.key"),
		"--passphrase-file", passphraseFileWith(t, "fourteenchars!", platform.PrivateFileMode),
	}, &stdout, &stderr)

	if code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Errorf("a short passphrase produced no warning: %s", stderr.String())
	}
	// The warning must not echo the passphrase itself.
	if strings.Contains(stdout.String()+stderr.String(), "fourteenchars!") {
		t.Error("the passphrase was echoed into the output")
	}
}

// TestInitWithRecoveryOutSucceeds checks the explicit-destination path end to
// end through the command layer.
func TestInitWithRecoveryOutSucceeds(t *testing.T) {
	isolateConfig(t)
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	recoveryPath := filepath.Join(base, "recovery.key")

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{
		"init", "--vault", vaultDir,
		"--recovery-out", recoveryPath,
		"--passphrase-file", passphraseFile(t),
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}

	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "AGE-SECRET-KEY") {
		t.Error("private key material was printed even though a file was given")
	}
	if strings.Contains(combined, testPassphrase) {
		t.Error("the passphrase was echoed into the output")
	}

	// The output must explain the one manual step, because that is the step
	// people get wrong.
	for _, want := range []string{"On another machine", "the one thing Git must never carry"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("init output does not mention %q", want)
		}
	}
}

// TestInitRequiresAVault covers the usage error path and its exit code.
//
// This is checked before the passphrase is read, so a missing vault costs the
// user no typing.
func TestInitRequiresAVault(t *testing.T) {
	isolateConfig(t)

	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{"init"}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "--vault") {
		t.Errorf("error does not name the missing flag: %s", stderr.String())
	}
}

// TestHelpRuns keeps `gk --help` working, which Phase 0 lists as an
// acceptance criterion.
func TestHelpRuns(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := ExecuteWith([]string{"--help"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Gatekeeper") {
		t.Error("help output does not name the program")
	}
	// The command is short, and the help must show it as such.
	if !strings.Contains(stdout.String(), "gk [flags]") {
		t.Error("help output does not show the `gk` command")
	}
	// And it must not claim more maturity than exists.
	if !strings.Contains(stdout.String(), "Pre-release") {
		t.Error("help text does not disclose pre-release status")
	}
}

// TestUnknownFlagIsAUsageError checks that bad input is not reported as an
// internal failure.
func TestUnknownFlagIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := ExecuteWith([]string{"init", "--nope"}, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
}

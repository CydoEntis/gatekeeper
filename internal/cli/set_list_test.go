package cli

import (
	"bytes"
	"gatekeeper/internal/platform"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testCanary is distinctive enough that finding it anywhere is proof of a
// disclosure, and obviously fake so it can never be mistaken for a credential.
const testCanary = "CANARY-do-not-disclose-8f3a91c4"

// testVault is a vault that has been initialized through the real command layer.
type testVault struct {
	dir      string
	passFile string
	// recovery is the offline recovery key written by init. It is the way back in
	// when the local identity is gone.
	recovery string
}

// newTestVault runs `gk init` exactly as a user would, so later assertions test
// the shipped path rather than a hand-built fixture.
func newTestVault(t *testing.T) testVault {
	t.Helper()
	isolateConfig(t)
	base := t.TempDir()

	v := testVault{
		dir:      filepath.Join(base, "vault"),
		passFile: passphraseFile(t),
		recovery: filepath.Join(base, "recovery.key"),
	}
	code, _, stderr := runArgs(t,
		"init", "--vault", v.dir,
		"--recovery-out", v.recovery,
		"--passphrase-file", v.passFile,
	)
	if code != ExitOK {
		t.Fatalf("init failed with exit %d; stderr: %s", code, stderr)
	}
	return v
}

// runArgs executes the CLI and returns the exit code and both streams.
func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := ExecuteWith(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// run executes a command against this vault, supplying the vault and passphrase.
func (v testVault) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	full := make([]string, 0, len(args)+4)
	full = append(full, args...)
	full = append(full, "--vault", v.dir, "--passphrase-file", v.passFile)
	return runArgs(t, full...)
}

// TestSetStoresWithoutDisclosingAnything is the core command-level acceptance
// test: the value goes in, and nothing about it comes out.
func TestSetStoresWithoutDisclosingAnything(t *testing.T) {
	v := newTestVault(t)
	valuePath := passphraseFileWith(t, testCanary, platform.PrivateFileMode)

	code, stdout, stderr := v.run(t, "set", "website-dev", "DATABASE_URL", "--value-file", valuePath)
	if code != ExitOK {
		t.Fatalf("set exit = %d; stderr: %s", code, stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("set echoed the value")
	}
	if !strings.Contains(stdout, "Created") {
		t.Errorf("set did not report creating the profile: %q", stdout)
	}

	// Nothing readable in the vault directory.
	assertVaultHasNoCanary(t, v.dir)

	// Listing names the variable, and still reveals nothing.
	code, stdout, stderr = v.run(t, "list", "website-dev")
	if code != ExitOK {
		t.Fatalf("list exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "DATABASE_URL") {
		t.Errorf("list did not name the variable: %q", stdout)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("list revealed the value")
	}
}

// TestListWithNoArgumentNamesTheProfiles covers the discovery path, which is the
// only way to find out what exists while `gk profile create` is deferred.
func TestListWithNoArgumentNamesTheProfiles(t *testing.T) {
	v := newTestVault(t)
	valuePath := passphraseFileWith(t, testCanary, platform.PrivateFileMode)

	// An empty vault says so rather than printing nothing.
	code, stdout, stderr := v.run(t, "list")
	if code != ExitOK {
		t.Fatalf("list exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "No profiles yet") {
		t.Errorf("empty vault output = %q", stdout)
	}

	for _, name := range []string{"website-dev", "website-prod"} {
		if code, _, stderr := v.run(t, "set", name, "DEMO_SECRET", "--value-file", valuePath); code != ExitOK {
			t.Fatalf("set %s exit = %d; stderr: %s", name, code, stderr)
		}
	}

	code, stdout, stderr = v.run(t, "list")
	if code != ExitOK {
		t.Fatalf("list exit = %d; stderr: %s", code, stderr)
	}
	for _, name := range []string{"website-dev", "website-prod"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("list did not name %q: %q", name, stdout)
		}
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("list revealed a value")
	}
}

// TestSetRefusesANonTerminalValueSource checks that a secret is never silently
// read from a pipe.
//
// A pipe is how a value would end up in a CI log or a shell transcript, which is
// the thing this command exists to avoid.
func TestSetRefusesANonTerminalValueSource(t *testing.T) {
	v := newTestVault(t)
	withNonTerminalStdin(t)

	code, stdout, stderr := v.run(t, "set", "website-dev", "DATABASE_URL")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "value-file") {
		t.Errorf("refusal does not say how to proceed: %s", stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("a value was read and echoed from a non-terminal")
	}
}

// TestAMissingPassphraseFileIsNotFoundNotAFailure checks a mistyped path is
// reported as a missing file.
//
// It used to fall through to ExitFailure, which ARCHITECTURE.md section 9
// reserves for "an unclassified problem the user cannot act on". A path the user
// fat-fingered is the opposite of that, and the generic code made a typo look
// like a bug in Gatekeeper.
func TestAMissingPassphraseFileIsNotFoundNotAFailure(t *testing.T) {
	v := newTestVault(t)
	missing := filepath.Join(t.TempDir(), "no-such-passphrase-file")

	// runArgs rather than v.run: v.run appends its own valid --passphrase-file,
	// and cobra takes the last value, which would hide the one under test.
	code, stdout, stderr := runArgs(t, "list", "--vault", v.dir, "--passphrase-file", missing)
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitNotFound, stderr)
	}
	if !strings.Contains(stderr, "no-such-passphrase-file") {
		t.Errorf("error does not name the missing file: %s", stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("a value was disclosed while reporting a missing file")
	}
}

// TestSetRejectsAWorldReadableValueFile applies the same rule as the passphrase:
// a secret in a readable file is not protected.
func TestSetRejectsAWorldReadableValueFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not available on Windows")
	}
	v := newTestVault(t)
	valuePath := passphraseFileWith(t, testCanary, 0o644)

	code, stdout, stderr := v.run(t, "set", "website-dev", "DATABASE_URL", "--value-file", valuePath)
	if code != ExitPermission {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitPermission, stderr)
	}
	if !strings.Contains(stderr, "readable by others") {
		t.Errorf("error does not explain the problem: %s", stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("the value from a rejected file was echoed")
	}
}

// TestSetRejectsBadNamesBeforePrompting checks that a typo costs the user nothing.
func TestSetRejectsBadNamesBeforePrompting(t *testing.T) {
	v := newTestVault(t)
	withNonTerminalStdin(t)

	for _, tc := range []struct{ profile, key string }{
		{"../escape", "OK"},
		{"website-dev", "../escape"},
		{"UPPER", "OK"},
	} {
		code, _, stderr := v.run(t, "set", tc.profile, tc.key)
		// Usage, not a lock failure: the names are checked before the vault is
		// ever unlocked.
		if code != ExitUsage {
			t.Errorf("set(%q, %q) exit = %d, want %d; stderr: %s",
				tc.profile, tc.key, code, ExitUsage, stderr)
		}
	}
}

// TestSetRequiresTwoArguments covers the argument-count path.
func TestSetRequiresTwoArguments(t *testing.T) {
	v := newTestVault(t)

	code, _, stderr := v.run(t, "set", "website-dev")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "gk set") {
		t.Errorf("error does not show the usage: %s", stderr)
	}
}

// TestWrongPassphraseIsLockedNotCorrupt checks the exit code tells a script the
// difference between "you cannot open it" and "it is damaged".
func TestWrongPassphraseIsLockedNotCorrupt(t *testing.T) {
	v := newTestVault(t)

	code, stdout, stderr := runArgs(t,
		"list", "--vault", v.dir, "--passphrase-file", passphraseFileWith(t, "wrong passphrase entirely", platform.PrivateFileMode),
	)
	if code != ExitLocked {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitLocked, stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("output leaked something")
	}
}

// TestSetAndListHelpIsExplicitAboutNotRevealing keeps the help honest about what
// each command does and does not disclose.
func TestSetAndListHelpIsExplicitAboutNotRevealing(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		// `set` must explain why the value cannot be an argument.
		{"set", []string{"shell history", "process list"}},
		// `list` must say plainly that it shows no values.
		{"list", []string{"shows a value"}},
	} {
		code, stdout, _ := runArgs(t, tc.command, "--help")
		if code != ExitOK {
			t.Fatalf("%s --help exit = %d", tc.command, code)
		}
		help := strings.ToLower(stdout)
		for _, want := range tc.want {
			if !strings.Contains(help, want) {
				t.Errorf("%s --help does not mention %q:\n%s", tc.command, want, stdout)
			}
		}
	}
}

// assertVaultHasNoCanary fails if the canary appears in any file in the vault.
func assertVaultHasNoCanary(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
		if strings.Contains(string(data), testCanary) {
			t.Errorf("the canary appears in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk vault: %v", err)
	}
}

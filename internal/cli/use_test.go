package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gatekeeper/internal/identity"
)

// TestUseVaultIsTheSecondMachineStep covers the gap that simulating a second
// machine exposed.
//
// `init` records a default vault, but `init` cannot run against a vault that
// already exists — so a new machine had no way to stop passing `--vault` on every
// command, and the error message pointed at a command that would refuse.
func TestUseVaultIsTheSecondMachineStep(t *testing.T) {
	// --- Machine A: make a vault with a profile, note where its identity is ---
	source := newTestVault(t)
	if code, _, stderr := source.run(t, "import", "demo", writeDotenv(t, "DEMO_SECRET="+testCanary+"\n")); code != ExitOK {
		t.Fatalf("seeding machine A: %s", stderr)
	}
	aIdentity := findIdentityFile(t)
	if aIdentity == "" {
		t.Fatal("machine A produced no identity")
	}
	aIdentityBytes, err := os.ReadFile(aIdentity)
	if err != nil {
		t.Fatal(err)
	}

	// --- Machine B: a fresh config directory, and the vault folder copied over.
	// This is the whole of "syncing": any tool that copies a directory will do.
	isolateConfig(t)
	destination := filepath.Join(t.TempDir(), "vault")
	if err := os.CopyFS(destination, os.DirFS(source.dir)); err != nil {
		t.Fatalf("copying the vault to the second machine: %v", err)
	}
	passFile := passphraseFile(t)

	// The vault folder alone is not enough. Without the identity it cannot be
	// opened, which is exactly the property that makes it safe to host.
	code, _, _ := runArgs(t, "list", "demo", "--vault", destination, "--passphrase-file", passFile)
	if code != ExitNotFound {
		t.Errorf("a vault with no local identity should report that; exit = %d", code)
	}

	// Point at the vault once.
	code, stdout, stderr := runArgs(t, "use", destination)
	if code != ExitOK {
		t.Fatalf("use exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "No command needs --vault") {
		t.Errorf("use output: %q", stdout)
	}

	// Copy the identity by hand, once. This is the step that never goes through
	// Git or any sync tool, by design.
	identitiesDir, err := identity.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(identitiesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(identitiesDir, filepath.Base(aIdentity)), aIdentityBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// And now no flag is needed.
	code, stdout, stderr = runArgs(t, "list", "demo", "--passphrase-file", passFile)
	if code != ExitOK {
		t.Fatalf("list without --vault exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "DEMO_SECRET") {
		t.Errorf("listing after use: %q", stdout)
	}
}

// TestUseVaultRefusesSomethingThatIsNotAVault keeps a typo from silently becoming
// the default for every later command.
func TestUseVaultRefusesSomethingThatIsNotAVault(t *testing.T) {
	isolateConfig(t)

	code, _, stderr := runArgs(t, "use", t.TempDir())
	if code == ExitOK {
		t.Fatal("use accepted a directory that is not a vault")
	}
	if !strings.Contains(strings.ToLower(stderr), "vault") {
		t.Errorf("error is not explanatory: %s", stderr)
	}
}

// TestUseVaultNeedsAnArgument covers the usage path.
func TestUseVaultNeedsAnArgument(t *testing.T) {
	isolateConfig(t)

	code, _, stderr := runArgs(t, "use")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "gk use") {
		t.Errorf("error does not show the form to use: %s", stderr)
	}
}

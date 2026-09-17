package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gatekeeper/internal/identity"
	"gatekeeper/internal/vault"
)

// testCanary is distinctive enough that finding it anywhere is proof of a
// disclosure, and obviously fake so it can never be mistaken for a credential.
const testCanary = "CANARY-do-not-disclose-8f3a91c4"

// readValueDirectly opens the vault without going through App, so the round-trip
// assertion does not depend on the same code path that wrote the value.
func readValueDirectly(t *testing.T, vaultDir, profile, key string) string {
	t.Helper()

	manifest, err := vault.ReadManifest(vaultDir)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	id, err := identity.Load(manifest.VaultID, testPassphrase)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	v, err := vault.Open(vaultDir, id.Private)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	p, err := v.Read(context.Background(), profile)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return p.Variables[key]
}

// TestSetCreatesProfileAndEncrypts is the core acceptance test for step 3.
func TestSetCreatesProfileAndEncrypts(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	mustInit(t, vaultDir)

	ctx := context.Background()
	a := New()
	ref := VaultRef{Dir: vaultDir, Passphrase: testPassphrase}

	// First set creates the profile: with `gk profile create` deferred, this is
	// what makes a profile exist at all.
	created, err := a.Set(ctx, ref, SetRequest{Profile: "demo", Key: "DEMO_SECRET", Value: testCanary})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !created.Created {
		t.Error("the first set did not report that it created the profile")
	}
	if created.Revision != 1 {
		t.Errorf("revision = %d, want 1", created.Revision)
	}
	if created.Profile != "demo" {
		t.Errorf("profile = %q, want demo", created.Profile)
	}

	// A second set updates in place and bumps the revision.
	updated, err := a.Set(ctx, ref, SetRequest{Profile: "demo", Key: "OTHER_KEY", Value: "another"})
	if err != nil {
		t.Fatalf("second set: %v", err)
	}
	if updated.Created {
		t.Error("the second set wrongly reported that it created the profile")
	}
	if updated.Revision != 2 {
		t.Errorf("revision = %d, want 2", updated.Revision)
	}

	// The value survives a round trip.
	if got := readValueDirectly(t, vaultDir, "demo", "DEMO_SECRET"); got != testCanary {
		t.Fatalf("stored value = %q, want the canary", got)
	}

	// The names come back sorted, so output is stable between runs.
	summary, err := a.List(ctx, ref, "demo")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"DEMO_SECRET", "OTHER_KEY"}
	if strings.Join(summary.Vars, ",") != strings.Join(want, ",") {
		t.Errorf("variables = %v, want %v", summary.Vars, want)
	}

	// And the plaintext is nowhere on disk.
	if tree := readTree(t, vaultDir); strings.Contains(tree, testCanary) {
		t.Fatal("the canary appears somewhere in the vault directory")
	}
}

// TestProfilesNamesProfilesWithoutValues checks the listing path a user runs
// before they know what exists.
func TestProfilesNamesProfilesWithoutValues(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	mustInit(t, vaultDir)

	ctx := context.Background()
	a := New()
	ref := VaultRef{Dir: vaultDir, Passphrase: testPassphrase}

	// An empty vault lists nothing and is not an error.
	if got, err := a.Profiles(ctx, ref); err != nil {
		t.Fatalf("profiles on an empty vault: %v", err)
	} else if len(got) != 0 {
		t.Errorf("empty vault listed %d profiles", len(got))
	}

	for _, name := range []string{"website-dev", "website-prod"} {
		if _, err := a.Set(ctx, ref, SetRequest{Profile: name, Key: "DEMO_SECRET", Value: testCanary}); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}

	got, err := a.Profiles(ctx, ref)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d profiles, want 2", len(got))
	}
	for _, s := range got {
		if len(s.Vars) != 1 || s.Vars[0] != "DEMO_SECRET" {
			t.Errorf("profile %s names = %v", s.Name, s.Vars)
		}
	}
}

// TestWrongPassphraseIsRefusedByVaultOperations checks the failure is the typed
// "locked" error and not something ambiguous.
func TestWrongPassphraseIsRefusedByVaultOperations(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	mustInit(t, vaultDir)

	bad := VaultRef{Dir: vaultDir, Passphrase: "the wrong passphrase entirely"}
	if _, err := New().Set(context.Background(), bad, SetRequest{Profile: "demo", Key: "K", Value: "v"}); !errors.Is(err, identity.ErrWrongPassphrase) {
		t.Errorf("Set err = %v, want ErrWrongPassphrase", err)
	}
	if _, err := New().Profiles(context.Background(), bad); !errors.Is(err, identity.ErrWrongPassphrase) {
		t.Errorf("Profiles err = %v, want ErrWrongPassphrase", err)
	}
}

// TestSetRejectsHostileNamesBeforeUnlocking checks that a bad name is caught by
// pure validation, so it cannot reach the filesystem as a path.
func TestSetRejectsHostileNamesBeforeUnlocking(t *testing.T) {
	isolateConfig(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	mustInit(t, vaultDir)

	ref := VaultRef{Dir: vaultDir, Passphrase: testPassphrase}
	for _, tc := range []struct{ profile, key string }{
		{"../escape", "OK"},
		{"demo", "../escape"},
		{"UPPER", "OK"},
		{"demo", "1STARTS_WITH_DIGIT"},
		{"demo", "has space"},
		{"", "OK"},
	} {
		_, err := New().Set(context.Background(), ref, SetRequest{
			Profile: tc.profile, Key: tc.key, Value: testCanary,
		})
		if !errors.Is(err, vault.ErrInvalidName) {
			t.Errorf("Set(%q, %q) err = %v, want ErrInvalidName", tc.profile, tc.key, err)
		}
	}

	// Nothing was written, and the vault directory is unchanged.
	entries, err := os.ReadDir(filepath.Join(vaultDir, "profiles"))
	if err != nil {
		t.Fatalf("read profiles dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("rejected names still wrote %d file(s)", len(entries))
	}
}

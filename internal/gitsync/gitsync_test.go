package gitsync

import (
	"context"
	"errors"
	"gatekeeper/internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitIn runs a git command in dir and fails the test on error.
//
// Identity is configured per repository rather than through the environment,
// which is what a real user has — and it is set up rather than assumed, because
// `gk sync` commits and would otherwise fail on a machine with no git identity.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

// configureIdentity gives a repository a committer identity.
func configureIdentity(t *testing.T, dir string) {
	t.Helper()
	gitIn(t, dir, "config", "user.name", "Gatekeeper Test")
	gitIn(t, dir, "config", "user.email", "test@example.invalid")
}

// newBareRemote creates an empty bare repository to act as the server.
func newBareRemote(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	gitIn(t, t.TempDir(), "init", "-q", "--bare", dir)
	return dir
}

// cloneOf clones the remote into a fresh directory, with an identity set.
func cloneOf(t *testing.T, remote string) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "clone", "-q", remote, ".")
	configureIdentity(t, dir)
	return dir
}

// newRepo returns an initialised repository with one commit and no remote.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	configureIdentity(t, dir)
	writeFile(t, dir, "README", "x\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "init")
	return dir
}

// seedRemote creates a bare remote containing one commit, and returns it.
func seedRemote(t *testing.T) string {
	t.Helper()
	remote := newBareRemote(t)
	dir := cloneOf(t, remote)
	writeFile(t, dir, "profiles/website-dev.age", "original")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "seed")
	gitIn(t, dir, "push", "-q", "-u", "origin", "HEAD")
	return remote
}

func TestSyncRefusesADirectoryThatIsNotARepository(t *testing.T) {
	_, err := (Git{Dir: t.TempDir()}).Sync(context.Background(), "")
	if !errors.Is(err, ErrNotARepository) {
		t.Fatalf("err = %v, want ErrNotARepository", err)
	}
}

// TestSyncRoundTrip covers the ordinary case: local changes are committed and
// pushed, and the other side receives them on its next sync.
func TestSyncRoundTrip(t *testing.T) {
	remote := seedRemote(t)
	a := cloneOf(t, remote)
	b := cloneOf(t, remote)

	// B changes a profile and syncs.
	writeFile(t, b, "profiles/website-dev.age", "ciphertext-from-B")
	result, err := (Git{Dir: b}).Sync(context.Background(), "")
	if err != nil {
		t.Fatalf("sync on B: %v", err)
	}
	if result.Commit == "" {
		t.Error("sync committed nothing")
	}
	if len(result.Changed) != 1 || result.Changed[0] != "website-dev" {
		t.Errorf("changed = %v, want [website-dev]", result.Changed)
	}
	if len(result.Steps) == 0 {
		t.Error("sync reported no steps")
	}

	// A pulls it.
	if _, err := (Git{Dir: a}).Sync(context.Background(), ""); err != nil {
		t.Fatalf("sync on A: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(a, "profiles", "website-dev.age"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ciphertext-from-B" {
		t.Errorf("A did not receive B's change: %q", got)
	}
}

// TestSyncCommitMessageNamesOnlyProfiles is the disclosure test for this package.
//
// A commit message is permanent, and often public. It may name profiles, whose
// names are already filenames, and nothing else.
func TestSyncCommitMessageNamesOnlyProfiles(t *testing.T) {
	remote := seedRemote(t)
	dir := cloneOf(t, remote)

	writeFile(t, dir, "profiles/website-dev.age", "opaque")
	writeFile(t, dir, "profiles/website-prod.age", "opaque")
	writeFile(t, dir, "devices.json", `{"format":1}`)

	result, err := (Git{Dir: dir}).Sync(context.Background(), "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	if !strings.Contains(result.Commit, "website-dev") {
		t.Errorf("commit message does not name the changed profiles: %q", result.Commit)
	}
	for _, forbidden := range []string{"OPENAI", "API_KEY", "=", "sk-", "devices.json", "manifest"} {
		if strings.Contains(result.Commit, forbidden) {
			t.Errorf("commit message contains %q: %q", forbidden, result.Commit)
		}
	}

	// And the message really is what landed in history.
	log := gitIn(t, dir, "log", "-1", "--pretty=%s")
	if strings.TrimSpace(log) != result.Commit {
		t.Errorf("history says %q, sync reported %q", strings.TrimSpace(log), result.Commit)
	}
}

// TestSyncStopsOnAConflictAndSaysWhatToDo covers the case ciphertext cannot
// handle: two machines changing the same profile.
func TestSyncStopsOnAConflictAndSaysWhatToDo(t *testing.T) {
	remote := seedRemote(t)
	a := cloneOf(t, remote)
	b := cloneOf(t, remote)

	// Both change the same profile, differently.
	writeFile(t, a, "profiles/website-dev.age", "version-from-A")
	gitIn(t, a, "add", "-A")
	gitIn(t, a, "commit", "-q", "-m", "A changes it")
	gitIn(t, a, "push", "-q")

	writeFile(t, b, "profiles/website-dev.age", "version-from-B")
	gitIn(t, b, "add", "-A")
	gitIn(t, b, "commit", "-q", "-m", "B changes it")

	_, err := (Git{Dir: b}).Sync(context.Background(), "")
	if !errors.Is(err, ErrMergeConflict) {
		t.Fatalf("err = %v, want ErrMergeConflict", err)
	}

	// The message has to be actionable, not merely a failure.
	message := err.Error()
	for _, want := range []string{"cannot be merged", "git checkout --ours", "gk sync"} {
		if !strings.Contains(message, want) {
			t.Errorf("conflict message does not mention %q:\n%s", want, message)
		}
	}
}

// TestSyncWithNothingToDoIsQuiet checks a second run does not invent a commit.
func TestSyncWithNothingToDoIsQuiet(t *testing.T) {
	remote := seedRemote(t)
	dir := cloneOf(t, remote)

	result, err := (Git{Dir: dir}).Sync(context.Background(), "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if result.Commit != "" {
		t.Errorf("sync invented a commit: %q", result.Commit)
	}
	if len(result.Changed) != 0 {
		t.Errorf("changed = %v, want none", result.Changed)
	}
}

// TestSyncHonoursAnExplicitMessage covers the --message flag.
func TestSyncHonoursAnExplicitMessage(t *testing.T) {
	remote := seedRemote(t)
	dir := cloneOf(t, remote)

	writeFile(t, dir, "profiles/website-dev.age", "changed")
	result, err := (Git{Dir: dir}).Sync(context.Background(), "Rotate the dev profile")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if result.Commit != "Rotate the dev profile" {
		t.Errorf("commit = %q", result.Commit)
	}
	if got := strings.TrimSpace(gitIn(t, dir, "log", "-1", "--pretty=%s")); got != "Rotate the dev profile" {
		t.Errorf("history = %q", got)
	}
}

func TestProfileNamesIgnoresMetadata(t *testing.T) {
	status := []string{
		" M profiles/website-dev.age",
		" M devices.json",
		"?? manifest.json",
		" M profiles/website-prod.age",
		"?? profiles/website-dev.age",
	}
	got := profileNames(status)
	want := []string{"website-dev", "website-prod"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("profileNames = %v, want %v", got, want)
	}
}

func TestCommitMessageStaysShort(t *testing.T) {
	if got := commitMessage(nil); got != "Update vault" {
		t.Errorf("empty = %q", got)
	}
	if got := commitMessage([]string{"one"}); got != "Update one" {
		t.Errorf("one = %q", got)
	}
	if got := commitMessage([]string{"a", "b", "c"}); got != "Update a, b, c" {
		t.Errorf("three = %q", got)
	}
	if got := commitMessage([]string{"a", "b", "c", "d", "e"}); got != "Update 5 profiles" {
		t.Errorf("five = %q", got)
	}
}

// TestSyncWithNoRemoteReportsClearly checks a repository with nowhere to push
// fails with something a person can act on.
func TestSyncWithNoRemoteReportsClearly(t *testing.T) {
	dir := newRepo(t)

	if _, err := (Git{Dir: dir}).Sync(context.Background(), ""); err == nil {
		t.Fatal("sync succeeded with no remote configured")
	}
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), platform.PrivateFileMode); err != nil {
		t.Fatal(err)
	}
}

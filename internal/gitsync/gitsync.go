// Package gitsync moves a vault through Git.
//
// Named gitsync rather than sync so it does not shadow the standard library.
//
// This is **not** a sync engine. It runs the same few git commands you would run
// yourself, in the vault directory, and stops the moment anything looks
// ambiguous. Ciphertext cannot be merged, so it never attempts to resolve a
// conflict — it reports one and hands back instructions.
//
// Git is invoked with argument arrays and a working directory, never through a
// shell, for the same reason `run` is: nothing here should be able to interpolate
// a filename into a command.
package gitsync

import (
	"context"
	"errors"
	"fmt"
	"gatekeeper/internal/vault"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var (
	// ErrNotARepository reports a vault directory that is not a Git work tree.
	ErrNotARepository = errors.New("vault is not a Git repository")
	// ErrMergeConflict reports that a pull could not be completed.
	ErrMergeConflict = errors.New("vault changes could not be merged")
	// ErrGitMissing reports that git is not installed.
	ErrGitMissing = errors.New("git is not installed, or not on PATH")
)

// Result reports what a sync actually did, in order.
type Result struct {
	Steps   []string
	Changed []string
	Commit  string
}

// Git syncs a vault directory through Git.
type Git struct {
	Dir string
}

// Sync pulls, commits any local changes, and pushes.
//
// Pull first, always. If a local commit were made before pulling, a conflict
// would already exist locally and the recovery would be messier.
func (g Git) Sync(ctx context.Context, message string) (Result, error) {
	var result Result

	if _, err := exec.LookPath("git"); err != nil {
		return result, ErrGitMissing
	}

	if _, err := g.run(ctx, "rev-parse", "--is-inside-work-tree"); err != nil {
		return result, fmt.Errorf(
			"%w: run `git init` in %s, add a remote, and push once", ErrNotARepository, g.Dir)
	}

	// --- Pull ---------------------------------------------------------------
	if out, err := g.run(ctx, "pull", "--no-rebase"); err != nil {
		return result, fmt.Errorf("%w\n\n%s%s", ErrMergeConflict, indent(out), conflictHelp)
	}
	result.Steps = append(result.Steps, "pulled")

	// --- Commit anything local ---------------------------------------------
	status, err := g.status(ctx)
	if err != nil {
		return result, err
	}
	result.Changed = profileNames(status)

	if len(status) == 0 {
		result.Steps = append(result.Steps, "no local changes")
	} else {
		if _, err := g.run(ctx, "add", "-A"); err != nil {
			return result, fmt.Errorf("staging vault changes: %w", err)
		}
		if message == "" {
			message = commitMessage(result.Changed)
		}
		if out, err := g.run(ctx, "commit", "-m", message); err != nil {
			return result, fmt.Errorf("committing vault changes: %w%s", err, indent(out))
		}
		result.Commit = message
		result.Steps = append(result.Steps, "committed: "+message)
	}

	// --- Push ---------------------------------------------------------------
	// Pushing even when nothing was committed is deliberate: a previous run may
	// have committed and then failed to reach the network.
	if out, err := g.run(ctx, "push"); err != nil {
		return result, fmt.Errorf("%w%s", err, indent(out))
	}
	result.Steps = append(result.Steps, "pushed")

	return result, nil
}

// status returns git's porcelain status lines.
func (g Git) status(ctx context.Context) ([]string, error) {
	out, err := g.run(ctx, "status", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("reading vault status: %w", err)
	}

	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func (g Git) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.Dir

	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	return out.String(), err
}

// profileNames extracts profile names from porcelain status lines.
//
// Only names, and only ones already visible as filenames in the repository — so
// a commit message built from them reveals nothing that `git log --stat` would
// not. Variable names and values never appear.
func profileNames(status []string) []string {
	seen := map[string]bool{}
	var names []string

	for _, line := range status {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		base := filepath.Base(fields[len(fields)-1])
		if !strings.HasSuffix(base, vault.ProfileFileExt) {
			continue
		}
		name := strings.TrimSuffix(base, vault.ProfileFileExt)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	sort.Strings(names)
	return names
}

func commitMessage(changed []string) string {
	switch {
	case len(changed) == 0:
		return "Update vault"
	case len(changed) == 1:
		return "Update " + changed[0]
	case len(changed) <= 3:
		return "Update " + strings.Join(changed, ", ")
	default:
		return fmt.Sprintf("Update %d profiles", len(changed))
	}
}

func indent(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('\n')
	for _, line := range strings.Split(s, "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// conflictHelp is the beginning of the conflict-recovery workflow the plan left
// open. Ciphertext cannot be merged, so the honest answer is "pick a side and say
// so", not "let git sort it out".
const conflictHelp = `
Encrypted profiles cannot be merged, so two machines changing the same profile
have to be reconciled by hand. Nothing was committed or pushed.

In the vault directory:

    git status                      see which profiles conflict
    git checkout --ours  <file>     keep this machine's version
    git checkout --theirs <file>    keep the other machine's version
    git add <file> && git commit    finish the merge
    gk sync                         carry on

If you need both changes, run ` + "`gk export`" + ` on each machine and re-apply them by hand.`

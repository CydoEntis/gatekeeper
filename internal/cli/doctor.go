package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/guard"
)

func newDoctorCmd() *cobra.Command {
	var (
		preCommit bool
		path      string
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the vault, the identity, and whether secrets are about to be committed",
		Long: "Diagnose the machine and the vault.\n\n" +
			"With no flags, it checks that the vault is readable, that a local identity\n" +
			"exists for it, that the identity is protected, that no key material has\n" +
			"found its way into the vault directory, and that the vault carries ignore\n" +
			"rules.\n\n" +
			"It does not need your passphrase, so it still works when the vault will not\n" +
			"open and you do not yet know why.\n\n" +
			"With --pre-commit it instead scans a directory for files that must never be\n" +
			"committed, and exits non-zero if it finds any. Install it as a hook:\n\n" +
			"  printf '#!/bin/sh\\nexec gk doctor --pre-commit\\n' > .git/hooks/pre-commit\n" +
			"  chmod +x .git/hooks/pre-commit",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%w: doctor takes no arguments, got %q", app.ErrUsage, args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if preCommit {
				return runPreCommitCheck(cmd, path)
			}
			return runDoctor(cmd)
		},
	}

	cmd.Flags().BoolVar(&preCommit, "pre-commit", false,
		"scan a directory for secrets that must not be committed")
	cmd.Flags().StringVar(&path, "path", ".",
		"directory to scan with --pre-commit")

	return cmd
}

func runDoctor(cmd *cobra.Command) error {
	dir, err := resolveVaultDir(cmd)
	if err != nil {
		// Not fatal here: a missing or unconfigured vault is one of the things
		// doctor exists to report, so let it report that rather than erroring out
		// with a less useful message.
		dir = ""
	}

	report, err := app.New().Doctor(cmd.Context(), dir)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	for _, c := range report.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "  %s  %-28s %s\n", mark, c.Name, c.Detail)
	}

	if failed := report.Failed(); len(failed) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "\n%d check(s) failed.\n", len(failed))
		return app.ErrUnhealthy
	}
	fmt.Fprintln(out, "\nEverything checks out.")
	return nil
}

// runPreCommitCheck refuses a commit that contains secrets.
//
// It reports every finding rather than stopping at the first, because one commit
// usually contains the whole mistake at once and a partial list means repeated
// attempts.
func runPreCommitCheck(cmd *cobra.Command, root string) error {
	findings, err := guard.Scan(root)
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No secrets found in %s.\n", root)
		return nil
	}

	stderr := cmd.ErrOrStderr()
	fmt.Fprintf(stderr, "Refusing to commit %d file(s) that look like secrets:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(stderr, "  %s\n      %s\n", f.Path, f.Reason)
	}
	fmt.Fprintf(stderr,
		"\nIf one of these is a false positive, take it out of the commit or add it\n"+
			"to .gitignore. If it is a real key, treat it as compromised — anything\n"+
			"already pushed has to be rotated, not just deleted.\n")

	return fmt.Errorf("%w: %d file(s) listed above", guard.ErrKeyMaterialFound, len(findings))
}

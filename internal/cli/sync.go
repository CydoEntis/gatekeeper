package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/gitsync"
)

func newSyncCmd() *cobra.Command {
	var message string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull the vault, save local changes, and push",
		Long: "Move the vault through its Git remote.\n\n" +
			"This is three ordinary git commands run in the vault directory, in order:\n" +
			"`git pull`, then `git add -A` with a commit if anything changed, then\n" +
			"`git push`.\n\n" +
			"It is a convenience, not an engine. There is no background behaviour, and\n" +
			"this is the only command in Gatekeeper that touches the network — and only\n" +
			"when you run it. Nothing else, including `set` and `run`, ever does.\n\n" +
			"A generated commit message contains profile names at most, never variable\n" +
			"names or values. If the pull cannot be merged it stops and explains what to\n" +
			"do, rather than guessing.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%w: sync takes no arguments, got %q", app.ErrUsage, args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolveVaultDir(cmd)
			if err != nil {
				return err
			}

			result, err := (gitsync.Git{Dir: dir}).Sync(cmd.Context(), message)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			for _, step := range result.Steps {
				fmt.Fprintf(out, "  %s\n", step)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&message, "message", "",
		"commit message to use instead of the generated one")

	return cmd
}

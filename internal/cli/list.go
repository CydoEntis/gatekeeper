package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
)

func newListCmd() *cobra.Command {
	var passphraseFile string

	cmd := &cobra.Command{
		Use:   "list [PROFILE]",
		Short: "Name the profiles, or the variables in one profile",
		Long: "With no argument, name the profiles in the vault.\n" +
			"With a profile, name its variables.\n\n" +
			"Neither ever shows a value. Listing is the safe operation; revealing a\n" +
			"value is deliberately something else you have to ask for explicitly.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("%w: list takes at most one profile name, got %d",
					app.ErrUsage, len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolveVaultDir(cmd)
			if err != nil {
				return err
			}
			ref, err := resolveUnlock(cmd, passphraseFile, false)
			if err != nil {
				return err
			}
			ref.Dir = dir
			out := cmd.OutOrStdout()
			a := app.New()

			// No profile named: list the profiles themselves. With
			// `gk profile list` deferred, this is the only way to discover what
			// exists.
			if len(args) == 0 {
				summaries, err := a.Profiles(cmd.Context(), ref)
				if err != nil {
					return err
				}
				if len(summaries) == 0 {
					fmt.Fprintln(out, "No profiles yet. Add one with: gk set PROFILE KEY")
					return nil
				}
				for _, s := range summaries {
					flagged := ""
					if n := len(s.Flags); n > 0 {
						flagged = fmt.Sprintf("\t%d flagged", n)
					}
					fmt.Fprintf(out, "%s\t%d variable(s)\trevision %d%s\n",
						s.Name, len(s.Vars), s.Revision, flagged)
				}
				return nil
			}

			summary, err := a.List(cmd.Context(), ref, args[0])
			if err != nil {
				return err
			}
			if len(summary.Vars) == 0 {
				fmt.Fprintf(out, "%s has no variables yet.\n", summary.Name)
				return nil
			}
			// Names only. There is nowhere in this loop a value could come from.
			for _, name := range summary.Vars {
				if flag, ok := summary.Flags[name]; ok {
					fmt.Fprintf(out, "%s\t%s\n", name, flagSuffix(flag))
					continue
				}
				fmt.Fprintln(out, name)
			}
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)

	return cmd
}

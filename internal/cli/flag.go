package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/vault"
)

func newFlagCmd() *cobra.Command {
	var (
		passphraseFile string
		note           string
	)

	cmd := &cobra.Command{
		Use:   "flag PROFILE KEY",
		Short: "Mark a key as exposed so it keeps showing up until you replace it",
		Long: "Mark one variable as needing attention.\n\n" +
			"Gatekeeper cannot detect that a key was exposed — it has no network access,\n" +
			"and it cannot know what you pasted into a chat. This is you telling it, so\n" +
			"that months later the key that leaked is not the one nobody remembers.\n\n" +
			"A flagged key shows up in `gk list` and in `gk doctor` until you replace the\n" +
			"value. Replacing it clears the flag by itself, because a new value is the\n" +
			"rotation. If you decide a flag never mattered after all, use `gk unflag`.\n\n" +
			"Nothing else changes: flagging does not alter the value, and it does not\n" +
			"rotate anything at the provider. Rotating is still your job.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf(
					"%w: flag needs a profile and a variable name, for example:\n"+
						"  gk flag website-dev OPENAI_API_KEY --note \"pasted into a chat\"",
					app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, key := args[0], args[1]
			unlock, _, err := resolveUnlockAndDir(cmd, passphraseFile)
			if err != nil {
				return err
			}

			summary, err := app.New().Flag(cmd.Context(), unlock,
				app.FlagRequest{Profile: profile, Key: key, Note: note})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Flagged %s in %s (revision %d).\n", key, profile, summary.Revision)
			fmt.Fprintf(out, "It will show in `gk list` until you replace the value.\n")
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)
	cmd.Flags().StringVar(&note, flagNote, "",
		helpNote)

	return cmd
}

func newUnflagCmd() *cobra.Command {
	var passphraseFile string

	cmd := &cobra.Command{
		Use:   "unflag PROFILE KEY",
		Short: "Clear a flag without changing the value",
		Long: "Clear a flag you decided did not matter after all.\n\n" +
			"This does not change the value. If you are clearing a flag because you\n" +
			"rotated the key, just set the new value instead — that clears it for you,\n" +
			"which is a stronger signal that something actually changed.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf(
					"%w: unflag needs a profile and a variable name, for example:\n"+
						"  gk unflag website-dev OPENAI_API_KEY", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, key := args[0], args[1]
			unlock, _, err := resolveUnlockAndDir(cmd, passphraseFile)
			if err != nil {
				return err
			}

			summary, err := app.New().Unflag(cmd.Context(), unlock, profile, key)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Cleared the flag on %s in %s (revision %d).\n",
				key, profile, summary.Revision)
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)

	return cmd
}

// resolveUnlockAndDir resolves the vault directory and how to open it.
func resolveUnlockAndDir(cmd *cobra.Command, passphraseFile string) (app.VaultRef, string, error) {
	dir, err := resolveVaultDir(cmd)
	if err != nil {
		return app.VaultRef{}, "", err
	}
	unlock, err := resolveUnlock(cmd, passphraseFile, false)
	if err != nil {
		return app.VaultRef{}, "", err
	}
	unlock.Dir = dir
	return unlock, dir, nil
}

// flagDateLayout is how a flag's date is rendered: an unambiguous, sortable form,
// deliberately not the user's locale, because this appears in a listing meant to
// be read and diffed rather than admired.
const flagDateLayout = "2006-01-02"

// flagSuffix renders a flag for `gk list`, in plain text rather than a symbol so
// it reads the same on every terminal.
func flagSuffix(flag vault.Flag) string {
	out := "[flagged"
	if flag.Note != "" {
		out += ": " + flag.Note
	}
	if !flag.At.IsZero() {
		out += " (" + flag.At.Format(flagDateLayout) + ")"
	}
	return out + "]"
}

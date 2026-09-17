package cli

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/runner"
	"gatekeeper/internal/vault"
)

func newRunCmd() *cobra.Command {
	var passphraseFile string

	cmd := &cobra.Command{
		Use:   "run PROFILE -- COMMAND [ARG...]",
		Short: "Run a program with a profile injected into its environment",
		Long: "Run a command with a profile's variables added to its environment, so that no\n" +
			"plaintext .env file is ever created.\n\n" +
			"Everything after -- is the command and its arguments, passed through\n" +
			"untouched. No shell is involved, so spaces, quotes and metacharacters keep\n" +
			"their literal meaning:\n\n" +
			"  gk run website-dev -- npm run dev\n\n" +
			"The profile wins over your current environment for every variable it defines;\n" +
			"every other variable passes through unchanged.\n\n" +
			"The value of a variable is never printed by Gatekeeper. It reaches the child\n" +
			"process's environment and stops there.\n\n" +
			"On Windows, tools like npm and yarn are batch files, which cannot be started\n" +
			"directly. Those are run through cmd.exe, and Gatekeeper says so on standard\n" +
			"error rather than doing it silently. Everything else is started directly.\n\n" +
			"Once the command starts, its exit status is yours: gk exits with the child's\n" +
			"code. Gatekeeper's own exit codes apply only when it fails before starting\n" +
			"anything.",
		Args: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			switch {
			case dash < 0:
				return fmt.Errorf(
					"%w: put -- before the command, so there is no guessing where the "+
						"profile ends:\n  gk run website-dev -- npm run dev", app.ErrUsage)
			case dash != 1:
				return fmt.Errorf(
					"%w: expected exactly one profile name before --, found %d", app.ErrUsage, dash)
			case len(args) < 2:
				return fmt.Errorf("%w: no command given after --", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, argv := args[0], args[1:]

			if !vault.ValidProfileName(profile) {
				return fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, profile)
			}

			dir, err := resolveVaultDir(cmd)
			if err != nil {
				return err
			}
			unlock, err := resolveUnlock(cmd, passphraseFile, false)
			if err != nil {
				return err
			}
			unlock.Dir = dir

			profileEnv, err := app.New().Environment(cmd.Context(), unlock, profile)
			if err != nil {
				return err
			}

			// The profile wins over the current environment; every other variable
			// the parent has passes through untouched.
			merged := runner.FromOS().Merge(runner.Environment(profileEnv))

			// While the child runs, do not die on Ctrl-C ahead of it. The child
			// shares this process group, so the terminal already delivers the
			// signal to it directly — the parent exiting first would only discard
			// the child's exit status.
			signal.Ignore(os.Interrupt)
			defer signal.Reset(os.Interrupt)

			result, err := (runner.Exec{
				Stdin:  cmd.InOrStdin(),
				Notice: cmd.ErrOrStderr(),
			}).Run(cmd.Context(), argv, merged, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			// Propagate the child's status verbatim and silently: it has already
			// reported for itself, and printing anything here would be noise on
			// top of the child's own output.
			return &silentExit{Code: result.Code}
		},
	}

	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "",
		"read the passphrase from this 0600 file instead of prompting")

	return cmd
}

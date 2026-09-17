package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"gatekeeper/internal/app"
	"gatekeeper/internal/platform"
	"gatekeeper/internal/vault"
)

func newSetCmd() *cobra.Command {
	var (
		passphraseFile string
		valueFile      string
	)

	cmd := &cobra.Command{
		Use:   "set PROFILE KEY",
		Short: "Prompt without echo and store one value",
		Long: "Store one value in a profile.\n\n" +
			"The value is never taken from an argument, so it cannot end up in your\n" +
			"shell history or in the process list. It is read from the terminal with\n" +
			"echo disabled, or from a file you name with --value-file.\n\n" +
			"The profile is created if it does not exist.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf(
					"%w: set needs a profile and a variable name, for example:\n"+
						"  gk set website-dev DATABASE_URL", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, key := args[0], args[1]

			// Cheap name checks first, so a typo costs no typing at all.
			if !vault.ValidProfileName(profile) {
				return fmt.Errorf(
					"%w: profile name %q — use lowercase letters, digits, dot, dash or "+
						"underscore, starting with a letter or digit", vault.ErrInvalidName, profile)
			}
			if !vault.ValidVariableName(key) {
				return fmt.Errorf(
					"%w: variable name %q — use letters, digits and underscore, not "+
						"starting with a digit", vault.ErrInvalidName, key)
			}

			dir, err := resolveVaultDir(cmd)
			if err != nil {
				return err
			}
			stderr := cmd.ErrOrStderr()

			unlock, err := resolveUnlock(cmd, passphraseFile, false)
			if err != nil {
				return err
			}
			unlock.Dir = dir

			value, err := readValue(stderr, key, valueFile)
			if err != nil {
				return err
			}

			result, err := app.New().Set(
				cmd.Context(),
				unlock,
				app.SetRequest{Profile: profile, Key: key, Value: value},
			)
			if err != nil {
				return err
			}

			// The result deliberately names only the profile, the variable count
			// and the revision. No value can reach this line.
			verb := "Updated"
			if result.Created {
				verb = "Created"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s — %d variable(s), revision %d\n",
				verb, result.Profile, len(result.Variables), result.Revision)
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)
	cmd.Flags().StringVar(&valueFile, flagValueFile, "",
		helpValueFile)

	return cmd
}

// readValue obtains the secret to store.
//
// Same rules as the passphrase, for the same reasons: never an argument, never an
// environment variable. A value given as an argument would land in shell history
// and in the process list, which is precisely what this tool exists to prevent.
func readValue(w io.Writer, key, file string) (string, error) {
	if file != "" {
		contents, err := platform.ReadPrivateFile(file)
		if err != nil {
			return "", fmt.Errorf("read value file: %w", err)
		}
		// Only line endings are trimmed. A value is otherwise taken exactly as
		// written, which matters for keys that legitimately end in whitespace.
		return strings.TrimRight(string(contents), "\r\n"), nil
	}

	if !isTerminal(os.Stdin) {
		return "", fmt.Errorf(
			"%w: standard input is not a terminal, so the value cannot be read "+
				"without echoing it. Pass --value-file PATH, or use `gk import` for a "+
				"dotenv file", app.ErrUsage)
	}

	fmt.Fprintf(w, "Value for %s: ", key)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(w)
	if err != nil {
		return "", fmt.Errorf("read value: %w", err)
	}
	return string(value), nil
}

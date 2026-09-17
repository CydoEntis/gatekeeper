package cli

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/dotenv"
	"gatekeeper/internal/vault"
)

func newImportCmd() *cobra.Command {
	var (
		passphraseFile string
		overwrite      bool
	)

	cmd := &cobra.Command{
		Use:   "import PROFILE FILE",
		Short: "Import variables from a dotenv file",
		Long: "Read KEY=value pairs from a dotenv file into a profile.\n\n" +
			"This is the bulk entry path: one command, one passphrase, every variable.\n\n" +
			"The file is parsed as data and never evaluated — no variable expansion, no\n" +
			"command substitution, no shell. A file you did not write cannot run code by\n" +
			"being imported.\n\n" +
			"Use - as FILE to read standard input.\n\n" +
			"The profile is created if it does not exist. A variable that already exists\n" +
			"with a different value stops the import unless --overwrite is given.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf(
					"%w: import needs a profile and a file, for example:\n"+
						"  gk import website-dev .env.local", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, file := args[0], args[1]
			if !vault.ValidProfileName(profile) {
				return fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, profile)
			}

			source, closeSource, err := openDotenvSource(cmd, file)
			if err != nil {
				return err
			}
			defer closeSource()

			pairs, err := dotenv.Parse(source)
			if err != nil {
				return err
			}
			if len(pairs) == 0 {
				return fmt.Errorf("%w: %s contained no variables", app.ErrUsage, file)
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

			result, err := app.New().Import(
				cmd.Context(),
				unlock,
				app.ImportRequest{Profile: profile, Pairs: pairs, Overwrite: overwrite},
			)
			if err != nil {
				return err
			}

			// Names and counts only. No value can reach this line.
			verb := "Imported into"
			if result.Created {
				verb = "Created"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s %s — added %d, updated %d, unchanged %d (%d variable(s), revision %d)\n",
				verb, result.Profile, result.Added, result.Updated, result.Unchanged,
				len(result.Variables), result.Revision)
			return nil
		},
	}

	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "",
		"read the passphrase from this 0600 file instead of prompting")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false,
		"replace variables that already exist with a different value")

	return cmd
}

// openDotenvSource opens the file to import, or standard input for "-".
//
// Unlike the passphrase and single-value files, a dotenv being imported is
// pre-existing data rather than something Gatekeeper asked you to create. So a
// readable file draws a warning instead of a refusal: refusing here would block
// the main way anyone adopts this tool, because a checked-out .env is usually
// 0644, and scolding the user about a file they already had is not useful.
func openDotenvSource(cmd *cobra.Command, file string) (io.Reader, func(), error) {
	if file == "-" {
		return cmd.InOrStdin(), func() {}, nil
	}

	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(file); err == nil && fi.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"warning: %s is readable by other users (%04o). It holds secrets in the\n"+
					"         clear; delete it or chmod 600 it once you are done.\n",
				file, fi.Mode().Perm())
		}
	}

	f, err := os.Open(file)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", file, err)
	}
	return f, func() { f.Close() }, nil
}

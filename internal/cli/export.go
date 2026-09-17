package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/platform"
	"gatekeeper/internal/vault"
)

func newExportCmd() *cobra.Command {
	var (
		passphraseFile string
		output         string
		toStdout       bool
		force          bool
	)

	cmd := &cobra.Command{
		Use:   "export PROFILE",
		Short: "Write a profile out as plaintext",
		Long: "Write a profile out as a plaintext dotenv file.\n\n" +
			"This is the one operation that deliberately produces plaintext. Nothing else\n" +
			"Gatekeeper does writes a secret to disk in the clear, and once this file\n" +
			"exists its lifecycle is yours rather than Gatekeeper's:\n\n" +
			"  - it will not be encrypted\n" +
			"  - it will not be deleted for you\n" +
			"  - anything that reads it, backs it up, or syncs it now has your secrets\n\n" +
			"Delete it when you are done. Use --stdout only when you mean it.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf(
					"%w: export needs one profile name, for example:\n"+
						"  gk export website-dev --output .env", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := args[0]
			if !vault.ValidProfileName(profile) {
				return vault.InvalidProfileName(profile)
			}

			// Require an explicit destination. Printing secrets must never be
			// what happens because a flag was forgotten.
			if output == "" && !toStdout {
				return fmt.Errorf(
					"%w: name an --output FILE, or pass --stdout if you really mean to "+
						"print secrets to the terminal", app.ErrUsage)
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

			contents, summary, err := app.New().Export(
				cmd.Context(),
				unlock,
				app.ExportRequest{Profile: profile},
			)
			if err != nil {
				return err
			}

			stderr := cmd.ErrOrStderr()

			if toStdout {
				fmt.Fprintf(stderr,
					"warning: printing %d variable(s) from %s to standard output.\n"+
						"         Your terminal's scrollback, a log, or a screen recording may\n"+
						"         keep a copy.\n", len(summary.Vars), summary.Name)
				if _, err := cmd.OutOrStdout().Write(contents); err != nil {
					return fmt.Errorf("write profile to standard output: %w", err)
				}
				return nil
			}

			// Never clobber a file the user already has without being told to.
			if _, err := os.Stat(output); err == nil && !force {
				return fmt.Errorf("%w: %s already exists — pass --force to overwrite it",
					app.ErrUsage, output)
			}

			if err := writePlaintext(output, contents); err != nil {
				return err
			}

			fmt.Fprintf(stderr,
				"warning: wrote %d variable(s) from %s to %s in the clear.\n"+
					"         It is not encrypted and will not be deleted for you.\n"+
					"         Delete it when you are done.\n",
				len(summary.Vars), summary.Name, output)
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)
	cmd.Flags().StringVar(&output, flagOutput, "",
		helpOutput)
	cmd.Flags().BoolVar(&toStdout, flagStdout, false,
		helpStdout)
	cmd.Flags().BoolVar(&force, flagForce, false,
		helpForce)

	return cmd
}

// writePlaintext writes a dotenv file with owner-only permissions.
//
// The mode is set explicitly after writing as well as at creation, because
// O_CREATE does not tighten the permissions of a file that already exists.
func writePlaintext(path string, contents []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, platform.PrivateFileMode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("flush %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(path, platform.PrivateFileMode); err != nil {
		return fmt.Errorf("restrict %s: %w", path, err)
	}
	return nil
}

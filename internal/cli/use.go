package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
)

func newUseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use VAULT_DIR",
		Short: "Make an existing vault the one commands use by default",
		Long: "Record an existing vault directory as this machine's default.\n\n" +
			"This is what you run on a second computer. Copy the vault directory\n" +
			"there, put the identity file in place, and point at it once:\n\n" +
			"  gk use ~/gatekeeper-vault\n\n" +
			"After that, no command needs --vault. The directory is checked to be a real\n" +
			"vault first, so a typo cannot quietly become the default.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf(
					"%w: use needs one vault directory, for example:\n"+
						"  gk use ~/gatekeeper-vault", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, err := app.New().UseVault(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Now using %s (vault %q). No command needs --vault any more.\n",
				manifest.VaultID, manifest.Name)
			return nil
		},
	}
	return cmd
}

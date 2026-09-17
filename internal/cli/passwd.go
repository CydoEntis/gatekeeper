package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/vault"
)

func newPasswdCmd() *cobra.Command {
	var (
		passphraseFile    string
		newPassphraseFile string
	)

	cmd := &cobra.Command{
		Use:   "passwd",
		Short: "Change the passphrase that protects this machine's identity",
		Long: "Re-encrypt the local identity under a new passphrase.\n\n" +
			"The current passphrase is required, so this cannot be used to lock yourself\n" +
			"out of a vault you cannot already open. The new key file is written and then\n" +
			"swapped in atomically, so an interruption leaves the old passphrase working\n" +
			"rather than leaving you with none.\n\n" +
			"This does not re-encrypt any profiles. They are encrypted to the identity,\n" +
			"not to the passphrase, so the vault itself is untouched and the other\n" +
			"machines are unaffected.\n\n" +
			"The offline recovery key has no passphrase to change — it is stored raw so\n" +
			"that it works from a piece of paper.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%w: passwd takes no arguments", app.ErrUsage)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			stderr := cmd.ErrOrStderr()

			// Refuse early rather than prompting for two passphrases first.
			if usingRecoveryKey, err := cmd.Flags().GetString(flagIdentity); err == nil && usingRecoveryKey != "" {
				return fmt.Errorf(
					"%w: the recovery key has no passphrase to change — it is stored raw so "+
						"that it works from paper. Change the passphrase on the identity this "+
						"machine normally uses", app.ErrUsage)
			}

			dir, err := resolveVaultDir(cmd)
			if err != nil {
				return err
			}
			manifest, err := vault.ReadManifest(dir)
			if err != nil {
				return err
			}

			if !identity.Exists(manifest.VaultID) {
				path, pathErr := identity.Path(manifest.VaultID)
				if pathErr != nil {
					return pathErr
				}
				return fmt.Errorf("%w: no identity for this vault at %s", identity.ErrNotFound, path)
			}

			current, err := obtainPassphrase(stderr, passphraseFile, false)
			if err != nil {
				return err
			}

			// Confirmed when typed, because a typo here is not discovered until
			// the next unlock — by which point it is indistinguishable from a
			// wrong passphrase.
			var replacement string
			if newPassphraseFile != "" {
				replacement, err = readPassphraseFile(newPassphraseFile)
			} else {
				replacement, err = promptPassphrase(stderr, "New passphrase", true)
			}
			if err != nil {
				return err
			}
			if err := identity.ValidatePassphrase(replacement); err != nil {
				return err
			}
			warnIfWeakPassphrase(stderr, replacement)

			path, err := identity.ChangePassphrase(manifest.VaultID, current, replacement)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Passphrase changed. %s was re-encrypted in place.\n", path)
			fmt.Fprintln(cmd.OutOrStdout(),
				"Your profiles were not touched, and your other machines are unaffected.")
			return nil
		},
	}

	addPassphraseFlag(cmd, &passphraseFile)
	cmd.Flags().StringVar(&newPassphraseFile, flagNewPassphraseFile, "",
		helpNewPassphraseFile)

	return cmd
}

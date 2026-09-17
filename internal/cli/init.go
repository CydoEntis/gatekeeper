package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"gatekeeper/internal/app"
	"gatekeeper/internal/identity"
)

func newInitCmd() *cobra.Command {
	var (
		name           string
		deviceName     string
		recoveryOut    string
		passphraseFile string
		noDefault      bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a vault, a passphrase-protected identity, and an offline recovery identity",
		Long: "Create a new vault.\n\n" +
			"Generates two key pairs: one used by your machines, and one recovery key\n" +
			"meant to be stored offline. Every profile is encrypted to both, so losing\n" +
			"every computer is survivable as long as the recovery key survives.\n\n" +
			"The machine identity is encrypted at rest under a passphrase, so a stolen\n" +
			"or copied key file is useless without it. The recovery key is deliberately\n" +
			"not encrypted: it belongs on paper or removable media, and it is also the\n" +
			"way back in if the passphrase is forgotten.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%w: init takes no arguments, got %q", app.ErrUsage, args[0])
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := cmd.Flags().GetString("vault")
			if err != nil {
				return err
			}
			if dir == "" {
				return fmt.Errorf(
					"%w: --vault DIR is required, because init decides where the vault lives "+
						"and how it will be copied between machines", app.ErrUsage)
			}

			// Confirmed on a terminal, where a typo is invisible and would not be
			// discovered until the next time the vault is opened.
			stderr := cmd.ErrOrStderr()
			passphrase, err := obtainPassphrase(stderr, passphraseFile, passphraseFile == "")
			if err != nil {
				return err
			}
			warnIfWeakPassphrase(stderr, passphrase)

			result, err := app.New().Init(cmd.Context(), app.InitRequest{
				VaultDir:    dir,
				Name:        name,
				DeviceName:  deviceName,
				RecoveryOut: recoveryOut,
				Passphrase:  passphrase,
				// Only an interactive terminal may receive a private key.
				RecoveryPrintable: isTerminal(os.Stdout),
				SetDefault:        !noDefault,
			})
			if err != nil {
				return err
			}
			return renderInit(cmd.OutOrStdout(), result)
		},
	}

	cmd.Flags().StringVar(&name, "name", "personal",
		"label for this vault, for example personal or work")
	cmd.Flags().StringVar(&deviceName, "device-name", "",
		"label for the recipient identity (defaults to the vault name)")
	cmd.Flags().StringVar(&recoveryOut, "recovery-out", "",
		"write the offline recovery identity to this file instead of printing it")
	cmd.Flags().StringVar(&passphraseFile, "passphrase-file", "",
		"read the passphrase from this 0600 file instead of prompting")
	cmd.Flags().BoolVar(&noDefault, "no-default", false,
		"do not record this vault as the machine-local default")

	return cmd
}

// renderInit reports what was created and how to use it elsewhere.
//
// The "another machine" section is printed every time on purpose. It is the step
// people get wrong, and it is the whole point of the tool.
func renderInit(w io.Writer, res app.InitResult) error {
	identitiesDir, err := identity.Dir()
	if err != nil {
		identitiesDir = "<config-directory>/identities"
	}

	writef(w, "Vault created.\n\n")
	writef(w, "  vault       %s\n", res.Name)
	writef(w, "  vault id    %s\n", res.VaultID)
	writef(w, "  directory   %s\n", res.VaultDir)
	writef(w, "  identity    %s\n", res.IdentityPath)
	writef(w, "  recipient   %s\n", res.DeviceRecipient)
	writef(w, "\nThe private identity sits outside the vault, so it can never be\n")
	writef(w, "committed by accident. It is the one thing Git must never carry.\n")

	switch {
	case res.RecoveryWrittenTo != "":
		writef(w, "\nRecovery identity written to:\n  %s\n", res.RecoveryWrittenTo)
		writef(w, "\nMove it somewhere you trust -- a password manager, or printed and\n")
		writef(w, "locked away. It is the only way back in if every machine is lost.\n")
		writef(w, "It is not stored anywhere else; if you lose this file, it is gone.\n")

	case res.RecoveryIdentity != "":
		writef(w, "\n%s\n", recoveryRule)
		writef(w, "  RECOVERY IDENTITY -- write this down now, it is shown once\n")
		writef(w, "%s\n\n", recoveryRule)
		writef(w, "  %s\n\n", res.RecoveryIdentity)
		writef(w, "%s\n", recoveryRule)
		writef(w, "\nPut it in your password manager, or print it. It is the only way\n")
		writef(w, "back in if every machine is lost, and it is stored nowhere else.\n")
	}

	writef(w, "\nPut the vault in Git -- only ciphertext is ever committed:\n\n")
	writef(w, "  cd %s\n", res.VaultDir)
	writef(w, "  git init && git add -A && git commit -m \"Add Gatekeeper vault\"\n")
	writef(w, "  git remote add origin <your repository>\n")
	writef(w, "  git push -u origin main\n")

	writef(w, "\nOn another machine:\n\n")
	writef(w, "  1. git clone <your repository> ~/gatekeeper-vault\n")
	writef(w, "  2. copy this file there, unchanged:\n")
	writef(w, "       %s\n", res.IdentityPath)
	writef(w, "     to the same filename under:\n")
	writef(w, "       %s\n", identitiesDir)
	writef(w, "  3. gk --vault ~/gatekeeper-vault list\n\n")
	writef(w, "Only that one file moves by hand, once per machine. Everything else,\n")
	writef(w, "including every secret you add later, arrives with `git pull` as\n")
	writef(w, "ciphertext.\n")

	return nil
}

const recoveryRule = "  ----------------------------------------------------------------"

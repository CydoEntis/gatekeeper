package cli

import "github.com/spf13/cobra"

// Flag names and help text, named once.
//
// Nine commands register the passphrase flag, and eight of them repeated its help
// string verbatim. A flag name is part of the command's public interface, so a
// typo in one command would be a silent inconsistency rather than a compile
// error. Naming them makes that impossible.
const (
	flagVault             = "vault"
	flagIdentity          = "identity"
	flagPassphraseFile    = "passphrase-file"
	flagNewPassphraseFile = "new-passphrase-file"
	flagValueFile         = "value-file"
	flagRecoveryOut       = "recovery-out"
	flagName              = "name"
	flagDeviceName        = "device-name"
	flagNoDefault         = "no-default"
	flagOutput            = "output"
	flagStdout            = "stdout"
	flagForce             = "force"
	flagOverwrite         = "overwrite"
	flagMessage           = "message"
	flagNote              = "note"
	flagPreCommit         = "pre-commit"
	flagPath              = "path"
)

const (
	helpVault          = "vault directory (defaults to $" + EnvVault + ", then the configured default)"
	helpIdentity       = "open the vault with this raw age private key instead of the local identity (the recovery path)"
	helpPassphraseFile = "read the passphrase from this 0600 file instead of prompting"
	// helpPassphraseFileOption is the same flag on `doctor`, where supplying it is
	// optional because doctor never prompts.
	helpPassphraseFileOption = "unlock the vault to include the flagged-variable check; optional, because doctor never prompts"
	helpNewPassphraseFile    = "read the new passphrase from this 0600 file instead of prompting"
	helpValueFile            = "read the value from this 0600 file instead of prompting"
	helpRecoveryOut          = "write the offline recovery identity to this file instead of printing it"
	helpName                 = "label for this vault, for example personal or work"
	helpDeviceName           = "label for the recipient identity (defaults to the vault name)"
	helpNoDefault            = "do not record this vault as the machine-local default"
	helpOutput               = "write the plaintext dotenv file here"
	helpStdout               = "print the secrets to standard output instead of a file (dangerous)"
	helpForce                = "overwrite --output if it already exists"
	helpOverwrite            = "replace variables that already exist with a different value"
	helpMessage              = "commit message to use instead of the generated one"
	helpNote                 = `why it is flagged, for example "pasted into a chat"`
	helpPreCommit            = "scan a directory for secrets that must not be committed"
	helpPath                 = "directory to scan with --pre-commit"
)

// addPassphraseFlag registers the flag every vault-opening command shares.
//
// The rule it carries — the file must not be readable by anyone else — is
// enforced in readPassphraseFile. Declaring it in one place is what keeps the
// nine commands that offer it honest about the same rule.
func addPassphraseFlag(cmd *cobra.Command, target *string) {
	cmd.Flags().StringVar(target, flagPassphraseFile, "", helpPassphraseFile)
}

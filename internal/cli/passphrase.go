package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"gatekeeper/internal/app"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/platform"
)

// Passphrase handling.
//
// Three rules, each of which exists to keep the passphrase out of somewhere that
// leaks it:
//
//   - **Never an environment variable.** Every child process inherits the
//     environment, so an exported passphrase would be handed to every program
//     `gk run` starts — including a malicious dependency.
//   - **Never a command-line argument.** Arguments are visible in the process
//     list to any other user on the machine.
//   - **Only a terminal, or an explicitly named file that others cannot read.**
//
// The prompt is written to standard error, so standard output stays clean enough
// to pipe.

// promptPassphrase reads a passphrase from the terminal without echoing it.
//
// When confirm is set it asks twice, which is what `init` wants: a typo in a new
// passphrase is not discovered until the next time the vault is opened, by which
// point the mistake is indistinguishable from a corrupted file.
//
// Prompts are written to w -- the command's standard error -- so standard output
// stays clean enough to pipe, and so tests can capture them.
func promptPassphrase(w io.Writer, label string, confirm bool) (string, error) {
	if !isTerminal(os.Stdin) {
		return "", fmt.Errorf(
			"%w: standard input is not a terminal, so the passphrase cannot be read "+
				"without echoing it. Pass --passphrase-file PATH to read it from a file",
			app.ErrUsage)
	}

	fmt.Fprintf(w, "%s: ", label)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(w)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if !confirm {
		return string(first), nil
	}

	fmt.Fprintf(w, "Confirm %s: ", strings.ToLower(label))
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(w)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("%w: the two passphrases do not match", app.ErrUsage)
	}
	return string(first), nil
}

// readPassphraseFile reads a passphrase from an explicit file.
//
// The permission check is not ceremony: a passphrase sitting in a world-readable
// file defeats the entire reason the identity is encrypted at rest.
func readPassphraseFile(path string) (string, error) {
	if err := platform.CheckSecretFilePerms(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read passphrase file: %w", err)
	}
	// A trailing newline from an editor or `echo` is not part of the passphrase.
	return strings.TrimRight(string(data), "\r\n"), nil
}

// obtainPassphrase resolves the passphrase from a file when one is named, and
// from the terminal otherwise.
//
// There is no environment fallback and no argument fallback by design, so this is
// the only two ways in.
func obtainPassphrase(w io.Writer, file string, confirm bool) (string, error) {
	var (
		passphrase string
		err        error
	)
	if file != "" {
		passphrase, err = readPassphraseFile(file)
	} else {
		passphrase, err = promptPassphrase(w, "Passphrase", confirm)
	}
	if err != nil {
		return "", err
	}

	// Enforced here so the user is told before anything is written, and again in
	// the identity package so no caller can bypass it.
	if err := identity.ValidatePassphrase(passphrase); err != nil {
		return "", err
	}
	return passphrase, nil
}

// resolveUnlock works out how to open a vault.
//
// Two ways in, and no others:
//
//   - the everyday path: the local identity, unlocked with a passphrase;
//   - the recovery path: an explicit raw identity file, named with --identity.
//     That file is the offline recovery key, which is not passphrase-encrypted
//     and therefore needs no prompt.
//
// The caller fills in Dir afterwards.
func resolveUnlock(cmd *cobra.Command, passphraseFile string, confirm bool) (app.VaultRef, error) {
	identityPath, err := cmd.Flags().GetString("identity")
	if err != nil {
		return app.VaultRef{}, err
	}

	if identityPath != "" {
		private, err := identity.ReadRawPrivateKey(identityPath)
		if err != nil {
			return app.VaultRef{}, err
		}
		return app.VaultRef{Identity: private}, nil
	}

	passphrase, err := obtainPassphrase(cmd.ErrOrStderr(), passphraseFile, confirm)
	if err != nil {
		return app.VaultRef{}, err
	}
	return app.VaultRef{Passphrase: passphrase}, nil
}

// warnIfWeakPassphrase writes a warning. It is a warning and never a refusal:
// blocking a 15-character passphrase pushes people toward writing it down, which
// is worse.
func warnIfWeakPassphrase(w io.Writer, passphrase string) {
	if identity.PassphraseIsWeak(passphrase) {
		fmt.Fprintf(w,
			"warning: that passphrase is under %d characters. It is the only thing\n"+
				"         protecting your keys if this machine is stolen, and an attacker\n"+
				"         who copies the identity file can attack it offline. Prefer five or\n"+
				"         six random words, and never reuse a password from elsewhere.\n",
			identity.WarnPassphraseLen)
	}
}

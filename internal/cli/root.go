// Package cli holds the Cobra commands.
//
// Commands are thin adapters. Each one parses non-secret arguments, calls a
// single application operation, renders the result, and maps a typed error to a
// documented exit code. No command reaches for age or reads an encrypted file
// directly -- that boundary is what keeps a future MCP or UI entry point from
// bypassing the safety rules.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"gatekeeper/internal/app"
	"gatekeeper/internal/envelope"
	"gatekeeper/internal/guard"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/localconfig"
	"gatekeeper/internal/platform"
	"gatekeeper/internal/runner"
	"gatekeeper/internal/vault"
)

// Exit codes, from ARCHITECTURE.md section 9. They are stable: scripts may rely
// on them, so a change is a breaking change.
const (
	ExitOK         = 0
	ExitFailure    = 1
	ExitUsage      = 2
	ExitNotFound   = 3
	ExitLocked     = 4
	ExitConflict   = 5
	ExitIntegrity  = 6
	ExitPermission = 7
	ExitExternal   = 8
)

// ExitCode maps a typed error to a stable process exit code.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK

	case errors.Is(err, app.ErrUsage),
		errors.Is(err, app.ErrAlreadyInitialized),
		errors.Is(err, app.ErrRecoveryUndeliverable),
		errors.Is(err, vault.ErrInvalidName),
		errors.Is(err, vault.ErrInvalidValue),
		errors.Is(err, vault.ErrAlreadyExists),
		errors.Is(err, identity.ErrWeakPassphrase),
		errors.Is(err, identity.ErrExists):
		return ExitUsage

	case errors.Is(err, vault.ErrNotFound),
		errors.Is(err, identity.ErrNotFound):
		return ExitNotFound

	// A wrong passphrase is a locked vault, not a corrupt one: the ciphertext is
	// intact and the caller simply cannot open it.
	case errors.Is(err, vault.ErrLocked),
		errors.Is(err, identity.ErrWrongPassphrase):
		return ExitLocked

	case errors.Is(err, vault.ErrConflict),
		errors.Is(err, app.ErrCollision):
		return ExitConflict

	case errors.Is(err, vault.ErrUnsupportedFormat),
		errors.Is(err, vault.ErrDuplicateKey),
		errors.Is(err, vault.ErrTrailingContent),
		errors.Is(err, vault.ErrNameMismatch),
		errors.Is(err, vault.ErrNotVault),
		errors.Is(err, envelope.ErrNotDecryptable),
		errors.Is(err, envelope.ErrBadIdentity):
		return ExitIntegrity

	case errors.Is(err, platform.ErrUnsafePerm),
		errors.Is(err, guard.ErrKeyMaterialFound):
		return ExitPermission

	// A command that could not be started is an environment problem, not a
	// Gatekeeper problem.
	case errors.Is(err, runner.ErrExecutableNotFound):
		return ExitExternal

	default:
		return ExitFailure
	}
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string) int {
	return ExecuteWith(args, os.Stdout, os.Stderr)
}

// silentExit carries a child process's exit status out of a command.
//
// It exists for `gk run`, which must propagate the child's code verbatim. The
// child has already reported its own failure, so printing "gk: exit status 5" on
// top of its output would be noise — and it would also be indistinguishable from
// Gatekeeper's own exit-code taxonomy.
type silentExit struct {
	Code int
}

func (e *silentExit) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExecuteWith runs the CLI against explicit output streams.
//
// Separated from Execute so tests can capture what a command prints -- in
// particular to prove a private key never reaches a non-terminal destination.
func ExecuteWith(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	if err := root.Execute(); err != nil {
		// A command that ran a child process passes the child's status through
		// untouched, and reports nothing of its own.
		var passthrough *silentExit
		if errors.As(err, &passthrough) {
			return passthrough.Code
		}

		// SilenceErrors is set on the root, so this is the only place the error
		// is rendered. Errors never contain secret values.
		fmt.Fprintf(stderr, "gk: %v\n", err)
		return ExitCode(err)
	}
	return ExitOK
}

func newRootCmd() *cobra.Command {
	var (
		vaultDir     string
		identityPath string
	)

	root := &cobra.Command{
		Use:   "gk",
		Short: "A local-first vault for project environment variables",
		Long: "Gatekeeper keeps project environment variables in age-encrypted files that\n" +
			"can be synchronized with Git. Only ciphertext is ever committed; private\n" +
			"identities stay on each machine.\n\n" +
			"Pre-release: this is a personal tool without an external security audit.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare `gk` should explain itself rather than fail silently.
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.PersistentFlags().StringVar(&vaultDir, "vault", "",
		"vault directory (defaults to $GK_VAULT, then the configured default)")
	root.PersistentFlags().StringVar(&identityPath, "identity", "",
		"open the vault with this raw age private key instead of the local identity (the recovery path)")

	// Without this, an unknown or malformed flag surfaces as a plain error and
	// would be reported as an internal failure (exit 1) instead of a usage error
	// (exit 2). Scripts distinguish those.
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %v", app.ErrUsage, err)
	})

	root.AddCommand(
		newInitCmd(),
		newSetCmd(),
		newListCmd(),
		newImportCmd(),
		newExportCmd(),
		newRunCmd(),
		newDoctorCmd(),
	)
	return root
}

// resolveVaultDir finds the vault a command should operate on.
//
// Three sources, in order: the --vault flag, the GK_VAULT environment
// variable, then the machine-local default recorded by `init`. Explicit wins, so
// a work and a personal vault can coexist and be selected per invocation.
func resolveVaultDir(cmd *cobra.Command) (string, error) {
	flagValue, err := cmd.Flags().GetString("vault")
	if err != nil {
		return "", err
	}
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	if env := os.Getenv("GK_VAULT"); env != "" {
		return filepath.Abs(env)
	}

	cfg, err := localconfig.Load()
	if err != nil {
		return "", err
	}
	if cfg.DefaultVault != "" {
		return cfg.DefaultVault, nil
	}

	return "", fmt.Errorf(
		"%w: no vault selected. Pass --vault DIR, set GK_VAULT, or run "+
			"`gk init --vault DIR` to record a default", app.ErrUsage)
}

// isTerminal reports whether f is an interactive terminal.
//
// Used to decide whether a private key may be printed, and whether a passphrase
// can be read without echoing it. Both answers must be conservative, so this asks
// the terminal directly rather than testing for a character device: /dev/null and
// NUL are character devices that are not terminals, and treating them as
// terminals would print a recovery key into nothing and then fail on an ioctl.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func writef(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...)
}

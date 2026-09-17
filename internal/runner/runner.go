// Package runner starts a child process with a profile injected into its
// environment, without ever writing a plaintext .env file.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// How a Windows batch shim is started.
//
// CreateProcess cannot launch a .cmd file, so cmd.exe is the only way to run one.
// Named because it is the one place in this package that deliberately involves a
// shell, and that should be visible rather than buried in a slice literal.
const (
	windowsShell       = "cmd.exe"
	windowsShellSwitch = "/c"
)

// ErrExecutableNotFound reports that the named command could not be found.
//
// Typed so the command layer can report it as an external failure with its own
// exit code, rather than as an unclassified internal error.
var ErrExecutableNotFound = errors.New("executable not found")

// Environment is a set of variables to inject. It is a map rather than a
// []string so that merging and precedence are explicit and testable.
type Environment map[string]string

// FromOS returns the current process environment, for use as the base that a
// profile is merged over.
//
// An entry with no `=` is skipped rather than fatal: it cannot occur in practice,
// and refusing to run anything because of it would be worse than ignoring it.
func FromOS() Environment {
	env := make(Environment, len(os.Environ()))
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			env[key] = value
		}
	}
	return env
}

// Merge builds the child environment.
//
// Documented precedence rule (the plan leaves this open in Phase 6, but the
// runner cannot be written without deciding it):
//
//   - the profile wins for every key it defines;
//   - every other parent variable passes through untouched;
//   - an empty profile value means "set to empty", not "delete".
//
// PATH is intentionally included in this rule rather than special-cased. If
// profiles silently could not override PATH, `run` would quietly lie about
// what it does -- and a user who wants a venv or toolchain bin directory on
// PATH is a legitimate use case.
func (base Environment) Merge(profile Environment) Environment {
	out := make(Environment, len(base)+len(profile))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range profile {
		out[k] = v
	}
	return out
}

// Slice renders the environment in exec.Cmd's expected "KEY=value" form.
func (e Environment) Slice() []string {
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(e))
	for _, k := range keys {
		out = append(out, k+"="+e[k])
	}
	return out
}

// ExitResult carries the child's exit status.
type ExitResult struct {
	Code int
}

// Runner starts a child process.
type Runner interface {
	Run(ctx context.Context, argv []string, env Environment, stdout, stderr io.Writer) (ExitResult, error)
}

// Exec runs children directly with os/exec.
type Exec struct {
	Dir    string
	Stdin  io.Reader
	DryRun bool
	// Notice receives a short line whenever a batch shim had to be started
	// through cmd.exe. Nil means the caller does not want to be told.
	Notice io.Writer
}

// ResolveExecutable mirrors the platform's own lookup rules -- PATH, plus
// PATHEXT on Windows -- and returns the absolute path.
func ResolveExecutable(name string) (string, error) {
	if name == "" {
		return "", errors.New("no executable given")
	}

	if strings.ContainsAny(name, `/\`) {
		return name, nil
	}

	found, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not in PATH", ErrExecutableNotFound, name)
	}
	return found, nil
}

// isShellShim reports whether a resolved path is a Windows batch shim.
//
// It is a separate function so the classification can be unit-tested on any
// operating system: this is the single most likely way the tool feels broken on
// the primary platform, and it should not be testable only on Windows.
func isShellShim(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cmd", ".bat":
		return true
	}
	return false
}

// launchArgv decides how a resolved executable should be started.
//
// On Windows, `npm`, `yarn`, `tsc` and most other developer tools are `.cmd`
// batch files, and CreateProcess cannot start a batch file — cmd.exe is the only
// way to run one. That is not Gatekeeper interpreting your arguments as shell
// syntax; it is running the file you named, which happens to be a batch script.
//
// The security property that matters is unchanged either way: arguments are still
// handed over as a slice and never joined into a command line by us. And running
// `npm run dev` imposes exactly the quoting rules it would if you had typed it
// into your own prompt.
//
// goos is a parameter rather than a direct runtime.GOOS check so that the Windows
// decision is testable from any platform.
func launchArgv(goos, path string, args []string) (argv []string, usedShell bool) {
	if goos == "windows" && isShellShim(path) {
		return append([]string{windowsShell, windowsShellSwitch, path}, args...), true
	}
	return append([]string{path}, args...), false
}

// Run launches the command with the given environment.
//
// Arguments are passed straight to exec. There is no shell, so metacharacters
// in arguments stay literal.
func (e Exec) Run(ctx context.Context, argv []string, env Environment, stdout, stderr io.Writer) (ExitResult, error) {
	if len(argv) == 0 {
		return ExitResult{}, errors.New("no command given")
	}

	path, err := ResolveExecutable(argv[0])
	if err != nil {
		return ExitResult{}, err
	}

	if e.DryRun {
		return ExitResult{}, nil
	}

	// On Windows a batch shim has to go through cmd.exe. That is the only way to
	// run the file, not Gatekeeper re-reading your arguments as shell syntax.
	launch, usedShell := launchArgv(runtime.GOOS, path, argv[1:])
	if usedShell && e.Notice != nil {
		fmt.Fprintf(e.Notice,
			"note: %s is a Windows batch file, so it was started through cmd.exe\n",
			filepath.Base(path))
	}

	cmd := exec.CommandContext(ctx, launch[0], launch[1:]...)
	cmd.Dir = e.Dir
	cmd.Env = env.Slice()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if e.Stdin != nil {
		cmd.Stdin = e.Stdin
	} else {
		cmd.Stdin = os.Stdin
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		// A non-zero child exit is a result, not a Gatekeeper failure: pass the
		// code up so the caller can exit with the same status.
		if errors.As(err, &exitErr) {
			return ExitResult{Code: exitErr.ExitCode()}, nil
		}
		// A path that was named directly rather than looked up never went through
		// LookPath, so a missing file surfaces here instead.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return ExitResult{}, fmt.Errorf("%w: %q", ErrExecutableNotFound, argv[0])
		}
		// Any other startup failure (permission denied, bad format) is an external
		// error. The message names the executable only -- never the full argv,
		// which could in principle carry a value the user passed by hand.
		return ExitResult{}, fmt.Errorf("start %q: %w", filepath.Base(path), err)
	}
	return ExitResult{Code: 0}, nil
}

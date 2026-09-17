package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gatekeeper/internal/platform"
	"os"
	"strconv"
	"strings"
	"testing"
)

// runFixtureEnv marks the re-executed child so the fixture body runs.
const runFixtureEnv = "GK_RUN_FIXTURE"

// TestRunFixtureProcess is not a real test.
//
// `gk run` re-executes this test binary with a filter selecting only this
// function, which gives the suite a genuine child process without shipping and
// building a separate fixture binary. It reports whether it received variables,
// and hashes values rather than printing them — so the parent can assert the
// value arrived byte-for-byte while this output stays safe to keep.
func TestRunFixtureProcess(t *testing.T) {
	if os.Getenv(runFixtureEnv) != "1" {
		t.Skip("not the fixture child")
	}

	if value, ok := os.LookupEnv("DEMO_SECRET"); ok {
		sum := sha256.Sum256([]byte(value))
		fmt.Printf("SECRET=present sha256=%s\n", hex.EncodeToString(sum[:]))
	} else {
		fmt.Println("SECRET=absent")
	}

	if inherited, ok := os.LookupEnv("INHERITED_FROM_PARENT"); ok {
		fmt.Printf("INHERITED=%s\n", inherited)
	} else {
		fmt.Println("INHERITED=absent")
	}

	for i, arg := range fixtureArgs() {
		fmt.Printf("ARG%d=%s\n", i, arg)
	}

	if code := os.Getenv("GK_RUN_FIXTURE_EXIT"); code != "" {
		n, err := strconv.Atoi(code)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad fixture exit code %q\n", code)
			os.Exit(99)
		}
		os.Exit(n)
	}
}

// fixtureArgs returns the arguments that follow the test filter.
//
// The child is a test binary, so its own flags come first and Go's flag package
// stops at `--`. Skipping that separator is what lets an argument beginning with
// a dash reach the fixture intact instead of being parsed as a test flag.
func fixtureArgs() []string {
	start := -1
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.run=") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	rest := os.Args[start:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	return rest
}

// runCommand executes `gk run` with the vault flags placed before the `--`.
//
// This ordering is not cosmetic: everything after `--` belongs to the child
// process, so a flag appended there would be handed to the child instead of being
// read by Gatekeeper.
func (v testVault) runCommand(t *testing.T, profile string, argv ...string) (int, string, string) {
	t.Helper()
	args := []string{"run", profile, "--vault", v.dir, "--passphrase-file", v.passFile, "--"}
	args = append(args, argv...)
	return runArgs(t, args...)
}

// fixtureCommand is the argv that re-runs this test binary as the fixture child.
func fixtureCommand() []string {
	return []string{os.Args[0], "-test.run=^TestRunFixtureProcess$", "--"}
}

func (v testVault) seed(t *testing.T, content string) {
	t.Helper()
	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, content)); code != ExitOK {
		t.Fatalf("seeding the profile failed: %s", stderr)
	}
}

// TestRunInjectsTheProfileWithoutDisclosingIt is the core acceptance test.
func TestRunInjectsTheProfileWithoutDisclosingIt(t *testing.T) {
	v := newTestVault(t)
	t.Setenv(runFixtureEnv, "1")
	v.seed(t, "DEMO_SECRET="+testCanary+"\n")

	code, stdout, stderr := v.runCommand(t, "demo", fixtureCommand()...)
	if code != ExitOK {
		t.Fatalf("run exit = %d; stderr: %s", code, stderr)
	}

	// The child proves it received the real value without printing it.
	sum := sha256.Sum256([]byte(testCanary))
	if !strings.Contains(stdout, "SECRET=present sha256="+hex.EncodeToString(sum[:])) {
		t.Errorf("the child did not receive the value intact:\n%s", stdout)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("Gatekeeper disclosed the value in its output")
	}
}

// TestRunPassesArgumentsThroughLiterally is the no-shell guarantee.
//
// If any of these were interpreted, the argument would arrive split, expanded, or
// globbed rather than exactly as written.
func TestRunPassesArgumentsThroughLiterally(t *testing.T) {
	v := newTestVault(t)
	t.Setenv(runFixtureEnv, "1")
	v.seed(t, "K=1\n")

	tricky := []string{
		"a b c",
		"semi;colon",
		"star*glob",
		"dollar$HOME",
		"pipe|chain",
		"quote'single",
		`double"quote`,
		`back\slash`,
		"-not-a-gatekeeper-flag",
		"$(command substitution)",
		"`backticks`",
	}

	argv := append(fixtureCommand(), tricky...)
	code, stdout, stderr := v.runCommand(t, "demo", argv...)
	if code != ExitOK {
		t.Fatalf("run exit = %d; stderr: %s", code, stderr)
	}

	for i, want := range tricky {
		if !strings.Contains(stdout, fmt.Sprintf("ARG%d=%s\n", i, want)) {
			t.Errorf("argument %d (%q) did not arrive intact:\n%s", i, want, stdout)
		}
	}

	// A shell would have expanded this one to a path.
	if strings.Contains(stdout, "dollar/home") || strings.Contains(stdout, "dollar"+string(os.PathSeparator)) {
		t.Errorf("$HOME was expanded by a shell:\n%s", stdout)
	}
}

// TestRunProfileWinsOverTheParentEnvironment pins the documented precedence.
func TestRunProfileWinsOverTheParentEnvironment(t *testing.T) {
	v := newTestVault(t)
	t.Setenv(runFixtureEnv, "1")
	t.Setenv("DEMO_SECRET", "the-parent-value-should-lose")
	t.Setenv("INHERITED_FROM_PARENT", "kept")
	v.seed(t, "DEMO_SECRET="+testCanary+"\n")

	code, stdout, stderr := v.runCommand(t, "demo", fixtureCommand()...)
	if code != ExitOK {
		t.Fatalf("run exit = %d; stderr: %s", code, stderr)
	}

	profileSum := sha256.Sum256([]byte(testCanary))
	parentSum := sha256.Sum256([]byte("the-parent-value-should-lose"))

	if !strings.Contains(stdout, "sha256="+hex.EncodeToString(profileSum[:])) {
		t.Error("the profile value did not win over the parent environment")
	}
	if strings.Contains(stdout, "sha256="+hex.EncodeToString(parentSum[:])) {
		t.Error("the parent's value won, contradicting the documented precedence")
	}
	if !strings.Contains(stdout, "INHERITED=kept") {
		t.Error("an unrelated parent variable did not pass through")
	}
}

// TestRunPropagatesTheChildExitCode checks that the child's status is the user's
// status, which is what makes `gk run` usable in a script or a Makefile.
func TestRunPropagatesTheChildExitCode(t *testing.T) {
	v := newTestVault(t)
	t.Setenv(runFixtureEnv, "1")
	v.seed(t, "K=1\n")

	for _, want := range []int{0, 1, 3, 42, 130} {
		t.Setenv("GK_RUN_FIXTURE_EXIT", strconv.Itoa(want))
		code, stdout, stderr := v.runCommand(t, "demo", fixtureCommand()...)
		if code != want {
			t.Errorf("child exited %d, gk exited %d; stdout: %s stderr: %s",
				want, code, stdout, stderr)
		}
	}
}

// TestRunMissingExecutableIsAnExternalError checks a startup failure is reported
// as Gatekeeper's own failure, with its own exit code.
func TestRunMissingExecutableIsAnExternalError(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "K=1\n")

	code, stdout, stderr := v.runCommand(t, "demo", "definitely-not-a-real-executable-xyz", "arg")
	if code != ExitExternal {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitExternal, stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Error("a startup failure disclosed something")
	}
}

// TestRunRequiresTheDashDash checks the separator is insisted on rather than
// guessed at.
func TestRunRequiresTheDashDash(t *testing.T) {
	v := newTestVault(t)

	code, _, stderr := v.run(t, "run", "demo", "echo", "hi")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "--") || !strings.Contains(stderr, "gk run") {
		t.Errorf("the refusal does not show the form to use: %s", stderr)
	}
}

// TestRunUnknownProfileIsNotFound checks the failure happens before any process
// starts, with the right exit code.
func TestRunUnknownProfileIsNotFound(t *testing.T) {
	v := newTestVault(t)

	code, _, stderr := v.runCommand(t, "no-such-profile", fixtureCommand()...)
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitNotFound, stderr)
	}
}

// TestRunWrongPassphraseIsLocked checks a locked vault never reaches the point of
// starting a process.
func TestRunWrongPassphraseIsLocked(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "K=1\n")

	code, _, stderr := runArgs(t,
		"run", "demo",
		"--vault", v.dir,
		"--passphrase-file", passphraseFileWith(t, "wrong passphrase entirely", platform.PrivateFileMode),
		"--", os.Args[0], "-test.run=^TestRunFixtureProcess$", "--",
	)
	if code != ExitLocked {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitLocked, stderr)
	}
}

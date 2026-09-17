package cli

import (
	"bytes"
	"gatekeeper/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runWithStdin executes the CLI with standard input replaced by the given text,
// which is how `gk import PROFILE -` is exercised.
func runWithStdin(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	previous := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = previous
		f.Close()
	})

	var stdout, stderr bytes.Buffer
	code := ExecuteWith(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// writeDotenv writes a dotenv source file for an import test.
func writeDotenv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte(content), platform.PrivateFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, platform.PrivateFileMode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestImportIsTheBatchEntryPath is the acceptance test for the friction that
// motivated import: many variables, one command, one passphrase.
func TestImportIsTheBatchEntryPath(t *testing.T) {
	v := newTestVault(t)
	source := writeDotenv(t, strings.Join([]string{
		"# a normal project env file",
		"DATABASE_URL=postgres://localhost/dev",
		"OPENAI_API_KEY=" + testCanary,
		"export DEBUG=true",
		"EMPTY=",
	}, "\n"))

	code, stdout, stderr := v.run(t, "import", "website-dev", source)
	if code != ExitOK {
		t.Fatalf("import exit = %d; stderr: %s", code, stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("import disclosed a value")
	}
	if !strings.Contains(stdout, "Created website-dev") {
		t.Errorf("import did not report creating the profile: %q", stdout)
	}
	if !strings.Contains(stdout, "added 4") {
		t.Errorf("import counts look wrong: %q", stdout)
	}

	// The names are there; the values are not anywhere on disk.
	code, stdout, stderr = v.run(t, "list", "website-dev")
	if code != ExitOK {
		t.Fatalf("list exit = %d; stderr: %s", code, stderr)
	}
	for _, name := range []string{"DATABASE_URL", "OPENAI_API_KEY", "DEBUG", "EMPTY"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("list is missing %q: %q", name, stdout)
		}
	}
	assertVaultHasNoCanary(t, v.dir)
}

// TestImportNeverEvaluatesAFile is the security test at the command level.
func TestImportNeverEvaluatesAFile(t *testing.T) {
	v := newTestVault(t)
	marker := filepath.Join(t.TempDir(), "should-never-exist")
	source := writeDotenv(t, "EVIL=$(touch "+marker+")\nBACKTICK=`touch "+marker+"`\n")

	code, _, stderr := v.run(t, "import", "website-dev", source)
	if code != ExitOK {
		t.Fatalf("import exit = %d; stderr: %s", code, stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("importing executed a command from the file")
	}

	// The value is stored literally, which is what "never evaluated" means.
	exported := filepath.Join(t.TempDir(), "out.env")
	if code, _, stderr := v.run(t, "export", "website-dev", "--output", exported); code != ExitOK {
		t.Fatalf("export exit = %d; stderr: %s", code, stderr)
	}
	data, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "$(touch "+marker+")") {
		t.Errorf("the value was altered rather than stored literally:\n%s", data)
	}
}

// TestImportRefusesCollisionsLeavingTheProfileUntouched checks that a refused
// import is a no-op, not a partial application.
func TestImportRefusesCollisionsLeavingTheProfileUntouched(t *testing.T) {
	v := newTestVault(t)

	// Distinctive values, so "did this text leak?" is a real question. A word like
	// "changed" would match the refusal message's own prose and prove nothing.
	const kept = "CANARY-kept-9f2a41"
	const attempt = "CANARY-attempt-7b3c52"

	code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "KEEP="+kept+"\nADDED=first\n"))
	if code != ExitOK {
		t.Fatalf("first import exit = %d; stderr: %s", code, stderr)
	}

	// Re-import with one changed and one new value.
	code, stdout, stderr := v.run(t, "import", "demo", writeDotenv(t, "KEEP="+attempt+"\nNEW=second\n"))
	if code != ExitConflict {
		t.Fatalf("exit = %d, want %d (conflict); stderr: %s", code, ExitConflict, stderr)
	}
	if !strings.Contains(stderr, "KEEP") {
		t.Errorf("the error does not name the colliding key: %s", stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, kept) || strings.Contains(combined, attempt) {
		t.Errorf("a collision error disclosed a value:\n%s", combined)
	}

	// Nothing changed: neither the colliding value nor the new key landed.
	exported := filepath.Join(t.TempDir(), "out.env")
	if code, _, stderr := v.run(t, "export", "demo", "--output", exported); code != ExitOK {
		t.Fatalf("export exit = %d; stderr: %s", code, stderr)
	}
	data, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), kept) {
		t.Error("the refused import modified the existing value")
	}
	if strings.Contains(string(data), "NEW=") {
		t.Error("the refused import partially applied a new key")
	}
}

// TestImportOverwriteReplaces covers the explicit opt-in.
func TestImportOverwriteReplaces(t *testing.T) {
	v := newTestVault(t)

	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "K=original\n")); code != ExitOK {
		t.Fatalf("first import: %s", stderr)
	}

	code, stdout, stderr := v.run(t, "import", "demo", writeDotenv(t, "K=replaced\n"), "--overwrite")
	if code != ExitOK {
		t.Fatalf("overwrite import exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "updated 1") {
		t.Errorf("overwrite counts look wrong: %q", stdout)
	}

	exported := filepath.Join(t.TempDir(), "out.env")
	if code, _, stderr := v.run(t, "export", "demo", "--output", exported); code != ExitOK {
		t.Fatalf("export: %s", stderr)
	}
	data, _ := os.ReadFile(exported)
	if !strings.Contains(string(data), "replaced") {
		t.Errorf("the overwrite did not take effect:\n%s", data)
	}
}

// TestImportOfIdenticalValuesIsIdempotent lets the same file be re-imported
// without ceremony, which is what a person actually does.
func TestImportOfIdenticalValuesIsIdempotent(t *testing.T) {
	v := newTestVault(t)
	source := writeDotenv(t, "A=1\nB=2\n")
	// Two separate files with the same content, since import refuses nothing here.
	second := writeDotenv(t, "A=1\nB=2\n")

	if code, _, stderr := v.run(t, "import", "demo", source); code != ExitOK {
		t.Fatalf("first import: %s", stderr)
	}
	code, stdout, stderr := v.run(t, "import", "demo", second)
	if code != ExitOK {
		t.Fatalf("re-import exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "unchanged 2") {
		t.Errorf("re-import counts look wrong: %q", stdout)
	}
}

// TestImportFromStdin covers the "-" source.
func TestImportFromStdin(t *testing.T) {
	v := newTestVault(t)

	// ExecuteWith reads stdin from the process, so give the command a real reader.
	code, stdout, stderr := runWithStdin(t, "A=from-stdin\n", "import", "demo", "-", "--vault", v.dir, "--passphrase-file", v.passFile)
	if code != ExitOK {
		t.Fatalf("exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "added 1") {
		t.Errorf("stdin import counts look wrong: %q", stdout)
	}
}

// TestExportRequiresAnExplicitDestination checks that secrets never reach a
// terminal because a flag was forgotten.
func TestExportRequiresAnExplicitDestination(t *testing.T) {
	v := newTestVault(t)
	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "K="+testCanary+"\n")); code != ExitOK {
		t.Fatalf("import: %s", stderr)
	}

	code, stdout, stderr := v.run(t, "export", "demo")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitUsage, stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Fatal("export printed a value without being asked")
	}
}

// TestExportWritesRestrictiveFileAndWarns covers the deliberate plaintext path.
func TestExportWritesRestrictiveFileAndWarns(t *testing.T) {
	v := newTestVault(t)
	if code, _, stderr := v.run(t, "import", "demo", writeDotenv(t, "K="+testCanary+"\n")); code != ExitOK {
		t.Fatalf("import: %s", stderr)
	}

	out := filepath.Join(t.TempDir(), "exported.env")
	code, stdout, stderr := v.run(t, "export", "demo", "--output", out)
	if code != ExitOK {
		t.Fatalf("export exit = %d; stderr: %s", code, stderr)
	}

	// The warning must be loud, and on stderr so a redirect cannot hide it.
	if !strings.Contains(stderr, "in the clear") {
		t.Errorf("export did not warn about plaintext: %q", stderr)
	}
	if strings.Contains(stdout, testCanary) {
		t.Error("the exported value was echoed to standard output as well")
	}

	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("exported file missing: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != platform.PrivateFileMode {
		t.Errorf("exported file permissions = %04o, want 0600", perm)
	}

	// And it refuses to clobber without --force.
	if code, _, _ := v.run(t, "export", "demo", "--output", out); code == ExitOK {
		t.Error("export overwrote an existing file without --force")
	}
}

// TestExportImportRoundTrips is the property that makes export useful rather than
// merely dangerous.
func TestExportImportRoundTrips(t *testing.T) {
	v := newTestVault(t)
	source := writeDotenv(t, strings.Join([]string{
		`SIMPLE=value`,
		`SPACED="a value with spaces"`,
		`MULTI="line1\nline2"`,
		`QUOTED="say \"hi\""`,
		`HASH=pass#word`,
		`EMPTY=`,
		`UNICODE=🔐 café`,
	}, "\n"))

	if code, _, stderr := v.run(t, "import", "original", source); code != ExitOK {
		t.Fatalf("import: %s", stderr)
	}

	exported := filepath.Join(t.TempDir(), "roundtrip.env")
	if code, _, stderr := v.run(t, "export", "original", "--output", exported); code != ExitOK {
		t.Fatalf("export: %s", stderr)
	}
	if code, _, stderr := v.run(t, "import", "copy", exported); code != ExitOK {
		t.Fatalf("re-import: %s", stderr)
	}

	// Export both and compare: the values must be identical.
	second := filepath.Join(t.TempDir(), "copy.env")
	if code, _, stderr := v.run(t, "export", "copy", "--output", second); code != ExitOK {
		t.Fatalf("export copy: %s", stderr)
	}

	first, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(again) {
		t.Errorf("round trip changed the data:\n--- first ---\n%s\n--- second ---\n%s", first, again)
	}
}

// TestImportReportsSyntaxErrorsWithoutLeaking checks a malformed file fails
// cleanly and names the line.
func TestImportReportsSyntaxErrorsWithoutLeaking(t *testing.T) {
	v := newTestVault(t)

	code, stdout, stderr := v.run(t, "import", "demo", writeDotenv(t, "GOOD=1\nBAD LINE HERE\n"))
	if code != ExitUsage && code != ExitFailure {
		t.Fatalf("exit = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "line 2") {
		t.Errorf("error does not name the offending line: %s", stderr)
	}
	if strings.Contains(stdout+stderr, testCanary) {
		t.Error("a syntax error disclosed a value")
	}
}

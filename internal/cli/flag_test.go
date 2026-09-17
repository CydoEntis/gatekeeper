package cli

import (
	"gatekeeper/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFlagShowsUpUntilTheValueIsReplaced is the whole point of the feature: the
// one key that leaked should not become the one nobody remembers.
func TestFlagShowsUpUntilTheValueIsReplaced(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\nDATABASE_URL=postgres://localhost/dev\n")

	// Flag it.
	code, stdout, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", "pasted into a chat")
	if code != ExitOK {
		t.Fatalf("flag exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Flagged OPENAI_API_KEY") {
		t.Errorf("flag output: %q", stdout)
	}

	// It shows in the profile listing, with the note.
	code, stdout, stderr = v.run(t, "list", "demo")
	if code != ExitOK {
		t.Fatalf("list exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "flagged") || !strings.Contains(stdout, "pasted into a chat") {
		t.Errorf("the flag is not visible in the listing:\n%s", stdout)
	}

	// And it is counted on the profile overview.
	code, stdout, _ = v.run(t, "list")
	if code != ExitOK {
		t.Fatalf("list exited %d", code)
	}
	if !strings.Contains(stdout, "1 flagged") {
		t.Errorf("the overview does not count the flag:\n%s", stdout)
	}

	// Replacing the value clears it: a new value is the rotation.
	replacement := passphraseFileWith(t, "sk-live-rotated-value", platform.PrivateFileMode)
	code, _, stderr = v.run(t, "set", "demo", "OPENAI_API_KEY", "--value-file", replacement)
	if code != ExitOK {
		t.Fatalf("set exited %d; stderr: %s", code, stderr)
	}

	code, stdout, _ = v.run(t, "list", "demo")
	if code != ExitOK {
		t.Fatalf("list exited %d", code)
	}
	if strings.Contains(stdout, "flagged") {
		t.Errorf("the flag survived the rotation:\n%s", stdout)
	}
}

// TestReEnteringTheSameValueKeepsTheFlag is the subtle half.
//
// If re-typing the same secret cleared the flag, the warning would disappear
// without anything having been fixed — which is worse than no warning.
func TestReEnteringTheSameValueKeepsTheFlag(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")

	if code, _, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", "leaked"); code != ExitOK {
		t.Fatalf("flag: %s", stderr)
	}

	// Set the *same* value again.
	same := passphraseFileWith(t, testCanary, platform.PrivateFileMode)
	if code, _, stderr := v.run(t, "set", "demo", "OPENAI_API_KEY", "--value-file", same); code != ExitOK {
		t.Fatalf("set: %s", stderr)
	}

	code, stdout, _ := v.run(t, "list", "demo")
	if code != ExitOK {
		t.Fatalf("list exited %d", code)
	}
	if !strings.Contains(stdout, "flagged") {
		t.Errorf("re-entering the same value silently cleared the flag:\n%s", stdout)
	}
}

// TestUnflagClearsWithoutChangingTheValue covers the other answer: "this never
// mattered after all".
func TestUnflagClearsWithoutChangingTheValue(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")

	if code, _, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", "maybe leaked"); code != ExitOK {
		t.Fatalf("flag: %s", stderr)
	}
	code, stdout, stderr := v.run(t, "unflag", "demo", "OPENAI_API_KEY")
	if code != ExitOK {
		t.Fatalf("unflag exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Cleared the flag") {
		t.Errorf("unflag output: %q", stdout)
	}

	code, stdout, _ = v.run(t, "list", "demo")
	if code != ExitOK {
		t.Fatalf("list exited %d", code)
	}
	if strings.Contains(stdout, "flagged") {
		t.Errorf("the flag is still showing:\n%s", stdout)
	}

	// The value is untouched, and still there.
	if !strings.Contains(stdout, "OPENAI_API_KEY") {
		t.Errorf("unflag removed the variable itself:\n%s", stdout)
	}
}

// TestDoctorReportsFlaggedVariables is the nag.
func TestDoctorReportsFlaggedVariables(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")
	if code, _, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", "pasted into a chat"); code != ExitOK {
		t.Fatalf("flag: %s", stderr)
	}

	// Without a passphrase doctor cannot see inside, so the check is skipped and
	// must not be reported as a pass.
	code, stdout, _ := v.runDoctor(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor without a passphrase exited %d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "skip") || !strings.Contains(stdout, "no flagged variables") {
		t.Errorf("the skipped check is not reported as skipped:\n%s", stdout)
	}

	// With a passphrase it runs, fails, and says which key.
	code, stdout, stderr := runArgs(t, "doctor", "--vault", v.dir, "--passphrase-file", v.passFile)
	if code == ExitOK {
		t.Fatalf("doctor passed with a flagged key:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "demo/OPENAI_API_KEY") {
		t.Errorf("doctor did not name the flagged key:\n%s", stdout)
	}
	if !strings.Contains(stderr, "check(s) failed") {
		t.Errorf("stderr does not summarise: %s", stderr)
	}
}

// TestFlagNoteIsEncryptedAtRest checks the note lives inside the ciphertext.
//
// A note like "pasted into #eng-secrets" is not a secret value, but it says
// something about one, and the repository is not the place for it.
func TestFlagNoteIsEncryptedAtRest(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")

	const note = "CANARY-note-7b3c52 pasted somewhere embarrassing"
	if code, _, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", note); code != ExitOK {
		t.Fatalf("flag: %s", stderr)
	}

	var found bool
	err := filepath.WalkDir(v.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(data), "CANARY-note-7b3c52") {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("the flag note is readable in the vault directory")
	}
}

// TestFlagRefusesAnUnknownKey checks a typo is caught rather than creating a flag
// for something that does not exist.
func TestFlagRefusesAnUnknownKey(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")

	code, _, stderr := v.run(t, "flag", "demo", "NOT_A_REAL_KEY", "--note", "x")
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want %d; stderr: %s", code, ExitNotFound, stderr)
	}
	if !strings.Contains(stderr, "no variable called") {
		t.Errorf("error is not explanatory: %s", stderr)
	}
}

// TestFlagSurvivesSyncAndReload checks the flag travels with the vault, because
// it lives in the payload rather than in local state.
func TestFlagSurvivesSyncAndReload(t *testing.T) {
	v := newTestVault(t)
	v.seed(t, "OPENAI_API_KEY="+testCanary+"\n")
	if code, _, stderr := v.run(t, "flag", "demo", "OPENAI_API_KEY", "--note", "kept"); code != ExitOK {
		t.Fatalf("flag: %s", stderr)
	}

	// A fresh read of the same vault sees it, which is what a second machine
	// would do after pulling.
	code, stdout, stderr := v.run(t, "list", "demo")
	if code != ExitOK {
		t.Fatalf("list exited %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "kept") {
		t.Errorf("the flag did not survive a reload:\n%s", stdout)
	}
}

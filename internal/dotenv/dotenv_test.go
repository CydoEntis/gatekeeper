package dotenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gatekeeper/internal/vault"
)

func parseString(t *testing.T, input string) []Pair {
	t.Helper()
	pairs, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse(%q): %v", input, err)
	}
	return pairs
}

func asMap(pairs []Pair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.Key] = p.Value
	}
	return m
}

func TestParseBasic(t *testing.T) {
	got := asMap(parseString(t, "A=1\nB=two\nC=\n"))
	want := map[string]string{"A": "1", "B": "two", "C": ""}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("parsed %d pairs, want %d", len(got), len(want))
	}
}

// TestParserNeverEvaluatesAnything is the security test for this package.
//
// A dotenv file is data. Command substitution, variable expansion and backticks
// must all arrive as literal text — a file someone else wrote must not be able to
// run code by being imported.
func TestParserNeverEvaluatesAnything(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "should-never-exist")

	input := strings.Join([]string{
		"COMMAND=$(touch " + marker + ")",
		"BACKTICK=`touch " + marker + "`",
		"EXPANSION=$HOME",
		"BRACED=${HOME}",
		"QUOTED=\"$(touch " + marker + ")\"",
	}, "\n")

	got := asMap(parseString(t, input))

	// Nothing ran.
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("importing a dotenv file executed a command")
	}

	// And every value is the literal text, unexpanded.
	for key, want := range map[string]string{
		"COMMAND":   "$(touch " + marker + ")",
		"BACKTICK":  "`touch " + marker + "`",
		"EXPANSION": "$HOME",
		"BRACED":    "${HOME}",
		"QUOTED":    "$(touch " + marker + ")",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want the literal %q", key, got[key], want)
		}
	}

	// Specifically, an environment variable was not substituted.
	if strings.Contains(got["EXPANSION"], "/") {
		t.Errorf("$HOME was expanded to %q", got["EXPANSION"])
	}
}

func TestParseQuoting(t *testing.T) {
	got := asMap(parseString(t, strings.Join([]string{
		`SINGLE='a $b \n c'`,
		`DOUBLE="line1\nline2\ttab"`,
		`LITERAL_HASH=pass#word`,
		`TRAILING_COMMENT=value # a comment`,
		`QUOTED_HASH="value # not a comment"`,
		`ESCAPED_QUOTE="say \"hi\""`,
		`BACKSLASH="c:\\path"`,
		`EMPTY_QUOTED=""`,
		`SPACES=   trimmed   `,
	}, "\n")))

	want := map[string]string{
		"SINGLE":           `a $b \n c`, // single quotes are literal
		"DOUBLE":           "line1\nline2\ttab",
		"LITERAL_HASH":     "pass#word", // no space before #, so it is part of the value
		"TRAILING_COMMENT": "value",
		"QUOTED_HASH":      "value # not a comment",
		"ESCAPED_QUOTE":    `say "hi"`,
		"BACKSLASH":        `c:\path`,
		"EMPTY_QUOTED":     "",
		"SPACES":           "trimmed",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// TestParseMultiline covers the case that makes PEM keys and certificates
// possible in a dotenv file.
func TestParseMultiline(t *testing.T) {
	got := asMap(parseString(t, "PEM=\"-----BEGIN-----\nAAAABBBB\n-----END-----\"\nAFTER=1\n"))

	want := "-----BEGIN-----\nAAAABBBB\n-----END-----"
	if got["PEM"] != want {
		t.Errorf("PEM = %q, want %q", got["PEM"], want)
	}
	// The line counter must not be thrown off by the continuation.
	if got["AFTER"] != "1" {
		t.Errorf("AFTER = %q, want 1 — a continuation line confused the parser", got["AFTER"])
	}
}

// TestParseCRLF is the Windows case, and it is not hypothetical: a stray
// carriage return inside a value is invisible and breaks whatever reads it next.
func TestParseCRLF(t *testing.T) {
	got := asMap(parseString(t, "A=1\r\nB=two\r\nC=\"quoted\"\r\n"))
	for k, v := range map[string]string{"A": "1", "B": "two", "C": "quoted"} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseUnicodeAndSpecialCharacters(t *testing.T) {
	got := asMap(parseString(t, "EMOJI=🔐\nACCENT=café\nURL=postgres://u:p@h:5432/db?sslmode=require\n"))

	for k, v := range map[string]string{
		"EMOJI":  "🔐",
		"ACCENT": "café",
		"URL":    "postgres://u:p@h:5432/db?sslmode=require",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseExportPrefixAndComments(t *testing.T) {
	got := asMap(parseString(t, strings.Join([]string{
		"# a comment",
		"   # an indented comment",
		"",
		"export A=1",
		"export\tB=2",
		"exported=3", // a variable whose name merely starts with "export"
		"export=4",
	}, "\n")))

	for k, v := range map[string]string{"A": "1", "B": "2", "exported": "3", "export": "4"} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	for name, input := range map[string]string{
		"no equals":           "JUSTAKEY\n",
		"empty key":           "=value\n",
		"key with a space":    "A B=1\n",
		"key with a dash":     "A-B=1\n",
		"key starting digit":  "1A=1\n",
		"unterminated single": "A='oops\n",
		"unterminated double": `A="oops` + "\n",
		"text after quote":    `A="1" trailing` + "\n",
		"nul in value":        "A=a\x00b\n",
	} {
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Errorf("%s: accepted %q", name, input)
		}
	}
}

// TestParseRejectsDuplicateKeys keeps import deterministic. Last-one-wins would
// make the stored value depend on line order in a file nobody re-reads.
func TestParseRejectsDuplicateKeys(t *testing.T) {
	_, err := Parse(strings.NewReader("A=1\nB=2\nA=3\n"))
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error does not name the offending line: %v", err)
	}
}

// TestKeyPatternMatchesTheVault pins the parser's name rule to the vault's.
//
// They are separate definitions on purpose — a parser should not import a storage
// module — so this test is what stops them drifting apart.
func TestKeyPatternMatchesTheVault(t *testing.T) {
	for _, key := range []string{
		"A", "_A", "A1", "a_b_C", "export", "exported", "OPENAI_API_KEY",
		"1A", "", "A B", "A-B", "A.B", "A$", "A\n", "É", "A=",
	} {
		if got, want := keyRE.MatchString(key), vault.ValidVariableName(key); got != want {
			t.Errorf("key %q: dotenv says %v, vault says %v — the two rules have drifted",
				key, got, want)
		}
	}
}

func TestParseRecordsLineNumbers(t *testing.T) {
	pairs := parseString(t, "# comment\n\nA=1\nB=2\n")
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs", len(pairs))
	}
	if pairs[0].Line != 3 || pairs[1].Line != 4 {
		t.Errorf("lines = %d, %d; want 3, 4", pairs[0].Line, pairs[1].Line)
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	big := strings.Repeat("A=1\n", MaxSize/4+10)
	if _, err := Parse(strings.NewReader(big)); err == nil {
		t.Fatal("accepted an oversized dotenv file")
	}
}

package guard

import (
	"errors"
	"gatekeeper/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write creates a file, making parent directories as needed.
func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), platform.PrivateFileMode); err != nil {
		t.Fatal(err)
	}
}

func TestScanFindsADotenvFile(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".env"), "SECRET=value\n")

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1", findings)
	}
	if !strings.Contains(findings[0].Reason, "dotenv") {
		t.Errorf("reason = %q", findings[0].Reason)
	}
}

// TestScanFindsTheIdentityFileByName is the case a content scan cannot catch.
//
// A Gatekeeper identity is passphrase-encrypted, so its bytes are opaque. The
// filename is the only signal available, which is why name checks exist.
func TestScanFindsTheIdentityFileByName(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "identities", "8c680667.key"),
		"-----BEGIN AGE ENCRYPTED FILE-----\nnot readable as a key\n-----END AGE ENCRYPTED FILE-----\n")

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1", findings)
	}
	if !strings.Contains(findings[0].Reason, "private key") {
		t.Errorf("reason = %q", findings[0].Reason)
	}
}

func TestScanFindsKeyMaterialByContent(t *testing.T) {
	// Realistic bodies: the PEM match requires actual base64 after the header, so
	// a header with a placeholder after it is correctly not a finding.
	body := strings.Repeat("MIIEowIBAAKCAQEA", 4)

	for name, content := range map[string]string{
		"an age key":     "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58) + "\n",
		"an RSA key":     "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n",
		"an EC key":      "-----BEGIN EC PRIVATE KEY-----\n" + strings.Repeat("MHcCAQEEI", 8) + "\n",
		"an OpenSSH key": "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Repeat("b3BlbnNzaC1rZXk", 8) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write(t, filepath.Join(root, "innocent.txt"), content)

			findings, err := Scan(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want 1 for %s", findings, name)
			}
		})
	}
}

// TestScanAllowsEnvExamples keeps the guard from being unusable. A `.env.example`
// is meant to be committed; flagging it would train people to bypass the check.
func TestScanAllowsEnvExamples(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env.example", ".env.sample", ".env.template", ".env.dist"} {
		write(t, filepath.Join(root, name), "DATABASE_URL=postgres://localhost/dev\n")
	}

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

// TestScanDoesNotFlagAMereMention is what stops the guard crying wolf.
//
// Source code and documentation talk about key formats constantly. Only a
// full-length key is a key.
func TestScanDoesNotFlagAMereMention(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "notes.md"), strings.Join([]string{
		"The private half looks like AGE-SECRET-KEY-1... and is written to a file.",
		"Keys are stored as AGE-SECRET-KEY-1 followed by base32 data.",
		"AGE-SECRET-KEY-1SHORT",
		"A PEM block starts with -----BEGIN PRIVATE KEY----- but we never store one.",
	}, "\n"))

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

func TestScanIgnoresDependencyTrees(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".git", "config"), "AGE-SECRET-KEY-1"+strings.Repeat("Q", 58))
	write(t, filepath.Join(root, "node_modules", "pkg", "id_rsa"), "irrelevant")
	write(t, filepath.Join(root, "src", "main.go"), "package main\n")

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none — ignored trees were walked", findings)
	}
}

func TestScanFindsNothingInACleanTree(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "README.md"), "# Project\n")
	write(t, filepath.Join(root, "main.go"), "package main\n")
	write(t, filepath.Join(root, "vault", "profiles", "dev.age"), "age-encryption.org/v1\n\x00binary")

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", findings)
	}
}

// TestScanReportsEveryFinding checks a commit with several mistakes is reported
// in full, rather than one attempt at a time.
func TestScanReportsEveryFinding(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".env"), "A=1\n")
	write(t, filepath.Join(root, "deploy.key"), "opaque")
	write(t, filepath.Join(root, "id_ed25519"), "opaque")

	findings, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %v, want 3", findings)
	}
	// Sorted, so the output is stable and diffable.
	if findings[0].Path > findings[1].Path || findings[1].Path > findings[2].Path {
		t.Errorf("findings are not sorted: %v", findings)
	}
}

func TestErrKeyMaterialFoundIsTheTypedError(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".env"), "A=1\n")

	findings, err := Scan(root)
	if err != nil || len(findings) == 0 {
		t.Fatalf("expected findings, got %v / %v", findings, err)
	}
	// The command layer wraps findings in this error to pick an exit code.
	wrapped := errors.Join(ErrKeyMaterialFound, errors.New("detail"))
	if !errors.Is(wrapped, ErrKeyMaterialFound) {
		t.Error("the sentinel does not survive wrapping")
	}
}

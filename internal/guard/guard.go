// Package guard looks for secrets that are about to be committed.
//
// This is the mitigation for the risk the security model calls dominant. Nobody
// loses a vault to a broken cipher; people lose them by running `git add -A` in
// the wrong directory, or by committing the `.env` they swore they would delete.
//
// It is deliberately a *filename and content* check rather than a Git check. That
// keeps it usable as a pre-commit hook, as a plain directory scan, and in tests,
// without shelling out to Git or depending on a repository being present.
package guard

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// ErrKeyMaterialFound reports that a scan found something which must not be
// committed.
var ErrKeyMaterialFound = errors.New("private key material is present")

// MaxFileSize bounds how much of a file is inspected. A private key is small; a
// larger file is a binary or an archive, and reading it costs time for nothing.
const MaxFileSize = 2 << 20 // 2 MiB

// Finding is one reason not to commit.
type Finding struct {
	Path   string
	Reason string
}

func (f Finding) String() string { return fmt.Sprintf("%s: %s", f.Path, f.Reason) }

// The shape of a complete age private key.
const (
	// ageSecretKeyPrefix is how every age private key begins.
	ageSecretKeyPrefix = "AGE-SECRET-KEY-1"

	// ageSecretKeyLength is how many base32 characters follow the prefix.
	//
	// Matching the full length, rather than the prefix alone, is what makes the
	// scanner usable: source code, documentation and fixtures mention the prefix
	// constantly, and a guard that flags all of them is a guard nobody keeps
	// installed.
	ageSecretKeyLength = 58
)

var (
	// ageKeyRE matches a real age private key: the prefix followed by the full
	// bech32 contents part.
	ageKeyRE = regexp.MustCompile(ageSecretKeyPrefix + `[0-9A-Z]{` + strconv.Itoa(ageSecretKeyLength) + `}`)

	// privateKeyRE matches a PEM private key block *with content*.
	//
	// Requiring base64 after the header matters: documentation, error messages and
	// test fixtures quote the header constantly, and flagging those would make the
	// guard useless in exactly the repositories most likely to care.
	privateKeyRE = regexp.MustCompile(
		`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=]{20,}`)
)

// ignoredDirs are never descended into: they are dependency or output trees, and
// walking them is slow and noisy.
var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "target": true,
	".venv": true, "venv": true, "__pycache__": true, ".toolchain": true,
}

// allowedEnvNames are dotenv-shaped files that are meant to be committed.
var allowedEnvNames = map[string]bool{
	".env.example": true, ".env.sample": true, ".env.template": true,
	".env.dist": true, ".env.defaults": true,
}

// Scan walks root and returns everything that looks like it must not be
// committed. It stops at the first finding per file, and reports none for files
// it cannot read.
func Scan(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory should not abort the scan: a partial answer
			// is more useful than none.
			return nil
		}
		if d.IsDir() {
			if path != root && ignoredDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		if reason := suspectName(d.Name()); reason != "" {
			findings = append(findings, Finding{Path: path, Reason: reason})
			return nil
		}
		if reason := suspectContent(path); reason != "" {
			findings = append(findings, Finding{Path: path, Reason: reason})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

// Names that identify a secret by filename alone.
//
// These carry more weight than a content check: a Gatekeeper identity is
// passphrase-encrypted, so its bytes are opaque and the name is the only signal
// there is.
const (
	dotenvName   = ".env"
	dotenvPrefix = ".env."

	reasonDotenv     = "a dotenv file, which holds secrets in the clear"
	reasonKeyFile    = "a file named like a private key"
	reasonSSHKeyFile = "an SSH private key"
)

// privateKeyExtensions name a private key by convention.
var privateKeyExtensions = []string{".key", ".p12", ".pfx"}

// sshKeyNames are the conventional filenames of an SSH private key.
var sshKeyNames = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}

// suspectName reports why a filename alone is a reason to stop.
func suspectName(name string) string {
	lower := strings.ToLower(name)

	if lower == dotenvName {
		return reasonDotenv
	}
	if strings.HasPrefix(lower, dotenvPrefix) && !allowedEnvNames[lower] {
		return reasonDotenv
	}
	if slices.Contains(privateKeyExtensions, filepath.Ext(lower)) {
		return reasonKeyFile
	}
	if slices.Contains(sshKeyNames, lower) {
		return reasonSSHKeyFile
	}
	return ""
}

// suspectContent reports why a file's contents are a reason to stop.
func suspectContent(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > MaxFileSize {
		return ""
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Ciphertext and binaries are not text, and scanning them is meaningless.
	if bytes.IndexByte(contents, 0) >= 0 {
		return ""
	}

	if ageKeyRE.Match(contents) {
		return "an unencrypted age private key"
	}
	if privateKeyRE.Match(contents) {
		return "a private key"
	}
	return ""
}

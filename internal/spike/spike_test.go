// Package spike implements the vertical spike from IMPLEMENTATION_PLAN.md
// section 18 and nothing else.
//
// The point is not to build the product. The point is to prove the load-bearing
// path --
//
//	structured profile -> age encryption -> safe persistence -> decryption -> child environment
//
// -- and to prove it did not leak the secret along the way. Everything here is
// disposable once the real CLI exists; what must survive is the knowledge that
// this path works.
package spike

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"gatekeeper/internal/envelope"
	"gatekeeper/internal/runner"
	"gatekeeper/internal/vault"
)

// canary is a value distinctive enough that finding it anywhere is proof of a
// disclosure, and obviously fake so it can never be mistaken for a credential.
const canary = "CANARY-do-not-disclose-8f3a91c4"

// TestFixtureProcess is not a real test. The spike re-executes this test binary
// with GK_FIXTURE=1 to obtain a child process that reports *whether* it
// received the variable and a hash of the value -- never the value itself.
//
// Hashing rather than printing is the whole trick: the parent can assert the
// value arrived byte-for-byte intact while the child's output stays safe to log.
func TestFixtureProcess(t *testing.T) {
	if os.Getenv("GK_FIXTURE") != "1" {
		t.Skip("not the fixture child")
	}
	v, ok := os.LookupEnv("DEMO_SECRET")
	if !ok {
		fmt.Println("DEMO_SECRET=absent")
		return
	}
	sum := sha256.Sum256([]byte(v))
	fmt.Printf("DEMO_SECRET=present sha256=%s\n", hex.EncodeToString(sum[:]))
}

// newVault builds a vault with a device identity and a separate offline
// recovery identity, mirroring the recipient model from ARCHITECTURE.md 3.2.
func newVault(t *testing.T, dir string) (v *vault.FileVault, recoveryPrivate string, devicePrivate string) {
	t.Helper()

	devPrivate, devPublic, err := envelope.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate device identity: %v", err)
	}
	recPrivate, recPublic, err := envelope.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate recovery identity: %v", err)
	}

	devIdentity, err := envelope.ParseIdentity(devPrivate)
	if err != nil {
		t.Fatalf("parse device identity: %v", err)
	}
	devRecipient, err := envelope.ParseRecipient(devPublic)
	if err != nil {
		t.Fatalf("parse device recipient: %v", err)
	}
	recRecipient, err := envelope.ParseRecipient(recPublic)
	if err != nil {
		t.Fatalf("parse recovery recipient: %v", err)
	}

	return &vault.FileVault{
		Dir:      dir,
		Envelope: envelope.Age{},
		// Every profile is encrypted to the device AND the offline recovery
		// identity, so losing every device is survivable.
		Recipients: []age.Recipient{devRecipient, recRecipient},
		Identities: []age.Identity{devIdentity},
		Now:        time.Now,
		NewID:      func() (string, error) { return "prof-0001", nil },
	}, recPrivate, devPrivate
}

// TestVerticalSpike walks the six steps of IMPLEMENTATION_PLAN.md section 18.
func TestVerticalSpike(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Step 1: generate age identities.
	v, _, _ := newVault(t, dir)

	// Steps 2 and 3: encrypt a versioned profile holding the canary, and make
	// sure only ciphertext reaches the directory.
	summary, err := v.Create(ctx, "demo", map[string]string{"DEMO_SECRET": canary})
	if err != nil {
		t.Fatalf("create profile: %v", err)
	}
	if summary.Name != "demo" || summary.Revision != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	path := filepath.Join(dir, "profiles", "demo.age")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if bytes.Contains(raw, []byte(canary)) {
		t.Fatal("plaintext canary is present in the stored profile")
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		t.Fatal("stored profile looks like plaintext JSON, not age ciphertext")
	}
	// age's native binary format. This file MUST be treated as binary by Git:
	// see .gitattributes. Git for Windows defaults to core.autocrlf=true, which
	// rewrites line endings -- and doing that inside ciphertext corrupts the
	// vault in a way that looks like a wrong key. This is a Windows-primary
	// failure mode that has nothing to do with the crypto.
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/v1")) {
		t.Fatalf("stored profile is not an age file; first line: %q", firstLine(raw))
	}

	if perm := fileMode(t, path); perm != 0o600 {
		t.Errorf("profile permissions = %04o, want 0600", perm)
	}

	// Step 4: decrypt through the Vault interface.
	got, err := v.Read(ctx, "demo")
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if got.Variables["DEMO_SECRET"] != canary {
		t.Fatal("round trip did not return the original value")
	}

	// Step 5: run a fixture child process with the value injected.
	var stdout, stderr bytes.Buffer
	env := runner.Environment{
		"PATH":       os.Getenv("PATH"),
		"GK_FIXTURE": "1",
	}.Merge(runner.Environment(got.Variables))

	result, err := (runner.Exec{Dir: dir}).Run(
		ctx,
		[]string{os.Args[0], "-test.run=^TestFixtureProcess$"},
		env,
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("run fixture: %v (stderr: %s)", err, stderr.String())
	}
	if result.Code != 0 {
		t.Fatalf("fixture exited %d; stderr: %s", result.Code, stderr.String())
	}

	// The child proves it received the real value without ever printing it.
	want := sha256.Sum256([]byte(canary))
	wantHex := hex.EncodeToString(want[:])
	if !strings.Contains(stdout.String(), "DEMO_SECRET=present") {
		t.Fatalf("fixture did not report the variable; stdout: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), wantHex) {
		t.Fatalf("fixture received a different value; stdout: %s", stdout.String())
	}

	// Step 6: scan the directory and captured output for the canary.
	assertNoCanary(t, dir, stdout.Bytes(), stderr.Bytes())
}

// TestRecoveryIdentityCanDecrypt proves the offline recovery path is real and
// not merely documented. This is the capability that makes losing a laptop
// survivable.
func TestRecoveryIdentityCanDecrypt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// primary is the everyday device. recPrivate is the key the user printed
	// and locked in a drawer.
	primary, recPrivate, devPrivate := newVault(t, dir)
	if _, err := primary.Create(ctx, "demo", map[string]string{"DEMO_SECRET": canary}); err != nil {
		t.Fatalf("create profile: %v", err)
	}

	// The everyday device can read it.
	if _, err := primary.Read(ctx, "demo"); err != nil {
		t.Fatalf("device identity could not decrypt: %v", err)
	}

	// Simulate the device being lost: a vault holding ONLY the recovery
	// identity, with no access to the device key, must still decrypt.
	recIdentity, err := envelope.ParseIdentity(recPrivate)
	if err != nil {
		t.Fatalf("parse recovery identity: %v", err)
	}
	recoveryVault := &vault.FileVault{
		Dir:        dir,
		Envelope:   envelope.Age{},
		Identities: []age.Identity{recIdentity},
	}
	got, err := recoveryVault.Read(ctx, "demo")
	if err != nil {
		t.Fatalf("recovery identity could not decrypt: %v", err)
	}
	if got.Variables["DEMO_SECRET"] != canary {
		t.Fatal("recovery identity decrypted a different value")
	}

	// And the device key is genuinely a different key.
	if recPrivate == devPrivate {
		t.Fatal("recovery identity and device identity are the same key")
	}

	assertNoCanary(t, dir)
}

// TestUnauthorizedIdentityCannotDecrypt is the negative case. Without it, the
// round-trip test above would also "pass" if encryption were a no-op.
func TestUnauthorizedIdentityCannotDecrypt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	v, _, _ := newVault(t, dir)
	if _, err := v.Create(ctx, "demo", map[string]string{"DEMO_SECRET": canary}); err != nil {
		t.Fatalf("create profile: %v", err)
	}

	attackerPrivate, _, err := envelope.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate attacker identity: %v", err)
	}
	attackerIdentity, err := envelope.ParseIdentity(attackerPrivate)
	if err != nil {
		t.Fatalf("parse attacker identity: %v", err)
	}

	attackerVault := &vault.FileVault{
		Dir:        dir,
		Envelope:   envelope.Age{},
		Identities: []age.Identity{attackerIdentity},
	}
	if _, err := attackerVault.Read(ctx, "demo"); !errors.Is(err, envelope.ErrNotDecryptable) {
		t.Fatalf("unauthorized identity got err = %v, want ErrNotDecryptable", err)
	}
}

// TestStrictDecodingRejectsHostilePayloads covers the decoding rules that
// encoding/json does not give us for free.
func TestStrictDecodingRejectsHostilePayloads(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    error
	}{
		{
			name:    "duplicate key",
			payload: `{"format":1,"name":"demo","variables":{"A":"1","A":"2"}}`,
			want:    vault.ErrDuplicateKey,
		},
		{
			name:    "unsupported format",
			payload: `{"format":99,"name":"demo","variables":{}}`,
			want:    vault.ErrUnsupportedFormat,
		},
		{
			name:    "unknown field",
			payload: `{"format":1,"name":"demo","variables":{},"extra":true}`,
			want:    nil, // any error is acceptable; asserted below
		},
		{
			name:    "trailing content",
			payload: `{"format":1,"name":"demo","variables":{}}{"format":1}`,
			want:    vault.ErrTrailingContent,
		},
		{
			name:    "illegal variable name",
			payload: `{"format":1,"name":"demo","variables":{"not a name":"1"}}`,
			want:    vault.ErrInvalidName,
		},
		{
			name:    "NUL in value",
			payload: `{"format":1,"name":"demo","variables":{"A":"a\u0000b"}}`,
			want:    vault.ErrInvalidValue,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vault.DecodeProfile(strings.NewReader(tc.payload))
			if err == nil {
				t.Fatalf("payload was accepted; it must fail closed")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestChangeBumpsRevision checks the mutation path used by `set` and `unset`.
func TestChangeBumpsRevision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	v, _, _ := newVault(t, dir)
	if _, err := v.Create(ctx, "demo", map[string]string{"A": "1"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	summary, err := v.Change(ctx, "demo", func(p *vault.Profile) error {
		p.Variables["B"] = canary
		return nil
	})
	if err != nil {
		t.Fatalf("change: %v", err)
	}
	if summary.Revision != 2 {
		t.Fatalf("revision = %d, want 2", summary.Revision)
	}
	assertNoCanary(t, dir)
}

// TestNoPlaintextTempFilesLeftBehind checks the atomic-write cleanup.
func TestNoPlaintextTempFilesLeftBehind(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	v, _, _ := newVault(t, dir)
	if _, err := v.Create(ctx, "demo", map[string]string{"DEMO_SECRET": canary}); err != nil {
		t.Fatalf("create: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "profiles"))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

// assertNoCanary fails if the canary appears in any captured output or in any
// file under dir. This is the automated version of "did we leak?".
func assertNoCanary(t *testing.T, dir string, blobs ...[]byte) {
	t.Helper()

	needle := []byte(canary)
	for i, b := range blobs {
		if bytes.Contains(b, needle) {
			t.Errorf("canary disclosed in captured output %d", i)
		}
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, needle) {
			t.Errorf("canary disclosed in file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk vault dir: %v", err)
	}
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func fileMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

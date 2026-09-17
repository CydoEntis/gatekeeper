package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gatekeeper/internal/platform"
)

func writeMeta(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), platform.PrivateFileMode); err != nil {
		t.Fatal(err)
	}
}

// TestMetadataRejectsDuplicateKeys is the regression test for a strictness gap.
//
// Profiles rejected duplicate JSON keys and metadata did not, even though
// encoding/json silently keeps the *last* of two identical keys. That matters most
// for devices.json, which is what decides who can read the vault: a file saying
// two different things about a recipient should be refused, not resolved by
// position.
func TestMetadataRejectsDuplicateKeys(t *testing.T) {
	cases := map[string]string{
		"manifest.json": `{"format":1,"vault_id":"a","vault_id":"b"}`,
		"devices.json": `{"format":1,"revision":1,"revision":2,` +
			`"devices":[{"id":"1","name":"d","recipient":"age1x"}],"recovery_recipient":"age1y"}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeMeta(t, dir, name, content)

			var err error
			if name == ManifestFile {
				_, err = ReadManifest(dir)
			} else {
				_, err = ReadDevices(dir)
			}
			if !errors.Is(err, ErrDuplicateKey) {
				t.Fatalf("err = %v, want ErrDuplicateKey", err)
			}
		})
	}
}

// TestMetadataStillRejectsUnknownAndTrailingContent checks the existing strictness
// was not traded away for the new one.
func TestMetadataStillRejectsUnknownAndTrailingContent(t *testing.T) {
	dir := t.TempDir()
	writeMeta(t, dir, ManifestFile, `{"format":1,"vault_id":"a","unexpected":true}`)
	if _, err := ReadManifest(dir); err == nil {
		t.Error("an unknown field was accepted")
	}

	writeMeta(t, dir, ManifestFile, `{"format":1,"vault_id":"a"}{"format":1}`)
	if _, err := ReadManifest(dir); !errors.Is(err, ErrTrailingContent) {
		t.Errorf("err = %v, want ErrTrailingContent", err)
	}
}

// TestReadManifestAcceptsTheShapeInitWrites guards against the stricter decoder
// rejecting this project's own output.
func TestReadManifestAcceptsTheShapeInitWrites(t *testing.T) {
	dir := t.TempDir()
	manifest := Manifest{Format: FormatVersion, VaultID: "0195f03a-0000-4000-8000-000000000000", Name: "personal"}
	if err := WriteManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}

	got, err := ReadManifest(dir)
	if err != nil {
		t.Fatalf("reading back what we just wrote failed: %v", err)
	}
	if got.VaultID != manifest.VaultID || got.Name != manifest.Name {
		t.Errorf("got %+v, want %+v", got, manifest)
	}
}

// TestReadDevicesRefusesAnEmptyRecipientSet keeps the fail-closed rule: a vault
// with nobody authorized cannot decrypt anything, so it is not a valid vault.
func TestReadDevicesRefusesAnEmptyRecipientSet(t *testing.T) {
	dir := t.TempDir()
	writeMeta(t, dir, DevicesFile, `{"format":1,"revision":1,"devices":[],"recovery_recipient":"age1y"}`)

	_, err := ReadDevices(dir)
	if err == nil {
		t.Fatal("a vault with no recipients was accepted")
	}
	if !strings.Contains(err.Error(), "no recipients") {
		t.Errorf("error is not explanatory: %v", err)
	}
}

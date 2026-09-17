//go:build !windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadPrivateFileEnforcesModeOnTheReader covers the contract that makes the
// identity and passphrase files safe to read: an unsafe file is refused, and the
// refusal comes back with no bytes attached.
//
// Note what this does and does not prove. The time-of-check/time-of-use race that
// ReadPrivateFile exists to close is closed *structurally* -- the mode is taken
// from the same descriptor the bytes are read from, so there is no window to lose
// -- and that cannot be demonstrated from outside by a test, because exploiting it
// needs the file swapped between two calls that are no longer two calls. What is
// tested here is the behavior a caller depends on.
func TestReadPrivateFileEnforcesModeOnTheReader(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, mode os.FileMode, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		// os.WriteFile applies the umask, so set the mode explicitly to be sure
		// the test asserts what it means to.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		return path
	}

	private := write("identity.key", PrivateFileMode, "AGE-SECRET-KEY-1PRIVATE")
	worldReadable := write("loose.key", 0o644, "AGE-SECRET-KEY-1LOOSE")

	t.Run("a 0600 file is read", func(t *testing.T) {
		got, err := ReadPrivateFile(private)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if string(got) != "AGE-SECRET-KEY-1PRIVATE" {
			t.Errorf("contents = %q", got)
		}
	})

	t.Run("a world-readable file is refused", func(t *testing.T) {
		got, err := ReadPrivateFile(worldReadable)
		if !errors.Is(err, ErrUnsafePerm) {
			t.Fatalf("err = %v, want ErrUnsafePerm", err)
		}
		// Refusing has to mean refusing the bytes too, or a caller that logged
		// the error and carried on would still hold the secret.
		if len(got) != 0 {
			t.Errorf("returned %d bytes alongside an unsafe-permission error", len(got))
		}
		// The message must name the file and say how to fix it.
		if !strings.Contains(err.Error(), worldReadable) {
			t.Errorf("the error does not name the file: %v", err)
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("the error does not say how to fix it: %v", err)
		}
	})

	t.Run("a symlink to a world-readable file is refused", func(t *testing.T) {
		// Recorded because it is the shape a user actually hits: a key copied
		// somewhere convenient and left behind as a link. The mode that matters
		// is the target's, because that is where the bytes are.
		link := filepath.Join(dir, "link.key")
		if err := os.Symlink(worldReadable, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := ReadPrivateFile(link); !errors.Is(err, ErrUnsafePerm) {
			t.Fatalf("err = %v, want ErrUnsafePerm", err)
		}
	})

	t.Run("a missing file reports not-exist", func(t *testing.T) {
		// identity.Load turns this into its own ErrNotFound, so the sentinel has
		// to survive the wrapper.
		_, err := ReadPrivateFile(filepath.Join(dir, "absent.key"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("err = %v, want os.ErrNotExist", err)
		}
	})
}

// TestCheckPrivateFilePermsAgreesWithReadPrivateFile keeps the diagnostic form
// and the real read from drifting apart.
//
// doctor reports on a file using CheckPrivateFilePerms while the loader enforces
// the rule using ReadPrivateFile. If they disagreed, doctor would either bless a
// key that then fails to load, or warn about one that loads fine.
func TestCheckPrivateFilePermsAgreesWithReadPrivateFile(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"private", PrivateFileMode},
		{"group readable", 0o640},
		{"world readable", 0o644},
		{"group writable", 0o620},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".key")
			if err := os.WriteFile(path, []byte("x"), tc.mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			checkErr := CheckPrivateFilePerms(path)
			_, readErr := ReadPrivateFile(path)

			if (checkErr == nil) != (readErr == nil) {
				t.Fatalf("disagreement: check = %v, read = %v", checkErr, readErr)
			}
		})
	}
}

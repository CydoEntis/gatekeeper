//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// ReplaceFile atomically replaces dst with tmp.
//
// This single function is where the plan's POSIX assumption actually breaks.
//
// os.Rename maps to MoveFileEx(MOVEFILE_REPLACE_EXISTING). Unlike rename(2) it
// FAILS with a sharing violation whenever any other process has the
// destination open -- and on a Windows-primary machine that is routine, not
// exotic: Defender scanning the new file, the search indexer, an editor with
// the vault open, or OneDrive/Dropbox syncing the directory.
//
// A naive port would surface those as random "access denied" errors during
// ordinary `gk set`. They are transient, so retry with backoff.
func ReplaceFile(tmp, dst string) error {
	const attempts = 10
	var err error
	for i := 0; i < attempts; i++ {
		if err = os.Rename(tmp, dst); err == nil {
			return nil
		}
		if !isTransientLock(err) {
			return err
		}
		time.Sleep(time.Duration(10*(i+1)) * time.Millisecond)
	}
	return fmt.Errorf("replace %s after %d attempts: %w", dst, attempts, err)
}

func isTransientLock(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// SyncDir is a no-op on Windows: the OS does not offer a directory fsync, and
// FlushFileBuffers on a directory handle is not equivalent.
func SyncDir(dir string) error { return nil }

// Per-user directories Windows already restricts to the owning user, which is
// what makes them usable for a key without writing an explicit DACL.
const (
	envLocalAppData = "LOCALAPPDATA"
	envAppData      = "APPDATA"
)

// CheckIdentityPerms verifies the private key is in a per-user location.
//
// It deliberately does NOT check mode bits, because on Windows there are none:
// os.Chmod only toggles the read-only attribute and does nothing to stop another
// user on the machine from reading the file. A "0600" identity on Windows can
// still be world-readable, so copying the POSIX check across would be worse than
// having no check at all -- it would report safety that does not exist.
//
// Real enforcement means writing a DACL (SetNamedSecurityInfo with inheritance
// removed) via golang.org/x/sys/windows. That is deliberately not done: it is
// fiddly, needs the key's SID rather than its path, and a mistake can lock the
// user out of their own key. Requiring the key to live under the per-user profile
// is the cheap safe route, because Windows already ACLs those directories to the
// owning user.
//
// The gap is documented rather than closed, and it is worth stating plainly: a key
// inside the profile is protected by that inherited ACL and by nothing more, so a
// machine where another local account can read the profile directory is a machine
// where the key is readable.
func CheckIdentityPerms(path string) error {
	return checkPerUserProfile(path, "identity")
}

// CheckSecretFilePerms applies the same rule to any other file holding a secret,
// such as a passphrase file.
func CheckSecretFilePerms(path string) error {
	return checkPerUserProfile(path, "file")
}

func checkPerUserProfile(path, what string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	for _, base := range []string{os.Getenv(envLocalAppData), os.Getenv(envAppData)} {
		if base == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(abs), strings.ToLower(base)) {
			return nil
		}
	}

	return fmt.Errorf(
		"%w: %s %s is outside the per-user profile; on Windows its ACL may let other "+
			"local users read it, and mode bits cannot fix that", ErrUnsafePerm, what, abs)
}

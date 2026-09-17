//go:build !windows

// Package platform holds every place where the operating system's behavior
// differs enough to change the design.
//
// This file is the POSIX implementation. The Windows one is a genuinely
// different algorithm, not a different constant -- which is the whole point of
// giving the OS its own module instead of scattering runtime.GOOS checks
// through the vault.
package platform

import (
	"fmt"
	"os"
)

// ReplaceFile atomically replaces dst with tmp.
//
// On POSIX, rename(2) is atomic and replaces the destination unconditionally.
func ReplaceFile(tmp, dst string) error {
	return os.Rename(tmp, dst)
}

// SyncDir flushes the directory entry so a crash cannot lose the rename.
//
// Best-effort: some filesystems reject fsync on a directory, and that failure
// is not worth aborting a completed write over.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}

// CheckIdentityPerms refuses to use a private key other local users could read.
//
// On POSIX this is a real check: the kernel enforces the mode bits.
func CheckIdentityPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: identity %s has permissions %04o; want 0600 (try: chmod 600 %s)",
			ErrUnsafePerm, path, perm, path)
	}
	return nil
}

// CheckSecretFilePerms applies the same rule to any other file holding a secret,
// such as a passphrase file. Same check, different message, because "identity"
// would be misleading.
func CheckSecretFilePerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s is readable by others (%04o); want 0600 (try: chmod 600 %s)",
			ErrUnsafePerm, path, perm, path)
	}
	return nil
}

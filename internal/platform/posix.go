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
	"io"
	"io/fs"
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

// ReadPrivateFile reads a file holding a secret, refusing it if other local
// users could read it.
//
// The permission check runs against the open file descriptor, not the path.
// Checking a path and then reading it separately is a time-of-check to
// time-of-use race: the file can be replaced in between, so the check would
// describe a different file than the one whose bytes come back. Reading through
// the very descriptor that was checked removes the window -- which is why the
// check and the read are one function, rather than two calls a caller has to
// order correctly every time.
func ReadPrivateFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPerms(fi, path); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// CheckPrivateFilePerms reports whether a private file is readable by other local
// users, without opening it.
//
// This is the diagnostic form, for reporting *on* a file rather than using it.
// It stats by path, so it must never be used to decide whether a file is safe to
// read -- ReadPrivateFile is that decision, and it makes the check race-free.
func CheckPrivateFilePerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkPerms(fi, path)
}

// checkPerms is the one rule, so the diagnostic and the real read cannot drift
// apart and disagree about what "safe" means.
func checkPerms(fi fs.FileInfo, path string) error {
	if perm := fi.Mode().Perm(); perm&GroupOrOtherBits != 0 {
		return fmt.Errorf("%w: %s is readable by others (%04o); want 0600 (try: chmod 600 %s)",
			ErrUnsafePerm, path, perm, path)
	}
	return nil
}

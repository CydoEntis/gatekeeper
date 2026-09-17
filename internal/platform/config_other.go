//go:build !windows

package platform

import (
	"os"
	"path/filepath"
)

// ConfigDir returns the per-user directory holding Gatekeeper's non-secret local
// configuration and its private identities.
//
// This directory is deliberately NOT inside any vault. See ARCHITECTURE.md
// invariant #1: private identities never enter a synchronized vault directory.
func ConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "gatekeeper"), nil
}

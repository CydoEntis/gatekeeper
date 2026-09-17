//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
)

// ConfigDir returns %LOCALAPPDATA%\gatekeeper.
//
// Deliberately LOCALAPPDATA rather than the Roaming AppData that Go's
// os.UserConfigDir returns. Roaming profiles are copied to and from a domain
// controller at logon, and a private key should not travel that way. This is a
// case where the platform-appropriate answer differs between Windows and
// everything else, which is exactly why it lives in the platform module.
func ConfigDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", fmt.Errorf("LOCALAPPDATA is not set; cannot locate the per-user configuration directory")
	}
	return filepath.Join(base, "gatekeeper"), nil
}

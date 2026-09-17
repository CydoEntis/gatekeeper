// Package localconfig stores non-secret, machine-local settings.
//
// Nothing here is synchronized and nothing here is secret. It exists so that
// commands can find the vault without being told every time, while keeping the
// private identity in a separate file with separate handling.
package localconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gatekeeper/internal/platform"
)

const fileName = "config.json"

// Config is the machine-local configuration.
type Config struct {
	// DefaultVault is the vault a command uses when no flag or environment
	// variable names one. With a personal vault and a work vault, this is what
	// makes the common case need no arguments.
	DefaultVault string `json:"default_vault,omitempty"`
}

// Path returns the location of the local configuration file.
func Path() (string, error) {
	dir, err := platform.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fileName), nil
}

// Load reads the configuration. A missing file is not an error: it is the
// normal state before `init` has run, and it yields a zero Config.
func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("read local config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(encoded, &c); err != nil {
		return Config{}, fmt.Errorf("read local config %s: %w", path, err)
	}
	return c, nil
}

// Save writes the configuration with owner-only permissions.
//
// There is nothing secret in here, but the file names where a vault lives, and
// there is no reason to advertise that to other local users.
func Save(c Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), platform.PrivateDirMode); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	payload, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode local config: %w", err)
	}
	payload = append(payload, '\n')

	// Write-then-rename so a crash cannot leave a truncated config that would
	// silently send later commands to the wrong vault.
	tmp, err := os.CreateTemp(filepath.Dir(path), platform.TempFilePrefix+"config-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(platform.PrivateFileMode); err != nil {
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	return platform.ReplaceFile(tmpName, path)
}

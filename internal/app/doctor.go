package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gatekeeper/internal/guard"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/platform"
	"gatekeeper/internal/vault"
)

// ErrUnhealthy reports that at least one diagnostic check failed.
var ErrUnhealthy = errors.New("some checks failed")

// Check is one diagnostic result.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// DoctorReport is the outcome of a diagnostic run.
type DoctorReport struct {
	VaultDir string
	Checks   []Check
}

// Failed returns the checks that did not pass.
func (r DoctorReport) Failed() []Check {
	var failed []Check
	for _, c := range r.Checks {
		if !c.OK {
			failed = append(failed, c)
		}
	}
	return failed
}

// Doctor inspects a vault and the machine state around it.
//
// It deliberately does **not** require the passphrase. It checks presence,
// permissions, and hygiene rather than decryption, so it still works in the
// situation where you most need it: when the vault will not open and you do not
// yet know why.
func (a App) Doctor(ctx context.Context, vaultDir string) (DoctorReport, error) {
	if err := ctx.Err(); err != nil {
		return DoctorReport{}, err
	}

	report := DoctorReport{VaultDir: vaultDir}
	add := func(name string, ok bool, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail})
	}

	if vaultDir == "" {
		add("vault selected", false, "no vault directory was given or configured")
		return report, nil
	}

	manifest, err := vault.ReadManifest(vaultDir)
	if err != nil {
		add("vault readable", false, err.Error())
		// Everything below depends on knowing which vault this is, so stop here
		// rather than reporting a cascade of consequences.
		return report, nil
	}
	add("vault readable", true, fmt.Sprintf("%s (%s)", manifest.Name, manifest.VaultID))

	if devices, err := vault.ReadDevices(vaultDir); err != nil {
		add("recipients readable", false, err.Error())
	} else {
		add("recipients readable", true,
			fmt.Sprintf("%d device recipient(s) plus an offline recovery recipient", len(devices.Devices)))
	}

	path, err := identity.Path(manifest.VaultID)
	switch {
	case err != nil:
		add("identity present", false, err.Error())
	default:
		if _, statErr := os.Stat(path); statErr != nil {
			add("identity present", false, "no local identity for this vault at "+path)
		} else {
			add("identity present", true, path)
			if permErr := platform.CheckIdentityPerms(path); permErr != nil {
				add("identity protected", false, permErr.Error())
			} else {
				add("identity protected", true, "encrypted at rest, and where it should be")
			}
		}
	}

	// Invariant #1, checked against the user's real data rather than a fixture.
	findings, err := guard.Scan(vaultDir)
	switch {
	case err != nil:
		add("no key material in the vault", false, err.Error())
	case len(findings) > 0:
		add("no key material in the vault", false,
			fmt.Sprintf("%d file(s), starting with %s", len(findings), findings[0].Path))
	default:
		add("no key material in the vault", true, "nothing that looks like a secret")
	}

	if _, err := os.Stat(filepath.Join(vaultDir, vault.GitignoreFile)); err != nil {
		add("vault has ignore rules", false,
			"no "+vault.GitignoreFile+" in the vault directory; a stray key could be committed")
	} else {
		add("vault has ignore rules", true, vault.GitignoreFile+" is present")
	}

	return report, nil
}

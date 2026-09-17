package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gatekeeper/internal/guard"
	"gatekeeper/internal/identity"
	"gatekeeper/internal/platform"
	"gatekeeper/internal/vault"
)

// ErrUnhealthy reports that at least one diagnostic check failed.
var ErrUnhealthy = errors.New("some checks failed")

// Names of the checks doctor reports.
//
// They are stable identifiers as much as prose: the CLI renders them, and a test
// asserts on them, so a reworded label in one place would be a silent break
// somewhere else.
const (
	checkVaultSelected     = "vault selected"
	checkVaultReadable     = "vault readable"
	checkRecipients        = "recipients readable"
	checkIdentityPresent   = "identity present"
	checkIdentityProtected = "identity protected"
	checkNoKeyMaterial     = "no key material in the vault"
	checkIgnoreRules       = "vault has ignore rules"
	checkNoFlags           = "no flagged variables"
)

// Check is one diagnostic result.
type Check struct {
	Name   string
	OK     bool
	Detail string
	// Skipped marks a check that could not run. It is neither a pass nor a
	// failure, and reporting it as a pass would be a lie.
	Skipped bool
}

// DoctorReport is the outcome of a diagnostic run.
type DoctorReport struct {
	VaultDir string
	Checks   []Check
}

// Failed returns the checks that did not pass. Skipped checks are not failures.
func (r DoctorReport) Failed() []Check {
	var failed []Check
	for _, c := range r.Checks {
		if !c.OK && !c.Skipped {
			failed = append(failed, c)
		}
	}
	return failed
}

// Doctor inspects a vault and the machine state around it.
//
// It deliberately does **not** require the passphrase. Its checks are about
// presence, permissions and hygiene rather than decryption, so it still works in
// the situation where you most need it: when the vault will not open and you do
// not yet know why.
//
// The one check that does need the vault decrypted — flagged variables — runs
// only when `unlock` carries a passphrase or an identity, and is reported as
// skipped otherwise. Saying "ok" for a check that never ran would be worse than
// having no check at all.
func (a App) Doctor(ctx context.Context, vaultDir string, unlock VaultRef) (DoctorReport, error) {
	if err := ctx.Err(); err != nil {
		return DoctorReport{}, err
	}

	report := DoctorReport{VaultDir: vaultDir}
	add := func(name string, ok bool, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, OK: ok, Detail: detail})
	}
	addSkipped := func(name, detail string) {
		report.Checks = append(report.Checks, Check{Name: name, Skipped: true, Detail: detail})
	}

	if vaultDir == "" {
		add(checkVaultSelected, false, "no vault directory was given or configured")
		return report, nil
	}

	manifest, err := vault.ReadManifest(vaultDir)
	if err != nil {
		add(checkVaultReadable, false, err.Error())
		// Everything below depends on knowing which vault this is, so stop here
		// rather than reporting a cascade of consequences.
		return report, nil
	}
	add(checkVaultReadable, true, fmt.Sprintf("%s (%s)", manifest.Name, manifest.VaultID))

	if devices, err := vault.ReadDevices(vaultDir); err != nil {
		add(checkRecipients, false, err.Error())
	} else {
		add(checkRecipients, true,
			fmt.Sprintf("%d device recipient(s) plus an offline recovery recipient", len(devices.Devices)))
	}

	path, err := identity.Path(manifest.VaultID)
	switch {
	case err != nil:
		add(checkIdentityPresent, false, err.Error())
	default:
		if _, statErr := os.Stat(path); statErr != nil {
			add(checkIdentityPresent, false, "no local identity for this vault at "+path)
		} else {
			add(checkIdentityPresent, true, path)
			if permErr := platform.CheckIdentityPerms(path); permErr != nil {
				add(checkIdentityProtected, false, permErr.Error())
			} else {
				add(checkIdentityProtected, true, "encrypted at rest, and where it should be")
			}
		}
	}

	// Invariant #1, checked against the user's real data rather than a fixture.
	findings, err := guard.Scan(vaultDir)
	switch {
	case err != nil:
		add(checkNoKeyMaterial, false, err.Error())
	case len(findings) > 0:
		add(checkNoKeyMaterial, false,
			fmt.Sprintf("%d file(s), starting with %s", len(findings), findings[0].Path))
	default:
		add(checkNoKeyMaterial, true, "nothing that looks like a secret")
	}

	if _, err := os.Stat(filepath.Join(vaultDir, vault.GitignoreFile)); err != nil {
		add(checkIgnoreRules, false,
			"no "+vault.GitignoreFile+" in the vault directory; a stray key could be committed")
	} else {
		add(checkIgnoreRules, true, vault.GitignoreFile+" is present")
	}

	// Flagged variables live inside the encrypted payload, so this is the one
	// check that needs the vault opened.
	if unlock.Passphrase == "" && unlock.Identity == "" {
		addSkipped(checkNoFlags,
			"needs the vault unlocked; pass --passphrase-file to include it")
		return report, nil
	}

	unlock.Dir = vaultDir
	opened, err := a.open(unlock)
	if err != nil {
		add(checkNoFlags, false, err.Error())
		return report, nil
	}

	flagged, err := flaggedVariables(ctx, opened)
	switch {
	case err != nil:
		add(checkNoFlags, false, err.Error())
	case len(flagged) == 0:
		add(checkNoFlags, true, "nothing marked as exposed")
	default:
		add(checkNoFlags, false,
			fmt.Sprintf("%d still flagged: %s", len(flagged), strings.Join(flagged, ", ")))
	}

	return report, nil
}

// flaggedVariables lists every flagged variable as "profile/KEY".
func flaggedVariables(ctx context.Context, v *vault.FileVault) ([]string, error) {
	summaries, err := v.List(ctx)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, s := range summaries {
		for _, name := range s.Flagged() {
			out = append(out, s.Name+"/"+name)
		}
	}
	sort.Strings(out)
	return out, nil
}

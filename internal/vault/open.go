package vault

import (
	"fmt"
	"time"

	"filippo.io/age"

	"gatekeeper/internal/envelope"
)

// Open prepares a vault for use: it reads the recipient set from devices.json and
// parses the caller's private identity.
//
// The passphrase is deliberately not involved. Unlocking an identity belongs to
// the identity package, and keeping it out of here means the vault cannot
// accidentally acquire a reason to handle a key in the clear.
func Open(dir, privateIdentity string) (*FileVault, error) {
	if _, err := ReadManifest(dir); err != nil {
		return nil, err
	}
	devices, err := ReadDevices(dir)
	if err != nil {
		return nil, err
	}

	// Every profile is encrypted to every device recipient plus the recovery
	// recipient. A recipient that will not parse is fatal rather than skipped:
	// silently dropping one would produce a profile that its holder cannot open,
	// and the loss would not be noticed until they needed it.
	recipients := make([]age.Recipient, 0, len(devices.Devices)+1)
	for _, d := range devices.Devices {
		r, err := envelope.ParseRecipient(d.Recipient)
		if err != nil {
			return nil, fmt.Errorf("device %q: %w", d.Name, err)
		}
		recipients = append(recipients, r)
	}
	if devices.RecoveryRecipient != "" {
		r, err := envelope.ParseRecipient(devices.RecoveryRecipient)
		if err != nil {
			return nil, fmt.Errorf("recovery recipient: %w", err)
		}
		recipients = append(recipients, r)
	}

	identity, err := envelope.ParseIdentity(privateIdentity)
	if err != nil {
		return nil, err
	}

	return &FileVault{
		Dir:        dir,
		Envelope:   envelope.Age{},
		Recipients: recipients,
		Identities: []age.Identity{identity},
		Now:        time.Now,
	}, nil
}

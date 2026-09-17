package platform

import "os"

// Permission modes, named because a bare 0o600 at a call site says nothing about
// why it is there, and because the two values mean genuinely different things: a
// file holding a secret is 0600, the directory holding it is 0700.
const (
	// PrivateFileMode is for every file Gatekeeper writes: identities, passphrase
	// files, exported plaintext, the temporary files used during an atomic write,
	// and the vault's own metadata.
	//
	// The non-secret files could be looser. They are not, because one rule is one
	// thing to reason about, and nothing in a vault needs to be group-readable.
	PrivateFileMode os.FileMode = 0o600

	// PrivateDirMode is for the directories that hold those files.
	PrivateDirMode os.FileMode = 0o700

	// GroupOrOtherBits is the mask of permission bits that must be clear on
	// anything holding a secret. Testing it is how Gatekeeper refuses to use a key
	// it cannot actually protect.
	GroupOrOtherBits os.FileMode = 0o077
)

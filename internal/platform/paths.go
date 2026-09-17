package platform

// Names Gatekeeper owns. They live in this module because it is also the module
// that decides where they go.
const (
	// AppDirName is the directory Gatekeeper owns under the platform's
	// per-user configuration location.
	AppDirName = "gatekeeper"

	// TempFilePrefix begins every temporary file Gatekeeper writes.
	//
	// It is a constant rather than a literal at each call site because the vault
	// ships a .gitignore that has to ignore the same prefix, and those two must
	// not be able to drift apart.
	TempFilePrefix = ".tmp-"
)

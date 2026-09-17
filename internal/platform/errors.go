package platform

import "errors"

// ErrUnsafePerm reports that a private key or secret file is readable by
// someone other than its owner. Commands map this to the permission exit code.
var ErrUnsafePerm = errors.New("unsafe file permissions")

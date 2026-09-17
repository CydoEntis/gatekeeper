package vault

import (
	"crypto/rand"
	"fmt"
)

// NewID returns a random RFC 4122 version 4 UUID.
//
// Written here rather than taken as a dependency: it is sixteen random bytes and
// six bit operations, and a tool that handles secrets benefits from a small
// dependency graph.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

// FormatVersion is the only payload version this build understands. Anything
// else fails closed rather than being guessed at.
const FormatVersion = 1

// Typed error categories. Commands map these to stable exit codes; see
// ARCHITECTURE.md section 9.
var (
	ErrUnsupportedFormat = errors.New("unsupported profile format")
	ErrInvalidName       = errors.New("invalid name")
	ErrInvalidValue      = errors.New("invalid value")
	ErrDuplicateKey      = errors.New("duplicate JSON key")
	ErrTrailingContent   = errors.New("unexpected trailing content")
	ErrNotFound          = errors.New("profile not found")
	ErrAlreadyExists     = errors.New("profile already exists")
	ErrNameMismatch      = errors.New("profile name does not match filename")
	ErrLocked            = errors.New("vault is locked")
	ErrConflict          = errors.New("conflict")
)

var (
	// Portable subset: lowercase-ish, no path separators, no leading dot.
	profileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// The portable environment-variable subset from ARCHITECTURE.md 4.3.
	varNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Profile is the decrypted shape of one environment profile. It only ever
// exists in memory, or inside an age payload.
type Profile struct {
	Format    int               `json:"format"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Revision  int               `json:"revision"`
	UpdatedAt time.Time         `json:"updated_at"`
	Variables map[string]string `json:"variables"`
	// Flags marks variables that need attention — most often because the value
	// was exposed and has to be replaced.
	//
	// It lives inside the encrypted payload rather than in plaintext metadata, so
	// it travels with the vault and a note like "pasted into a chat" never leaks
	// to whoever can see the repository.
	Flags map[string]Flag `json:"flags,omitempty"`
}

// Flag is a note attached to one variable.
type Flag struct {
	Note string    `json:"note,omitempty"`
	At   time.Time `json:"at"`
}

// Validate enforces every rule that must hold before a profile is encrypted.
func (p Profile) Validate() error {
	if p.Format != FormatVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedFormat, p.Format, FormatVersion)
	}
	if !profileNameRE.MatchString(p.Name) {
		return fmt.Errorf("%w: profile name %q", ErrInvalidName, p.Name)
	}
	for k, v := range p.Variables {
		if !varNameRE.MatchString(k) {
			return fmt.Errorf("%w: variable name %q", ErrInvalidName, k)
		}
		// NUL cannot be represented in a process environment on any platform.
		if bytes.IndexByte([]byte(v), 0) >= 0 {
			return fmt.Errorf("%w: variable %q contains a NUL byte", ErrInvalidValue, k)
		}
	}
	return nil
}

// DecodeProfile enforces the strict decoding rules from ARCHITECTURE.md 4.3:
// known fields only, no duplicate keys, no trailing content, supported version.
//
// Note that encoding/json alone gives us only one of those four. Unknown fields
// need DisallowUnknownFields, trailing content needs a second read, and
// duplicate keys are NOT detected at all -- hence rejectDuplicateKeys below.
func DecodeProfile(r io.Reader) (Profile, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile: %w", err)
	}

	if err := rejectDuplicateKeys(raw); err != nil {
		return Profile{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var p Profile
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	if dec.More() {
		return Profile{}, ErrTrailingContent
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// rejectDuplicateKeys walks the JSON token stream looking for a repeated key
// inside any single object.
//
// encoding/json silently keeps the last duplicate, which matters here: if a
// profile ever carried two "variables" objects, the decrypted profile would not
// be the profile that was signed off on.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))

	type frame struct {
		object bool
		seen   map[string]bool
	}
	var stack []frame
	expectKey := false

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decode profile: %w", err)
		}

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{object: true, seen: map[string]bool{}})
				expectKey = true
			case '[':
				stack = append(stack, frame{})
				expectKey = false
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				expectKey = len(stack) > 0 && stack[len(stack)-1].object
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object {
				f := &stack[len(stack)-1]
				if expectKey {
					if f.seen[t] {
						return fmt.Errorf("%w: %q", ErrDuplicateKey, t)
					}
					f.seen[t] = true
					expectKey = false
				} else {
					// This string was a *value* (for example "demo"), not a
					// key. The next string in this object is a key again.
					//
					// Forgetting this branch is a real bug: string values are
					// common, and without it every key following a string value
					// is skipped, so duplicates go undetected.
					expectKey = true
				}
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				expectKey = true
			}
		}
	}
}

// ValidProfileName reports whether name is an acceptable profile name.
//
// Exported so the command layer can reject a bad name instantly, before it
// prompts for a passphrase or a secret the user would then have typed for
// nothing.
func ValidProfileName(name string) bool { return profileNameRE.MatchString(name) }

// ValidVariableName reports whether name is an acceptable portable variable name.
func ValidVariableName(name string) bool { return varNameRE.MatchString(name) }

// Summary renders a profile without exposing any value. This is the type that
// `list` prints, and it is why `list` cannot leak.
type Summary struct {
	Name     string
	Revision int
	Vars     []string
	// Flags is copied, not aliased, so a caller cannot mutate the profile it came
	// from by editing a summary.
	Flags map[string]Flag
}

// Flagged returns the flagged variable names, sorted.
func (s Summary) Flagged() []string {
	names := make([]string, 0, len(s.Flags))
	for name := range s.Flags {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p Profile) Summary() Summary {
	names := make([]string, 0, len(p.Variables))
	for k := range p.Variables {
		names = append(names, k)
	}
	// Sorted, because a map has no order and `gk list` output that reshuffles
	// between runs is untrustworthy to read and impossible to diff.
	sort.Strings(names)

	flags := make(map[string]Flag, len(p.Flags))
	for name, flag := range p.Flags {
		flags[name] = flag
	}

	return Summary{Name: p.Name, Revision: p.Revision, Vars: names, Flags: flags}
}

package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gatekeeper/internal/dotenv"
	"gatekeeper/internal/vault"
)

// ErrCollision reports that an import would replace values that already exist.
var ErrCollision = errors.New("import collides with existing values")

// CollisionError names the variables an import would change.
//
// It names keys only, never values — an error message is the easiest place to
// leak a secret by accident.
type CollisionError struct {
	Profile string
	Keys    []string
}

func (e *CollisionError) Error() string {
	return fmt.Sprintf(
		"%s already has %d variable(s) with a different value: %s\n"+
			"Nothing was changed. Re-run with --overwrite to replace them",
		e.Profile, len(e.Keys), strings.Join(e.Keys, ", "))
}

func (e *CollisionError) Unwrap() error { return ErrCollision }

// ImportRequest brings a parsed dotenv file into a profile.
type ImportRequest struct {
	Profile string
	Pairs   []dotenv.Pair
	// Overwrite permits replacing a variable that already exists with a
	// different value. Without it, a collision is refused before anything is
	// written.
	Overwrite bool
}

// ImportResult reports what changed, without revealing any value.
type ImportResult struct {
	Profile   string
	Revision  int
	Variables []string
	Created   bool
	Added     int
	Updated   int
	Unchanged int
}

// Import merges pairs into a profile, creating it if it does not exist.
//
// Collisions are detected before anything is written, so a refused import leaves
// the profile exactly as it was. That matters more than it sounds: a half-applied
// import would leave the user unsure which keys are current.
func (a App) Import(ctx context.Context, ref VaultRef, req ImportRequest) (ImportResult, error) {
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}
	if !vault.ValidProfileName(req.Profile) {
		return ImportResult{}, fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, req.Profile)
	}
	if len(req.Pairs) == 0 {
		return ImportResult{}, fmt.Errorf("%w: the file contained no variables", ErrUsage)
	}

	incoming := make(map[string]string, len(req.Pairs))
	for _, p := range req.Pairs {
		if !vault.ValidVariableName(p.Key) {
			return ImportResult{}, fmt.Errorf("%w: variable name %q on line %d",
				vault.ErrInvalidName, p.Key, p.Line)
		}
		incoming[p.Key] = p.Value
	}

	v, err := a.open(ref)
	if err != nil {
		return ImportResult{}, err
	}

	existing, err := v.Read(ctx, req.Profile)
	created := false
	if err != nil {
		if !errors.Is(err, vault.ErrNotFound) {
			return ImportResult{}, err
		}
		created = true
	}

	if !created && !req.Overwrite {
		var collisions []string
		for key, value := range incoming {
			if current, ok := existing.Variables[key]; ok && current != value {
				collisions = append(collisions, key)
			}
		}
		if len(collisions) > 0 {
			sort.Strings(collisions)
			return ImportResult{}, &CollisionError{Profile: req.Profile, Keys: collisions}
		}
	}

	var summary vault.Summary
	if created {
		summary, err = v.Create(ctx, req.Profile, incoming)
	} else {
		summary, err = v.Change(ctx, req.Profile, func(p *vault.Profile) error {
			for key, value := range incoming {
				p.Variables[key] = value
			}
			return nil
		})
	}
	if err != nil {
		return ImportResult{}, err
	}

	result := ImportResult{
		Profile:   summary.Name,
		Revision:  summary.Revision,
		Variables: summary.Vars,
		Created:   created,
	}
	for key, value := range incoming {
		if current, ok := existing.Variables[key]; !ok {
			result.Added++
		} else if current == value {
			result.Unchanged++
		} else {
			result.Updated++
		}
	}
	return result, nil
}

// ExportRequest names a profile to render as plaintext.
type ExportRequest struct {
	Profile string
}

// Export renders a profile as dotenv bytes.
//
// It deliberately returns bytes instead of writing them. Where plaintext lands is
// a decision for the command layer, and keeping the filesystem out of here means
// the rendering can be tested without ever creating a plaintext file.
func (a App) Export(ctx context.Context, ref VaultRef, req ExportRequest) ([]byte, vault.Summary, error) {
	if err := ctx.Err(); err != nil {
		return nil, vault.Summary{}, err
	}
	if !vault.ValidProfileName(req.Profile) {
		return nil, vault.Summary{}, fmt.Errorf("%w: profile name %q", vault.ErrInvalidName, req.Profile)
	}

	v, err := a.open(ref)
	if err != nil {
		return nil, vault.Summary{}, err
	}
	p, err := v.Read(ctx, req.Profile)
	if err != nil {
		return nil, vault.Summary{}, err
	}

	pairs := make([]dotenv.Pair, 0, len(p.Variables))
	for key, value := range p.Variables {
		pairs = append(pairs, dotenv.Pair{Key: key, Value: value})
	}
	return dotenv.Marshal(pairs), p.Summary(), nil
}

// Package dotenv parses dotenv files as raw.
//
// The single most important property of this package: **parsing never evaluates
// anything.** There is no variable expansion, no command substitution, no
// backticks, and no shell. A `.env` file that someone else wrote — or that you
// downloaded — cannot execute code by being imported.
//
// That is a deliberate reduction in compatibility. Real dotenv tooling sometimes
// expands `$VAR`; this does not, and says so. The cost is that a file relying on
// expansion must be expanded before import. The benefit is that importing is as
// safe as reading a text file, which is the whole point.
package dotenv

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxSize bounds a dotenv file. Profiles are kilobytes; anything at this limit is
// not a file of environment variables.
const MaxSize = 1 << 20 // 1 MiB

var (
	// ErrSyntax reports a line that is not valid dotenv.
	ErrSyntax = errors.New("invalid dotenv syntax")
	// ErrDuplicate reports the same key set twice in one file.
	ErrDuplicate = errors.New("duplicate key")
)

// keyRE is the portable variable-name subset.
//
// It matches vault.ValidVariableName deliberately. This package could import the
// vault for that function, but a parser should not depend on a storage module;
// a test asserts the two agree so they cannot drift.
var keyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Pair is one assignment, with the line it came from so errors can point at it.
type Pair struct {
	Key   string
	Value string
	Line  int
}

// Parse reads a dotenv file.
//
// Supported, because it is what real files contain:
//
//	KEY=value
//	KEY="quoted value"
//	KEY='literal value'
//	export KEY=value
//	# comment
//	KEY="a value that
//	spans lines"
//
// Deliberately NOT supported: `$VAR` expansion, `$(command)`, backticks, and any
// other evaluation. See the package comment.
func Parse(r io.Reader) ([]Pair, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read dotenv: %w", err)
	}
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("dotenv file is larger than %d bytes", MaxSize)
	}

	// Normalise line endings before anything else. Most of these files come from
	// Windows, and a stray carriage return would otherwise end up inside a value
	// — where it is invisible and breaks whatever reads it next.
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")

	var pairs []Pair
	seenAt := make(map[string]int, len(lines))

	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimSpace(trimExportPrefix(line))

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%w on line %d: expected KEY=value, got %q", ErrSyntax, lineNo, line)
		}

		key := strings.TrimSpace(line[:eq])
		if !keyRE.MatchString(key) {
			return nil, fmt.Errorf(
				"%w on line %d: %q is not a valid variable name (letters, digits and "+
					"underscore, not starting with a digit)", ErrSyntax, lineNo, key)
		}

		value, extraLines, err := parseValue(strings.TrimSpace(line[eq+1:]), lines, i, lineNo)
		if err != nil {
			return nil, err
		}
		i += extraLines

		if first, dup := seenAt[key]; dup {
			return nil, fmt.Errorf("%w on line %d: %q was already set on line %d",
				ErrDuplicate, lineNo, key, first)
		}
		seenAt[key] = lineNo

		// A NUL cannot be represented in a process environment on any platform,
		// and the vault rejects it too. Catch it here so the error names the line.
		if strings.IndexByte(value, 0) >= 0 {
			return nil, fmt.Errorf("%w on line %d: the value for %q contains a NUL byte",
				ErrSyntax, lineNo, key)
		}

		pairs = append(pairs, Pair{Key: key, Value: value, Line: lineNo})
	}

	return pairs, nil
}

// trimExportPrefix removes a leading `export`, which shell-style files use.
func trimExportPrefix(line string) string {
	const prefix = "export"
	if !strings.HasPrefix(line, prefix) {
		return line
	}
	rest := line[len(prefix):]
	if rest == "" {
		return line
	}
	// Only when followed by whitespace, so a variable actually named `exported`
	// is not mangled.
	if rest[0] != ' ' && rest[0] != '\t' {
		return line
	}
	return strings.TrimLeft(rest, " \t")
}

// parseValue reads the value beginning at rest, returning it and how many
// additional lines it consumed.
func parseValue(rest string, lines []string, idx, lineNo int) (string, int, error) {
	if rest == "" {
		return "", 0, nil
	}

	switch rest[0] {
	case '\'':
		return parseSingleQuoted(rest, lineNo)
	case '"':
		return parseDoubleQuoted(rest, lines, idx, lineNo)
	default:
		return parseBare(rest), 0, nil
	}
}

// parseSingleQuoted reads a literal value. No escapes are processed, so a
// backslash is just a backslash.
func parseSingleQuoted(rest string, lineNo int) (string, int, error) {
	end := strings.IndexByte(rest[1:], '\'')
	if end < 0 {
		return "", 0, fmt.Errorf("%w on line %d: unterminated single quote", ErrSyntax, lineNo)
	}
	value := rest[1 : 1+end]
	if err := rejectTrailing(rest[2+end:], lineNo); err != nil {
		return "", 0, err
	}
	return value, 0, nil
}

// parseDoubleQuoted reads a value that processes escapes and may span lines,
// which is how PEM keys and certificates end up in dotenv files.
func parseDoubleQuoted(rest string, lines []string, idx, lineNo int) (string, int, error) {
	var b strings.Builder
	consumed := 0
	cur := rest[1:]

	for {
		i := 0
		closed := false
		for i < len(cur) {
			c := cur[i]
			if c == '\\' && i+1 < len(cur) {
				b.WriteString(unescape(cur[i+1]))
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			b.WriteByte(c)
			i++
		}

		if closed {
			if err := rejectTrailing(cur[i:], lineNo); err != nil {
				return "", 0, err
			}
			return b.String(), consumed, nil
		}

		// Not closed on this line: continue on the next one.
		if idx+consumed+1 >= len(lines) {
			return "", 0, fmt.Errorf("%w on line %d: unterminated double quote", ErrSyntax, lineNo)
		}
		b.WriteByte('\n')
		consumed++
		cur = lines[idx+consumed]
	}
}

// unescape interprets the escape sequences dotenv files use.
//
// An unrecognised escape keeps both characters rather than dropping the
// backslash, because silently changing a value's meaning is worse than leaving it
// visibly odd.
func unescape(c byte) string {
	switch c {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '"':
		return `"`
	case '\\':
		return `\`
	case '$':
		return "$"
	default:
		return `\` + string(c)
	}
}

// rejectTrailing refuses text after a closing quote that is not a comment.
// Silently discarding it could hide a mistake in a hand-edited file.
func rejectTrailing(rest string, lineNo int) error {
	trailing := strings.TrimSpace(rest)
	if trailing == "" || strings.HasPrefix(trailing, "#") {
		return nil
	}
	return fmt.Errorf("%w on line %d: unexpected text after a closing quote: %q",
		ErrSyntax, lineNo, trailing)
}

// parseBare reads an unquoted value: up to an unquoted comment, trimmed.
//
// No expansion is performed. A `#` not preceded by whitespace is part of the
// value, so `pass#word` survives intact.
func parseBare(rest string) string {
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

package dotenv

import (
	"sort"
	"strings"
)

// Marshal renders pairs as a dotenv file that Parse reads back identically.
//
// Keys are sorted so the output is stable and diffable across machines. Every
// value that needs it is quoted, so a round trip is lossless — including values
// with newlines, which is how a PEM key survives export and re-import.
func Marshal(pairs []Pair) []byte {
	sorted := make([]Pair, len(pairs))
	copy(sorted, pairs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	var b strings.Builder
	for _, p := range sorted {
		b.WriteString(p.Key)
		b.WriteByte('=')
		b.WriteString(Quote(p.Value))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Quote renders a value so that Parse returns it unchanged.
//
// `$` is escaped as well as quoted. This parser does not expand variables, so it
// would round-trip either way — but escaping means the exported file is also safe
// to hand to other dotenv tooling that *does* expand, which is the common case for
// a file you just wrote to a project directory.
func Quote(value string) string {
	if !needsQuoting(value) {
		return value
	}

	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '$':
			b.WriteString(`\$`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// needsQuoting reports whether a value cannot survive being written bare.
func needsQuoting(value string) bool {
	if value == "" {
		return true
	}
	// Bare values are trimmed, so leading or trailing whitespace would be lost.
	if strings.TrimSpace(value) != value {
		return true
	}
	return strings.ContainsAny(value, " \t\n\r\"'\\#$")
}

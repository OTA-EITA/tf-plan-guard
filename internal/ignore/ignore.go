// Package ignore suppresses findings that a reviewer has accepted, such as a
// planned database migration that intentionally replaces the instance.
package ignore

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
)

// Entry ignores one rule for addresses matching a pattern. Pattern supports
// "*" as a wildcard; brackets and quotes in addresses are matched literally.
type Entry struct {
	Rule    string
	Pattern string
}

// Parse reads "RULE=ADDRESS_PATTERN" (or "RULE" alone for every address).
func Parse(s string) (Entry, error) {
	s = strings.TrimSpace(s)
	rule, pattern, found := strings.Cut(s, "=")
	if !found {
		pattern = "*"
	}
	rule, pattern = strings.TrimSpace(rule), strings.TrimSpace(pattern)
	if rule == "" || pattern == "" {
		return Entry{}, fmt.Errorf("invalid ignore %q (want RULE=ADDRESS_PATTERN)", s)
	}
	return Entry{Rule: rule, Pattern: pattern}, nil
}

// ParseFile reads one entry per line; blank lines and "#" comments are skipped.
func ParseFile(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		e, err := Parse(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Filter returns the findings that are not ignored, and how many were.
func Filter(fs []finding.Finding, entries []Entry) ([]finding.Finding, int) {
	var kept []finding.Finding
	ignored := 0
	for _, f := range fs {
		if matchesAny(f, entries) {
			ignored++
			continue
		}
		kept = append(kept, f)
	}
	return kept, ignored
}

func matchesAny(f finding.Finding, entries []Entry) bool {
	for _, e := range entries {
		if (e.Rule == "*" || e.Rule == f.RuleID) && glob(e.Pattern, f.Address) {
			return true
		}
	}
	return false
}

// glob matches s against a pattern where only "*" is special.
func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, p := range parts[1:] {
		last := i == len(parts)-2
		if last {
			return strings.HasSuffix(s, p)
		}
		idx := strings.Index(s, p)
		if idx < 0 {
			return false
		}
		s = s[idx+len(p):]
	}
	return true
}

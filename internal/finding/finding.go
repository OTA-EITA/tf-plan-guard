// Package finding defines the result types shared by rules and reports.
package finding

import (
	"sort"
	"strings"
)

// Severity ranks how risky a planned change is.
type Severity string

// Severities from most to least severe.
const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// ParseSeverity validates a user supplied severity.
func ParseSeverity(s string) (Severity, bool) {
	switch v := Severity(strings.ToUpper(s)); v {
	case High, Medium, Low:
		return v, true
	}
	return "", false
}

// Finding is one risky planned change.
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Severity Severity `json:"severity"`
	Address  string   `json:"address"`
	Action   string   `json:"action"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// Rule documents a rule.
type Rule struct {
	ID       string
	Severity Severity
	Title    string
}

// Sort orders findings worst first, then by address.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].Address < fs[j].Address
	})
}

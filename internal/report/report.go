// Package report renders findings and the plan summary.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
	"github.com/OTA-EITA/tf-plan-guard/internal/plan"
)

// Format is an output format.
type Format string

// Supported formats.
const (
	Table    Format = "table"
	JSON     Format = "json"
	Markdown Format = "markdown"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case Table, JSON, Markdown:
		return Format(s), nil
	}
	return "", fmt.Errorf("unknown output format %q (want table, json or markdown)", s)
}

// Result is everything a report shows.
type Result struct {
	Findings []finding.Finding   `json:"findings"`
	Ignored  int                 `json:"ignored"`
	Summary  map[plan.Action]int `json:"planSummary"`
}

func (r Result) count(s finding.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func (r Result) planLine() string {
	s := r.Summary
	return fmt.Sprintf("Plan: %d to add, %d to change, %d to destroy (%d replaced)",
		s[plan.Create]+s[plan.Replace], s[plan.Update], s[plan.Delete]+s[plan.Replace], s[plan.Replace])
}

func (r Result) findingLine() string {
	return fmt.Sprintf("Findings: %d high, %d medium, %d low (%d ignored)",
		r.count(finding.High), r.count(finding.Medium), r.count(finding.Low), r.Ignored)
}

// Write renders the result.
func Write(w io.Writer, r Result, f Format) error {
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if r.Findings == nil {
			r.Findings = []finding.Finding{}
		}
		return enc.Encode(r)
	case Markdown:
		return writeMarkdown(w, r)
	default:
		return writeTable(w, r)
	}
}

func writeTable(w io.Writer, r Result) error {
	if len(r.Findings) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tRULE\tACTION\tADDRESS\tMESSAGE")
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, f.Action, f.Address, f.Message)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	_, err := fmt.Fprintf(w, "%s\n%s\n", r.planLine(), r.findingLine())
	return err
}

func writeMarkdown(w io.Writer, r Result) error {
	var b strings.Builder
	icon := "✅"
	switch {
	case r.count(finding.High) > 0:
		icon = "🛑"
	case r.count(finding.Medium) > 0:
		icon = "⚠️"
	}
	fmt.Fprintf(&b, "### %s tf-plan-guard\n\n%s  \n%s\n", icon, r.planLine(), r.findingLine())
	if len(r.Findings) > 0 {
		b.WriteString("\n| Severity | Rule | Action | Address | Finding | Fix |\n|---|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s | %s |\n", f.Severity, f.RuleID, f.Action, f.Address, esc(f.Message), esc(f.Fix))
		}
		b.WriteString("\nIf a change is intended, add `RULE=ADDRESS` to `.tfplanguard-ignore` with a comment explaining why.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

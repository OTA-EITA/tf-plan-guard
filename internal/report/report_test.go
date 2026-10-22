package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
	"github.com/OTA-EITA/tf-plan-guard/internal/plan"
)

func sample() Result {
	return Result{
		Findings: []finding.Finding{{RuleID: "TF-NET-001", Severity: finding.High, Action: "create", Address: "aws_security_group.a", Message: "opens port 22 | ssh", Fix: "restrict"}},
		Ignored:  1,
		Summary:  map[plan.Action]int{plan.Create: 3, plan.Update: 1, plan.Replace: 1, plan.Delete: 2},
	}
}

func TestTable(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Table); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"aws_security_group.a", "Plan: 4 to add, 1 to change, 3 to destroy (1 replaced)", "Findings: 1 high, 0 medium, 0 low (1 ignored)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	if err := Write(&b, Result{}, Table); err != nil || strings.Contains(b.String(), "SEVERITY") {
		t.Errorf("a clean plan has no table: %q", b.String())
	}
}

func TestMarkdown(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Markdown); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "### 🛑 tf-plan-guard") || !strings.Contains(b.String(), `port 22 \| ssh`) {
		t.Errorf("markdown:\n%s", b.String())
	}
	b.Reset()
	_ = Write(&b, Result{}, Markdown)
	if !strings.HasPrefix(b.String(), "### ✅") {
		t.Errorf("clean markdown: %s", b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Result{}, JSON); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if fs, ok := got["findings"].([]any); !ok || len(fs) != 0 {
		t.Errorf("findings should be an empty array, got %v", got["findings"])
	}
	if _, err := ParseFormat("sarif"); err == nil {
		t.Error("unknown formats must be rejected")
	}
}

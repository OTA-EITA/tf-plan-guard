package ignore

import (
	"strings"
	"testing"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
)

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"aws_db_instance.main", "aws_db_instance.main", true},
		{"aws_db_instance.*", "aws_db_instance.main", true},
		{"module.db.*", "module.db.aws_rds_cluster.this[0]", true},
		{`aws_s3_bucket.this["logs"]`, `aws_s3_bucket.this["logs"]`, true},
		{`aws_s3_bucket.this[*]`, `aws_s3_bucket.this["logs"]`, true},
		{"*.legacy", "aws_instance.legacy", true},
		{"*db*", "module.db.x", true},
		{"aws_db_instance.*", "aws_rds_cluster.main", false},
		{"a*b*c", "abxc", true},
		{"a*b*c", "acb", false},
		{"a*a", "a", false},
	}
	for _, c := range cases {
		if got := glob(c.pattern, c.s); got != c.want {
			t.Errorf("glob(%q, %q) = %v", c.pattern, c.s, got)
		}
	}
}

func TestParseAndFilter(t *testing.T) {
	entries, err := ParseFile(strings.NewReader(`
# planned major version upgrade, data is migrated separately
TF-DATA-002 = aws_db_instance.orders
TF-NET-002   # public web ports are expected
`))
	if err != nil || len(entries) != 2 || entries[1].Pattern != "*" {
		t.Fatalf("got %+v, %v", entries, err)
	}
	fs := []finding.Finding{
		{RuleID: "TF-DATA-002", Address: "aws_db_instance.orders"},
		{RuleID: "TF-DATA-002", Address: "aws_db_instance.users"},
		{RuleID: "TF-NET-002", Address: "aws_security_group.web"},
	}
	kept, ignored := Filter(fs, entries)
	if ignored != 2 || len(kept) != 1 || kept[0].Address != "aws_db_instance.users" {
		t.Fatalf("kept %+v ignored %d", kept, ignored)
	}
	if _, err := Parse("=x"); err == nil {
		t.Error("empty rule must be rejected")
	}
	if _, err := ParseFile(strings.NewReader("ok\n= bad")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("got %v", err)
	}
}

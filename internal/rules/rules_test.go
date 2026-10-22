package rules

import (
	"strings"
	"testing"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
	"github.com/OTA-EITA/tf-plan-guard/internal/plan"
)

type obj = map[string]any

func rc(typ, name string, actions []string, before, after obj) plan.ResourceChange {
	return plan.ResourceChange{
		Address: typ + "." + name, Mode: "managed", Type: typ, Name: name,
		Change: plan.Change{Actions: actions, Before: before, After: after},
	}
}

var (
	create  = []string{"create"}
	update  = []string{"update"}
	destroy = []string{"delete"}
	replace = []string{"delete", "create"}
)

func check(changes ...plan.ResourceChange) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, f := range Check(plan.Plan{FormatVersion: "1.2", ResourceChanges: changes}) {
		out[f.Address] = append(out[f.Address], f)
	}
	return out
}

func ids(fs []finding.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return strings.Join(out, ",")
}

func TestLifecycle(t *testing.T) {
	db := rc("aws_db_instance", "main", replace, obj{"engine_version": "15"}, obj{"engine_version": "16"})
	db.Change.ReplacePaths = [][]any{{"engine_version"}}
	got := check(
		rc("aws_s3_bucket", "logs", destroy, obj{}, nil),
		db,
		rc("aws_instance", "web", destroy, obj{}, nil),
		rc("aws_instance", "api", replace, obj{}, obj{}),
		rc("aws_rds_cluster", "main", update, obj{"deletion_protection": true}, obj{"deletion_protection": false, "skip_final_snapshot": true}),
		rc("aws_s3_bucket", "assets", update, obj{"force_destroy": false}, obj{"force_destroy": true}),
		rc("aws_lb", "public", update, obj{"enable_deletion_protection": true}, obj{"enable_deletion_protection": true}),
	)
	cases := map[string]string{
		"aws_s3_bucket.logs":   "TF-DATA-001",
		"aws_db_instance.main": "TF-DATA-002",
		"aws_instance.web":     "TF-CHANGE-001",
		"aws_instance.api":     "TF-CHANGE-002",
		"aws_rds_cluster.main": "TF-DATA-003,TF-DATA-004",
		"aws_s3_bucket.assets": "TF-DATA-004",
		"aws_lb.public":        "",
	}
	for addr, want := range cases {
		if g := ids(got[addr]); g != want {
			t.Errorf("%s: got %q, want %q", addr, g, want)
		}
	}
	if !strings.Contains(got["aws_db_instance.main"][0].Message, "forced by engine_version") {
		t.Errorf("replace reason missing: %s", got["aws_db_instance.main"][0].Message)
	}
}

func sg(ingress ...obj) obj {
	l := []any{}
	for _, i := range ingress {
		l = append(l, map[string]any(i))
	}
	return obj{"ingress": l}
}

func rule(from, to float64, proto string, cidrs ...any) obj {
	return obj{"from_port": from, "to_port": to, "protocol": proto, "cidr_blocks": cidrs}
}

func TestNetwork(t *testing.T) {
	got := check(
		rc("aws_security_group", "ssh", create, nil, sg(rule(22, 22, "tcp", "0.0.0.0/0"))),
		rc("aws_security_group", "web", create, nil, sg(rule(443, 443, "tcp", "0.0.0.0/0"), rule(80, 80, "tcp", "0.0.0.0/0"))),
		rc("aws_security_group", "internal", create, nil, sg(rule(5432, 5432, "tcp", "10.0.0.0/8"))),
		rc("aws_security_group", "all", create, nil, sg(rule(0, 0, "-1", "0.0.0.0/0"))),
		rc("aws_security_group", "existing", update, sg(rule(22, 22, "tcp", "0.0.0.0/0")), sg(rule(22, 22, "tcp", "0.0.0.0/0"), rule(443, 443, "tcp", "10.0.0.0/8"))),
		rc("aws_vpc_security_group_ingress_rule", "rdp", create, nil, obj{"from_port": 3389.0, "to_port": 3389.0, "ip_protocol": "tcp", "cidr_ipv6": "::/0"}),
		rc("aws_security_group_rule", "egress", create, nil, obj{"type": "egress", "from_port": 0.0, "to_port": 0.0, "protocol": "-1", "cidr_blocks": []any{"0.0.0.0/0"}}),
		rc("google_compute_firewall", "ssh", create, nil, obj{"source_ranges": []any{"0.0.0.0/0"}, "allow": []any{map[string]any{"protocol": "tcp", "ports": []any{"22", "8000-8080"}}}}),
	)
	cases := map[string]string{
		"aws_security_group.ssh":                  "TF-NET-001",
		"aws_security_group.web":                  "TF-NET-002,TF-NET-002",
		"aws_security_group.internal":             "",
		"aws_security_group.all":                  "TF-NET-001",
		"aws_security_group.existing":             "",
		"aws_vpc_security_group_ingress_rule.rdp": "TF-NET-001",
		"aws_security_group_rule.egress":          "",
		"google_compute_firewall.ssh":             "TF-NET-001,TF-NET-001",
	}
	for addr, want := range cases {
		if g := ids(got[addr]); g != want {
			t.Errorf("%s: got %q, want %q", addr, g, want)
		}
	}
	if !strings.Contains(got["aws_security_group.all"][0].Message, "all ports") {
		t.Errorf("message: %s", got["aws_security_group.all"][0].Message)
	}
}

const (
	adminPolicy  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	s3AllPolicy  = `{"Statement":{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}}`
	scopedPolicy = `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}]}`
	denyAll      = `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	publicTrust  = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
	guardedTrust = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-123"}}}]}`
)

func TestIAM(t *testing.T) {
	got := check(
		rc("aws_iam_policy", "admin", create, nil, obj{"policy": adminPolicy}),
		rc("aws_iam_role_policy", "s3", create, nil, obj{"policy": s3AllPolicy}),
		rc("aws_iam_policy", "scoped", create, nil, obj{"policy": scopedPolicy}),
		rc("aws_iam_policy", "deny", create, nil, obj{"policy": denyAll}),
		rc("aws_iam_policy", "already", update, obj{"policy": adminPolicy}, obj{"policy": adminPolicy}),
		rc("aws_iam_policy", "unknown", create, nil, obj{}),
		rc("aws_iam_role", "public", create, nil, obj{"assume_role_policy": publicTrust}),
		rc("aws_iam_role", "guarded", create, nil, obj{"assume_role_policy": guardedTrust}),
		rc("aws_iam_role", "inline", create, nil, obj{"assume_role_policy": guardedTrust, "inline_policy": []any{map[string]any{"policy": scopedPolicy}, map[string]any{"policy": adminPolicy}}}),
		rc("aws_iam_role_policy_attachment", "admin", create, nil, obj{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
		rc("aws_iam_role_policy_attachment", "ro", create, nil, obj{"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
	)
	cases := map[string]string{
		"aws_iam_policy.admin":                 "TF-IAM-001",
		"aws_iam_role_policy.s3":               "TF-IAM-002",
		"aws_iam_policy.scoped":                "",
		"aws_iam_policy.deny":                  "",
		"aws_iam_policy.already":               "",
		"aws_iam_policy.unknown":               "",
		"aws_iam_role.public":                  "TF-IAM-004",
		"aws_iam_role.guarded":                 "",
		"aws_iam_role.inline":                  "TF-IAM-001",
		"aws_iam_role_policy_attachment.admin": "TF-IAM-003",
		"aws_iam_role_policy_attachment.ro":    "",
	}
	for addr, want := range cases {
		if g := ids(got[addr]); g != want {
			t.Errorf("%s: got %q, want %q", addr, g, want)
		}
	}
}

func TestStorageAndAudit(t *testing.T) {
	got := check(
		rc("aws_s3_bucket_public_access_block", "b", update,
			obj{"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
			obj{"block_public_acls": true, "block_public_policy": false, "ignore_public_acls": true, "restrict_public_buckets": true}),
		rc("aws_s3_bucket_acl", "b", create, nil, obj{"acl": "public-read"}),
		rc("aws_s3_bucket_policy", "b", create, nil, obj{"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`}),
		rc("aws_db_instance", "db", create, nil, obj{"publicly_accessible": true, "storage_encrypted": false}),
		rc("aws_ebs_volume", "v", create, nil, obj{"encrypted": true}),
		rc("aws_efs_file_system", "fs", update, obj{"encrypted": false}, obj{"encrypted": false}),
		rc("aws_cloudtrail", "org", update, obj{"enable_logging": true}, obj{"enable_logging": false}),
		rc("aws_guardduty_detector", "main", destroy, obj{}, nil),
	)
	cases := map[string]string{
		"aws_s3_bucket_public_access_block.b": "TF-S3-001",
		"aws_s3_bucket_acl.b":                 "TF-S3-002",
		"aws_s3_bucket_policy.b":              "TF-S3-003",
		"aws_db_instance.db":                  "TF-DB-001,TF-ENC-001",
		"aws_ebs_volume.v":                    "",
		"aws_efs_file_system.fs":              "",
		"aws_cloudtrail.org":                  "TF-AUDIT-001",
		"aws_guardduty_detector.main":         "TF-AUDIT-001",
	}
	for addr, want := range cases {
		if g := ids(got[addr]); g != want {
			t.Errorf("%s: got %q, want %q", addr, g, want)
		}
	}
}

func TestDataSourcesAndNoOpsAreIgnored(t *testing.T) {
	ds := rc("aws_iam_policy_document", "x", []string{"read"}, nil, obj{"json": adminPolicy})
	ds.Mode = "data"
	got := check(ds, rc("aws_s3_bucket", "keep", []string{"no-op"}, obj{}, obj{}))
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestRulesAreDocumented(t *testing.T) {
	documented := map[string]bool{}
	for _, r := range Rules {
		documented[r.ID] = true
	}
	for _, id := range []string{"TF-DATA-001", "TF-NET-001", "TF-IAM-004", "TF-S3-003", "TF-AUDIT-001"} {
		if !documented[id] {
			t.Errorf("%s is not in Rules", id)
		}
	}
}

// Package rules flags risky changes in a Terraform plan. Rules look at what
// the plan changes: an issue that already exists in the "before" state is not
// reported again, so the output stays focused on the change under review.
package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
	"github.com/OTA-EITA/tf-plan-guard/internal/plan"
)

// Rules documents every rule.
var Rules = []finding.Rule{
	{ID: "TF-DATA-001", Severity: finding.High, Title: "Stateful resource is destroyed"},
	{ID: "TF-DATA-002", Severity: finding.High, Title: "Stateful resource is replaced (destroyed and recreated)"},
	{ID: "TF-DATA-003", Severity: finding.High, Title: "Deletion protection is turned off"},
	{ID: "TF-DATA-004", Severity: finding.Medium, Title: "Final snapshot is skipped or force_destroy is enabled"},
	{ID: "TF-CHANGE-001", Severity: finding.Medium, Title: "Resource is destroyed"},
	{ID: "TF-CHANGE-002", Severity: finding.Low, Title: "Resource is replaced"},
	{ID: "TF-NET-001", Severity: finding.High, Title: "New ingress from the internet on a non-web port"},
	{ID: "TF-NET-002", Severity: finding.Low, Title: "New ingress from the internet on a web port"},
	{ID: "TF-IAM-001", Severity: finding.High, Title: "IAM policy grants every action"},
	{ID: "TF-IAM-002", Severity: finding.Medium, Title: "IAM policy grants a whole service on every resource"},
	{ID: "TF-IAM-003", Severity: finding.High, Title: "AdministratorAccess is attached"},
	{ID: "TF-IAM-004", Severity: finding.High, Title: "Role can be assumed by anyone"},
	{ID: "TF-S3-001", Severity: finding.High, Title: "S3 public access block is weakened"},
	{ID: "TF-S3-002", Severity: finding.High, Title: "S3 bucket ACL grants public access"},
	{ID: "TF-S3-003", Severity: finding.High, Title: "S3 bucket policy allows anyone"},
	{ID: "TF-DB-001", Severity: finding.High, Title: "Database becomes publicly accessible"},
	{ID: "TF-ENC-001", Severity: finding.Medium, Title: "Storage is created without encryption"},
	{ID: "TF-AUDIT-001", Severity: finding.High, Title: "Audit logging or threat detection is removed or disabled"},
}

// statefulTypes hold data that is lost when the resource is destroyed.
var statefulTypes = map[string]bool{
	"aws_db_instance": true, "aws_rds_cluster": true, "aws_rds_cluster_instance": true,
	"aws_docdb_cluster": true, "aws_neptune_cluster": true, "aws_redshift_cluster": true,
	"aws_dynamodb_table": true, "aws_s3_bucket": true, "aws_efs_file_system": true,
	"aws_ebs_volume": true, "aws_elasticache_cluster": true, "aws_elasticache_replication_group": true,
	"aws_opensearch_domain": true, "aws_elasticsearch_domain": true, "aws_msk_cluster": true,
	"aws_kms_key": true, "aws_eks_cluster": true, "aws_route53_zone": true, "aws_secretsmanager_secret": true,
	"aws_ecr_repository": true, "aws_cognito_user_pool": true,
	"google_sql_database_instance": true, "google_storage_bucket": true, "google_container_cluster": true,
	"google_kms_crypto_key": true, "google_bigquery_dataset": true, "google_bigquery_table": true,
	"google_spanner_instance": true, "google_compute_disk": true, "google_redis_instance": true,
	"azurerm_storage_account": true, "azurerm_mssql_database": true, "azurerm_postgresql_flexible_server": true,
	"azurerm_kubernetes_cluster": true, "azurerm_key_vault": true, "azurerm_cosmosdb_account": true,
}

var auditTypes = map[string]bool{
	"aws_cloudtrail": true, "aws_guardduty_detector": true, "aws_config_configuration_recorder": true,
	"aws_flow_log": true, "aws_securityhub_account": true, "google_logging_project_sink": true,
}

var deletionProtectionAttrs = []string{"deletion_protection", "enable_deletion_protection"}

// webPorts may legitimately be open to the internet.
var webPorts = map[int]bool{80: true, 443: true}

// Check evaluates every rule against the plan.
func Check(p plan.Plan) []finding.Finding {
	var out []finding.Finding
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "managed" {
			continue
		}
		c := &checker{rc: rc, action: rc.Change.Action()}
		c.lifecycle()
		c.network()
		c.iam()
		c.storage()
		c.audit()
		out = append(out, c.out...)
	}
	finding.Sort(out)
	return out
}

type checker struct {
	rc     plan.ResourceChange
	action plan.Action
	out    []finding.Finding
}

func (c *checker) add(id string, sev finding.Severity, msg, fix string) {
	c.out = append(c.out, finding.Finding{
		RuleID: id, Severity: sev, Address: c.rc.Address, Action: string(c.action), Message: msg, Fix: fix,
	})
}

func (c *checker) before() map[string]any { return c.rc.Change.Before }
func (c *checker) after() map[string]any  { return c.rc.Change.After }

// introduced reports whether a condition holds after the change but did not
// hold before it. Creates have no "before".
func (c *checker) introduced(cond func(map[string]any) bool) bool {
	if c.after() == nil || !cond(c.after()) {
		return false
	}
	return c.before() == nil || !cond(c.before())
}

func (c *checker) lifecycle() {
	stateful := statefulTypes[c.rc.Type]
	switch c.action {
	case plan.Delete:
		if stateful {
			c.add("TF-DATA-001", finding.High, c.rc.Type+" is destroyed; its data is lost",
				"Take a backup first, or add lifecycle { prevent_destroy = true } if this is unintended.")
		} else if !auditTypes[c.rc.Type] {
			c.add("TF-CHANGE-001", finding.Medium, "resource is destroyed", "")
		}
	case plan.Replace:
		why := c.replaceReason()
		if stateful {
			c.add("TF-DATA-002", finding.High, c.rc.Type+" is destroyed and recreated"+why+"; its data is lost",
				"Change the attribute in place if the provider allows it, or migrate the data before applying.")
		} else {
			c.add("TF-CHANGE-002", finding.Low, "resource is replaced"+why, "")
		}
	case plan.Update:
		for _, attr := range deletionProtectionAttrs {
			before, okB := plan.Bool(c.before(), attr)
			after, okA := plan.Bool(c.after(), attr)
			if okB && okA && before && !after {
				c.add("TF-DATA-003", finding.High, attr+" changes from true to false",
					"Keep deletion protection on unless the resource is about to be retired on purpose.")
			}
		}
		if c.introduced(func(o map[string]any) bool { v, _ := plan.Bool(o, "skip_final_snapshot"); return v }) {
			c.add("TF-DATA-004", finding.Medium, "skip_final_snapshot is enabled; no snapshot is taken on deletion", "")
		}
		if c.introduced(func(o map[string]any) bool { v, _ := plan.Bool(o, "force_destroy"); return v }) {
			c.add("TF-DATA-004", finding.Medium, "force_destroy is enabled; the bucket and its objects can be deleted", "")
		}
	}
}

func (c *checker) replaceReason() string {
	var paths []string
	for _, p := range c.rc.Change.ReplacePaths {
		paths = append(paths, plan.FormatPath(p))
	}
	if len(paths) == 0 {
		return ""
	}
	return " (forced by " + strings.Join(paths, ", ") + ")"
}

// ingressRule is a normalised inbound rule.
type ingressRule struct {
	from, to int
	all      bool // all protocols / ports
	cidrs    []string
}

func (r ingressRule) public() bool {
	for _, c := range r.cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n != nil {
			if ones, _ := n.Mask.Size(); ones == 0 {
				return true
			}
		}
	}
	return false
}

func (r ingressRule) webOnly() bool {
	if r.all {
		return false
	}
	for p := r.from; p <= r.to; p++ {
		if !webPorts[p] {
			return false
		}
	}
	return true
}

func (r ingressRule) ports() string {
	switch {
	case r.all:
		return "all ports"
	case r.from == r.to:
		return fmt.Sprintf("port %d", r.from)
	default:
		return fmt.Sprintf("ports %d-%d", r.from, r.to)
	}
}

func awsRule(m map[string]any, cidrKeys ...string) ingressRule {
	from, _ := plan.Number(m, "from_port")
	to, _ := plan.Number(m, "to_port")
	proto := fmt.Sprint(plan.Attr(m, "protocol"))
	if proto == "<nil>" {
		proto = plan.String(m, "ip_protocol")
	}
	r := ingressRule{from: int(from), to: int(to), all: proto == "-1" || proto == "all"}
	for _, k := range cidrKeys {
		if v := plan.String(m, k); v != "" {
			r.cidrs = append(r.cidrs, v)
		}
		r.cidrs = append(r.cidrs, plan.Strings(m, k)...)
	}
	return r
}

func (c *checker) ingress(obj map[string]any) []ingressRule {
	if obj == nil {
		return nil
	}
	switch c.rc.Type {
	case "aws_security_group":
		var out []ingressRule
		for _, v := range plan.List(obj, "ingress") {
			if m, ok := v.(map[string]any); ok {
				out = append(out, awsRule(m, "cidr_blocks", "ipv6_cidr_blocks"))
			}
		}
		return out
	case "aws_security_group_rule":
		if plan.String(obj, "type") != "ingress" {
			return nil
		}
		return []ingressRule{awsRule(obj, "cidr_blocks", "ipv6_cidr_blocks")}
	case "aws_vpc_security_group_ingress_rule":
		return []ingressRule{awsRule(obj, "cidr_ipv4", "cidr_ipv6")}
	case "google_compute_firewall":
		if d := plan.String(obj, "direction"); d != "" && d != "INGRESS" {
			return nil
		}
		ranges := plan.Strings(obj, "source_ranges")
		var out []ingressRule
		for _, v := range plan.List(obj, "allow") {
			m, _ := v.(map[string]any)
			ports := plan.Strings(m, "ports")
			if len(ports) == 0 {
				out = append(out, ingressRule{all: true, cidrs: ranges})
				continue
			}
			for _, p := range ports {
				from, to := parsePortRange(p)
				out = append(out, ingressRule{from: from, to: to, cidrs: ranges})
			}
		}
		return out
	}
	return nil
}

func parsePortRange(s string) (int, int) {
	var from, to int
	if n, _ := fmt.Sscanf(s, "%d-%d", &from, &to); n == 2 {
		return from, to
	}
	_, _ = fmt.Sscanf(s, "%d", &from)
	return from, from
}

func (c *checker) network() {
	existing := map[string]bool{}
	for _, r := range c.ingress(c.before()) {
		if r.public() {
			existing[r.ports()] = true
		}
	}
	for _, r := range c.ingress(c.after()) {
		if !r.public() || existing[r.ports()] {
			continue
		}
		if r.webOnly() {
			c.add("TF-NET-002", finding.Low, "opens "+r.ports()+" to the internet", "")
		} else {
			c.add("TF-NET-001", finding.High, "opens "+r.ports()+" to the internet (0.0.0.0/0 or ::/0)",
				"Restrict the source to known CIDRs, a VPN, or use a load balancer / SSM Session Manager instead.")
		}
	}
}

func (c *checker) iam() {
	switch c.rc.Type {
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
		c.policyWildcards(func(o map[string]any) []string { return []string{plan.String(o, "policy")} })
	case "aws_iam_role":
		c.policyWildcards(func(o map[string]any) []string {
			var docs []string
			for _, v := range plan.List(o, "inline_policy") {
				if m, ok := v.(map[string]any); ok {
					docs = append(docs, plan.String(m, "policy"))
				}
			}
			return docs
		})
		if c.introduced(func(o map[string]any) bool { return publicPrincipal(plan.String(o, "assume_role_policy")) }) {
			c.add("TF-IAM-004", finding.High, `assume_role_policy allows Principal "*" without conditions`,
				"Name the account, role or federated provider that may assume the role.")
		}
	case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment":
		if c.introduced(func(o map[string]any) bool {
			return strings.HasSuffix(plan.String(o, "policy_arn"), ":policy/AdministratorAccess")
		}) {
			c.add("TF-IAM-003", finding.High, "attaches the AWS managed AdministratorAccess policy",
				"Attach a policy scoped to the actions and resources this principal needs.")
		}
	}
}

// worstWildcard returns the broadest grant across several policy documents.
func worstWildcard(docs []string) (int, string) {
	level, detail := 0, ""
	for _, d := range docs {
		if l, dt := wildcardLevel(d); l > level {
			level, detail = l, dt
		}
	}
	return level, detail
}

func (c *checker) policyWildcards(docs func(map[string]any) []string) {
	if c.after() == nil {
		return
	}
	level, detail := worstWildcard(docs(c.after()))
	before := 0
	if c.before() != nil {
		before, _ = worstWildcard(docs(c.before()))
	}
	if level <= before {
		return
	}
	switch level {
	case 2:
		c.add("TF-IAM-001", finding.High, "policy allows "+detail+" (full administrator)",
			"List only the actions this principal needs.")
	case 1:
		c.add("TF-IAM-002", finding.Medium, "policy allows "+detail, "Scope the resources to specific ARNs.")
	}
}

func (c *checker) storage() {
	switch c.rc.Type {
	case "aws_s3_bucket_public_access_block":
		weak := func(o map[string]any) bool {
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, ok := plan.Bool(o, k); ok && !v {
					return true
				}
			}
			return false
		}
		if c.introduced(weak) {
			c.add("TF-S3-001", finding.High, "one or more public access block settings are false",
				"Keep all four settings true unless the bucket must be public (prefer CloudFront with OAC).")
		}
	case "aws_s3_bucket_acl":
		if c.introduced(func(o map[string]any) bool {
			acl := plan.String(o, "acl")
			return acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read"
		}) {
			c.add("TF-S3-002", finding.High, "bucket ACL is "+plan.String(c.after(), "acl"), "Use the private ACL.")
		}
	case "aws_s3_bucket_policy":
		if c.introduced(func(o map[string]any) bool { return publicPrincipal(plan.String(o, "policy")) }) {
			c.add("TF-S3-003", finding.High, `bucket policy allows Principal "*" without conditions`,
				"Restrict the principal, or add conditions such as aws:SourceArn for CloudFront.")
		}
	case "aws_db_instance", "aws_rds_cluster_instance":
		if c.introduced(func(o map[string]any) bool { v, _ := plan.Bool(o, "publicly_accessible"); return v }) {
			c.add("TF-DB-001", finding.High, "publicly_accessible is true", "Keep databases in private subnets.")
		}
	}
	if c.action != plan.Create && c.action != plan.Replace {
		return
	}
	encAttr := map[string]string{
		"aws_db_instance": "storage_encrypted", "aws_rds_cluster": "storage_encrypted",
		"aws_ebs_volume": "encrypted", "aws_efs_file_system": "encrypted",
	}[c.rc.Type]
	if encAttr == "" {
		return
	}
	if v, ok := plan.Bool(c.after(), encAttr); ok && !v {
		c.add("TF-ENC-001", finding.Medium, encAttr+" is false",
			"Enable encryption at rest; it cannot be turned on later without recreating the resource.")
	}
}

func (c *checker) audit() {
	if !auditTypes[c.rc.Type] {
		return
	}
	switch c.action {
	case plan.Delete:
		c.add("TF-AUDIT-001", finding.High, c.rc.Type+" is destroyed", "Keep audit logging and threat detection enabled.")
	case plan.Update:
		for _, attr := range []string{"enable_logging", "enable", "is_enabled"} {
			before, okB := plan.Bool(c.before(), attr)
			after, okA := plan.Bool(c.after(), attr)
			if okB && okA && before && !after {
				c.add("TF-AUDIT-001", finding.High, attr+" changes from true to false", "Keep audit logging and threat detection enabled.")
			}
		}
	}
}

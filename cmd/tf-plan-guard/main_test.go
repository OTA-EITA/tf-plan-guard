package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// risky-plan.json is real `terraform show -json` output of e2e/risky.
const (
	risky = "testdata/risky-plan.json"
	clean = "testdata/clean-plan.json"
)

func TestRiskyPlanFails(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--ignore-file", "none", risky}, nil, &out, io.Discard); code != exitUsage {
		t.Fatalf("a missing non-default ignore file is an error, got %d", code)
	}
	code := run([]string{risky}, nil, &out, io.Discard)
	if code != exitFail {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	for _, want := range []string{"TF-DB-001", "TF-IAM-001", "TF-S3-001", "TF-NET-001", "TF-ENC-001", "Plan: 5 to add"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %s:\n%s", want, out.String())
		}
	}
}

func TestIgnoresAndThreshold(t *testing.T) {
	args := []string{
		"--ignore", "TF-DB-001=aws_db_instance.orders",
		"--ignore", "TF-IAM-001=*",
		"--ignore", "TF-S3-001=aws_s3_bucket_public_access_block.*",
		"--ignore", "TF-NET-001",
		risky,
	}
	var out bytes.Buffer
	if code := run(args, nil, &out, io.Discard); code != exitOK {
		t.Fatalf("only MEDIUM left, want exit 0, got %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "(4 ignored)") {
		t.Errorf("output:\n%s", out.String())
	}
	if code := run(append([]string{"--fail-on", "medium"}, args...), nil, io.Discard, io.Discard); code != exitFail {
		t.Fatalf("--fail-on medium must fail on the remaining MEDIUM, got %d", code)
	}
}

func TestIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ignore")
	if err := os.WriteFile(path, []byte("* = *   # accept everything\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--ignore-file", path, "--fail-on", "low", risky}, nil, io.Discard, io.Discard); code != exitOK {
		t.Fatalf("exit %d", code)
	}
}

func TestStdinAndCleanPlan(t *testing.T) {
	data, err := os.ReadFile(clean)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := run([]string{"--output", "markdown", "-"}, bytes.NewReader(data), &out, io.Discard); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "✅") || !strings.Contains(out.String(), "0 to add, 1 to change") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--output", "xml", risky},
		{"--fail-on", "critical", risky},
		{"--ignore", "=x", risky},
		{"missing.json"},
	} {
		if code := run(args, nil, io.Discard, io.Discard); code != exitUsage {
			t.Errorf("run(%v) = %d", args, code)
		}
	}
	if code := run([]string{"-"}, strings.NewReader(`{"values":{}}`), io.Discard, io.Discard); code != exitUsage {
		t.Error("state JSON must be rejected")
	}
	var out bytes.Buffer
	if code := run([]string{"--list"}, nil, &out, io.Discard); code != exitOK || !strings.Contains(out.String(), "TF-AUDIT-001") {
		t.Errorf("--list: %d %s", code, out.String())
	}
}

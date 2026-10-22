// Command tf-plan-guard reviews a Terraform plan for risky changes: lost
// data, removed deletion protection, internet exposure, wildcard IAM, public
// storage, missing encryption and disabled audit logging.
//
//	terraform plan -out plan.tfplan
//	terraform show -json plan.tfplan | tf-plan-guard -
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/OTA-EITA/tf-plan-guard/internal/finding"
	"github.com/OTA-EITA/tf-plan-guard/internal/ignore"
	"github.com/OTA-EITA/tf-plan-guard/internal/plan"
	"github.com/OTA-EITA/tf-plan-guard/internal/report"
	"github.com/OTA-EITA/tf-plan-guard/internal/rules"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

const defaultIgnoreFile = ".tfplanguard-ignore"

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tf-plan-guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: terraform show -json PLANFILE | tf-plan-guard [flags] -")
		fmt.Fprintln(stderr, "       tf-plan-guard [flags] plan.json")
		fs.PrintDefaults()
	}
	output := fs.String("output", "table", "output format: table, json or markdown")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding is at least this severe: high, medium or low")
	ignoreFile := fs.String("ignore-file", defaultIgnoreFile, "file with RULE=ADDRESS_PATTERN lines to ignore (skipped if missing)")
	var ignores multiFlag
	fs.Var(&ignores, "ignore", "ignore RULE=ADDRESS_PATTERN (repeatable; * is a wildcard)")
	list := fs.Bool("list", false, "list rules and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, "tf-plan-guard", version)
		return exitOK
	}
	if *list {
		return listRules(stdout)
	}
	format, err := report.ParseFormat(*output)
	if err != nil {
		return usageErr(stderr, err)
	}
	threshold, ok := finding.ParseSeverity(*failOn)
	if !ok {
		return usageErr(stderr, fmt.Errorf("--fail-on must be high, medium or low, got %q", *failOn))
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}

	entries, err := loadIgnores(*ignoreFile, ignores)
	if err != nil {
		return usageErr(stderr, err)
	}
	data, err := readInput(fs.Arg(0), stdin)
	if err != nil {
		return usageErr(stderr, err)
	}
	p, err := plan.Parse(data)
	if err != nil {
		return usageErr(stderr, err)
	}

	kept, ignored := ignore.Filter(rules.Check(p), entries)
	if err := report.Write(stdout, report.Result{Findings: kept, Ignored: ignored, Summary: p.Summary()}, format); err != nil {
		return usageErr(stderr, err)
	}
	for _, f := range kept {
		if f.Severity.Rank() >= threshold.Rank() {
			return exitFail
		}
	}
	return exitOK
}

func usageErr(w io.Writer, err error) int {
	fmt.Fprintln(w, "error:", err)
	return exitUsage
}

func loadIgnores(path string, flags []string) ([]ignore.Entry, error) {
	var entries []ignore.Entry
	f, err := os.Open(path) // #nosec G304 -- the ignore file path is chosen by the operator
	switch {
	case err == nil:
		defer func() { _ = f.Close() }()
		fromFile, err := ignore.ParseFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		entries = append(entries, fromFile...)
	case path != defaultIgnoreFile || !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	for _, s := range flags {
		e, err := ignore.Parse(s)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path) // #nosec G304 -- reading the given plan file is the purpose of the tool
}

func listRules(w io.Writer) int {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tTITLE")
	for _, r := range rules.Rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Title)
	}
	if tw.Flush() != nil {
		return exitUsage
	}
	return exitOK
}

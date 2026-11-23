package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const fixtureYAML = "exceptions:\n" +
	"- rule: within-window\n  path: within.go\n  expires: 2026-12-03\n" +
	"- rule: outside-window\n  path: future.go\n  expires: 2026-12-08\n"

// TestRunReport verifies stdout and optional summary output for planted dates.
func TestRunReport(t *testing.T) {
	t.Parallel()
	cases := [2]struct {
		name    string
		summary bool
	}{
		{"stdout and summary", true},
		{"stdout only", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			checkRunReport(t, c.summary)
		})
	}
}

func checkRunReport(t *testing.T, withSummary bool) {
	t.Helper()
	root := t.TempDir()
	const source = "exceptions.yml"
	writeFixture(t, filepath.Join(root, source), fixtureYAML)
	const prefix = "Existing summary\n\n"
	summaryPath := filepath.Join(root, "summary.md")
	var summary string
	if withSummary {
		summary = summaryPath
		writeFixture(t, summaryPath, prefix)
	}
	var stdout strings.Builder
	if err := run(t.Context(), root, []string{source}, reportDay(), &stdout, summary); err != nil {
		t.Fatal(err)
	}
	report := stdout.String()
	if !strings.Contains(report, "| 2026-12-03 | 10 | exceptions.yml:4 | within.go | within-window |") ||
		strings.Contains(report, "outside-window") || strings.Contains(report, "2026-12-08") {
		t.Errorf("stdout report = %q", report)
	}
	verifySummary(t, summaryPath, prefix+report, withSummary)
}

func verifySummary(t *testing.T, path, want string, withSummary bool) {
	t.Helper()
	output, err := os.ReadFile(path)
	if !withSummary {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unset summary unexpectedly present or unreadable: %v", err)
		}
		return
	}
	if err != nil || string(output) != want {
		t.Fatalf("summary = %q, %v; want %q", output, err, want)
	}
}

// TestRunRejectsSourceErrors verifies read and parse failures prevent a partial report.
func TestRunRejectsSourceErrors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "bad.yaml"), "expires: bad-date\n")
	for _, source := range [2]string{"missing.yml", "bad.yaml"} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			var stdout strings.Builder
			err := run(t.Context(), root, []string{source}, reportDay(), &stdout, "")
			if err == nil || !strings.Contains(err.Error(), source) || stdout.Len() != 0 {
				t.Fatalf("run = %v, stdout %q; want source error", err, stdout.String())
			}
		})
	}
}

// TestRepositoryDiscoveryAndReaders opens the actual tracked exception sources.
func TestRepositoryDiscoveryAndReaders(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "..")
	files, err := trackedFiles(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [5]string{
		".golangci.yml", ".standards.yaml", "upstream/endpoints-allow.yaml",
		"tools/go/osv-scanner.toml", "tools/semgrep-filter.sh",
	} {
		if !slices.Contains(files, source) {
			t.Errorf("git ls-files did not find %s", source)
		}
	}
	var report strings.Builder
	args := []string{"-root", root, "-today", "2027-01-05"}
	if err := execute(t.Context(), args, reportDay(), &report, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "as of 2027-01-05") {
		t.Fatalf("repository report = %q", report.String())
	}
}

// TestExecuteRejectsBadDate verifies an invalid report date fails before discovery.
func TestExecuteRejectsBadDate(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	err := execute(t.Context(), []string{"-today", "2026-02-30"}, reportDay(), &stdout, "")
	if err == nil || !strings.Contains(err.Error(), "-today") {
		t.Fatalf("execute = %v; want date error", err)
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func reportDay() time.Time {
	return time.Date(2026, time.November, 23, 0, 0, 0, 0, time.UTC)
}

package lintexceptions

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestConfigEntries exercises dated rules, baselines, and invalid dates.
func TestConfigEntries(t *testing.T) {
	t.Parallel()
	const baseline = "      # baseline #141\n" +
		"      - path: ^arr/b_test\\.go$\n        linters:\n          - funlen\n" +
		"        text: Function 'TestB'\n"
	const linter = "          - funlen\n"
	const source = ".golangci.yml"
	want := Entry{Source: source, Line: 8, File: `^arr/a_test\.go$`, Rule: "gocognit", Expires: "2026-10-29"}
	today := day(t, "2026-11-23")
	entries, err := ConfigEntries(source, header+begin+rule+baseline+end, today)
	if err != nil || !slices.Equal(entries, []Entry{want}) {
		t.Fatalf("ConfigEntries = %v, %v; want %v", entries, err, want)
	}
	want.Rule += ", funlen"
	entries, err = ConfigEntries(source, header+begin+rule+linter+end, today)
	if err != nil || !slices.Equal(entries, []Entry{want}) {
		t.Fatalf("multiple linters ConfigEntries = %v, %v; want %v", entries, err, want)
	}
	entries, err = ConfigEntries(source, header+begin+baseline+end, today)
	if err != nil || len(entries) != 0 {
		t.Fatalf("baseline ConfigEntries = %v, %v; want no entries", entries, err)
	}
	bad := strings.Replace(rule, "expires 2026-10-29", "expires 2026-13-29", 1)
	_, err = ConfigEntries(source, header+begin+bad+end, today)
	requireErrorText(t, err, ".golangci.yml: line 9: expiry")
}

// TestSourceReaders verifies fields and line numbers across the source formats.
func TestSourceReaders(t *testing.T) {
	t.Parallel()
	const yamlSource = "upstream/endpoints-allow.yaml"
	const osvSource = "tools/go/osv-scanner.toml"
	const semgrepSource = "tools/semgrep-filter.sh"
	cases := []struct {
		name, source, data string
		read               func(string, []byte) ([]Entry, error)
		want               Entry
	}{
		{
			"YAML module", yamlSource,
			"allow:\n- module: arr/sonarr\n  func: Client.UpdateRootFolder\n  path: /api/v3/rootfolder/{}\n  expires: 2027-03-02\n",
			YAMLEntries,
			Entry{yamlSource, 5, "arr/sonarr", "Client.UpdateRootFolder", "2027-03-02"},
		},
		{
			"YAML second document", ".standards.yaml",
			"unrelated: value\n---\nexceptions:\n- rule: HISS-19\n  path: file.go\n  expires: '2027-01-16'\n",
			YAMLEntries,
			Entry{".standards.yaml", 6, "file.go", "HISS-19", "2027-01-16"},
		},
		{
			"OSV", osvSource,
			"ignoreUntil = 2026-12-03\n[[IgnoredVulns]]\nignoreUntil = 2027-01-09 # date\nid = \"GO-2026-5932\"\n[other]\n",
			OSVEntries,
			Entry{osvSource, 3, "", "GO-2026-5932", "2027-01-09"},
		},
		{
			"Semgrep", semgrepSource,
			"#!/bin/sh\nexceptions='[{\"file\":\"a.go\",\"rule\":\"rule-1\",\"expires\":\"2026-12-03\",\"reason\":\"test\"}]'\n",
			SemgrepEntries,
			Entry{semgrepSource, 2, "a.go", "rule-1", "2026-12-03"},
		},
	}
	for i := 0; i < len(cases) && i < maxNodes; i++ {
		c := cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := c.read(c.source, []byte(c.data))
			if err != nil || !slices.Equal(got, []Entry{c.want}) {
				t.Fatalf("read %s = %v, %v; want %v", c.source, got, err, c.want)
			}
		})
	}
}

// TestSourceReadersRejectMalformedInput verifies errors retain the source location.
func TestSourceReadersRejectMalformedInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, data, want string
		read             func(string, []byte) ([]Entry, error)
	}{
		{"YAML syntax", "expires: [\n", "decode YAML", YAMLEntries},
		{"YAML date", "expires: 2027-02-29", "expiry", YAMLEntries},
		{"YAML non-scalar", "expires: [2027-01-16]", "scalar expires", YAMLEntries},
		{"OSV date", "[[IgnoredVulns]]\nid = \"GO-1\"\nignoreUntil = yesterday", "expiry", OSVEntries},
		{"Semgrep absent", "# renamed filter\n", "missing exceptions assignment", SemgrepEntries},
		{"Semgrep JSON", "exceptions='[}'\n", "decode exceptions JSON", SemgrepEntries},
		{"Semgrep date", "exceptions='[{\"expires\":\"yesterday\"}]'\n", "expiry", SemgrepEntries},
	}
	for i := 0; i < len(cases) && i < maxNodes; i++ {
		c := cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := c.read("fixture", []byte(c.data))
			requireErrorText(t, err, "fixture")
			requireErrorText(t, err, c.want)
		})
	}
}

func requireErrorText(t *testing.T, err error, text string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), text) {
		t.Fatalf("error = %v; want %q", err, text)
	}
}

// TestSelfEntrySource checks that the report points to the expiry declaration.
func TestSelfEntrySource(t *testing.T) {
	t.Parallel()
	entry := SelfEntry()
	if entry.File != "tools/go/lintexceptions" || entry.Rule != "HISS-19" {
		t.Fatalf("SelfEntry = %v", entry)
	}
	data, err := os.ReadFile("lintexceptions.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if entry.Line <= 0 || entry.Line > len(lines) {
		t.Fatalf("SelfEntry line %d outside source", entry.Line)
	}
	want := `const selfExpiry = "` + entry.Expires + `"`
	if strings.TrimSpace(lines[entry.Line-1]) != want || !strings.HasSuffix(entry.Source, "/lintexceptions.go") {
		t.Fatalf("SelfEntry points to %s:%d (%q); want %q", entry.Source, entry.Line, lines[entry.Line-1], want)
	}
}

// TestExpiring checks both sides of the UTC lead-time boundary and overdue entries.
func TestExpiring(t *testing.T) {
	t.Parallel()
	today := day(t, "2026-11-23").Add(time.Hour).In(time.FixedZone("west", -2*60*60))
	cases := []struct {
		name, expiry string
		want         bool
	}{
		{"ten days", "2026-12-03", true},
		{"fifteen days", "2026-12-08", false},
		{"fourteen days", "2026-12-07", true},
		{"overdue", "2026-11-22", true},
	}
	for i := 0; i < len(cases) && i < maxNodes; i++ {
		c := cases[i]
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			entry := Entry{Source: "waivers.yml", Expires: c.expiry}
			got, err := Expiring([]Entry{entry}, today, LeadDays)
			if err != nil || (len(got) == 1) != c.want {
				t.Fatalf("Expiring = %v, %v; want listed: %t", got, err, c.want)
			}
		})
	}
}

// TestExpiringOrderAndMarkdown verifies sort order, escaping, and signed days left.
func TestExpiringOrderAndMarkdown(t *testing.T) {
	t.Parallel()
	today := day(t, "2026-11-23")
	older := Entry{Source: "c.yml", Line: 3, Expires: "2026-11-22"}
	first := Entry{Source: "a|.yml", Line: 1, File: "x|y", Rule: "a|b", Expires: "2026-12-07"}
	second := Entry{Source: "b.yml", Line: 2, Expires: first.Expires}
	got, err := Expiring([]Entry{second, first, older}, today, LeadDays)
	if err != nil || !slices.Equal(got, []Entry{older, first, second}) {
		t.Fatalf("Expiring order = %v, %v", got, err)
	}
	report := Markdown(got, 3, today, LeadDays)
	for _, want := range [3]string{
		"### Dated exceptions expiring within 14 days (as of 2026-11-23)",
		"| 2026-11-22 | -1 | c.yml:3 |",
		`| 2026-12-07 | 14 | a\|.yml:1 | x\|y | a\|b |`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("Markdown missing %q in %q", want, report)
		}
	}
	if empty := Markdown(nil, 3, today, LeadDays); !strings.Contains(empty, "None of the 3 dated exceptions expires within 14 days.") {
		t.Errorf("empty Markdown = %q", empty)
	}
}

// TestExpiringRejectsInvalidDate verifies bad dates fail even outside the listing path.
func TestExpiringRejectsInvalidDate(t *testing.T) {
	t.Parallel()
	_, err := Expiring([]Entry{{Source: "waivers.yml", Line: 42, Expires: "invalid"}}, day(t, "2026-11-23"), LeadDays)
	requireErrorText(t, err, `waivers.yml:42: expiry "invalid"`)
}

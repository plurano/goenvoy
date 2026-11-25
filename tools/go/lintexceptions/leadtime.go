package lintexceptions

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

// LeadDays is the inclusive number of days before expiry to report.
const LeadDays = 14

const (
	maxDocuments = 10000
	maxNodes     = 100000
)

// Entry identifies a dated exception and the source line that declares its date.
type Entry struct {
	Source  string
	Line    int
	File    string
	Rule    string
	Expires string
}

// Due is a dated exception with the signed number of days until it expires.
type Due struct {
	Entry
	DaysLeft int64
}

var selfExpiryLine = regexp.MustCompile(`^const selfExpiry = "(\d{4}-\d{2}-\d{2})"$`)

// SelfExpiryEntries reads the expiry declaration for this package's own exception.
func SelfExpiryEntries(source string, data []byte) ([]Entry, error) {
	lines, err := sourceLines(source, data)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(lines) && i < maxLines; i++ {
		match := selfExpiryLine.FindStringSubmatch(strings.TrimSuffix(lines[i], "\r"))
		if match == nil {
			continue
		}
		entry := Entry{Source: source, Line: i + 1, File: "tools/go/lintexceptions", Rule: "HISS-19", Expires: match[1]}
		if err := entry.validateDate(); err != nil {
			return nil, err
		}
		return []Entry{entry}, nil
	}
	return nil, fmt.Errorf("%s: missing const selfExpiry declaration", source)
}

// ConfigEntries reads the dated rules from the generated lint exclusions block.
func ConfigEntries(source, config string, today time.Time) ([]Entry, error) {
	s := &scan{today: today, source: source}
	if err := s.read(config); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return s.entries, nil
}

// YAMLEntries reads mappings with an expires key from every YAML document.
func YAMLEntries(source string, data []byte) ([]Entry, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var entries []Entry
	for i := 0; i <= maxDocuments; i++ {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		switch {
		case errors.Is(err, io.EOF):
			return entries, nil
		case err != nil:
			return nil, fmt.Errorf("%s: decode YAML: %w", source, err)
		case i == maxDocuments:
			return nil, fmt.Errorf("%s: YAML exceeds %d documents", source, maxDocuments)
		}
		entries, err = yamlDocumentEntries(source, &doc, entries)
		if err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// yamlDocumentEntries walks the declared nodes once without expanding aliases.
func yamlDocumentEntries(source string, doc *yaml.Node, entries []Entry) ([]Entry, error) {
	stack := []*yaml.Node{doc}
	for i := 0; len(stack) > 0 && i < maxNodes; i++ {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entry, err := yamlEntry(source, node)
		if err != nil {
			return nil, err
		}
		if entry.Line != 0 {
			entries = append(entries, entry)
		}
		if len(node.Content) > maxNodes-i-1-len(stack) {
			return nil, fmt.Errorf("%s:%d: YAML document exceeds %d nodes", source, node.Line, maxNodes)
		}
		for j := len(node.Content) - 1; j >= 0 && j < maxNodes; j-- {
			stack = append(stack, node.Content[j])
		}
	}
	return entries, nil
}

// yamlEntry reads the exception fields of one mapping.
func yamlEntry(source string, node *yaml.Node) (Entry, error) {
	if node.Kind != yaml.MappingNode {
		return Entry{}, nil
	}
	fields, line, err := yamlFields(source, node)
	if err != nil {
		return Entry{}, err
	}
	if line == 0 {
		return Entry{}, nil
	}
	entry := Entry{
		Source:  source,
		Line:    line,
		File:    cmp.Or(yamlScalar(fields["module"]), yamlScalar(fields["path"])),
		Rule:    cmp.Or(yamlScalar(fields["rule"]), yamlScalar(fields["func"])),
		Expires: yamlScalar(fields["expires"]),
	}
	return entry, entry.validateDate()
}

// yamlFields gathers the keys used in an exception row.
func yamlFields(source string, node *yaml.Node) (map[string]*yaml.Node, int, error) {
	fields := make(map[string]*yaml.Node)
	var line int
	for i := 0; i+1 < len(node.Content) && i < maxNodes; i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "expires":
			if line != 0 || value.Kind != yaml.ScalarNode {
				return nil, 0, fmt.Errorf("%s:%d: expected one scalar expires value", source, key.Line)
			}
			line = key.Line
			fields[key.Value] = value
		case "module", "path", "rule", "func":
			fields[key.Value] = value
		}
	}
	return fields, line, nil
}

// yamlScalar returns a scalar field's value when present.
func yamlScalar(node *yaml.Node) string {
	if node != nil && node.Kind == yaml.ScalarNode {
		return node.Value
	}
	return ""
}

// OSVEntries reads the ignoreUntil dates in OSV scanner's IgnoredVulns tables.
func OSVEntries(source string, data []byte) ([]Entry, error) {
	lines, err := sourceLines(source, data)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	var entry Entry
	var active bool
	for i := 0; i < len(lines) && i < maxLines; i++ {
		line, _, _ := strings.Cut(lines[i], "#")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			entries = appendOSV(entries, entry)
			entry = Entry{Source: source}
			active = line == "[[IgnoredVulns]]"
			continue
		}
		if !active {
			continue
		}
		if err := osvField(&entry, line, i+1); err != nil {
			return nil, err
		}
	}
	return appendOSV(entries, entry), nil
}

// appendOSV records a table with an explicit expiry.
func appendOSV(entries []Entry, entry Entry) []Entry {
	if entry.Line == 0 {
		return entries
	}
	return append(entries, entry)
}

// osvField reads the advisory ID and optional expiry of an ignore table.
func osvField(entry *Entry, line string, number int) error {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return nil
	}
	value = strings.TrimSpace(value)
	switch strings.TrimSpace(key) {
	case "id":
		id, err := strconv.Unquote(value)
		if err != nil {
			return fmt.Errorf("%s:%d: parse OSV id: %w", entry.Source, number, err)
		}
		entry.Rule = id
	case "ignoreUntil":
		entry.Line, entry.Expires = number, value
		return entry.validateDate()
	}
	return nil
}

// SemgrepEntries reads the JSON exception array assigned by the Semgrep filter.
func SemgrepEntries(source string, data []byte) ([]Entry, error) {
	lines, err := sourceLines(source, data)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(lines) && i < maxLines; i++ {
		value, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), "exceptions=")
		if ok {
			return semgrepArray(source, value, i+1)
		}
	}
	return nil, fmt.Errorf("%s: missing exceptions assignment", source)
}

// semgrepArray reads one shell-quoted JSON array of dates.
func semgrepArray(source, value string, line int) ([]Entry, error) {
	if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
		return nil, fmt.Errorf("%s:%d: expected a single-quoted exceptions array", source, line)
	}
	data := strings.TrimSpace(value[1 : len(value)-1])
	if !strings.HasPrefix(data, "[") {
		return nil, fmt.Errorf("%s:%d: expected a JSON exceptions array", source, line)
	}
	var records []struct {
		File    string `json:"file"`
		Rule    string `json:"rule"`
		Expires string `json:"expires"`
	}
	if err := json.Unmarshal([]byte(data), &records); err != nil {
		return nil, fmt.Errorf("%s:%d: decode exceptions JSON: %w", source, line, err)
	}
	if len(records) > maxNodes {
		return nil, fmt.Errorf("%s:%d: exceptions array exceeds %d entries", source, line, maxNodes)
	}
	entries := make([]Entry, 0, len(records))
	for i := 0; i < len(records) && i < maxNodes; i++ {
		record := records[i]
		entry := Entry{Source: source, Line: line, File: record.File, Rule: record.Rule, Expires: record.Expires}
		if err := entry.validateDate(); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// sourceLines bounds the line-oriented readers without silently truncating the source.
func sourceLines(source string, data []byte) ([]string, error) {
	lines := strings.SplitN(string(data), "\n", maxLines+1)
	if len(lines) > maxLines {
		return nil, fmt.Errorf("%s: exceeds %d lines", source, maxLines)
	}
	return lines, nil
}

// validateDate attaches the source location to a date parse error.
func (e Entry) validateDate() error {
	_, err := time.Parse(time.DateOnly, e.Expires)
	if err != nil {
		return fmt.Errorf("%s:%d: expiry %q: %w", e.Source, e.Line, e.Expires, err)
	}
	return nil
}

// Expiring returns the exceptions due within days of the UTC date, including overdue entries.
func Expiring(entries []Entry, today time.Time, days int) ([]Due, error) {
	if len(entries) > maxNodes {
		return nil, fmt.Errorf("exceptions list exceeds %d entries", maxNodes)
	}
	today = today.UTC()
	result := make([]Due, 0, len(entries))
	for i := 0; i < len(entries) && i < maxNodes; i++ {
		entry := entries[i]
		remaining, err := daysUntil(entry.Expires, today)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", entry.Source, entry.Line, err)
		}
		if remaining <= int64(days) {
			result = append(result, Due{Entry: entry, DaysLeft: remaining})
		}
	}
	slices.SortStableFunc(result, func(a, b Due) int {
		return cmp.Or(cmp.Compare(a.Expires, b.Expires), cmp.Compare(a.Source, b.Source))
	})
	return result, nil
}

// daysUntil returns the signed distance from the supplied calendar day to expiry.
func daysUntil(expiry string, today time.Time) (int64, error) {
	date, err := time.Parse(time.DateOnly, expiry)
	if err != nil {
		return 0, fmt.Errorf("expiry %q: %w", expiry, err)
	}
	day := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	const secondsPerDay = int64(24 * time.Hour / time.Second)
	return date.Unix()/secondsPerDay - day.Unix()/secondsPerDay, nil
}

// Markdown renders the entries returned by Expiring as a GitHub job summary.
func Markdown(list []Due, total int, today time.Time, days int) string {
	today = today.UTC()
	text := fmt.Appendf(nil, "### Dated exceptions expiring within %d days (as of %s)\n\n", days, today.Format(time.DateOnly))
	if len(list) == 0 {
		return string(fmt.Appendf(text, "None of the %d dated exceptions expires within %d days.\n", total, days))
	}
	text = append(text, "| Expires | Days left | Source | File | Rule |\n| --- | ---: | --- | --- | --- |\n"...)
	escape := strings.NewReplacer("|", "\\|", "\r", " ", "\n", " ")
	for i := 0; i < len(list) && i < maxNodes; i++ {
		entry := list[i]
		location := escape.Replace(entry.Source) + ":" + strconv.Itoa(entry.Line)
		text = fmt.Appendf(text, "| %s | %d | %s | %s | %s |\n", escape.Replace(entry.Expires), entry.DaysLeft,
			location, escape.Replace(entry.File), escape.Replace(entry.Rule))
	}
	return string(text)
}

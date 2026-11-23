// Package lintexceptions checks the generated complexity exceptions in .golangci.yml.
//
// Every rule between the praetor:generated-exceptions markers under linters.exclusions.rules
// names one test file and one of funlen, gocyclo, gocognit or cyclop, carries the comment
// "category <A-D>, entered <date>, expires <date>, #<issue>" on the line above it, and is not
// past its date. A "baseline #<issue>" rule instead pins one function of a test file under
// funlen, gocyclo or gocognit through a "text:" line; the engine ratchet only lets it shrink.
// A complexity linter outside that block fails, so no file tier comes back.
//
// The lead-time report lists dated exceptions across the repository, including expired ones.
//
// This check is itself an exception to one mechanism per behavior (HISS-19; category D,
// entered 2026-11-23, expires 2027-03-23, #141): the engine audit judges the same block in
// the local hooks, but CI runs no server-side praetorctl audit by adoption, so this check is
// the second barrier for the block. Revisit when CI runs praetorctl audit.
// Adapted from tekmora/epitrop tools/lintexceptions (same author).
package lintexceptions

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// maxLines bounds the configuration lines one check reads.
const maxLines = 100000

// SelfEntry reports the expiry of the HISS-19 exception for this package.
func SelfEntry() Entry {
	// Why: The declaration immediately after this call is the reported source line.
	_, _, line, _ := runtime.Caller(0)
	const selfExpiry = "2027-03-23"
	return Entry{
		Source:  "tools/go/lintexceptions/lintexceptions.go",
		Line:    line + 1,
		File:    "tools/go/lintexceptions",
		Rule:    "HISS-19",
		Expires: selfExpiry,
	}
}

const (
	beginMarker = "      # praetor:generated-exceptions begin (praetorctl linters exceptions; never edit by hand)"
	endMarker   = "      # praetor:generated-exceptions end"
	lintersKey  = "        linters:"
)

var (
	baselineLine   = regexp.MustCompile(`^      # baseline #\d+$`)
	baselineLinter = regexp.MustCompile(`^          - (?:funlen|gocyclo|gocognit)$`)
	textLine       = regexp.MustCompile(`^        text: (?:func ` + "`" + `\w+` + "`" + `|Function '\w+')$`)
	commentLine    = regexp.MustCompile(`^      # category [A-D], (?:entered \d{4}-\d{2}-\d{2}, )?expires (\d{4}-\d{2}-\d{2}), #\d+$`)
	pathLine       = regexp.MustCompile(`^      - path: (\^\S+_test\\\.go\$)$`)
	linterLine     = regexp.MustCompile(`^          - (?:funlen|gocyclo|gocognit|cyclop)$`)
	complexityName = regexp.MustCompile(`\b(?:funlen|gocyclo|gocognit|cyclop)\b`)
)

// errNoRules is returned for a configuration without a linters.exclusions.rules block.
var errNoRules = errors.New("no linters.exclusions.rules block")

// Rule kinds: the comment above a path opens one kind, and the path consumes it.
const (
	kindNone = iota
	kindDated
	kindBaseline
)

// scan holds the reader state across the lines of the rules block.
type scan struct {
	today         time.Time
	rejectExpired bool
	source        string
	generated     bool
	seenBlock     bool
	pending       int  // kind named by the last comment, not yet consumed by a path
	rule          int  // kind of the rule being read
	hasKey        bool // the rule has its linters: key
	hasText       bool
	rules         int
	entry         Entry
	linters       []string
	entries       []Entry
}

// Check reads the configuration text and returns the number of generated rules it found, or
// an error naming the first line that breaks the contract in the package comment.
func Check(config string, today time.Time) (int, error) {
	s := &scan{today: today, rejectExpired: true}
	err := s.read(config)
	return s.rules, err
}

// read scans the configuration with the selected expiry policy.
func (s *scan) read(config string) error {
	// A Windows checkout ends lines with CRLF; the rules read LF lines.
	lines := strings.Split(strings.ReplaceAll(config, "\r\n", "\n"), "\n")
	start, err := rulesStart(lines)
	if err != nil {
		return err
	}
	for i := start; i < len(lines) && i < maxLines; i++ {
		line := lines[i]
		if line != "" && !strings.HasPrefix(line, "      ") {
			break
		}
		if err := s.line(line, i+1); err != nil {
			return err
		}
	}
	if s.generated {
		return errors.New("generated exceptions block has no end marker")
	}
	return nil
}

// line judges one line of the rules block.
func (s *scan) line(line string, lineNumber int) error {
	switch {
	case line == beginMarker && !s.seenBlock:
		s.generated, s.seenBlock = true, true
		return nil
	case line == endMarker && s.generated:
		s.generated = false
		if s.pending != kindNone {
			return fmt.Errorf("line %d: exception comment without a rule before the end marker", lineNumber)
		}
		return s.finish(lineNumber)
	case !s.generated:
		if complexityName.MatchString(line) {
			return fmt.Errorf("line %d: complexity linter excluded outside the generated block: %q", lineNumber, line)
		}
		return nil
	}
	return s.generatedLine(line, lineNumber)
}

// generatedLine judges one line inside the generated block against the allowed shapes.
func (s *scan) generatedLine(line string, lineNumber int) error {
	if match := commentLine.FindStringSubmatch(line); match != nil {
		return s.comment(kindDated, match[1], lineNumber)
	}
	if baselineLine.MatchString(line) {
		return s.comment(kindBaseline, "", lineNumber)
	}
	if match := pathLine.FindStringSubmatch(line); match != nil {
		return s.pathLine(match[1], lineNumber)
	}
	if line == "" {
		return nil
	}
	if line == lintersKey && s.rule != kindNone && !s.hasKey {
		s.hasKey = true
		return nil
	}
	if s.ruleLine(line) {
		return nil
	}
	return fmt.Errorf("line %d: %q is not an exception comment, test-file path or complexity linter line", lineNumber, line)
}

// comment closes the rule before it and records the kind the next path opens.
func (s *scan) comment(kind int, expiry string, lineNumber int) error {
	if err := s.finish(lineNumber); err != nil {
		return err
	}
	if s.pending != kindNone {
		return fmt.Errorf("line %d: exception comment without a rule below the one before it", lineNumber)
	}
	s.pending = kind
	s.entry = Entry{Source: s.source, Line: lineNumber, Expires: expiry}
	return nil
}

// pathLine opens one rule and consumes its comment.
func (s *scan) pathLine(path string, lineNumber int) error {
	if err := s.finish(lineNumber); err != nil {
		return err
	}
	switch s.pending {
	case kindBaseline:
		s.rule = kindBaseline
	default:
		if err := s.checkRule(lineNumber); err != nil {
			return err
		}
		s.rule = kindDated
		s.entry.File = path
	}
	s.pending = kindNone
	s.rules++
	return nil
}

// ruleLine records a linter or text line the current rule kind allows below its linters: key.
func (s *scan) ruleLine(line string) bool {
	if !s.hasKey {
		return false
	}
	switch {
	case s.rule == kindDated && linterLine.MatchString(line),
		s.rule == kindBaseline && baselineLinter.MatchString(line):
		s.linters = append(s.linters, strings.TrimPrefix(line, "          - "))
	case s.rule == kindBaseline && textLine.MatchString(line):
		s.hasText = true
	default:
		return false
	}
	return true
}

// finish refuses the rule just read when it lacks a linter, or a baseline lacks its function
// selector: either gap widens the exclusion to every linter or every function of the file.
func (s *scan) finish(lineNumber int) error {
	rule, hasText := s.rule, s.hasText
	s.rule, s.hasKey, s.hasText = kindNone, false, false
	switch {
	case rule == kindNone:
		return nil
	case len(s.linters) == 0:
		return fmt.Errorf("line %d: rule above has no complexity linter line", lineNumber)
	case rule == kindBaseline && !hasText:
		return fmt.Errorf("line %d: baseline rule above has no function text selector", lineNumber)
	}
	if rule == kindDated {
		s.entry.Rule = strings.Join(s.linters, ", ")
		s.entries = append(s.entries, s.entry)
	}
	s.entry, s.linters = Entry{}, s.linters[:0]
	return nil
}

// rulesStart returns the index of the first line after "    rules:" inside "  exclusions:".
func rulesStart(lines []string) (int, error) {
	inExclusions := false
	for i := 0; i < len(lines) && i < maxLines; i++ {
		switch {
		case lines[i] == "  exclusions:":
			inExclusions = true
		case inExclusions && lines[i] == "    rules:":
			return i + 1, nil
		}
	}
	return 0, errNoRules
}

// checkRule validates the date and enforces it when the scan rejects expired rules.
func (s *scan) checkRule(lineNumber int) error {
	if s.entry.Expires == "" {
		return fmt.Errorf("line %d: rule has no \"category <A-D>, entered <date>, expires <date>, #<issue>\" comment above it", lineNumber)
	}
	expired, err := Expired(s.entry.Expires, s.today)
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNumber, err)
	}
	if expired && s.rejectExpired {
		return fmt.Errorf("line %d: exception expired on %s", lineNumber, s.entry.Expires)
	}
	return nil
}

// Expired reports whether the date has passed: an exception holds through its expiry day.
func Expired(expiry string, today time.Time) (bool, error) {
	days, err := daysUntil(expiry, today)
	return days < 0, err
}

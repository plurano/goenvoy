// Command expiring reports dated repository exceptions that are due soon or overdue.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/golusoris/goenvoy/tools/go/lintexceptions"
)

const (
	gitTimeout = 30 * time.Second
	maxFiles   = 100000
)

func main() {
	err := execute(context.Background(), os.Args[1:], time.Now().UTC(), os.Stdout, os.Getenv("GITHUB_STEP_SUMMARY"))
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}

// execute parses arguments and discovers the files to report on.
func execute(ctx context.Context, args []string, today time.Time, stdout io.Writer, summary string) error {
	flags := flag.NewFlagSet("expiring", flag.ContinueOnError)
	root := flags.String("root", "../..", "repository root")
	date := flags.String("today", today.UTC().Format(time.DateOnly), "report date (YYYY-MM-DD, UTC)")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("expiring flags: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("expiring: unexpected arguments %q", flags.Args())
	}
	parsed, err := time.Parse(time.DateOnly, *date)
	if err != nil {
		return fmt.Errorf("expiring -today %q: %w", *date, err)
	}
	files, err := trackedFiles(ctx, *root)
	if err != nil {
		return err
	}
	return run(ctx, *root, files, parsed, stdout, summary)
}

// trackedFiles lists indexed paths without consulting a remote.
func trackedFiles(ctx context.Context, root string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-files", "-z")
	cmd.Dir = root
	body, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: git ls-files: %w", root, err)
	}
	paths := strings.TrimSuffix(string(body), "\x00")
	if paths == "" {
		return nil, nil
	}
	return strings.Split(paths, "\x00"), nil
}

// run renders the same report to stdout and to the optional CI summary.
func run(ctx context.Context, root string, files []string, today time.Time, stdout io.Writer, summary string) error {
	entries, err := collectEntries(ctx, root, files, today)
	if err != nil {
		return err
	}
	list, err := lintexceptions.Expiring(entries, today, lintexceptions.LeadDays)
	if err != nil {
		return err
	}
	report := lintexceptions.Markdown(list, len(entries), today, lintexceptions.LeadDays)
	if _, err := io.WriteString(stdout, report); err != nil {
		return fmt.Errorf("write report to stdout: %w", err)
	}
	if summary != "" {
		return appendSummary(summary, report)
	}
	return nil
}

// collectEntries opens the repository root and reads supported files within it.
func collectEntries(ctx context.Context, root string, files []string, today time.Time) ([]lintexceptions.Entry, error) {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open repository %s: %w", root, err)
	}
	entries, readErr := readEntries(ctx, dir, files, today)
	if err := dir.Close(); err != nil {
		return nil, errors.Join(readErr, fmt.Errorf("close repository %s: %w", root, err))
	}
	return entries, readErr
}

// readEntries scans the tracked files that can declare dated exceptions.
func readEntries(ctx context.Context, dir *os.Root, files []string, today time.Time) ([]lintexceptions.Entry, error) {
	if len(files) > maxFiles {
		return nil, fmt.Errorf("%s: tracked files exceed %d paths", dir.Name(), maxFiles)
	}
	var entries []lintexceptions.Entry
	for i := 0; i < len(files) && i < maxFiles; i++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("scan exception sources: %w", err)
		}
		file := files[i]
		reader := readerFor(file, today)
		if reader == nil {
			continue
		}
		data, err := dir.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("%s: read exception source: %w", file, err)
		}
		found, err := reader(file, data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, found...)
	}
	return entries, nil
}

type entryReader func(source string, data []byte) ([]lintexceptions.Entry, error)

// readerFor selects the reader for a tracked source path.
func readerFor(file string, today time.Time) entryReader {
	switch {
	case file == ".golangci.yml":
		return func(source string, data []byte) ([]lintexceptions.Entry, error) {
			return lintexceptions.ConfigEntries(source, string(data), today)
		}
	case file == "tools/semgrep-filter.sh":
		return lintexceptions.SemgrepEntries
	case file == "tools/go/lintexceptions/lintexceptions.go":
		return lintexceptions.SelfExpiryEntries
	case filepath.Base(file) == "osv-scanner.toml":
		return lintexceptions.OSVEntries
	case filepath.Ext(file) == ".yml", filepath.Ext(file) == ".yaml":
		return lintexceptions.YAMLEntries
	default:
		return nil
	}
}

// appendSummary adds the report to the job summary file.
func appendSummary(path, report string) error {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("%s: open summary directory: %w", path, err)
	}
	writeErr := writeSummary(dir, filepath.Base(path), report)
	if err := dir.Close(); err != nil {
		return errors.Join(writeErr, fmt.Errorf("%s: close summary directory: %w", path, err))
	}
	return writeErr
}

// writeSummary appends to a summary in an open directory.
func writeSummary(dir *os.Root, name, report string) error {
	file, err := dir.OpenFile(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("%s: open summary: %w", name, err)
	}
	_, writeErr := io.WriteString(file, report)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return fmt.Errorf("%s: write summary: %w", name, err)
	}
	return nil
}

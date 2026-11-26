package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunReportsPackageTypes checks declaration syntax and lookalikes in argument order.
func TestRunReportsPackageTypes(t *testing.T) {
	t.Parallel()
	cases := []struct{ source, result string }{
		{"type Wanted struct{}", "true"},
		{"type (Other int; Wanted struct{})", "true"},
		{"type (\n Other int\n Wanted struct{}\n)", "true"},
		{"type Wanted = int", "true"},
		{"// type Wanted struct{}", "false"},
		{`const s = "type Wanted struct{}"`, "false"},
		{"func f() { type Wanted int }", "false"},
		{"func (Wanted) f() {}", "false"},
		{"type WantedExtra int", "false"},
	}
	args := make([]string, 1, len(cases)+1)
	args[0] = "Wanted"
	var want strings.Builder
	for _, tc := range cases {
		args = append(args, writeSource(t, tc.source))
		want.WriteString(tc.result + "\n")
	}
	var output strings.Builder
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != want.String() {
		t.Errorf("got %q, want %q", output.String(), want.String())
	}
}

// TestRunRejectsInvalidGo checks that a declaration before a syntax error still fails.
func TestRunRejectsInvalidGo(t *testing.T) {
	t.Parallel()
	path := writeSource(t, "type Wanted int\nfunc broken(]")
	var output strings.Builder
	err := run([]string{"Wanted", path}, &output)
	if err == nil || !strings.Contains(err.Error(), path+":3:") {
		t.Errorf("run returned %v, want a parse error at line 3", err)
	}
	if output.Len() != 0 {
		t.Errorf("invalid input produced a result: %q", output.String())
	}
}

// writeSource writes a Go file with a fixed package clause.
func writeSource(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.go")
	if err := os.WriteFile(path, []byte("package fixture\n"+source+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

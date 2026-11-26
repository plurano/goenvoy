// Command redactdecl reports whether each Go file declares a named package-level type.
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
)

// main runs the declaration check on the file arguments and exits with a nonzero status on error.
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.New(os.Stderr, "redactdecl: ", 0).Fatal(err)
	}
}

// run writes one declaration result per file in argument order.
func run(args []string, output io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: redactdecl TYPE FILE [FILE ...]")
	}
	for _, path := range args[1:] {
		found, err := declaresType(path, args[0])
		if err != nil {
			return err
		}
		if _, writeErr := fmt.Fprintln(output, found); writeErr != nil {
			return fmt.Errorf("report declaration for %s: %w", path, writeErr)
		}
	}
	return nil
}

// declaresType finds the named type spec among the file's package-level declarations.
func declaresType(path, name string) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return false, fmt.Errorf("parse Go source: %w", err)
	}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, spec := range group.Specs {
			if typeSpec, isType := spec.(*ast.TypeSpec); isType && typeSpec.Name.Name == name {
				return true, nil
			}
		}
	}
	return false, nil
}

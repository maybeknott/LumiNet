//go:build ignore

// Standalone repository gate, invoked via `go run scripts/checks/check_go_declaration_integrity.go`.
// The ignore tag keeps this file out of module-level `go build`/`go vet`/package
// resolution; explicitly listed files bypass build constraints, so the Makefile
// invocation above is unaffected.
package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type declSite struct {
	file string
	line int
}

type platform struct {
	goos   string
	goarch string
}

var platforms = []platform{
	{"linux", "amd64"},
	{"windows", "amd64"},
	{"darwin", "amd64"},
	{"android", "arm64"},
}

func excluded(rel string) bool {
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, ".git/") || strings.Contains(rel, "/node_modules/") || strings.Contains(rel, "/target/") || strings.Contains(rel, "/.gradle/") {
		return true
	}
	if strings.HasPrefix(rel, "src/packages/control-ui/dist/") || strings.HasPrefix(rel, "src/packages/control-ui/public/") {
		return true
	}
	return false
}

func namesFromDecl(decl ast.Decl) []string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil || d.Name == nil || d.Name.Name == "init" {
			return nil
		}
		return []string{d.Name.Name}
	case *ast.GenDecl:
		if d.Tok == token.IMPORT {
			return nil
		}
		var out []string
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name != nil && s.Name.Name != "_" {
					out = append(out, s.Name.Name)
				}
			case *ast.ValueSpec:
				for _, n := range s.Names {
					if n != nil && n.Name != "_" {
						out = append(out, n.Name)
					}
				}
			}
		}
		return out
	default:
		return nil
	}
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	dirs := map[string][]string{}
	syntaxErrors := []string{}
	parsed := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if entry.IsDir() {
			if rel != "." && excluded(filepath.ToSlash(rel)+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".go") || excluded(rel) {
			return nil
		}
		fset := token.NewFileSet()
		if _, parseErr := parser.ParseFile(fset, path, nil, parser.AllErrors); parseErr != nil {
			syntaxErrors = append(syntaxErrors, fmt.Sprintf("%s: %v", filepath.ToSlash(rel), parseErr))
		}
		parsed++
		relSlash := filepath.ToSlash(rel)
		// Declaration collision admission is a production-source contract. Labs is
		// preserved as non-authoritative research and may intentionally contain
		// independent alternative packages with duplicate declarations.
		if strings.HasPrefix(relSlash, "src/") {
			dir := filepath.Dir(path)
			dirs[dir] = append(dirs[dir], entry.Name())
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	errors := append([]string{}, syntaxErrors...)
	summaries := make([]string, 0, len(platforms))
	for _, p := range platforms {
		ctx := build.Default
		ctx.GOOS = p.goos
		ctx.GOARCH = p.goarch
		activePackages := 0
		duplicates := 0
		for dir, names := range dirs {
			sort.Strings(names)
			byPackage := map[string]map[string]declSite{}
			active := false
			for _, name := range names {
				match, matchErr := ctx.MatchFile(dir, name)
				if matchErr != nil {
					rel, _ := filepath.Rel(root, filepath.Join(dir, name))
					errors = append(errors, fmt.Sprintf("%s/%s: build selection: %v", p.goos, filepath.ToSlash(rel), matchErr))
					continue
				}
				if !match {
					continue
				}
				active = true
				full := filepath.Join(dir, name)
				fset := token.NewFileSet()
				file, parseErr := parser.ParseFile(fset, full, nil, 0)
				if parseErr != nil {
					continue
				}
				pkg := file.Name.Name
				table := byPackage[pkg]
				if table == nil {
					table = map[string]declSite{}
					byPackage[pkg] = table
				}
				for _, decl := range file.Decls {
					pos := fset.Position(decl.Pos())
					for _, symbol := range namesFromDecl(decl) {
						if prev, exists := table[symbol]; exists {
							rel, _ := filepath.Rel(root, full)
							errors = append(errors, fmt.Sprintf("%s/%s: duplicate top-level %s.%s at %s:%d and %s:%d", p.goos, p.goarch, pkg, symbol, prev.file, prev.line, filepath.ToSlash(rel), pos.Line))
							duplicates++
						} else {
							rel, _ := filepath.Rel(root, full)
							table[symbol] = declSite{file: filepath.ToSlash(rel), line: pos.Line}
						}
					}
				}
			}
			if active {
				activePackages++
			}
		}
		summaries = append(summaries, fmt.Sprintf("%s/%s active_packages=%d duplicate_declarations=%d", p.goos, p.goarch, activePackages, duplicates))
	}

	fmt.Printf("go-declaration-integrity parsed_files=%d syntax_errors=%d errors=%d\n", parsed, len(syntaxErrors), len(errors))
	for _, s := range summaries {
		fmt.Println(s)
	}
	for _, e := range errors {
		fmt.Println("ERROR:", e)
	}
	if len(errors) > 0 {
		os.Exit(1)
	}
}

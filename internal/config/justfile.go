// Package config loads, validates and merges keg configuration.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ParseJustfileImports extracts all imported or included file paths from justfile content.
// It supports:
//   - import 'path' / import "path" / import path
//   - import? 'path' / import? "path" / import? path
//   - !include 'path' / !include "path" / !include path
//
// Comment lines and inline comments starting with '#' are ignored.
func ParseJustfileImports(content string) []string {
	var imports []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		cleanLine := stripJustComment(line)
		cleanLine = strings.TrimSpace(cleanLine)
		if cleanLine == "" {
			continue
		}

		var target string
		switch {
		case strings.HasPrefix(cleanLine, "import?"):
			target = strings.TrimSpace(strings.TrimPrefix(cleanLine, "import?"))
		case strings.HasPrefix(cleanLine, "import ") || strings.HasPrefix(cleanLine, "import\t"):
			target = strings.TrimSpace(strings.TrimPrefix(cleanLine, "import"))
		case strings.HasPrefix(cleanLine, "!include ") || strings.HasPrefix(cleanLine, "!include\t"):
			target = strings.TrimSpace(strings.TrimPrefix(cleanLine, "!include"))
		}

		if target != "" {
			unquoted := unquoteJustPath(target)
			if unquoted != "" {
				imports = append(imports, unquoted)
			}
		}
	}
	return imports
}

func stripJustComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func unquoteJustPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first := s[0]
		last := s[len(s)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') || (first == '`' && last == '`') {
			return s[1 : len(s)-1]
		}
	}
	fields := strings.Fields(s)
	if len(fields) > 0 {
		return fields[0]
	}
	return s
}

// collectJustfileAnchors recursively discovers justfiles and their imported files.
func collectJustfileAnchors(repoDir, relPath string, seen map[string]bool, list *[]string) {
	cleaned := filepath.Clean(relPath)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return
	}
	absPath := filepath.Join(repoDir, cleaned)
	info, err := os.Stat(absPath)
	if err != nil || info.IsDir() {
		return
	}
	if !seen[cleaned] {
		seen[cleaned] = true
		*list = append(*list, cleaned)
	}

	data, err := os.ReadFile(absPath) // #nosec G304
	if err != nil {
		return
	}

	dir := filepath.Dir(cleaned)
	for _, imp := range ParseJustfileImports(string(data)) {
		impClean := filepath.Clean(imp)
		if impClean == "" || impClean == "." {
			continue
		}
		var nextRel string
		if dir == "." || dir == "" {
			nextRel = impClean
		} else {
			nextRel = filepath.Join(dir, impClean)
		}
		nextRel = filepath.Clean(nextRel)
		if nextRel == ".." || strings.HasPrefix(nextRel, ".."+string(filepath.Separator)) {
			// escapes repository root
			continue
		}
		if !seen[nextRel] {
			collectJustfileAnchors(repoDir, nextRel, seen, list)
		}
	}
}

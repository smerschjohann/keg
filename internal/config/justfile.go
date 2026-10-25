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

// ParseJustfileDescriptions extracts recipe documentation comments and [doc('...')]
// attributes from a justfile's text content. It returns a map from recipe name to
// description. Decorative section banners (e.g. "# ── ...") and comments separated
// from a recipe by blank lines are ignored.
func ParseJustfileDescriptions(content string) map[string]string {
	descs := map[string]string{}
	var pendingComments []string
	var docAttr string
	var hasDocAttr bool

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		rawLine := scanner.Text()
		// Indented lines belong to recipe bodies or multi-line expressions.
		if strings.HasPrefix(rawLine, " ") || strings.HasPrefix(rawLine, "\t") {
			pendingComments = nil
			docAttr = ""
			hasDocAttr = false
			continue
		}

		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			pendingComments = nil
			docAttr = ""
			hasDocAttr = false
			continue
		}

		if strings.HasPrefix(trimmed, "#") {
			if strings.HasPrefix(trimmed, "#!") {
				continue
			}
			c := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			if c != "" && !isBannerComment(c) {
				pendingComments = append(pendingComments, c)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if d, ok := parseJustDocAttr(trimmed); ok {
				docAttr = d
				hasDocAttr = true
			}
			continue
		}

		if recipe := parseJustRecipeHeader(trimmed); recipe != "" {
			var chosen string
			if hasDocAttr {
				chosen = docAttr
			} else if len(pendingComments) > 0 {
				chosen = pendingComments[len(pendingComments)-1]
			}
			if chosen != "" {
				descs[recipe] = chosen
			}
		}

		pendingComments = nil
		docAttr = ""
		hasDocAttr = false
	}
	return descs
}

func isBannerComment(c string) bool {
	if strings.HasPrefix(c, "──") || strings.HasPrefix(c, "==") || strings.HasPrefix(c, "--") {
		return true
	}
	if strings.HasSuffix(c, "───") || strings.HasSuffix(c, "===") || strings.HasSuffix(c, "---") {
		return true
	}
	return false
}

func parseJustDocAttr(attrLine string) (string, bool) {
	inner := strings.TrimSpace(attrLine[1 : len(attrLine)-1])
	if inner == "doc" {
		return "", true
	}
	if !strings.HasPrefix(inner, "doc(") || !strings.HasSuffix(inner, ")") {
		return "", false
	}
	arg := strings.TrimSpace(inner[len("doc(") : len(inner)-1])
	return unquoteJustPath(arg), true
}

func parseJustRecipeHeader(line string) string {
	clean := stripJustComment(line)
	// Ignore assignments (:=) and directives
	for _, kw := range []string{"set ", "set\t", "export ", "export\t", "alias ", "alias\t", "import ", "import\t", "import?", "!include ", "!include\t", "mod ", "mod\t", "mod?"} {
		if strings.HasPrefix(clean, kw) {
			return ""
		}
	}
	colonIdx := strings.IndexByte(clean, ':')
	if colonIdx <= 0 {
		return ""
	}
	if colonIdx+1 < len(clean) && clean[colonIdx+1] == '=' {
		return ""
	}
	head := strings.TrimSpace(clean[:colonIdx])
	if head == "" {
		return ""
	}
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return ""
	}
	name := strings.TrimLeft(fields[0], "@-")
	if !isValidJustRecipeName(name) {
		return ""
	}
	return name
}

func isValidJustRecipeName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		isDigit := r >= '0' && r <= '9'
		if i == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isDigit && r != '-' {
			return false
		}
	}
	return true
}

// DiscoverJustfileDescriptions traverses the repository's root justfile and any
// imported .just files within repoDir, returning recipe doc-comments mapped by recipe name.
// Root justfile definitions take precedence over imported ones if names collide.
func DiscoverJustfileDescriptions(repoDir string) map[string]string {
	descs := map[string]string{}
	if repoDir == "" {
		return descs
	}
	var rootName string
	for _, name := range []string{"justfile", "Justfile", ".justfile"} {
		p := filepath.Join(repoDir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			rootName = name
			break
		}
	}
	if rootName == "" {
		return descs
	}
	var files []string
	seen := map[string]bool{}
	collectJustfileAnchors(repoDir, rootName, seen, &files)
	// Process in reverse order so earlier files (the root justfile) override later imports.
	for i := len(files) - 1; i >= 0; i-- {
		absPath := filepath.Join(repoDir, files[i])
		data, err := os.ReadFile(absPath) // #nosec G304 -- path jailed to repoDir by collectJustfileAnchors
		if err != nil {
			continue
		}
		for k, v := range ParseJustfileDescriptions(string(data)) {
			descs[k] = v
		}
	}
	return descs
}

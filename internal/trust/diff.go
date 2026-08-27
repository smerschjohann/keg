package trust

import (
	"slices"
	"strings"
)

// FormatDiff returns a human-readable diff between oldContent and newContent.
// When isNew is true, it displays the whole new configuration as newly added.
func FormatDiff(oldContent, newContent string, isNew bool) string {
	if isNew {
		var b strings.Builder
		b.WriteString("=== New repository configuration ===\n")
		if strings.TrimSpace(newContent) != "" {
			for _, line := range strings.Split(strings.TrimRight(newContent, "\n"), "\n") {
				b.WriteString("+ ")
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
		return b.String()
	}

	var oldLines []string
	if strings.TrimSpace(oldContent) != "" {
		oldLines = strings.Split(strings.TrimRight(oldContent, "\n"), "\n")
	}
	var newLines []string
	if strings.TrimSpace(newContent) != "" {
		newLines = strings.Split(strings.TrimRight(newContent, "\n"), "\n")
	}

	var b strings.Builder
	b.WriteString("--- approved\n")
	b.WriteString("+++ current\n")
	for _, line := range computeLCSDiff(oldLines, newLines) {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// FormatAnchorDiff returns a human-readable diff for a trust anchor file.
// When isNew is true, it displays the whole new anchor content as newly added.
func FormatAnchorDiff(relPath, oldContent, newContent string, isNew bool) string {
	if isNew {
		var b strings.Builder
		b.WriteString("=== New trust anchor: " + relPath + " ===\n")
		if strings.TrimSpace(newContent) != "" {
			for _, line := range strings.Split(strings.TrimRight(newContent, "\n"), "\n") {
				b.WriteString("+ ")
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
		return b.String()
	}

	var oldLines []string
	if strings.TrimSpace(oldContent) != "" {
		oldLines = strings.Split(strings.TrimRight(oldContent, "\n"), "\n")
	}
	var newLines []string
	if strings.TrimSpace(newContent) != "" {
		newLines = strings.Split(strings.TrimRight(newContent, "\n"), "\n")
	}

	var b strings.Builder
	b.WriteString("=== Trust anchor: " + relPath + " ===\n")
	b.WriteString("--- approved\n")
	b.WriteString("+++ current\n")
	for _, line := range computeLCSDiff(oldLines, newLines) {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func computeLCSDiff(a, b []string) []string {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			if a[i] == b[j] {
				dp[i+1][j+1] = dp[i][j] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i+1][j+1] = dp[i+1][j]
			} else {
				dp[i+1][j+1] = dp[i][j+1]
			}
		}
	}

	var diff []string
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && a[i-1] == b[j-1] {
			diff = append(diff, "  "+a[i-1])
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			diff = append(diff, "+ "+b[j-1])
			j--
		} else if i > 0 && (j == 0 || dp[i][j-1] < dp[i-1][j]) {
			diff = append(diff, "- "+a[i-1])
			i--
		}
	}
	slices.Reverse(diff)
	return diff
}

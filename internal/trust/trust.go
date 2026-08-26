// Package trust manages repo config approval states and security gates.
//
// Every repository with a non-empty .keg.yaml is tracked in a local
// trust store ($XDG_CONFIG_HOME/keg/trust.yaml). Sandboxes require
// explicit trust whenever a repo config is new or its contents change.
package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// Entry records the current and approved state of a repository configuration.
type Entry struct {
	CurrentSHA      string    `yaml:"current_sha"`
	ApprovedSHA     string    `yaml:"approved_sha"`
	ApprovedContent string    `yaml:"approved_content"`
	Updated         time.Time `yaml:"updated"`
}

// Store holds the approval records for all known repositories keyed by realpath.
type Store struct {
	Repos map[string]Entry `yaml:"repos"`
}

// DefaultTrustPath returns the default location of the trust store file.
func DefaultTrustPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "keg", "trust.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "keg", "trust.yaml")
}

// Path returns overridePath if non-empty, otherwise DefaultTrustPath().
func Path(overridePath string) string {
	if overridePath != "" {
		return overridePath
	}
	return DefaultTrustPath()
}

// CleanRepoKey canonicalizes a repository path by resolving symlinks and absolute paths.
func CleanRepoKey(repoPath string) string {
	cleaned := repoPath
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		cleaned = resolved
	}
	if abs, err := filepath.Abs(cleaned); err == nil {
		cleaned = abs
	}
	return filepath.Clean(cleaned)
}

// Sha256 computes the hexadecimal SHA-256 digest of data.
// It returns an error if data is empty.
func Sha256(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("cannot compute sha256 of empty data")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Sha256File reads path and computes its SHA-256 digest.
func Sha256File(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from config resolution
	if err != nil {
		return "", fmt.Errorf("read file for sha256 %s: %w", path, err)
	}
	return Sha256(data)
}

// Load parses raw YAML bytes into a Store with strict field checking.
func Load(data []byte) (*Store, error) {
	var store Store
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&store); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if store.Repos == nil {
		store.Repos = make(map[string]Entry)
	}
	return &store, nil
}

// Save encodes the Store to YAML with deterministically sorted repo keys.
func Save(store *Store) ([]byte, error) {
	if store == nil {
		return []byte("repos: {}\n"), nil
	}
	// Sort keys for deterministic output
	keys := make([]string, 0, len(store.Repos))
	for k := range store.Repos {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var doc yaml.Node
	doc.Kind = yaml.DocumentNode

	var root yaml.Node
	root.Kind = yaml.MappingNode

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "repos"}
	valNode := &yaml.Node{Kind: yaml.MappingNode}

	for _, k := range keys {
		e := store.Repos[k]
		kNode := &yaml.Node{Kind: yaml.ScalarNode, Value: k}
		var eNode yaml.Node
		if err := eNode.Encode(e); err != nil {
			return nil, fmt.Errorf("encode trust entry for %s: %w", k, err)
		}
		valNode.Content = append(valNode.Content, kNode, &eNode)
	}

	root.Content = append(root.Content, keyNode, valNode)
	doc.Content = append(doc.Content, &root)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode trust store: %w", err)
	}
	return buf.Bytes(), nil
}

// LoadFile reads and parses a trust store from path.
// If the file does not exist, an empty store is returned without error.
func LoadFile(path string) (*Store, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from config resolution
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{Repos: make(map[string]Entry)}, nil
		}
		return nil, fmt.Errorf("load trust store %s: %w", path, err)
	}
	return Load(data)
}

// SaveFile writes the store to path in YAML format, creating parent directories if needed.
func SaveFile(path string, store *Store) error {
	data, err := Save(store)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G703 -- local config dir
		return fmt.Errorf("create trust store dir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { // #nosec G703 -- local trust file
		return fmt.Errorf("write trust store %s: %w", path, err)
	}
	return nil
}

// IsTrusted reports whether entry is approved for currentSHA.
func IsTrusted(e Entry, currentSHA string) bool {
	return e.ApprovedSHA != "" && currentSHA != "" && e.ApprovedSHA == currentSHA
}

// NoteCurrent calculates the SHA of content and updates CurrentSHA and Updated for repoPath.
// It returns whether the CurrentSHA has changed and does not modify ApprovedSHA or ApprovedContent.
func NoteCurrent(store *Store, repoPath string, content []byte) (bool, error) {
	sha, err := Sha256(content)
	if err != nil {
		return false, err
	}
	key := CleanRepoKey(repoPath)
	if store.Repos == nil {
		store.Repos = make(map[string]Entry)
	}
	existing, exists := store.Repos[key]
	changed := !exists || existing.CurrentSHA != sha

	store.Repos[key] = Entry{
		CurrentSHA:      sha,
		ApprovedSHA:     existing.ApprovedSHA,
		ApprovedContent: existing.ApprovedContent,
		Updated:         time.Now().UTC(),
	}
	return changed, nil
}

// Approve calculates the SHA of content, sets ApprovedSHA and ApprovedContent equal to the
// current content, and returns the approved SHA.
func Approve(store *Store, repoPath string, content []byte) (string, error) {
	sha, err := Sha256(content)
	if err != nil {
		return "", err
	}
	key := CleanRepoKey(repoPath)
	if store.Repos == nil {
		store.Repos = make(map[string]Entry)
	}
	store.Repos[key] = Entry{
		CurrentSHA:      sha,
		ApprovedSHA:     sha,
		ApprovedContent: string(content),
		Updated:         time.Now().UTC(),
	}
	return sha, nil
}

// Revoke clears ApprovedSHA and ApprovedContent for repoPath.
func Revoke(store *Store, repoPath string) {
	key := CleanRepoKey(repoPath)
	if store.Repos == nil {
		return
	}
	existing, exists := store.Repos[key]
	if !exists {
		return
	}
	store.Repos[key] = Entry{
		CurrentSHA:      existing.CurrentSHA,
		ApprovedSHA:     "",
		ApprovedContent: "",
		Updated:         time.Now().UTC(),
	}
}

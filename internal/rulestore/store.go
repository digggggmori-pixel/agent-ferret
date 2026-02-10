package rulestore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
)

const rulesFileName = "rules.json"

// RuleStore manages the lifecycle of rule bundles.
// It handles loading from disk and atomic hot-swapping at runtime.
type RuleStore struct {
	mu       sync.RWMutex
	bundle   *RuleBundle
	rulesDir string // directory where rules.json lives (exe directory)
}

// NewRuleStore creates a new RuleStore.
// The rules directory defaults to the directory containing the executable.
func NewRuleStore() *RuleStore {
	return &RuleStore{
		rulesDir: execDir(),
	}
}

// Load attempts to load rules.json from the exe directory or working directory.
// Returns an error if the file is missing or invalid.
func (rs *RuleStore) Load() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Try exe directory first, then working directory
	candidates := []string{
		filepath.Join(rs.rulesDir, rulesFileName),
	}
	if wd, err := os.Getwd(); err == nil && wd != rs.rulesDir {
		candidates = append(candidates, filepath.Join(wd, rulesFileName))
	}

	var path string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			path = c
			break
		}
	}

	if path == "" {
		searchedPaths := ""
		for i, c := range candidates {
			if i > 0 {
				searchedPaths += ", "
			}
			searchedPaths += c
		}
		return fmt.Errorf("rules.json not found. Searched: [%s]", searchedPaths)
	}

	bundle, err := LoadBundleFromFile(path)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	rs.bundle = bundle
	logger.Info("Rules loaded: version=%s, sigma=%d rules, path=%s", bundle.Version, bundle.Sigma.TotalRules(), path)
	return nil
}

// Reload re-reads rules.json from disk and atomically swaps the bundle.
// Safe to call while scans are running — ongoing scans keep their reference.
func (rs *RuleStore) Reload() error {
	path := filepath.Join(rs.rulesDir, rulesFileName)

	bundle, err := LoadBundleFromFile(path)
	if err != nil {
		return fmt.Errorf("failed to reload rules: %w", err)
	}

	rs.mu.Lock()
	rs.bundle = bundle
	rs.mu.Unlock()

	logger.Info("Rules reloaded: version=%s, sigma=%d rules", bundle.Version, bundle.Sigma.TotalRules())
	return nil
}

// GetBundle returns the currently loaded rule bundle.
// Returns nil if no rules have been loaded.
func (rs *RuleStore) GetBundle() *RuleBundle {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.bundle
}

// IsLoaded returns true if rules have been successfully loaded.
func (rs *RuleStore) IsLoaded() bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.bundle != nil
}

// Version returns the current rule bundle version, or "" if not loaded.
func (rs *RuleStore) Version() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.bundle == nil {
		return ""
	}
	return rs.bundle.Version
}

// execDir returns the directory containing the current executable.
// Falls back to "." if the executable path cannot be determined.
func execDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

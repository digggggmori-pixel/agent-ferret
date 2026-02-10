package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/internal/rulestore"
	"github.com/digggggmori-pixel/agent-ferret/internal/scan"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const Version = "1.0.0"

// App struct - methods exposed to the frontend via Wails bindings
type App struct {
	ctx        context.Context
	ruleStore  *rulestore.RuleStore
	scanner    *scan.Service
	lastResult *types.ScanResult
}

// NewApp creates a new App instance
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Initialize rule store and load rules from external file
	a.ruleStore = rulestore.NewRuleStore()
	if err := a.ruleStore.Load(); err != nil {
		logger.Error("Failed to load rules: %v", err)
	}

	a.scanner = scan.NewService(ctx, a.ruleStore)
}

func (a *App) shutdown(ctx context.Context) {
	// Cleanup if needed
}

// StartScan starts the security scan and returns the result
func (a *App) StartScan() (*types.ScanResult, error) {
	result, err := a.scanner.Execute()
	if err != nil {
		return nil, err
	}
	a.lastResult = result
	return result, nil
}

// GetHostInfo returns host system information
func (a *App) GetHostInfo() *types.HostInfo {
	info := a.scanner.GetHostInfo()
	return &info
}

// IsAdmin checks if running with administrator privileges
func (a *App) IsAdmin() bool {
	return a.scanner.IsAdmin()
}

// ExportJSON exports the last scan result to a JSON file and returns the file path
func (a *App) ExportJSON() (string, error) {
	if a.lastResult == nil {
		return "", fmt.Errorf("no scan result available")
	}

	filename := fmt.Sprintf("ferret_scan_%s.json", time.Now().Format("2006-01-02_150405"))

	// Try Desktop, fall back to current directory
	homeDir, err := os.UserHomeDir()
	var savePath string
	if err == nil {
		desktopDir := filepath.Join(homeDir, "Desktop")
		if _, statErr := os.Stat(desktopDir); statErr == nil {
			savePath = filepath.Join(desktopDir, filename)
		}
	}
	if savePath == "" {
		savePath = filename
	}

	data, err := json.MarshalIndent(a.lastResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}

	if err := os.WriteFile(savePath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return savePath, nil
}

// OpenBRIQA opens the BRIQA website in the default browser
func (a *App) OpenBRIQA() {
	runtime.BrowserOpenURL(a.ctx, "https://briqa.io")
}

// GetVersion returns the application version
func (a *App) GetVersion() string {
	return Version
}

// GetRuleVersion returns the loaded rule bundle version, or "" if not loaded
func (a *App) GetRuleVersion() string {
	return a.ruleStore.Version()
}

// IsRulesLoaded returns whether rules have been successfully loaded
func (a *App) IsRulesLoaded() bool {
	return a.ruleStore.IsLoaded()
}

// ReloadRules reloads rules.json from disk (hot-reload)
func (a *App) ReloadRules() error {
	return a.ruleStore.Reload()
}

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/internal/rulestore"
	"github.com/digggggmori-pixel/agent-ferret/internal/tui"
)

func main() {
	// Initialize logger — log file created next to ferret.exe
	exePath, _ := os.Executable()
	logDir := filepath.Dir(exePath)
	if err := logger.Init(logDir, true); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: logger init failed: %v\n", err)
	}
	defer logger.Close()

	// Initialize rule store and load rules from external file
	rs := rulestore.NewRuleStore()
	var loadErr string
	if err := rs.Load(); err != nil {
		logger.Error("Failed to load rules: %v", err)
		loadErr = err.Error()
	}

	// Launch TUI
	if err := tui.RunWithError(rs, loadErr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

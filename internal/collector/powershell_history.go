package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// PowerShellHistoryCollector collects PowerShell console history files
type PowerShellHistoryCollector struct{}

// NewPowerShellHistoryCollector creates a new PowerShell history collector
func NewPowerShellHistoryCollector() *PowerShellHistoryCollector {
	return &PowerShellHistoryCollector{}
}

// Collect reads ConsoleHost_history.txt from all user profiles
func (c *PowerShellHistoryCollector) Collect() ([]types.PowerShellHistoryEntry, error) {
	logger.Section("PowerShell History Collection")
	startTime := time.Now()

	var entries []types.PowerShellHistoryEntry

	// Enumerate user profiles under C:\Users
	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err != nil {
		logger.Error("Failed to read Users directory: %v", err)
		return entries, nil
	}

	filesRead := 0
	for _, userDir := range userDirs {
		if !userDir.IsDir() {
			continue
		}

		username := userDir.Name()
		// Skip system/default profiles
		if strings.EqualFold(username, "Public") || strings.EqualFold(username, "Default") ||
			strings.EqualFold(username, "Default User") || strings.EqualFold(username, "All Users") {
			continue
		}

		historyPath := filepath.Join(usersDir, username,
			`AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)

		userEntries := c.readHistoryFile(historyPath, username)
		if len(userEntries) > 0 {
			entries = append(entries, userEntries...)
			filesRead++
			logger.Debug("Read %d commands from %s", len(userEntries), username)
		}
	}

	logger.Timing("PowerShellHistoryCollector.Collect", startTime)
	logger.Info("PowerShell history: %d commands from %d users", len(entries), filesRead)

	return entries, nil
}

func (c *PowerShellHistoryCollector) readHistoryFile(path, username string) []types.PowerShellHistoryEntry {
	file, err := os.Open(path)
	if err != nil {
		return nil // File doesn't exist or not accessible — normal
	}
	defer file.Close()

	var entries []types.PowerShellHistoryEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		entries = append(entries, types.PowerShellHistoryEntry{
			User:       username,
			Command:    line,
			LineNumber: lineNum,
			FilePath:   path,
		})
	}

	return entries
}

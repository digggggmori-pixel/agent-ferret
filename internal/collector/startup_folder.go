package collector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// StartupFolderCollector collects files from startup folders
type StartupFolderCollector struct{}

// NewStartupFolderCollector creates a new startup folder collector
func NewStartupFolderCollector() *StartupFolderCollector {
	return &StartupFolderCollector{}
}

// Collect enumerates files in user and common startup folders
func (c *StartupFolderCollector) Collect() ([]types.StartupEntry, error) {
	logger.Section("Startup Folder Collection")
	startTime := time.Now()

	var entries []types.StartupEntry

	// Common startup folder
	commonStartup := os.Getenv("PROGRAMDATA") + `\Microsoft\Windows\Start Menu\Programs\Startup`
	if commonStartup == `\Microsoft\Windows\Start Menu\Programs\Startup` {
		commonStartup = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
	}
	entries = append(entries, c.scanFolder(commonStartup, "common", "")...)

	// Per-user startup folders
	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err == nil {
		for _, userDir := range userDirs {
			if !userDir.IsDir() {
				continue
			}
			username := userDir.Name()
			if strings.EqualFold(username, "Public") || strings.EqualFold(username, "Default") ||
				strings.EqualFold(username, "Default User") || strings.EqualFold(username, "All Users") {
				continue
			}

			userStartup := filepath.Join(usersDir, username,
				`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
			entries = append(entries, c.scanFolder(userStartup, "user", username)...)
		}
	}

	logger.Timing("StartupFolderCollector.Collect", startTime)
	logger.Info("Startup folder: %d entries found", len(entries))

	return entries, nil
}

func (c *StartupFolderCollector) scanFolder(folderPath, scope, user string) []types.StartupEntry {
	dirEntries, err := os.ReadDir(folderPath)
	if err != nil {
		return nil // Folder doesn't exist — normal
	}

	var entries []types.StartupEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}

		// Skip desktop.ini
		if strings.EqualFold(de.Name(), "desktop.ini") {
			continue
		}

		fullPath := filepath.Join(folderPath, de.Name())
		info, err := de.Info()
		if err != nil {
			continue
		}

		entry := types.StartupEntry{
			Name:       de.Name(),
			Path:       fullPath,
			Size:       info.Size(),
			ModifiedAt: info.ModTime(),
			IsHidden:   isHiddenFile(info),
			Scope:      scope,
			User:       user,
		}

		// Get creation time from Windows file attributes
		if sys := info.Sys(); sys != nil {
			if winData, ok := sys.(*syscall.Win32FileAttributeData); ok {
				entry.CreatedAt = time.Unix(0, winData.CreationTime.Nanoseconds())
			}
		}

		entries = append(entries, entry)
		logger.Debug("Startup entry: %s (%s, %s)", de.Name(), scope, fullPath)
	}

	return entries
}

func isHiddenFile(info os.FileInfo) bool {
	if sys := info.Sys(); sys != nil {
		if winData, ok := sys.(*syscall.Win32FileAttributeData); ok {
			const FILE_ATTRIBUTE_HIDDEN = 0x2
			return winData.FileAttributes&FILE_ATTRIBUTE_HIDDEN != 0
		}
	}
	return false
}

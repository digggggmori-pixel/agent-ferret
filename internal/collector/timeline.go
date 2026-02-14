package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// TimelineCollector reads the Windows Timeline (ActivitiesCache.db)
// Available on Windows 10 1803+ (Build 17134+), deprecated in Windows 11
type TimelineCollector struct{}

// NewTimelineCollector creates a new Timeline collector
func NewTimelineCollector() *TimelineCollector {
	return &TimelineCollector{}
}

type timelinePSEntry struct {
	AppID     string `json:"AppId"`
	Activity  string `json:"ActivityType"`
	StartTime string `json:"StartTime"`
	EndTime   string `json:"EndTime"`
	Payload   string `json:"Payload"`
}

// Collect reads ActivitiesCache.db for all user profiles
func (c *TimelineCollector) Collect() ([]types.TimelineEntry, error) {
	logger.Section("Timeline Collection")
	startTime := time.Now()

	var entries []types.TimelineEntry

	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err != nil {
		return entries, nil
	}

	for _, userDir := range userDirs {
		if !userDir.IsDir() || isSystemProfile(userDir.Name()) {
			continue
		}

		username := userDir.Name()
		dbPath := filepath.Join(usersDir, username,
			`AppData\Local\ConnectedDevicesPlatform\L.`+username+`\ActivitiesCache.db`)

		// Also check alternative locations
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			// Try without L. prefix
			altDir := filepath.Join(usersDir, username,
				`AppData\Local\ConnectedDevicesPlatform`)
			dirs, err := os.ReadDir(altDir)
			if err != nil {
				continue
			}
			found := false
			for _, d := range dirs {
				if d.IsDir() {
					candidate := filepath.Join(altDir, d.Name(), "ActivitiesCache.db")
					if _, err := os.Stat(candidate); err == nil {
						dbPath = candidate
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
		}

		userEntries := c.collectFromDB(dbPath, username)
		entries = append(entries, userEntries...)
	}

	logger.Timing("TimelineCollector.Collect", startTime)
	logger.Info("Timeline: %d activity entries collected", len(entries))

	return entries, nil
}

func (c *TimelineCollector) collectFromDB(dbPath, username string) []types.TimelineEntry {
	var entries []types.TimelineEntry

	// Copy DB to temp
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("ferret_timeline_%s.db", username))
	defer os.Remove(tempCopy)

	copyScript := fmt.Sprintf(`Copy-Item -Path '%s' -Destination '%s' -Force -ErrorAction SilentlyContinue`,
		strings.ReplaceAll(dbPath, "'", "''"), strings.ReplaceAll(tempCopy, "'", "''"))
	runPowerShell(copyScript)

	if _, err := os.Stat(tempCopy); err != nil {
		return entries
	}

	// Use sqlite3.exe or PowerShell to query
	entries = c.querySQLite(tempCopy, username)
	return entries
}

func (c *TimelineCollector) querySQLite(dbPath, username string) []types.TimelineEntry {
	var entries []types.TimelineEntry

	psScript := fmt.Sprintf(`
$dbPath = '%s'
$results = @()
try {
    $sqlite3 = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if ($sqlite3) {
        $query = "SELECT AppId, ActivityType, datetime(StartTime, 'unixepoch') as StartTime, datetime(EndTime, 'unixepoch') as EndTime, Payload FROM Activity ORDER BY StartTime DESC LIMIT 500;"
        $output = & sqlite3.exe $dbPath -json $query 2>$null
        if ($output) {
            $results = $output | ConvertFrom-Json
        }
    }
} catch {}
$results | ConvertTo-Json -Compress
`, strings.ReplaceAll(dbPath, "'", "''"))

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		return entries
	}

	var rawEntries []timelinePSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse timeline JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single timelinePSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		st, _ := time.Parse("2006-01-02 15:04:05", raw.StartTime)
		et, _ := time.Parse("2006-01-02 15:04:05", raw.EndTime)

		entries = append(entries, types.TimelineEntry{
			AppID:     raw.AppID,
			Activity:  raw.Activity,
			StartTime: st,
			EndTime:   et,
			Payload:   raw.Payload,
			User:      username,
		})
	}

	return entries
}

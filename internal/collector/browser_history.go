package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// BrowserHistoryCollector collects browser history from Chrome, Edge, and Firefox
type BrowserHistoryCollector struct{}

// NewBrowserHistoryCollector creates a new browser history collector
func NewBrowserHistoryCollector() *BrowserHistoryCollector {
	return &BrowserHistoryCollector{}
}

// Collect retrieves browser history entries from all supported browsers across all user profiles
func (c *BrowserHistoryCollector) Collect() ([]types.BrowserHistoryEntry, error) {
	logger.Section("Browser History Collection")
	startTime := time.Now()

	var allEntries []types.BrowserHistoryEntry

	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err != nil {
		logger.Error("Cannot list user directories: %v", err)
		return allEntries, nil
	}

	for _, userDir := range userDirs {
		if !userDir.IsDir() {
			continue
		}
		username := userDir.Name()
		if isSystemProfile(username) {
			continue
		}

		userHome := filepath.Join(usersDir, username)

		// Chrome
		chromePaths := []struct {
			browser string
			path    string
		}{
			{"Chrome", filepath.Join(userHome, `AppData\Local\Google\Chrome\User Data\Default\History`)},
			{"Edge", filepath.Join(userHome, `AppData\Local\Microsoft\Edge\User Data\Default\History`)},
		}

		for _, bp := range chromePaths {
			if _, err := os.Stat(bp.path); err == nil {
				entries := c.collectChromiumHistory(bp.browser, bp.path, username)
				allEntries = append(allEntries, entries...)
			}
		}

		// Firefox (profile directories have random prefixes)
		firefoxProfileDir := filepath.Join(userHome, `AppData\Roaming\Mozilla\Firefox\Profiles`)
		if profiles, err := os.ReadDir(firefoxProfileDir); err == nil {
			for _, profile := range profiles {
				if !profile.IsDir() {
					continue
				}
				placesPath := filepath.Join(firefoxProfileDir, profile.Name(), "places.sqlite")
				if _, err := os.Stat(placesPath); err == nil {
					entries := c.collectFirefoxHistory(placesPath, username)
					allEntries = append(allEntries, entries...)
				}
			}
		}
	}

	logger.Timing("BrowserHistoryCollector.Collect", startTime)
	logger.Info("Browser history: %d entries collected", len(allEntries))

	return allEntries, nil
}

// isSystemProfile checks if a username is a system profile that should be skipped
func isSystemProfile(username string) bool {
	system := []string{"Public", "Default", "Default User", "All Users", "desktop.ini"}
	for _, s := range system {
		if strings.EqualFold(username, s) {
			return true
		}
	}
	return false
}

type chromiumHistoryRow struct {
	URL           string `json:"url"`
	Title         string `json:"title"`
	VisitCount    int    `json:"visit_count"`
	LastVisitTime int64  `json:"last_visit_time"`
}

// collectChromiumHistory reads Chrome/Edge history using PowerShell + file copy + ADO.NET
func (c *BrowserHistoryCollector) collectChromiumHistory(browser, dbPath, username string) []types.BrowserHistoryEntry {
	// Copy DB to temp because browser may lock it
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("ferret_%s_history_%s.db", strings.ToLower(browser), username))
	defer os.Remove(tempCopy)

	// Use robocopy for byte-level copy (handles locks better than Go copy)
	srcDir := filepath.Dir(dbPath)
	srcFile := filepath.Base(dbPath)
	copyPSScript := fmt.Sprintf(`Copy-Item -Path '%s' -Destination '%s' -Force -ErrorAction SilentlyContinue`,
		strings.ReplaceAll(dbPath, "'", "''"), strings.ReplaceAll(tempCopy, "'", "''"))
	runPowerShell(copyPSScript)

	// Verify copy exists
	if _, err := os.Stat(tempCopy); err != nil {
		logger.Debug("Cannot copy %s history DB for user %s (dir: %s, file: %s)", browser, username, srcDir, srcFile)
		return nil
	}

	// Query using PowerShell with System.Data.SQLite or ADO.NET
	// Windows 10+ ships with System.Data.SQLite support via .NET
	psScript := fmt.Sprintf(`
$dbPath = '%s'
try {
    Add-Type -Path "$env:ProgramFiles\System.Data.SQLite\bin\System.Data.SQLite.dll" -ErrorAction SilentlyContinue
} catch {}

$results = @()
try {
    $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath;Read Only=True")
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000"
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) {
        $results += @{
            url = $reader["url"]
            title = $reader["title"]
            visit_count = [int]$reader["visit_count"]
            last_visit_time = [long]$reader["last_visit_time"]
        }
    }
    $conn.Close()
} catch {
    # Fallback: use sqlite3.exe if available
    $sqlite3 = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if ($sqlite3) {
        $output = & sqlite3.exe $dbPath "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000" -csv 2>$null
        # Parse CSV output... too complex for inline
    }
}
$results | ConvertTo-Json -Compress
`, strings.ReplaceAll(tempCopy, "'", "''"))

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		// Fallback: try direct sqlite3.exe
		return c.tryDirectSqlite(tempCopy, browser, username, true)
	}

	var rows []chromiumHistoryRow
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rows); err != nil {
			logger.Debug("Failed to parse %s history JSON: %v", browser, err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single chromiumHistoryRow
		if json.Unmarshal([]byte(output), &single) == nil {
			rows = append(rows, single)
		}
	}

	if len(rows) == 0 {
		return c.tryDirectSqlite(tempCopy, browser, username, true)
	}

	var entries []types.BrowserHistoryEntry
	for _, row := range rows {
		// Chromium last_visit_time is microseconds since Jan 1, 1601 (Windows FILETIME / 10)
		var lastVisited time.Time
		if row.LastVisitTime > 0 {
			// Convert Chromium timestamp to Unix
			const chromiumEpochDiff = 11644473600 // seconds between 1601 and 1970
			unixSeconds := (row.LastVisitTime / 1000000) - chromiumEpochDiff
			if unixSeconds > 0 {
				lastVisited = time.Unix(unixSeconds, 0)
			}
		}

		entries = append(entries, types.BrowserHistoryEntry{
			Browser:    browser,
			URL:        row.URL,
			Title:      row.Title,
			VisitCount: row.VisitCount,
			LastVisited: lastVisited,
			User:       username,
		})
	}

	return entries
}

func (c *BrowserHistoryCollector) collectFirefoxHistory(dbPath, username string) []types.BrowserHistoryEntry {
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("ferret_firefox_history_%s.db", username))
	defer os.Remove(tempCopy)

	copyPSScript := fmt.Sprintf(`Copy-Item -Path '%s' -Destination '%s' -Force -ErrorAction SilentlyContinue`,
		strings.ReplaceAll(dbPath, "'", "''"), strings.ReplaceAll(tempCopy, "'", "''"))
	runPowerShell(copyPSScript)

	if _, err := os.Stat(tempCopy); err != nil {
		return nil
	}

	return c.tryDirectSqlite(tempCopy, "Firefox", username, false)
}

// tryDirectSqlite attempts to use sqlite3.exe command-line tool
func (c *BrowserHistoryCollector) tryDirectSqlite(dbPath, browser, username string, isChromium bool) []types.BrowserHistoryEntry {
	// Try to find sqlite3.exe
	sqlite3Path, err := exec.LookPath("sqlite3.exe")
	if err != nil {
		// Also try common locations
		candidates := []string{
			`C:\ProgramData\chocolatey\bin\sqlite3.exe`,
			`C:\Tools\sqlite3.exe`,
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				sqlite3Path = candidate
				break
			}
		}
	}

	if sqlite3Path == "" {
		logger.Debug("sqlite3.exe not found, skipping %s history for %s", browser, username)
		return nil
	}

	var query string
	if isChromium {
		query = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000;"
	} else {
		query = "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1000;"
	}

	cmd := exec.Command(sqlite3Path, dbPath, "-json", query)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	type sqliteRow struct {
		URL           string `json:"url"`
		Title         string `json:"title"`
		VisitCount    int    `json:"visit_count"`
		LastVisitTime int64  `json:"last_visit_time,omitempty"`
		LastVisitDate int64  `json:"last_visit_date,omitempty"`
	}

	var rows []sqliteRow
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil
	}

	var entries []types.BrowserHistoryEntry
	for _, row := range rows {
		var lastVisited time.Time

		if isChromium && row.LastVisitTime > 0 {
			const chromiumEpochDiff = 11644473600
			unixSeconds := (row.LastVisitTime / 1000000) - chromiumEpochDiff
			if unixSeconds > 0 {
				lastVisited = time.Unix(unixSeconds, 0)
			}
		} else if !isChromium && row.LastVisitDate > 0 {
			// Firefox uses microseconds since Unix epoch
			lastVisited = time.Unix(row.LastVisitDate/1000000, 0)
		}

		entries = append(entries, types.BrowserHistoryEntry{
			Browser:    browser,
			URL:        row.URL,
			Title:      row.Title,
			VisitCount: row.VisitCount,
			LastVisited: lastVisited,
			User:       username,
		})
	}

	return entries
}

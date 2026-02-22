package collector

import (
	"database/sql"
	"os"
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

		// Chrome/Edge (Chromium-based)
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

// collectChromiumHistory reads Chrome/Edge history using native Go SQLite
func (c *BrowserHistoryCollector) collectChromiumHistory(browser, dbPath, username string) []types.BrowserHistoryEntry {
	prefix := strings.ToLower(browser) + "_history_" + username
	tempCopy, cleanup, err := copyFileSafe(dbPath, prefix)
	defer cleanup()
	if err != nil {
		logger.Debug("Cannot copy %s history DB for user %s: %v", browser, username, err)
		return nil
	}

	db, err := openSQLiteReadOnly(tempCopy)
	if err != nil {
		logger.Debug("Cannot open %s history DB: %v", browser, err)
		return nil
	}
	defer db.Close()

	var entries []types.BrowserHistoryEntry
	query := "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000"

	querySQLiteRows(db, query, func(rows *sql.Rows) error {
		var url, title string
		var visitCount int
		var lastVisitTime int64
		if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime); err != nil {
			return err
		}

		var lastVisited time.Time
		if lastVisitTime > 0 {
			// Chromium timestamp: microseconds since 1601-01-01
			const chromiumEpochDiff = 11644473600
			unixSeconds := (lastVisitTime / 1000000) - chromiumEpochDiff
			if unixSeconds > 0 {
				lastVisited = time.Unix(unixSeconds, 0)
			}
		}

		entries = append(entries, types.BrowserHistoryEntry{
			Browser:     browser,
			URL:         url,
			Title:       title,
			VisitCount:  visitCount,
			LastVisited: lastVisited,
			User:        username,
		})
		return nil
	})

	return entries
}

// collectFirefoxHistory reads Firefox history using native Go SQLite
func (c *BrowserHistoryCollector) collectFirefoxHistory(dbPath, username string) []types.BrowserHistoryEntry {
	tempCopy, cleanup, err := copyFileSafe(dbPath, "firefox_history_"+username)
	defer cleanup()
	if err != nil {
		return nil
	}

	db, err := openSQLiteReadOnly(tempCopy)
	if err != nil {
		return nil
	}
	defer db.Close()

	var entries []types.BrowserHistoryEntry
	query := "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1000"

	querySQLiteRows(db, query, func(rows *sql.Rows) error {
		var url string
		var title sql.NullString
		var visitCount int
		var lastVisitDate sql.NullInt64
		if err := rows.Scan(&url, &title, &visitCount, &lastVisitDate); err != nil {
			return err
		}

		var lastVisited time.Time
		if lastVisitDate.Valid && lastVisitDate.Int64 > 0 {
			// Firefox: microseconds since Unix epoch
			lastVisited = time.Unix(lastVisitDate.Int64/1000000, 0)
		}

		entries = append(entries, types.BrowserHistoryEntry{
			Browser:     "Firefox",
			URL:         url,
			Title:       title.String,
			VisitCount:  visitCount,
			LastVisited: lastVisited,
			User:        username,
		})
		return nil
	})

	return entries
}

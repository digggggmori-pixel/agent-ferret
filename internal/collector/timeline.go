package collector

import (
	"database/sql"
	"os"
	"path/filepath"
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
	tempCopy, cleanup, err := copyFileSafe(dbPath, "timeline_"+username)
	defer cleanup()
	if err != nil {
		return nil
	}

	db, err := openSQLiteReadOnly(tempCopy)
	if err != nil {
		return nil
	}
	defer db.Close()

	var entries []types.TimelineEntry
	query := "SELECT AppId, ActivityType, StartTime, EndTime, Payload FROM Activity ORDER BY StartTime DESC LIMIT 500"

	querySQLiteRows(db, query, func(rows *sql.Rows) error {
		var appID string
		var activityType sql.NullString
		var startTimeUnix, endTimeUnix sql.NullInt64
		var payload sql.NullString
		if err := rows.Scan(&appID, &activityType, &startTimeUnix, &endTimeUnix, &payload); err != nil {
			return err
		}

		var st, et time.Time
		if startTimeUnix.Valid && startTimeUnix.Int64 > 0 {
			st = time.Unix(startTimeUnix.Int64, 0)
		}
		if endTimeUnix.Valid && endTimeUnix.Int64 > 0 {
			et = time.Unix(endTimeUnix.Int64, 0)
		}

		entries = append(entries, types.TimelineEntry{
			AppID:     appID,
			Activity:  activityType.String,
			StartTime: st,
			EndTime:   et,
			Payload:   payload.String,
			User:      username,
		})
		return nil
	})

	return entries
}

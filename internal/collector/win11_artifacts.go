package collector

import (
	"database/sql"
	"os"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// Win11ArtifactsCollector collects Windows 11 specific artifacts
// (PcaAppLaunchDic, EventTranscript.db)
type Win11ArtifactsCollector struct{}

// NewWin11ArtifactsCollector creates a new Win11 artifacts collector
func NewWin11ArtifactsCollector() *Win11ArtifactsCollector {
	return &Win11ArtifactsCollector{}
}

// Collect reads Windows 11 specific execution artifacts
func (c *Win11ArtifactsCollector) Collect() ([]types.Win11ArtifactEntry, error) {
	logger.Section("Win11 Artifacts Collection")
	startTime := time.Now()

	var entries []types.Win11ArtifactEntry

	// PcaAppLaunchDic - Program Compatibility Assistant app launch dictionary
	// Available on Windows 11 (Build 22000+)
	pcaEntries := c.collectPCA()
	entries = append(entries, pcaEntries...)

	// EventTranscript.db - Diagnostic data
	etEntries := c.collectEventTranscript()
	entries = append(entries, etEntries...)

	logger.Timing("Win11ArtifactsCollector.Collect", startTime)
	logger.Info("Win11 artifacts: %d entries collected", len(entries))

	return entries, nil
}

// collectPCA reads PcaAppLaunchDic from registry
func (c *Win11ArtifactsCollector) collectPCA() []types.Win11ArtifactEntry {
	var entries []types.Win11ArtifactEntry

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store`,
		registry.READ)
	if err != nil {
		return entries
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return entries
	}

	for _, valueName := range valueNames {
		// Skip non-path entries
		if !strings.Contains(valueName, `\`) {
			continue
		}

		entries = append(entries, types.Win11ArtifactEntry{
			Path:   valueName,
			Source: "pca",
		})

		if len(entries) >= 1000 {
			break
		}
	}

	return entries
}

// collectEventTranscript reads from EventTranscript.db using native Go SQLite
func (c *Win11ArtifactsCollector) collectEventTranscript() []types.Win11ArtifactEntry {
	var entries []types.Win11ArtifactEntry

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	dbPath := programData + `\Microsoft\Diagnosis\EventTranscript\EventTranscript.db`

	if _, err := os.Stat(dbPath); err != nil {
		return entries
	}

	tempCopy, cleanup, err := copyFileSafe(dbPath, "event_transcript")
	defer cleanup()
	if err != nil {
		return entries
	}

	db, err := openSQLiteReadOnly(tempCopy)
	if err != nil {
		return entries
	}
	defer db.Close()

	query := "SELECT json_extract(payload, '$.data.app') as AppName, timestamp FROM events WHERE json_extract(payload, '$.data.app') IS NOT NULL ORDER BY timestamp DESC LIMIT 500"

	querySQLiteRows(db, query, func(rows *sql.Rows) error {
		var appName sql.NullString
		var timestamp sql.NullString
		if err := rows.Scan(&appName, &timestamp); err != nil {
			return err
		}

		var ts time.Time
		if timestamp.Valid {
			ts, _ = time.Parse(time.RFC3339, timestamp.String)
		}

		entries = append(entries, types.Win11ArtifactEntry{
			Path:          appName.String,
			LastExecution: ts,
			Source:        "event_transcript",
		})
		return nil
	})

	return entries
}

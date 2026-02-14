package collector

import (
	"encoding/json"
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
func (c *Win11ArtifactsCollector) Collect() ([]types.BAMEntry, error) {
	logger.Section("Win11 Artifacts Collection")
	startTime := time.Now()

	var entries []types.BAMEntry

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
func (c *Win11ArtifactsCollector) collectPCA() []types.BAMEntry {
	var entries []types.BAMEntry

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

		entries = append(entries, types.BAMEntry{
			Path:          valueName,
			LastExecution: time.Time{}, // PCA doesn't store timestamps in the same way
			User:          "",
		})

		if len(entries) >= 1000 {
			break
		}
	}

	return entries
}

// collectEventTranscript reads from EventTranscript.db if accessible
func (c *Win11ArtifactsCollector) collectEventTranscript() []types.BAMEntry {
	var entries []types.BAMEntry

	// EventTranscript.db is typically at:
	// C:\ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db
	// It requires admin access

	psScript := `
$results = @()
$dbPath = "$env:ProgramData\Microsoft\Diagnosis\EventTranscript\EventTranscript.db"
if (Test-Path $dbPath) {
    $tempCopy = "$env:TEMP\ferret_event_transcript.db"
    Copy-Item $dbPath $tempCopy -Force -ErrorAction SilentlyContinue
    if (Test-Path $tempCopy) {
        $sqlite3 = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
        if ($sqlite3) {
            $query = "SELECT json_extract(payload, '$.data.app') as AppName, timestamp FROM events WHERE json_extract(payload, '$.data.app') IS NOT NULL ORDER BY timestamp DESC LIMIT 500;"
            $output = & sqlite3.exe $tempCopy -json $query 2>$null
            if ($output) {
                try { $results = $output | ConvertFrom-Json } catch {}
            }
        }
        Remove-Item $tempCopy -Force -ErrorAction SilentlyContinue
    }
}
$results | ConvertTo-Json -Compress
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		return entries
	}

	type etEntry struct {
		AppName   string `json:"AppName"`
		Timestamp string `json:"timestamp"`
	}

	var rawEntries []etEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse EventTranscript JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single etEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		ts, _ := time.Parse(time.RFC3339, raw.Timestamp)
		entries = append(entries, types.BAMEntry{
			Path:          raw.AppName,
			LastExecution: ts,
		})
	}

	return entries
}

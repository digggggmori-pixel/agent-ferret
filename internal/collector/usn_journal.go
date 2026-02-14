package collector

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// USNJournalCollector reads the USN Change Journal for file change history
type USNJournalCollector struct{}

// NewUSNJournalCollector creates a new USN Journal collector
func NewUSNJournalCollector() *USNJournalCollector {
	return &USNJournalCollector{}
}

type usnPSEntry struct {
	FileName  string `json:"FileName"`
	Reason    string `json:"Reason"`
	TimeStamp string `json:"TimeStamp"`
	FileRef   uint64 `json:"FileReferenceNumber"`
	ParentRef uint64 `json:"ParentFileReferenceNumber"`
	USN       int64  `json:"Usn"`
}

// Collect reads recent USN Journal entries using fsutil
func (c *USNJournalCollector) Collect() ([]types.USNJournalEntry, error) {
	logger.Section("USN Journal Collection")
	startTime := time.Now()

	var entries []types.USNJournalEntry

	// Use PowerShell with fsutil to read USN journal
	// fsutil usn readjournal requires admin, so we try PowerShell approach
	psScript := `
$results = @()
try {
    # Query USN journal info first
    $journalInfo = fsutil usn queryjournal C: 2>$null
    if (-not $journalInfo) { return }

    # Read recent USN records (last 10000 records, focused on creates/deletes/renames)
    $output = fsutil usn enumdata 1 0 1 C: 2>$null
    if ($output) {
        $count = 0
        foreach ($line in $output) {
            if ($line -match 'File Ref#\s*:\s*(.+)') {
                $currentRef = $Matches[1].Trim()
            }
            if ($line -match 'Parent File Ref#\s*:\s*(.+)') {
                $currentParent = $Matches[1].Trim()
            }
            if ($line -match 'Usn\s*:\s*(\d+)') {
                $currentUsn = [long]$Matches[1]
            }
            if ($line -match 'File Name\s*:\s*(.+)') {
                $currentFileName = $Matches[1].Trim()
            }
            if ($line -match 'Reason\s*:\s*(.+)') {
                $currentReason = $Matches[1].Trim()
            }
            if ($line -match 'Time Stamp\s*:\s*(.+)') {
                $ts = $Matches[1].Trim()
                $results += @{
                    FileName = $currentFileName
                    Reason = $currentReason
                    TimeStamp = $ts
                    Usn = $currentUsn
                }
                $count++
                if ($count -ge 5000) { break }
            }
        }
    }
} catch {}
$results | ConvertTo-Json -Compress
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		logger.Debug("Cannot read USN journal (admin required)")
		return entries, nil
	}

	var rawEntries []usnPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse USN journal JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single usnPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		ts, _ := time.Parse("2006/01/02 15:04:05", raw.TimeStamp)
		if ts.IsZero() {
			ts, _ = time.Parse(time.RFC3339, raw.TimeStamp)
		}

		entries = append(entries, types.USNJournalEntry{
			USN:       raw.USN,
			FileName:  raw.FileName,
			Reason:    raw.Reason,
			Timestamp: ts,
			FileRef:   raw.FileRef,
			ParentRef: raw.ParentRef,
		})
	}

	logger.Timing("USNJournalCollector.Collect", startTime)
	logger.Info("USN Journal: %d entries collected", len(entries))

	return entries, nil
}

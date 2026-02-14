package collector

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// BITSCollector collects Background Intelligent Transfer Service jobs
type BITSCollector struct{}

// NewBITSCollector creates a new BITS collector
func NewBITSCollector() *BITSCollector {
	return &BITSCollector{}
}

type bitsPSEntry struct {
	JobID       string `json:"JobId"`
	DisplayName string `json:"DisplayName"`
	JobType     string `json:"TransferType"`
	JobState    string `json:"JobState"`
	Owner       string `json:"OwnerAccount"`
	URL         string `json:"RemoteName"`
	LocalFile   string `json:"LocalName"`
	BytesTotal  int64  `json:"BytesTotal"`
	CreatedAt   string `json:"CreationTime"`
}

// Collect retrieves BITS transfer jobs using PowerShell
func (c *BITSCollector) Collect() ([]types.BITSJobInfo, error) {
	logger.Section("BITS Job Collection")
	startTime := time.Now()

	var entries []types.BITSJobInfo

	psScript := `
$results = @()
try {
    Import-Module BitsTransfer -ErrorAction SilentlyContinue
    $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    if (-not $jobs) {
        $jobs = Get-BitsTransfer -ErrorAction SilentlyContinue
    }
    foreach ($job in $jobs) {
        $files = $job | Get-BitsTransfer -ErrorAction SilentlyContinue
        $url = ""
        $local = ""
        if ($job.FileList -and $job.FileList.Count -gt 0) {
            $url = $job.FileList[0].RemoteName
            $local = $job.FileList[0].LocalName
        }
        $results += @{
            JobId = [string]$job.JobId
            DisplayName = $job.DisplayName
            TransferType = [string]$job.TransferType
            JobState = [string]$job.JobState
            OwnerAccount = $job.OwnerAccount
            RemoteName = $url
            LocalName = $local
            BytesTotal = $job.BytesTotal
            CreationTime = $job.CreationTime.ToString('o')
        }
    }
} catch {}
$results | ConvertTo-Json -Compress -Depth 2
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		logger.Debug("Cannot collect BITS jobs: %v", err)
		return entries, nil
	}

	var rawEntries []bitsPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse BITS JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single bitsPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		createdAt, _ := time.Parse(time.RFC3339, raw.CreatedAt)

		entries = append(entries, types.BITSJobInfo{
			JobID:       raw.JobID,
			DisplayName: raw.DisplayName,
			JobType:     raw.JobType,
			State:       raw.JobState,
			Owner:       raw.Owner,
			URL:         raw.URL,
			LocalFile:   raw.LocalFile,
			BytesTotal:  raw.BytesTotal,
			CreatedAt:   createdAt,
		})
	}

	logger.Timing("BITSCollector.Collect", startTime)
	logger.Info("BITS: %d jobs collected", len(entries))

	return entries, nil
}

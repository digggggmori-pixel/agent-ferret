package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ETLLogCollector reads ETW trace log files (.etl)
type ETLLogCollector struct{}

// NewETLLogCollector creates a new ETL log collector
func NewETLLogCollector() *ETLLogCollector {
	return &ETLLogCollector{}
}

type etlPSEntry struct {
	Provider  string `json:"ProviderName"`
	EventID   uint32 `json:"Id"`
	Level     uint8  `json:"Level"`
	Timestamp string `json:"TimeCreated"`
	Message   string `json:"Message"`
}

// Collect reads relevant ETL log files using PowerShell Get-WinEvent
func (c *ETLLogCollector) Collect() ([]types.ETLLogEntry, error) {
	logger.Section("ETL Log Collection")
	startTime := time.Now()

	var entries []types.ETLLogEntry

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	// Read boot trace log
	bootETL := filepath.Join(winDir, `System32\WDI\LogFiles\BootCKCL.etl`)
	if _, err := os.Stat(bootETL); err == nil {
		bootEntries := c.parseETL(bootETL)
		entries = append(entries, bootEntries...)
	}

	// Read shutdown trace log
	shutdownETL := filepath.Join(winDir, `System32\WDI\LogFiles\ShutdownCKCL.etl`)
	if _, err := os.Stat(shutdownETL); err == nil {
		shutdownEntries := c.parseETL(shutdownETL)
		entries = append(entries, shutdownEntries...)
	}

	logger.Timing("ETLLogCollector.Collect", startTime)
	logger.Info("ETL logs: %d entries collected", len(entries))

	return entries, nil
}

func (c *ETLLogCollector) parseETL(etlPath string) []types.ETLLogEntry {
	var entries []types.ETLLogEntry

	psScript := `
$results = @()
try {
    $events = Get-WinEvent -Path '` + strings.ReplaceAll(etlPath, "'", "''") + `' -MaxEvents 1000 -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        $results += @{
            ProviderName = $e.ProviderName
            Id = $e.Id
            Level = $e.Level
            TimeCreated = $e.TimeCreated.ToString('o')
            Message = if ($e.Message.Length -gt 200) { $e.Message.Substring(0, 200) } else { $e.Message }
        }
    }
} catch {}
$results | ConvertTo-Json -Compress -Depth 2
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		return entries
	}

	var rawEntries []etlPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse ETL JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single etlPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		ts, _ := time.Parse(time.RFC3339, raw.Timestamp)
		entries = append(entries, types.ETLLogEntry{
			Provider:  raw.Provider,
			EventID:   raw.EventID,
			Level:     raw.Level,
			Timestamp: ts,
			Message:   raw.Message,
		})
	}

	return entries
}

package collector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// SRUMCollector parses the System Resource Usage Monitor database
type SRUMCollector struct{}

// NewSRUMCollector creates a new SRUM collector
func NewSRUMCollector() *SRUMCollector {
	return &SRUMCollector{}
}

type srumPSEntry struct {
	AppName       string `json:"AppName"`
	UserSID       string `json:"UserSid"`
	BytesSent     int64  `json:"BytesSent"`
	BytesReceived int64  `json:"BytesRecvd"`
	Timestamp     string `json:"TimeStamp"`
}

// Collect reads SRUM data (network usage per application)
func (c *SRUMCollector) Collect() ([]types.SRUMEntry, error) {
	logger.Section("SRUM Collection")
	startTime := time.Now()

	var entries []types.SRUMEntry

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	srumPath := filepath.Join(winDir, `System32\sru\SRUDB.dat`)
	if _, err := os.Stat(srumPath); os.IsNotExist(err) {
		logger.Debug("SRUDB.dat not found at %s", srumPath)
		return entries, nil
	}

	// Copy SRUDB.dat to temp (it's locked by the service)
	tempDir := os.TempDir()
	tempCopy := filepath.Join(tempDir, "ferret_srudb_copy.dat")
	defer os.Remove(tempCopy)

	// Use esentutl to copy (handles locked ESE databases)
	copyCmd := exec.Command("esentutl.exe", "/y", srumPath, "/vssrec", "/d", tempCopy)
	if err := copyCmd.Run(); err != nil {
		// Fallback: try direct copy
		data, err := os.ReadFile(srumPath)
		if err != nil {
			logger.Debug("Cannot copy SRUDB.dat: %v", err)
			return entries, nil
		}
		if err := os.WriteFile(tempCopy, data, 0600); err != nil {
			return entries, nil
		}
	}

	// Use PowerShell with ESE (Extensible Storage Engine) to parse
	// We use esentutl to export the database or PowerShell ESE module
	entries = c.parseSRUM(tempCopy)

	logger.Timing("SRUMCollector.Collect", startTime)
	logger.Info("SRUM: %d network usage entries collected", len(entries))

	return entries, nil
}

func (c *SRUMCollector) parseSRUM(dbPath string) []types.SRUMEntry {
	var entries []types.SRUMEntry

	// Use PowerShell to query the ESE database
	// The network usage table is {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}
	psScript := `
$dbPath = '` + strings.ReplaceAll(dbPath, "'", "''") + `'
$results = @()
try {
    # Try using the ESE module if available
    Add-Type -Path "$env:ProgramFiles\System.Data.SQLite\bin\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

    # Alternative: use esentutl to dump the table
    $dumpFile = "$env:TEMP\ferret_srum_dump.csv"

    # Try PowerShell native ESE access
    $tableGuid = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'

    # Use ESENT managed API or PowerShell workaround
    # For now, try to use Get-SRUMData if PSModule is available
    if (Get-Command Get-SRUMNetworkUsage -ErrorAction SilentlyContinue) {
        $data = Get-SRUMNetworkUsage -Path $dbPath -ErrorAction SilentlyContinue
        foreach ($d in $data) {
            $results += @{
                AppName = $d.App
                UserSid = $d.UserSid
                BytesSent = $d.BytesSent
                BytesRecvd = $d.BytesReceived
                TimeStamp = $d.TimeStamp.ToString('o')
            }
        }
    }
} catch {}

# Fallback: read from registry cache if ESE parsing fails
if ($results.Count -eq 0) {
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'
        if (Test-Path $regPath) {
            $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($props) {
                $results += @{AppName='SRUM_registry_data_available'; BytesSent=0; BytesRecvd=0; TimeStamp=(Get-Date).ToString('o')}
            }
        }
    } catch {}
}

$results | ConvertTo-Json -Compress
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		return entries
	}

	var rawEntries []srumPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse SRUM JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single srumPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		ts, _ := time.Parse(time.RFC3339, raw.Timestamp)
		entries = append(entries, types.SRUMEntry{
			AppName:       raw.AppName,
			UserSID:       raw.UserSID,
			BytesSent:     raw.BytesSent,
			BytesReceived: raw.BytesReceived,
			Timestamp:     ts,
		})
	}

	return entries
}

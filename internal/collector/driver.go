package collector

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// DriverCollector enumerates loaded kernel drivers
type DriverCollector struct{}

// NewDriverCollector creates a new driver collector
func NewDriverCollector() *DriverCollector {
	return &DriverCollector{}
}

type driverPSEntry struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	PathName    string `json:"PathName"`
	State       string `json:"State"`
	StartMode   string `json:"StartMode"`
	IsSigned    bool   `json:"IsSigned"`
	Signer      string `json:"Signer"`
	Description string `json:"Description"`
}

// Collect enumerates kernel drivers using PowerShell/WMI
func (c *DriverCollector) Collect() ([]types.DriverInfo, error) {
	logger.Section("Driver Collection")
	startTime := time.Now()

	var entries []types.DriverInfo

	// Use PowerShell to query Win32_SystemDriver + signature check
	psScript := `
$drivers = Get-WmiObject Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode, Description
$results = @()
foreach ($d in $drivers) {
    $signed = $false
    $signer = ""
    if ($d.PathName) {
        $path = $d.PathName
        # Normalize path (remove \SystemRoot\ prefix)
        if ($path -like '\SystemRoot\*') {
            $path = $path -replace '\\SystemRoot\\', "$env:SystemRoot\"
        }
        if ($path -like '\??\*') {
            $path = $path.Substring(4)
        }
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -eq 'Valid') {
                $signed = $true
                if ($sig.SignerCertificate) {
                    $signer = $sig.SignerCertificate.Subject
                }
            }
        }
    }
    $results += @{
        Name = $d.Name
        DisplayName = $d.DisplayName
        PathName = $d.PathName
        State = $d.State
        StartMode = $d.StartMode
        IsSigned = $signed
        Signer = $signer
        Description = $d.Description
    }
}
$results | ConvertTo-Json -Compress -Depth 2
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		// Fallback: simpler query without signature check
		entries = c.fallbackCollect()
		logger.Timing("DriverCollector.Collect", startTime)
		logger.Info("Drivers: %d entries (fallback)", len(entries))
		return entries, nil
	}

	var rawEntries []driverPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse driver JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single driverPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		entries = append(entries, types.DriverInfo{
			Name:        raw.Name,
			DisplayName: raw.DisplayName,
			Path:        raw.PathName,
			State:       raw.State,
			StartMode:   raw.StartMode,
			IsSigned:    raw.IsSigned,
			Signer:      raw.Signer,
			Description: raw.Description,
		})
	}

	logger.Timing("DriverCollector.Collect", startTime)
	logger.Info("Drivers: %d entries collected", len(entries))

	return entries, nil
}

func (c *DriverCollector) fallbackCollect() []types.DriverInfo {
	psScript := `
Get-WmiObject Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode, Description |
    ForEach-Object { @{Name=$_.Name; DisplayName=$_.DisplayName; PathName=$_.PathName; State=$_.State; StartMode=$_.StartMode; Description=$_.Description} } |
    ConvertTo-Json -Compress
`
	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}

	var rawEntries []driverPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse driver fallback JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single driverPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	var entries []types.DriverInfo
	for _, raw := range rawEntries {
		entries = append(entries, types.DriverInfo{
			Name:        raw.Name,
			DisplayName: raw.DisplayName,
			Path:        raw.PathName,
			State:       raw.State,
			StartMode:   raw.StartMode,
			Description: raw.Description,
		})
	}

	return entries
}

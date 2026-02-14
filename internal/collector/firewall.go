package collector

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// FirewallCollector collects Windows Firewall rules
type FirewallCollector struct{}

// NewFirewallCollector creates a new firewall collector
func NewFirewallCollector() *FirewallCollector {
	return &FirewallCollector{}
}

type firewallPSEntry struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Direction   string `json:"Direction"`
	Action      string `json:"Action"`
	Enabled     string `json:"Enabled"`
	Profile     string `json:"Profile"`
	Program     string `json:"Program"`
	LocalPort   string `json:"LocalPort"`
	RemoteAddr  string `json:"RemoteAddress"`
	RemotePort  string `json:"RemotePort"`
	Protocol    string `json:"Protocol"`
}

// Collect retrieves Windows Firewall rules using PowerShell
func (c *FirewallCollector) Collect() ([]types.FirewallRuleInfo, error) {
	logger.Section("Firewall Collection")
	startTime := time.Now()

	var entries []types.FirewallRuleInfo

	// Also check if firewall is enabled
	statusScript := `
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$profiles | ForEach-Object { @{Name=$_.Name; Enabled=$_.Enabled} } | ConvertTo-Json -Compress
`
	statusOutput, _ := runPowerShell(statusScript)
	if statusOutput != "" {
		logger.Debug("Firewall profile status: %s", strings.TrimSpace(statusOutput))
	}

	// Get all Allow rules (inbound) that are enabled - these are security-relevant
	psScript := `
$rules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
    Select-Object -First 500 Name, DisplayName, Direction, Action, Enabled, Profile
$results = @()
foreach ($r in $rules) {
    $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $addrFilter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    $appFilter = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $results += @{
        Name = $r.Name
        DisplayName = $r.DisplayName
        Direction = [string]$r.Direction
        Action = [string]$r.Action
        Enabled = [string]$r.Enabled
        Profile = [string]$r.Profile
        Program = if ($appFilter) { $appFilter.Program } else { "" }
        LocalPort = if ($portFilter) { [string]$portFilter.LocalPort } else { "" }
        RemoteAddress = if ($addrFilter) { [string]$addrFilter.RemoteAddress } else { "" }
        RemotePort = if ($portFilter) { [string]$portFilter.RemotePort } else { "" }
        Protocol = if ($portFilter) { [string]$portFilter.Protocol } else { "" }
    }
}
$results | ConvertTo-Json -Compress -Depth 2
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		logger.Debug("Cannot collect firewall rules: %v", err)
		return entries, nil
	}

	var rawEntries []firewallPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse firewall JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single firewallPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	for _, raw := range rawEntries {
		entries = append(entries, types.FirewallRuleInfo{
			Name:        raw.Name,
			DisplayName: raw.DisplayName,
			Direction:   raw.Direction,
			Action:      raw.Action,
			Enabled:     raw.Enabled == "True" || raw.Enabled == "1",
			Profile:     raw.Profile,
			Program:     raw.Program,
			LocalPort:   raw.LocalPort,
			RemoteAddr:  raw.RemoteAddr,
			RemotePort:  raw.RemotePort,
			Protocol:    raw.Protocol,
		})
	}

	logger.Timing("FirewallCollector.Collect", startTime)
	logger.Info("Firewall: %d inbound allow rules collected", len(entries))

	return entries, nil
}

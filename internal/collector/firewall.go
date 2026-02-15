package collector

import (
	"os/exec"
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

// Collect retrieves Windows Firewall rules using netsh.exe (native Windows binary)
func (c *FirewallCollector) Collect() ([]types.FirewallRuleInfo, error) {
	logger.Section("Firewall Collection")
	startTime := time.Now()

	var entries []types.FirewallRuleInfo

	// Check firewall status using netsh
	statusCmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state")
	statusOutput, _ := statusCmd.Output()
	if len(statusOutput) > 0 {
		logger.Debug("Firewall status: %s", strings.TrimSpace(string(statusOutput)))
	}

	// Get enabled inbound rules using netsh (native Windows binary, no PS)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule",
		"name=all", "dir=in", "status=enable", "type=static")
	output, err := cmd.Output()
	if err != nil {
		logger.Debug("Cannot collect firewall rules: %v", err)
		return entries, nil
	}

	entries = c.parseNetshOutput(string(output))

	logger.Timing("FirewallCollector.Collect", startTime)
	logger.Info("Firewall: %d inbound allow rules collected", len(entries))

	return entries, nil
}

// parseNetshOutput parses the text output from "netsh advfirewall firewall show rule"
func (c *FirewallCollector) parseNetshOutput(output string) []types.FirewallRuleInfo {
	var entries []types.FirewallRuleInfo
	var current *types.FirewallRuleInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip separator lines
		if strings.HasPrefix(line, "---") || line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Normalize key names (netsh output language may vary by locale)
		keyLower := strings.ToLower(key)

		if strings.Contains(keyLower, "rule name") {
			// Save previous rule if it was an Allow rule
			if current != nil && current.Action == "Allow" {
				entries = append(entries, *current)
			}
			current = &types.FirewallRuleInfo{
				DisplayName: value,
				Name:        value,
				Direction:   "Inbound",
			}
			continue
		}

		if current == nil {
			continue
		}

		switch {
		case strings.Contains(keyLower, "enabled"):
			current.Enabled = strings.EqualFold(value, "Yes") || strings.EqualFold(value, "True")
		case strings.Contains(keyLower, "direction"):
			current.Direction = value
		case strings.Contains(keyLower, "profiles") || strings.Contains(keyLower, "profile"):
			current.Profile = value
		case strings.Contains(keyLower, "localport") || strings.Contains(keyLower, "local port"):
			current.LocalPort = value
		case strings.Contains(keyLower, "remoteport") || strings.Contains(keyLower, "remote port"):
			current.RemotePort = value
		case strings.Contains(keyLower, "remoteip") || strings.Contains(keyLower, "remote address"):
			current.RemoteAddr = value
		case strings.Contains(keyLower, "protocol"):
			current.Protocol = value
		case strings.Contains(keyLower, "program"):
			current.Program = value
		case strings.Contains(keyLower, "action"):
			current.Action = value
		}
	}

	// Add last entry
	if current != nil && current.Action == "Allow" {
		entries = append(entries, *current)
	}

	// Limit to 500 entries
	if len(entries) > 500 {
		entries = entries[:500]
	}

	return entries
}

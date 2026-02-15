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
		logger.Debug("Firewall status: %s", strings.TrimSpace(decodeOEMOutput(statusOutput)))
	}

	// Get ALL rules without locale-dependent filters (name=all is the only safe param)
	// Filtering by dir/status/type fails on non-English Windows because param values are localized
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	output, err := cmd.Output()
	if err != nil {
		logger.Debug("Cannot collect firewall rules: %v", err)
		return entries, nil
	}

	// Decode from OEM codepage (e.g. CP949 on Korean Windows) to UTF-8
	outputStr := decodeOEMOutput(output)
	// Log first 500 chars to help diagnose locale parsing issues
	peek := outputStr
	if len(peek) > 500 {
		peek = peek[:500]
	}
	logger.Debug("Firewall rules output (first 500 chars): %s", peek)

	entries = c.parseNetshOutput(outputStr)

	logger.Timing("FirewallCollector.Collect", startTime)
	logger.Info("Firewall: %d inbound allow rules collected", len(entries))

	return entries, nil
}

// parseNetshOutput parses the text output from "netsh advfirewall firewall show rule"
// Supports both English and Korean locale field names.
func (c *FirewallCollector) parseNetshOutput(output string) []types.FirewallRuleInfo {
	var entries []types.FirewallRuleInfo
	var current *types.FirewallRuleInfo
	totalRules := 0

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

		keyLower := strings.ToLower(key)

		// Detect rule boundary: "Rule Name" (EN) or "규칙 이름" (KO)
		if strings.Contains(keyLower, "rule name") || strings.Contains(key, "규칙") {
			// Save previous rule if it passes filters
			if current != nil {
				totalRules++
				if c.shouldIncludeRule(current) {
					entries = append(entries, *current)
				}
			}
			current = &types.FirewallRuleInfo{
				DisplayName: value,
				Name:        value,
			}
			continue
		}

		if current == nil {
			continue
		}

		switch {
		// Enabled: EN "Enabled" / KO "사용"
		case strings.Contains(keyLower, "enabled") || key == "사용":
			current.Enabled = strings.EqualFold(value, "Yes") ||
				strings.EqualFold(value, "True") ||
				value == "예"

		// Direction: EN "Direction" / KO "방향"
		case strings.Contains(keyLower, "direction") || key == "방향":
			current.Direction = normalizeDirection(value)

		// Profiles: EN "Profiles" / KO "프로필"
		case strings.Contains(keyLower, "profiles") || strings.Contains(keyLower, "profile") || key == "프로필":
			current.Profile = value

		// Local Port: EN "LocalPort" / KO "로컬 포트"
		case strings.Contains(keyLower, "localport") || strings.Contains(keyLower, "local port") || strings.Contains(key, "로컬 포트"):
			current.LocalPort = value

		// Remote Port: EN "RemotePort" / KO "원격 포트"
		case strings.Contains(keyLower, "remoteport") || strings.Contains(keyLower, "remote port") || strings.Contains(key, "원격 포트"):
			current.RemotePort = value

		// Remote Address: EN "RemoteIP" / KO "원격 주소"
		case strings.Contains(keyLower, "remoteip") || strings.Contains(keyLower, "remote address") || strings.Contains(key, "원격 주소") || strings.Contains(key, "원격 IP"):
			current.RemoteAddr = value

		// Protocol: EN "Protocol" / KO "프로토콜"
		case strings.Contains(keyLower, "protocol") || strings.Contains(key, "프로토콜"):
			current.Protocol = value

		// Program: EN "Program" / KO "프로그램"
		case strings.Contains(keyLower, "program") || key == "프로그램":
			current.Program = value

		// Action: EN "Action" / KO "작업"
		case strings.Contains(keyLower, "action") || key == "작업":
			current.Action = normalizeAction(value)
		}
	}

	// Add last entry
	if current != nil {
		totalRules++
		if c.shouldIncludeRule(current) {
			entries = append(entries, *current)
		}
	}

	logger.Debug("Firewall: parsed %d total rules, %d matched inbound+allow+enabled filter", totalRules, len(entries))

	// Limit to 500 entries
	if len(entries) > 500 {
		entries = entries[:500]
	}

	return entries
}

// shouldIncludeRule filters for enabled inbound allow rules
func (c *FirewallCollector) shouldIncludeRule(rule *types.FirewallRuleInfo) bool {
	return rule.Enabled &&
		rule.Direction == "Inbound" &&
		rule.Action == "Allow"
}

// normalizeDirection converts localized direction values to English
func normalizeDirection(value string) string {
	lower := strings.ToLower(value)
	switch {
	case lower == "in" || lower == "inbound" || value == "인바운드":
		return "Inbound"
	case lower == "out" || lower == "outbound" || value == "아웃바운드":
		return "Outbound"
	}
	return value
}

// normalizeAction converts localized action values to English
func normalizeAction(value string) string {
	lower := strings.ToLower(value)
	switch {
	case lower == "allow" || value == "허용":
		return "Allow"
	case lower == "block" || value == "차단":
		return "Block"
	}
	return value
}

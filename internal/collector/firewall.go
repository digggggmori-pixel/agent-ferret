package collector

import (
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// FirewallCollector collects Windows Firewall rules
type FirewallCollector struct{}

// NewFirewallCollector creates a new firewall collector
func NewFirewallCollector() *FirewallCollector {
	return &FirewallCollector{}
}

// Collect retrieves Windows Firewall rules from the registry (locale-independent).
// Registry path: HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
// Each value is pipe-delimited with English keys: v2.31|Action=Allow|Active=TRUE|Dir=In|...
func (c *FirewallCollector) Collect() ([]types.FirewallRuleInfo, error) {
	logger.Section("Firewall Collection")
	startTime := time.Now()

	var entries []types.FirewallRuleInfo

	keyPath := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		logger.Debug("Cannot open firewall registry: %v", err)
		return entries, nil
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		logger.Debug("Cannot read firewall rule names: %v", err)
		return entries, nil
	}

	logger.Debug("Firewall registry: %d rule values found", len(valueNames))

	totalRules := 0
	for _, name := range valueNames {
		val, _, err := key.GetStringValue(name)
		if err != nil {
			continue
		}

		rule := c.parseRegistryRule(val)
		if rule == nil {
			continue
		}

		totalRules++
		if c.shouldIncludeRule(rule) {
			entries = append(entries, *rule)
		}
	}

	logger.Debug("Firewall: parsed %d total rules, %d matched inbound+allow+enabled filter", totalRules, len(entries))

	if len(entries) > 500 {
		entries = entries[:500]
	}

	logger.Timing("FirewallCollector.Collect", startTime)
	logger.Info("Firewall: %d inbound allow rules collected", len(entries))

	return entries, nil
}

// parseRegistryRule parses a pipe-delimited registry rule value.
// Format: v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=...|Name=...|
func (c *FirewallCollector) parseRegistryRule(value string) *types.FirewallRuleInfo {
	rule := &types.FirewallRuleInfo{}

	parts := strings.Split(value, "|")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		k := kv[0]
		v := kv[1]

		switch k {
		case "Action":
			rule.Action = v
		case "Active":
			rule.Enabled = strings.EqualFold(v, "TRUE")
		case "Dir":
			switch v {
			case "In":
				rule.Direction = "Inbound"
			case "Out":
				rule.Direction = "Outbound"
			default:
				rule.Direction = v
			}
		case "Protocol":
			rule.Protocol = normalizeProtocol(v)
		case "LPort":
			rule.LocalPort = v
		case "RPort":
			rule.RemotePort = v
		case "RA4", "RA6":
			if rule.RemoteAddr == "" {
				rule.RemoteAddr = v
			} else {
				rule.RemoteAddr += "," + v
			}
		case "App":
			rule.Program = v
		case "Name":
			rule.Name = v
			rule.DisplayName = v
		case "Profile":
			rule.Profile = v
		}
	}

	if rule.Name == "" {
		return nil
	}

	return rule
}

// shouldIncludeRule filters for enabled inbound allow rules
func (c *FirewallCollector) shouldIncludeRule(rule *types.FirewallRuleInfo) bool {
	return rule.Enabled &&
		rule.Direction == "Inbound" &&
		rule.Action == "Allow"
}

// normalizeProtocol converts numeric protocol values to names
func normalizeProtocol(value string) string {
	switch value {
	case "6":
		return "TCP"
	case "17":
		return "UDP"
	case "1":
		return "ICMPv4"
	case "58":
		return "ICMPv6"
	case "256":
		return "Any"
	default:
		return value
	}
}

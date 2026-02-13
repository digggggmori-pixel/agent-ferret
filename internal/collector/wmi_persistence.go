package collector

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// WMIPersistenceCollector collects WMI event subscription persistence
type WMIPersistenceCollector struct{}

// NewWMIPersistenceCollector creates a new WMI persistence collector
func NewWMIPersistenceCollector() *WMIPersistenceCollector {
	return &WMIPersistenceCollector{}
}

// wmiFilter represents a __EventFilter from WMI
type wmiFilter struct {
	Name           string `json:"Name"`
	QueryLanguage  string `json:"QueryLanguage"`
	Query          string `json:"Query"`
	CreatorSID     string `json:"CreatorSID"`
}

// wmiConsumer represents a __EventConsumer from WMI (CommandLine or ActiveScript)
type wmiConsumer struct {
	Name             string `json:"Name"`
	CommandLineTemplate string `json:"CommandLineTemplate,omitempty"`
	ExecutablePath   string `json:"ExecutablePath,omitempty"`
	ScriptText       string `json:"ScriptText,omitempty"`
	ScriptFileName   string `json:"ScriptFileName,omitempty"`
	ClassName        string `json:"__CLASS,omitempty"`
}

// wmiBinding represents a __FilterToConsumerBinding
type wmiBinding struct {
	Filter   string `json:"Filter"`
	Consumer string `json:"Consumer"`
}

// Collect retrieves WMI event subscription persistence entries
func (c *WMIPersistenceCollector) Collect() ([]types.WMIPersistenceInfo, error) {
	logger.Section("WMI Persistence Collection")
	startTime := time.Now()

	var entries []types.WMIPersistenceInfo

	// Query event filters
	filters := c.queryFilters()

	// Query event consumers
	consumers := c.queryConsumers()

	// Query bindings
	bindings := c.queryBindings()

	// Correlate: for each binding, find the filter and consumer
	for _, binding := range bindings {
		entry := types.WMIPersistenceInfo{
			BindingPath: binding.Filter + " -> " + binding.Consumer,
		}

		// Match filter
		filterName := extractWMIName(binding.Filter)
		for _, f := range filters {
			if f.Name == filterName {
				entry.FilterName = f.Name
				entry.FilterQuery = f.Query
				entry.CreatorSID = f.CreatorSID
				break
			}
		}

		// Match consumer
		consumerName := extractWMIName(binding.Consumer)
		for _, cons := range consumers {
			if cons.Name == consumerName {
				entry.ConsumerName = cons.Name
				entry.ConsumerType = classifyConsumer(cons)
				entry.ConsumerData = getConsumerData(cons)
				break
			}
		}

		// Only add if we have at least filter or consumer info
		if entry.FilterName != "" || entry.ConsumerName != "" {
			entries = append(entries, entry)
		}
	}

	// Also add orphan filters (filters without bindings)
	for _, f := range filters {
		found := false
		for _, e := range entries {
			if e.FilterName == f.Name {
				found = true
				break
			}
		}
		if !found {
			entries = append(entries, types.WMIPersistenceInfo{
				FilterName:  f.Name,
				FilterQuery: f.Query,
				CreatorSID:  f.CreatorSID,
			})
		}
	}

	logger.Timing("WMIPersistenceCollector.Collect", startTime)
	logger.Info("WMI persistence: %d entries found", len(entries))

	return entries, nil
}

func (c *WMIPersistenceCollector) queryFilters() []wmiFilter {
	psScript := `Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,QueryLanguage,Query,@{N='CreatorSID';E={($_.CreatorSID -join ',')}} | ConvertTo-Json -Compress`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}

	var filters []wmiFilter
	// Handle both single object and array
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &filters); err != nil {
			logger.Debug("Failed to parse WMI filters: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single wmiFilter
		if json.Unmarshal([]byte(output), &single) == nil {
			filters = append(filters, single)
		}
	}

	return filters
}

func (c *WMIPersistenceCollector) queryConsumers() []wmiConsumer {
	// Query all consumer types
	consumerClasses := []string{
		"CommandLineEventConsumer",
		"ActiveScriptEventConsumer",
		"LogFileEventConsumer",
		"NTEventLogEventConsumer",
		"SMTPEventConsumer",
	}

	var allConsumers []wmiConsumer

	for _, cls := range consumerClasses {
		psScript := `Get-WmiObject -Namespace root\subscription -Class ` + cls + ` -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,ExecutablePath,ScriptText,ScriptFileName,@{N='__CLASS';E={'` + cls + `'}} | ConvertTo-Json -Compress`

		output, err := runPowerShell(psScript)
		if err != nil || strings.TrimSpace(output) == "" {
			continue
		}

		output = strings.TrimSpace(output)
		if strings.HasPrefix(output, "[") {
			var consumers []wmiConsumer
			if json.Unmarshal([]byte(output), &consumers) == nil {
				allConsumers = append(allConsumers, consumers...)
			}
		} else if strings.HasPrefix(output, "{") {
			var single wmiConsumer
			if json.Unmarshal([]byte(output), &single) == nil {
				allConsumers = append(allConsumers, single)
			}
		}
	}

	return allConsumers
}

func (c *WMIPersistenceCollector) queryBindings() []wmiBinding {
	psScript := `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object @{N='Filter';E={$_.Filter}},@{N='Consumer';E={$_.Consumer}} | ConvertTo-Json -Compress`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}

	var bindings []wmiBinding
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &bindings); err != nil {
			logger.Debug("Failed to parse WMI bindings: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single wmiBinding
		if json.Unmarshal([]byte(output), &single) == nil {
			bindings = append(bindings, single)
		}
	}

	return bindings
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// extractWMIName extracts the Name property from a WMI object path
// e.g., "__EventFilter.Name=\"MyFilter\"" → "MyFilter"
func extractWMIName(path string) string {
	if idx := strings.Index(path, `Name="`); idx >= 0 {
		rest := path[idx+6:]
		if end := strings.Index(rest, `"`); end >= 0 {
			return rest[:end]
		}
	}
	// Fallback: just return the path as-is
	return path
}

func classifyConsumer(c wmiConsumer) string {
	if c.ClassName != "" {
		// Remove "EventConsumer" suffix for cleaner display
		return strings.TrimSuffix(c.ClassName, "EventConsumer")
	}
	if c.CommandLineTemplate != "" || c.ExecutablePath != "" {
		return "CommandLine"
	}
	if c.ScriptText != "" || c.ScriptFileName != "" {
		return "ActiveScript"
	}
	return "Unknown"
}

func getConsumerData(c wmiConsumer) string {
	if c.CommandLineTemplate != "" {
		return c.CommandLineTemplate
	}
	if c.ExecutablePath != "" {
		return c.ExecutablePath
	}
	if c.ScriptFileName != "" {
		return c.ScriptFileName
	}
	if c.ScriptText != "" {
		if len(c.ScriptText) > 500 {
			return c.ScriptText[:500] + "..."
		}
		return c.ScriptText
	}
	return ""
}

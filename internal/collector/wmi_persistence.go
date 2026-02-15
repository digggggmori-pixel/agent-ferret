package collector

import (
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

// Collect retrieves WMI event subscription persistence entries via native COM
func (c *WMIPersistenceCollector) Collect() ([]types.WMIPersistenceInfo, error) {
	logger.Section("WMI Persistence Collection")
	startTime := time.Now()

	var entries []types.WMIPersistenceInfo

	filters := c.queryFilters()
	consumers := c.queryConsumers()
	bindings := c.queryBindings()

	// Correlate: for each binding, find the filter and consumer
	for _, binding := range bindings {
		entry := types.WMIPersistenceInfo{
			BindingPath: binding["Filter"] + " -> " + binding["Consumer"],
		}

		filterName := extractWMIName(binding["Filter"])
		for _, f := range filters {
			if f["Name"] == filterName {
				entry.FilterName = f["Name"]
				entry.FilterQuery = f["Query"]
				entry.CreatorSID = f["CreatorSID"]
				break
			}
		}

		consumerName := extractWMIName(binding["Consumer"])
		for _, cons := range consumers {
			if cons["Name"] == consumerName {
				entry.ConsumerName = cons["Name"]
				entry.ConsumerType = classifyConsumerMap(cons)
				entry.ConsumerData = getConsumerDataMap(cons)
				break
			}
		}

		if entry.FilterName != "" || entry.ConsumerName != "" {
			entries = append(entries, entry)
		}
	}

	// Add orphan filters (filters without bindings)
	for _, f := range filters {
		found := false
		for _, e := range entries {
			if e.FilterName == f["Name"] {
				found = true
				break
			}
		}
		if !found {
			entries = append(entries, types.WMIPersistenceInfo{
				FilterName:  f["Name"],
				FilterQuery: f["Query"],
				CreatorSID:  f["CreatorSID"],
			})
		}
	}

	logger.Timing("WMIPersistenceCollector.Collect", startTime)
	logger.Info("WMI persistence: %d entries found", len(entries))

	return entries, nil
}

func (c *WMIPersistenceCollector) queryFilters() []map[string]string {
	rows, err := WMIQueryFields(`root\subscription`,
		"SELECT Name, QueryLanguage, Query, CreatorSID FROM __EventFilter",
		[]string{"Name", "QueryLanguage", "Query", "CreatorSID"})
	if err != nil {
		logger.Debug("WMI filter query failed: %v", err)
		return nil
	}
	return rows
}

func (c *WMIPersistenceCollector) queryConsumers() []map[string]string {
	consumerClasses := []string{
		"CommandLineEventConsumer",
		"ActiveScriptEventConsumer",
		"LogFileEventConsumer",
		"NTEventLogEventConsumer",
		"SMTPEventConsumer",
	}

	var allConsumers []map[string]string
	for _, cls := range consumerClasses {
		rows, err := WMIQueryFields(`root\subscription`,
			"SELECT Name, CommandLineTemplate, ExecutablePath, ScriptText, ScriptFileName FROM "+cls,
			[]string{"Name", "CommandLineTemplate", "ExecutablePath", "ScriptText", "ScriptFileName"})
		if err != nil {
			continue
		}
		for _, row := range rows {
			row["__CLASS"] = cls
		}
		allConsumers = append(allConsumers, rows...)
	}

	return allConsumers
}

func (c *WMIPersistenceCollector) queryBindings() []map[string]string {
	rows, err := WMIQueryFields(`root\subscription`,
		"SELECT Filter, Consumer FROM __FilterToConsumerBinding",
		[]string{"Filter", "Consumer"})
	if err != nil {
		logger.Debug("WMI binding query failed: %v", err)
		return nil
	}
	return rows
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
	return path
}

func classifyConsumerMap(c map[string]string) string {
	if cls, ok := c["__CLASS"]; ok && cls != "" {
		return strings.TrimSuffix(cls, "EventConsumer")
	}
	if c["CommandLineTemplate"] != "" || c["ExecutablePath"] != "" {
		return "CommandLine"
	}
	if c["ScriptText"] != "" || c["ScriptFileName"] != "" {
		return "ActiveScript"
	}
	return "Unknown"
}

func getConsumerDataMap(c map[string]string) string {
	if v := c["CommandLineTemplate"]; v != "" {
		return v
	}
	if v := c["ExecutablePath"]; v != "" {
		return v
	}
	if v := c["ScriptFileName"]; v != "" {
		return v
	}
	if v := c["ScriptText"]; v != "" {
		if len(v) > 500 {
			return v[:500] + "..."
		}
		return v
	}
	return ""
}

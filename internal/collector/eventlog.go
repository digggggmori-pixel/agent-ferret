// Package collector provides data collection from Windows APIs
package collector

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/internal/sigma"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

// Windows Event Log API constants
const (
	EvtQueryChannelPath         = 0x1
	EvtQueryFilePath            = 0x2
	EvtQueryForwardDirection    = 0x100
	EvtQueryReverseDirection    = 0x200
	EvtQueryTolerateQueryErrors = 0x1000

	EvtRenderEventXml   = 1
	EvtRenderEventValues = 0

	EvtSystemProviderName        = 1
	EvtSystemEventID             = 3
	EvtSystemTimeCreated         = 6
	EvtSystemComputer            = 11
	EvtSystemProviderGuid        = 2
	EvtSystemEventRecordId       = 9
	EvtSystemChannel             = 13

	ERROR_NO_MORE_ITEMS = 259
	ERROR_INSUFFICIENT_BUFFER = 122
)

var (
	wevtapi                    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery               = wevtapi.NewProc("EvtQuery")
	procEvtNext                = wevtapi.NewProc("EvtNext")
	procEvtRender              = wevtapi.NewProc("EvtRender")
	procEvtClose               = wevtapi.NewProc("EvtClose")
	procEvtGetEventMetadataProperty = wevtapi.NewProc("EvtGetEventMetadataProperty")
)

// rawSigmaMatch holds a sigma match paired with its source event for aggregation
type rawSigmaMatch struct {
	match *sigma.SigmaMatch
	entry *types.EventLogEntry
}

// EventLogCollector collects and scans Windows Event Logs
type EventLogCollector struct {
	channels       []string
	quickMode      bool
	cutoffTime     time.Time
	progressCB     sigma.ProgressCallback
	totalScanned   int64
	totalMatches   int
	sigmaEngine    *sigma.Engine
}

// EventLogOption is a functional option for EventLogCollector
type EventLogOption func(*EventLogCollector)

// DefaultChannels to scan (in priority order)
// Channels are ordered by security relevance and Sigma rule coverage
var DefaultChannels = []string{
	// High priority - most Sigma rules
	"Security",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	"System",
	// Medium priority - additional coverage
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	// Lower priority - supplementary
	"Microsoft-Windows-Bits-Client/Operational",
	"Microsoft-Windows-DNS-Client/Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-CodeIntegrity/Operational",
	"Application",
}

// NewEventLogCollector creates a new event log collector
func NewEventLogCollector(opts ...EventLogOption) *EventLogCollector {
	c := &EventLogCollector{
		channels:   DefaultChannels,
		quickMode:  false,
		cutoffTime: time.Time{},
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.quickMode && c.cutoffTime.IsZero() {
		c.cutoffTime = time.Now().Add(-24 * time.Hour)
	}

	return c
}

// WithChannels sets the channels to scan
func WithChannels(channels []string) EventLogOption {
	return func(c *EventLogCollector) {
		c.channels = channels
	}
}

// WithQuickMode enables quick mode (last 24 hours only)
func WithQuickMode(quick bool) EventLogOption {
	return func(c *EventLogCollector) {
		c.quickMode = quick
		if quick {
			c.cutoffTime = time.Now().Add(-24 * time.Hour)
		}
	}
}

// WithCutoffTime sets a custom cutoff time for event filtering
func WithCutoffTime(cutoff time.Time) EventLogOption {
	return func(c *EventLogCollector) {
		c.cutoffTime = cutoff
	}
}

// WithProgress sets the progress callback
func WithProgress(cb sigma.ProgressCallback) EventLogOption {
	return func(c *EventLogCollector) {
		c.progressCB = cb
	}
}

// TotalScanned returns the total number of events scanned
func (c *EventLogCollector) TotalScanned() int64 {
	return c.totalScanned
}

// TotalMatches returns the total number of Sigma matches
func (c *EventLogCollector) TotalMatches() int {
	return c.totalMatches
}

// Scan scans all configured channels and returns detections
func (c *EventLogCollector) Scan(engine *sigma.Engine) ([]types.Detection, error) {
	logger.Section("Event Log Collection")
	startTime := time.Now()

	c.sigmaEngine = engine
	c.totalScanned = 0
	c.totalMatches = 0

	logger.Info("Scanning %d event log channels", len(c.channels))
	if c.quickMode {
		logger.Info("Quick mode enabled: scanning last 24 hours only (since %s)", c.cutoffTime.Format("2006-01-02 15:04:05"))
	}
	logger.Info("Sigma engine has %d rules", engine.TotalRules())

	var allDetections []types.Detection

	for i, channel := range c.channels {
		logger.Debug("[%d/%d] Scanning channel: %s", i+1, len(c.channels), channel)
		channelStart := time.Now()

		detections, err := c.scanChannel(channel)
		if err != nil {
			logger.Warn("Failed to scan channel %s: %v", channel, err)
			continue
		}

		logger.Debug("Channel %s: scanned in %v, %d detections", channel, time.Since(channelStart), len(detections))
		allDetections = append(allDetections, detections...)
	}

	logger.Timing("EventLogCollector.Scan", startTime)
	logger.Info("Event log scan complete: %d total events, %d total detections", c.totalScanned, len(allDetections))

	return allDetections, nil
}

// scanChannel scans a single event log channel
func (c *EventLogCollector) scanChannel(channel string) ([]types.Detection, error) {
	// Build query
	query := "*"
	if !c.cutoffTime.IsZero() {
		// XPath query for time filtering
		query = fmt.Sprintf(
			"*[System[TimeCreated[@SystemTime >= '%s']]]",
			c.cutoffTime.UTC().Format("2006-01-02T15:04:05.000Z"),
		)
	}

	logger.Debug("Channel %s: query=%s", channel, query)
	logger.APICall("EvtQuery", channel, query)

	// Open query handle
	handle, err := evtQuery(channel, query, EvtQueryChannelPath|EvtQueryReverseDirection)
	if err != nil {
		logger.Error("EvtQuery failed for channel %s: %v (query: %s)", channel, err, query)
		// Provide more helpful error message
		errStr := err.Error()
		if strings.Contains(errStr, "5") || strings.Contains(errStr, "Access") {
			return nil, fmt.Errorf("access denied to channel %s (run as Administrator)", channel)
		}
		if strings.Contains(errStr, "15007") || strings.Contains(errStr, "not found") {
			return nil, fmt.Errorf("channel %s not found", channel)
		}
		return nil, fmt.Errorf("failed to query channel %s: %w", channel, err)
	}
	defer evtClose(handle)
	logger.Debug("Channel %s: query handle obtained", channel)

	var rawMatches []rawSigmaMatch
	startTime := time.Now()
	var count int64

	// Process events in batches
	const batchSize = 100
	eventHandles := make([]syscall.Handle, batchSize)

	for {
		// Get batch of events
		returned, err := evtNext(handle, eventHandles)
		if err != nil {
			if err == syscall.Errno(ERROR_NO_MORE_ITEMS) {
				break
			}
			return nil, fmt.Errorf("failed to get events: %w", err)
		}

		// Process each event
		for i := uint32(0); i < returned; i++ {
			eventHandle := eventHandles[i]

			// Render event to XML
			eventXML, err := renderEventXML(eventHandle)
			evtClose(eventHandle) // Close immediately after use

			if err != nil {
				continue
			}

			// Parse event
			entry, err := parseEventXML(eventXML, channel)
			if err != nil {
				continue
			}

			// Convert to Sigma event
			sigmaEvent := c.convertToSigmaEvent(entry, channel)

			// Match against Sigma rules — collect raw matches for aggregation
			if c.sigmaEngine != nil {
				matches := c.sigmaEngine.Match(sigmaEvent)
				for _, match := range matches {
					rawMatches = append(rawMatches, rawSigmaMatch{match: match, entry: entry})
					c.totalMatches++
				}
			}

			count++
		}

		c.totalScanned += int64(returned)

		// Report progress
		if c.progressCB != nil && count%1000 == 0 {
			c.progressCB(sigma.ScanProgress{
				Channel:   channel,
				Current:   count,
				Total:     0, // We don't know total upfront
				Matches:   len(rawMatches),
				StartTime: startTime,
				ElapsedMs: time.Since(startTime).Milliseconds(),
			})
		}

		if returned < batchSize {
			break
		}
	}

	// Final progress report
	if c.progressCB != nil {
		c.progressCB(sigma.ScanProgress{
			Channel:   channel,
			Current:   count,
			Total:     count,
			Matches:   len(rawMatches),
			StartTime: startTime,
			ElapsedMs: time.Since(startTime).Milliseconds(),
		})
	}

	// === Fix 4: Merge multi-rule matches on same event ===
	// Group by channel+eventID+timestamp (truncated to second)
	type eventKey struct {
		Channel   string
		EventID   uint32
		Timestamp string
	}

	eventGroups := make(map[eventKey][]rawSigmaMatch)
	for _, rm := range rawMatches {
		key := eventKey{
			Channel:   rm.entry.Channel,
			EventID:   rm.entry.EventID,
			Timestamp: rm.entry.Timestamp.Truncate(time.Second).Format(time.RFC3339),
		}
		eventGroups[key] = append(eventGroups[key], rm)
	}

	// Convert event groups to detections
	var mergedDetections []types.Detection
	for _, group := range eventGroups {
		if len(group) == 1 {
			mergedDetections = append(mergedDetections, convertSigmaMatchToDetection(group[0].match, group[0].entry))
		} else {
			// Multiple rules matched same event — merge into single detection
			mergedDetections = append(mergedDetections, mergeMultiRuleMatches(group))
		}
	}

	// === Fix 3: Aggregate by rule ID ===
	// Group detections by their sigma rule set
	ruleGroups := make(map[string][]types.Detection)
	for _, d := range mergedDetections {
		// Use sorted sigma rules as grouping key
		key := strings.Join(d.SigmaRules, "+")
		ruleGroups[key] = append(ruleGroups[key], d)
	}

	// Convert rule groups to final detections
	var detections []types.Detection
	for _, group := range ruleGroups {
		if len(group) == 1 {
			detections = append(detections, group[0])
		} else {
			// Same rule(s) matched multiple events — aggregate
			detections = append(detections, aggregateRuleDetections(group))
		}
	}

	logger.Debug("Channel %s aggregation: %d raw matches → %d event-merged → %d rule-aggregated",
		channel, len(rawMatches), len(mergedDetections), len(detections))

	return detections, nil
}

// convertToSigmaEvent converts an EventLogEntry to SigmaEvent
func (c *EventLogCollector) convertToSigmaEvent(entry *types.EventLogEntry, channel string) *sigma.SigmaEvent {
	// Determine category based on channel and event ID
	category := sigma.GetCategoryForEvent(channel, entry.EventID, entry.Provider)

	return &sigma.SigmaEvent{
		Category:  category,
		Channel:   channel,
		Provider:  entry.Provider,
		EventID:   entry.EventID,
		Timestamp: entry.Timestamp,
		Computer:  getStringField(entry.Data, "Computer"),
		Fields:    entry.Data,
	}
}

// convertSigmaMatchToDetection converts a SigmaMatch to a Detection
func convertSigmaMatchToDetection(match *sigma.SigmaMatch, entry *types.EventLogEntry) types.Detection {
	return types.Detection{
		ID:          fmt.Sprintf("sigma-%s-%d", match.RuleID[:8], entry.Timestamp.UnixNano()),
		Type:        types.DetectionTypeSigma,
		Severity:    match.Severity,
		Confidence:  0.8, // Sigma matches have good confidence
		Timestamp:   entry.Timestamp,
		Description: match.RuleName,
		MITRE: &types.MITREMapping{
			Tactics:    types.NormalizeTactics(match.MITRE.Tactics),
			Techniques: match.MITRE.Techniques,
		},
		SigmaRules: []string{match.RuleID},
		Details: map[string]interface{}{
			"rule_id":     match.RuleID,
			"rule_name":   match.RuleName,
			"description": match.Description,
			"category":    match.Category,
			"channel":     match.Channel,
			"event_id":    match.EventID,
			"tags":        match.Tags,
		},
	}
}

// severityRank returns a numeric rank for severity comparison (higher = more severe)
func severityRank(sev string) int {
	switch sev {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	case types.SeverityInfo:
		return 0
	default:
		return -1
	}
}

// mergeMultiRuleMatches merges multiple sigma rule matches from a single event
// into one Detection (Fix 4: PowerShell ScriptBlock multi-match)
func mergeMultiRuleMatches(group []rawSigmaMatch) types.Detection {
	// Find the highest severity match
	bestIdx := 0
	for i := 1; i < len(group); i++ {
		if severityRank(group[i].match.Severity) > severityRank(group[bestIdx].match.Severity) {
			bestIdx = i
		}
	}

	best := group[bestIdx]

	// Collect all rule IDs and build matched_rules list
	var ruleIDs []string
	var matchedRules []map[string]interface{}
	seenRules := make(map[string]bool)

	for _, rm := range group {
		if !seenRules[rm.match.RuleID] {
			seenRules[rm.match.RuleID] = true
			ruleIDs = append(ruleIDs, rm.match.RuleID)
			matchedRules = append(matchedRules, map[string]interface{}{
				"name":     rm.match.RuleName,
				"severity": rm.match.Severity,
				"rule_id":  rm.match.RuleID,
			})
		}
	}
	sort.Strings(ruleIDs)

	// Merge MITRE mappings
	tacticsSet := make(map[string]bool)
	techniquesSet := make(map[string]bool)
	for _, rm := range group {
		for _, t := range rm.match.MITRE.Tactics {
			tacticsSet[t] = true
		}
		for _, t := range rm.match.MITRE.Techniques {
			techniquesSet[t] = true
		}
	}
	var tactics, techniques []string
	for t := range tacticsSet {
		tactics = append(tactics, t)
	}
	for t := range techniquesSet {
		techniques = append(techniques, t)
	}

	return types.Detection{
		ID:          fmt.Sprintf("sigma-multi-%s-%d", best.match.RuleID[:8], best.entry.Timestamp.UnixNano()),
		Type:        types.DetectionTypeSigma,
		Severity:    best.match.Severity,
		Confidence:  0.85,
		Timestamp:   best.entry.Timestamp,
		Description: fmt.Sprintf("%s (+%d more rules)", best.match.RuleName, len(group)-1),
		MITRE: &types.MITREMapping{
			Tactics:    types.NormalizeTactics(tactics),
			Techniques: techniques,
		},
		SigmaRules: ruleIDs,
		Details: map[string]interface{}{
			"rule_id":       best.match.RuleID,
			"rule_name":     best.match.RuleName,
			"description":   best.match.Description,
			"category":      best.match.Category,
			"channel":       best.match.Channel,
			"event_id":      best.match.EventID,
			"matched_rules": matchedRules,
			"rules_count":   len(group),
		},
	}
}

// aggregateRuleDetections aggregates multiple detections from the same rule(s)
// into a single detection with event count (Fix 3: event log sigma aggregation)
func aggregateRuleDetections(group []types.Detection) types.Detection {
	first := group[0]

	// Find time range
	firstSeen := first.Timestamp
	lastSeen := first.Timestamp
	for _, d := range group[1:] {
		if d.Timestamp.Before(firstSeen) {
			firstSeen = d.Timestamp
		}
		if d.Timestamp.After(lastSeen) {
			lastSeen = d.Timestamp
		}
	}

	// Use highest severity from the group
	bestSeverity := first.Severity
	for _, d := range group[1:] {
		if severityRank(d.Severity) > severityRank(bestSeverity) {
			bestSeverity = d.Severity
		}
	}

	// Build aggregated description
	desc := first.Description
	// Strip any existing count suffix for clean aggregation
	if idx := strings.Index(desc, " (×"); idx > 0 {
		desc = desc[:idx]
	}
	if idx := strings.Index(desc, " (+"); idx > 0 {
		desc = desc[:idx]
	}
	desc = fmt.Sprintf("%s (×%d events)", desc, len(group))

	// Copy details from first detection, add aggregation info
	details := make(map[string]interface{})
	for k, v := range first.Details {
		details[k] = v
	}
	details["event_count"] = len(group)
	details["first_seen"] = firstSeen.Format(time.RFC3339)
	details["last_seen"] = lastSeen.Format(time.RFC3339)

	return types.Detection{
		ID:          first.ID,
		Type:        first.Type,
		Severity:    bestSeverity,
		Confidence:  first.Confidence,
		Timestamp:   firstSeen,
		Description: desc,
		MITRE:       first.MITRE,
		SigmaRules:  first.SigmaRules,
		Details:     details,
	}
}

// Windows API wrappers

func evtQuery(channel, query string, flags uint32) (syscall.Handle, error) {
	channelPtr, _ := syscall.UTF16PtrFromString(channel)
	queryPtr, _ := syscall.UTF16PtrFromString(query)

	r1, _, err := procEvtQuery.Call(
		0, // Session (local)
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		uintptr(flags),
	)

	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func evtNext(queryHandle syscall.Handle, events []syscall.Handle) (uint32, error) {
	var returned uint32

	r1, _, err := procEvtNext.Call(
		uintptr(queryHandle),
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&events[0])),
		uintptr(2000), // Timeout in ms
		0,             // Reserved
		uintptr(unsafe.Pointer(&returned)),
	)

	if r1 == 0 {
		return returned, err
	}
	return returned, nil
}

func evtClose(handle syscall.Handle) {
	if handle != 0 {
		procEvtClose.Call(uintptr(handle))
	}
}

func renderEventXML(eventHandle syscall.Handle) (string, error) {
	var bufferSize uint32 = 0
	var bufferUsed uint32 = 0
	var propertyCount uint32 = 0

	// First call to get required buffer size
	procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)

	if bufferUsed == 0 {
		return "", fmt.Errorf("failed to get buffer size")
	}

	// Allocate buffer
	bufferSize = bufferUsed
	buffer := make([]uint16, bufferSize/2)

	// Second call to get the actual data
	r1, _, err := procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXml),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)

	if r1 == 0 {
		return "", err
	}

	return syscall.UTF16ToString(buffer), nil
}

// XML parsing structures

type eventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  systemXML `xml:"System"`
	EventData eventDataXML `xml:"EventData"`
	UserData interface{} `xml:"UserData"`
}

type systemXML struct {
	Provider    providerXML   `xml:"Provider"`
	EventID     uint32        `xml:"EventID"`
	TimeCreated timeCreatedXML `xml:"TimeCreated"`
	Computer    string        `xml:"Computer"`
	Channel     string        `xml:"Channel"`
}

type providerXML struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type timeCreatedXML struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type eventDataXML struct {
	Data []dataXML `xml:"Data"`
}

type dataXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func parseEventXML(xmlStr string, channel string) (*types.EventLogEntry, error) {
	var event eventXML
	if err := xml.Unmarshal([]byte(xmlStr), &event); err != nil {
		return nil, err
	}

	// Parse timestamp
	timestamp, _ := time.Parse(time.RFC3339Nano, event.System.TimeCreated.SystemTime)

	// Build data map
	data := make(map[string]interface{})

	// Add system fields
	data["EventID"] = event.System.EventID
	data["Channel"] = event.System.Channel
	data["Computer"] = event.System.Computer
	data["Provider_Name"] = event.System.Provider.Name

	// Add event data fields
	for _, d := range event.EventData.Data {
		if d.Name != "" {
			data[d.Name] = d.Value
		}
	}

	return &types.EventLogEntry{
		Channel:   channel,
		Provider:  event.System.Provider.Name,
		EventID:   event.System.EventID,
		Timestamp: timestamp,
		Data:      data,
	}, nil
}

func getStringField(data map[string]interface{}, key string) string {
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CollectEvents collects events from a channel without Sigma matching
// This is useful for testing or when Sigma engine is not needed
func (c *EventLogCollector) CollectEvents(channel string, limit int) ([]types.EventLogEntry, error) {
	query := "*"
	if !c.cutoffTime.IsZero() {
		query = fmt.Sprintf(
			"*[System[TimeCreated[@SystemTime >= '%s']]]",
			c.cutoffTime.UTC().Format("2006-01-02T15:04:05.000Z"),
		)
	}

	handle, err := evtQuery(channel, query, EvtQueryChannelPath|EvtQueryReverseDirection)
	if err != nil {
		return nil, err
	}
	defer evtClose(handle)

	var entries []types.EventLogEntry
	eventHandles := make([]syscall.Handle, 100)

	for len(entries) < limit {
		returned, err := evtNext(handle, eventHandles)
		if err != nil {
			if err == syscall.Errno(ERROR_NO_MORE_ITEMS) {
				break
			}
			return entries, err
		}

		for i := uint32(0); i < returned && len(entries) < limit; i++ {
			eventXML, err := renderEventXML(eventHandles[i])
			evtClose(eventHandles[i])

			if err != nil {
				continue
			}

			entry, err := parseEventXML(eventXML, channel)
			if err != nil {
				continue
			}

			entries = append(entries, *entry)
		}

		if returned < uint32(len(eventHandles)) {
			break
		}
	}

	return entries, nil
}

// IsChannelAccessible checks if an event log channel is accessible
func IsChannelAccessible(channel string) bool {
	handle, err := evtQuery(channel, "*", EvtQueryChannelPath)
	if err != nil {
		logger.Debug("Channel %s not accessible: %v", channel, err)
		return false
	}
	evtClose(handle)
	logger.Debug("Channel %s is accessible", channel)
	return true
}

// GetAccessibleChannels returns a list of accessible channels from the default list
func GetAccessibleChannels() []string {
	var accessible []string
	for _, ch := range DefaultChannels {
		if IsChannelAccessible(ch) {
			accessible = append(accessible, ch)
		}
	}
	return accessible
}

// CountEventsInChannel returns the approximate number of events in a channel
func CountEventsInChannel(channel string, since time.Time) (int64, error) {
	query := "*"
	if !since.IsZero() {
		query = fmt.Sprintf(
			"*[System[TimeCreated[@SystemTime >= '%s']]]",
			since.UTC().Format("2006-01-02T15:04:05.000Z"),
		)
	}

	handle, err := evtQuery(channel, query, EvtQueryChannelPath)
	if err != nil {
		return 0, err
	}
	defer evtClose(handle)

	var count int64
	eventHandles := make([]syscall.Handle, 100)

	for {
		returned, err := evtNext(handle, eventHandles)
		if err != nil {
			if err == syscall.Errno(ERROR_NO_MORE_ITEMS) {
				break
			}
			return count, err
		}

		for i := uint32(0); i < returned; i++ {
			evtClose(eventHandles[i])
		}

		count += int64(returned)

		if returned < uint32(len(eventHandles)) {
			break
		}
	}

	return count, nil
}

// Placeholder for non-Windows builds
func init() {
	// Check if we're running on Windows
	osEnv, _ := syscall.Getenv("OS")
	if !strings.Contains(strings.ToLower(osEnv), "windows") {
		// On non-Windows, the wevtapi functions will fail gracefully
	}
}

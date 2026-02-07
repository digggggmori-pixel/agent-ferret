// Package sigma provides Sigma rule matching engine
package sigma

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ProcessToSigmaEvent converts live process info to Sigma event format
// This enables Sigma process_creation rules to match against live processes
func ProcessToSigmaEvent(proc types.ProcessInfo) *SigmaEvent {
	// Extract filename from path
	var image, originalFileName string
	if proc.Path != "" {
		image = proc.Path
		originalFileName = filepath.Base(proc.Path)
	} else {
		image = proc.Name
		originalFileName = proc.Name
	}

	// Extract parent image
	var parentImage string
	if proc.ParentPath != "" {
		parentImage = proc.ParentPath
	} else if proc.ParentName != "" {
		parentImage = proc.ParentName
	}

	// Build fields map matching Sigma field names
	fields := map[string]interface{}{
		"Image":            image,
		"OriginalFileName": originalFileName,
		"ProcessId":        proc.PID,
		"ParentProcessId":  proc.PPID,
		"ParentImage":      parentImage,
		"User":             proc.User,
	}

	// Add CommandLine if available (requires admin privileges)
	if proc.CommandLine != "" {
		fields["CommandLine"] = proc.CommandLine
		// Also add common variations
		fields["CommandLine|contains"] = proc.CommandLine
	}

	// Extract current directory from command line or path
	if proc.Path != "" {
		fields["CurrentDirectory"] = filepath.Dir(proc.Path)
	}

	return &SigmaEvent{
		Category:  "windows_process_creation",
		Timestamp: proc.CreateTime,
		Provider:  "LiveProcessCollector",
		EventID:   1, // Sysmon Event ID 1 equivalent
		Fields:    fields,
	}
}

// NetworkToSigmaEvent converts network connection to Sigma event format
// This enables Sigma network_connection rules to match against live connections
func NetworkToSigmaEvent(conn types.NetworkConnection, processPath string) *SigmaEvent {
	fields := map[string]interface{}{
		"SourceIp":        conn.LocalAddr,
		"SourcePort":      conn.LocalPort,
		"DestinationIp":   conn.RemoteAddr,
		"DestinationPort": conn.RemotePort,
		"Protocol":        strings.ToLower(conn.Protocol),
	}

	// Add process info if available
	if processPath != "" {
		fields["Image"] = processPath
	} else if conn.ProcessName != "" {
		fields["Image"] = conn.ProcessName
	}

	// Add connection state
	if conn.State != "" {
		fields["State"] = conn.State
	}

	// Determine if this is an initiated connection
	if conn.State == "ESTABLISHED" || conn.State == "SYN_SENT" {
		fields["Initiated"] = true
	}

	return &SigmaEvent{
		Category:  "windows_network_connection",
		Timestamp: time.Now(),
		Provider:  "LiveNetworkCollector",
		EventID:   3, // Sysmon Event ID 3 equivalent
		Fields:    fields,
	}
}

// ScanLiveProcesses scans live processes against Sigma rules
func ScanLiveProcesses(engine *Engine, processes []types.ProcessInfo) []*SigmaMatch {
	var matches []*SigmaMatch

	for _, proc := range processes {
		event := ProcessToSigmaEvent(proc)
		procMatches := engine.Match(event)
		matches = append(matches, procMatches...)
	}

	return matches
}

// ScanLiveNetwork scans live network connections against Sigma rules
// processMap provides PID to process path mapping for enrichment
func ScanLiveNetwork(engine *Engine, connections []types.NetworkConnection, processMap map[uint32]string) []*SigmaMatch {
	var matches []*SigmaMatch

	for _, conn := range connections {
		processPath := ""
		if path, ok := processMap[conn.OwningPID]; ok {
			processPath = path
		}

		event := NetworkToSigmaEvent(conn, processPath)
		connMatches := engine.Match(event)
		matches = append(matches, connMatches...)
	}

	return matches
}

// ConvertSigmaMatchToDetection converts a SigmaMatch to a types.Detection
func ConvertSigmaMatchToDetection(match *SigmaMatch, source string) types.Detection {
	desc := match.Description
	if desc == "" {
		desc = match.RuleName
	}
	return types.Detection{
		ID:          match.RuleID,
		Type:        types.DetectionTypeSigma,
		Severity:    match.Severity,
		Confidence:  0.85, // Live data has good confidence
		Timestamp:   match.Timestamp,
		Description: desc,
		MITRE: &types.MITREMapping{
			Tactics:    match.MITRE.Tactics,
			Techniques: match.MITRE.Techniques,
		},
		SigmaRules: []string{match.RuleID},
		Details: map[string]interface{}{
			"rule_id":     match.RuleID,
			"rule_name":   match.RuleName,
			"description": match.Description,
			"category":    match.Category,
			"source":      source,
			"tags":        match.Tags,
		},
	}
}

// BuildProcessMap creates a PID to process path mapping
func BuildProcessMap(processes []types.ProcessInfo) map[uint32]string {
	processMap := make(map[uint32]string)
	for _, proc := range processes {
		if proc.Path != "" {
			processMap[proc.PID] = proc.Path
		} else {
			processMap[proc.PID] = proc.Name
		}
	}
	return processMap
}

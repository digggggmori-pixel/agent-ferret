// Package sigma provides Sigma rule matching engine
package sigma

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ProcessSigmaResult pairs a sigma match with the source process that triggered it.
type ProcessSigmaResult struct {
	Match   *SigmaMatch
	Process types.ProcessInfo
}

// NetworkSigmaResult pairs a sigma match with the source connection that triggered it.
type NetworkSigmaResult struct {
	Match      *SigmaMatch
	Connection types.NetworkConnection
}

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

// ScanLiveProcesses scans live processes against Sigma rules.
// Returns results paired with the source process for context enrichment.
func ScanLiveProcesses(engine *Engine, processes []types.ProcessInfo) []ProcessSigmaResult {
	var results []ProcessSigmaResult

	for _, proc := range processes {
		event := ProcessToSigmaEvent(proc)
		procMatches := engine.Match(event)
		for _, m := range procMatches {
			results = append(results, ProcessSigmaResult{Match: m, Process: proc})
		}
	}

	return results
}

// ScanLiveNetwork scans live network connections against Sigma rules.
// processMap provides PID to process path mapping for enrichment.
// Returns results paired with the source connection for context enrichment.
func ScanLiveNetwork(engine *Engine, connections []types.NetworkConnection, processMap map[uint32]string) []NetworkSigmaResult {
	var results []NetworkSigmaResult

	for _, conn := range connections {
		processPath := ""
		if path, ok := processMap[conn.OwningPID]; ok {
			processPath = path
		}

		event := NetworkToSigmaEvent(conn, processPath)
		connMatches := engine.Match(event)
		for _, m := range connMatches {
			results = append(results, NetworkSigmaResult{Match: m, Connection: conn})
		}
	}

	return results
}

// baseSigmaDetection builds the common Detection fields for a live sigma match.
func baseSigmaDetection(match *SigmaMatch, source string) types.Detection {
	desc := match.Description
	if desc == "" {
		desc = match.RuleName
	}
	return types.Detection{
		ID:          fmt.Sprintf("sigma-%s-%d", match.RuleID[:8], match.Timestamp.UnixNano()),
		Type:        types.DetectionTypeSigma,
		Severity:    match.Severity,
		Confidence:  0.85,
		Timestamp:   match.Timestamp,
		Description: desc,
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
			"source":      source,
			"tags":        match.Tags,
		},
	}
}

// ConvertSigmaMatchToDetection converts a SigmaMatch to a types.Detection (no context).
func ConvertSigmaMatchToDetection(match *SigmaMatch, source string) types.Detection {
	return baseSigmaDetection(match, source)
}

// ConvertProcessSigmaMatch converts a sigma match with its source process context.
func ConvertProcessSigmaMatch(result ProcessSigmaResult) types.Detection {
	d := baseSigmaDetection(result.Match, "live_process")
	proc := result.Process
	d.Process = &types.ProcessInfo{
		PID:        proc.PID,
		PPID:       proc.PPID,
		Name:       proc.Name,
		Path:       proc.Path,
		CommandLine: proc.CommandLine,
		CreateTime: proc.CreateTime,
		User:       proc.User,
		ParentName: proc.ParentName,
		ParentPath: proc.ParentPath,
	}
	return d
}

// ConvertNetworkSigmaMatch converts a sigma match with its source network context.
func ConvertNetworkSigmaMatch(result NetworkSigmaResult) types.Detection {
	d := baseSigmaDetection(result.Match, "live_network")
	conn := result.Connection
	d.Network = &types.NetworkConnection{
		Protocol:    conn.Protocol,
		LocalAddr:   conn.LocalAddr,
		LocalPort:   conn.LocalPort,
		RemoteAddr:  conn.RemoteAddr,
		RemotePort:  conn.RemotePort,
		State:       conn.State,
		OwningPID:   conn.OwningPID,
		ProcessName: conn.ProcessName,
	}
	return d
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

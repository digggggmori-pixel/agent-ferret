// Package output handles CLI output formatting
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
)

// Options for output handler
type Options struct {
	Quiet   bool
	Verbose bool
	JSON    bool
}

// Handler manages CLI output
type Handler struct {
	opts Options
}

// New creates a new output handler
func New(opts Options) *Handler {
	return &Handler{opts: opts}
}

// PrintHeader prints the scan header
func (h *Handler) PrintHeader(version string) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}

	hostname, _ := os.Hostname()
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Agent Lite v%s - Baseline Security Scan                          ║\n", version)
	fmt.Printf("║  Host: %-60s║\n", hostname)
	fmt.Printf("║  Time: %-60s║\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// PrintStep prints a scan step
func (h *Handler) PrintStep(current, total int, message string) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("[%d/%d] %s\n", current, total, message)
}

// PrintDetail prints a detail line
func (h *Handler) PrintDetail(format string, args ...interface{}) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("      └─ "+format+"\n", args...)
}

// PrintDone prints completion time
func (h *Handler) PrintDone(duration time.Duration) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("      └─ Done (%.1fs)\n\n", duration.Seconds())
}

// PrintError prints an error message
func (h *Handler) PrintError(format string, args ...interface{}) {
	if h.opts.JSON {
		return
	}
	fmt.Printf("      └─ ERROR: "+format+"\n", args...)
}

// PrintDetectorResult prints detector result with alignment
func (h *Handler) PrintDetectorResult(name string, count int) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	dots := 45 - len(name)
	if dots < 3 {
		dots = 3
	}
	dotStr := ""
	for i := 0; i < dots; i++ {
		dotStr += "."
	}
	fmt.Printf("      ├─ %s%s %d found\n", name, dotStr, count)
}

// PrintSummary prints the scan summary
func (h *Handler) PrintSummary(result *types.ScanResult, duration time.Duration) {
	if h.opts.JSON {
		return
	}

	total := result.Summary.Detections.Critical +
		result.Summary.Detections.High +
		result.Summary.Detections.Medium +
		result.Summary.Detections.Low

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Scan Complete! (%.1fs total)                                        ║\n", duration.Seconds())
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Detection Summary                                                   ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────────── ║")
	fmt.Printf("║  🔴 Critical: %2d                                                     ║\n", result.Summary.Detections.Critical)
	fmt.Printf("║  🟠 High:     %2d                                                     ║\n", result.Summary.Detections.High)
	fmt.Printf("║  🟡 Medium:   %2d                                                     ║\n", result.Summary.Detections.Medium)
	fmt.Printf("║  🟢 Low:      %2d                                                     ║\n", result.Summary.Detections.Low)
	fmt.Println("║  ─────────────────────────────────────────────────────────────────── ║")
	fmt.Printf("║  Total: %d detections                                                ║\n", total)
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// PrintHighSeverityDetections prints high and critical detections
func (h *Handler) PrintHighSeverityDetections(detections []types.Detection) {
	if h.opts.JSON {
		return
	}

	var highSeverity []types.Detection
	for _, d := range detections {
		if d.Severity == types.SeverityCritical || d.Severity == types.SeverityHigh {
			highSeverity = append(highSeverity, d)
		}
	}

	if len(highSeverity) == 0 {
		return
	}

	fmt.Println("High Severity Detections:")
	fmt.Println("┌────┬─────────────────────────────────────────────────────────────────┐")

	for i, d := range highSeverity {
		severityStr := "HIGH"
		if d.Severity == types.SeverityCritical {
			severityStr = "CRITICAL"
		}

		fmt.Printf("│ #%d │ [%s] %s\n", i+1, severityStr, truncate(d.Description, 50))

		if d.Process != nil {
			fmt.Printf("│    │ PID: %d", d.Process.PID)
			if d.Process.ParentName != "" {
				fmt.Printf(", Parent: %s (PID: %d)", d.Process.ParentName, d.Process.PPID)
			}
			fmt.Println()
			if d.Process.CommandLine != "" {
				fmt.Printf("│    │ Cmdline: %s\n", truncate(d.Process.CommandLine, 50))
			}
		}

		if len(d.SigmaRules) > 0 {
			fmt.Printf("│    │ Sigma: %s\n", d.SigmaRules[0])
		}

		if i < len(highSeverity)-1 {
			fmt.Println("├────┼─────────────────────────────────────────────────────────────────┤")
		}
	}

	fmt.Println("└────┴─────────────────────────────────────────────────────────────────┘")
	fmt.Println()
}

// PrintUploadStatus prints upload status
func (h *Handler) PrintUploadStatus(endpoint string, success bool) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}

	fmt.Println("Uploading to server...")
	fmt.Printf("      └─ Endpoint: %s\n", endpoint)
	if success {
		fmt.Println("      └─ Upload complete (HTTP 200)")
	} else {
		fmt.Println("      └─ Upload failed")
	}
	fmt.Println()
}

// SaveResults saves scan results to file
func (h *Handler) SaveResults(result *types.ScanResult, outputDir string) {
	filename := fmt.Sprintf("scan_%s.json", time.Now().Format("2006-01-02_150405"))
	fullPath := filepath.Join(outputDir, filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		h.PrintError("Failed to marshal results: %v", err)
		return
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		h.PrintError("Failed to create output directory: %v", err)
		return
	}

	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		h.PrintError("Failed to write results: %v", err)
		return
	}

	if !h.opts.Quiet && !h.opts.JSON {
		fmt.Printf("Full results: %s\n", fullPath)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// SaveDetailedReport saves a detailed human-readable text report
func (h *Handler) SaveDetailedReport(result *types.ScanResult, outputDir string) {
	filename := fmt.Sprintf("scan_report_%s.txt", time.Now().Format("2006-01-02_150405"))
	fullPath := filepath.Join(outputDir, filename)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		h.PrintError("Failed to create output directory: %v", err)
		return
	}

	file, err := os.Create(fullPath)
	if err != nil {
		h.PrintError("Failed to create report file: %v", err)
		return
	}
	defer file.Close()

	// Write header
	fmt.Fprintln(file, "================================================================================")
	fmt.Fprintln(file, "                    AGENT LITE - SECURITY SCAN REPORT")
	fmt.Fprintln(file, "================================================================================")
	fmt.Fprintln(file)
	fmt.Fprintf(file, "Scan ID:       %s\n", result.ScanID)
	fmt.Fprintf(file, "Agent Version: %s\n", result.AgentVersion)
	fmt.Fprintf(file, "Scan Time:     %s\n", result.ScanTime.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(file, "Duration:      %d ms\n", result.ScanDurationMs)
	fmt.Fprintln(file)

	// Write host info
	fmt.Fprintln(file, "--------------------------------------------------------------------------------")
	fmt.Fprintln(file, "HOST INFORMATION")
	fmt.Fprintln(file, "--------------------------------------------------------------------------------")
	fmt.Fprintf(file, "Hostname:      %s\n", result.Host.Hostname)
	fmt.Fprintf(file, "OS Version:    %s\n", result.Host.OSVersion)
	fmt.Fprintf(file, "Architecture:  %s\n", result.Host.Arch)
	fmt.Fprintf(file, "Domain:        %s\n", result.Host.Domain)
	fmt.Fprintf(file, "IP Addresses:  %v\n", result.Host.IPAddresses)
	fmt.Fprintln(file)

	// Write summary
	fmt.Fprintln(file, "--------------------------------------------------------------------------------")
	fmt.Fprintln(file, "SCAN SUMMARY")
	fmt.Fprintln(file, "--------------------------------------------------------------------------------")
	fmt.Fprintf(file, "Total Processes:   %d\n", result.Summary.TotalProcesses)
	fmt.Fprintf(file, "Total Connections: %d\n", result.Summary.TotalConnections)
	fmt.Fprintf(file, "Total Services:    %d\n", result.Summary.TotalServices)
	fmt.Fprintln(file)
	fmt.Fprintln(file, "Detection Counts:")
	fmt.Fprintf(file, "  [CRITICAL] %d\n", result.Summary.Detections.Critical)
	fmt.Fprintf(file, "  [HIGH]     %d\n", result.Summary.Detections.High)
	fmt.Fprintf(file, "  [MEDIUM]   %d\n", result.Summary.Detections.Medium)
	fmt.Fprintf(file, "  [LOW]      %d\n", result.Summary.Detections.Low)
	total := result.Summary.Detections.Critical + result.Summary.Detections.High +
		result.Summary.Detections.Medium + result.Summary.Detections.Low
	fmt.Fprintf(file, "  TOTAL:     %d\n", total)
	fmt.Fprintln(file)

	// Write all detections
	fmt.Fprintln(file, "================================================================================")
	fmt.Fprintln(file, "                         DETAILED DETECTIONS")
	fmt.Fprintln(file, "================================================================================")
	fmt.Fprintln(file)

	if len(result.Detections) == 0 {
		fmt.Fprintln(file, "No detections found.")
	} else {
		// Group by severity
		criticals := filterBySeverity(result.Detections, types.SeverityCritical)
		highs := filterBySeverity(result.Detections, types.SeverityHigh)
		mediums := filterBySeverity(result.Detections, types.SeverityMedium)
		lows := filterBySeverity(result.Detections, types.SeverityLow)

		if len(criticals) > 0 {
			fmt.Fprintln(file, "=== CRITICAL SEVERITY ===")
			writeDetections(file, criticals)
		}
		if len(highs) > 0 {
			fmt.Fprintln(file, "=== HIGH SEVERITY ===")
			writeDetections(file, highs)
		}
		if len(mediums) > 0 {
			fmt.Fprintln(file, "=== MEDIUM SEVERITY ===")
			writeDetections(file, mediums)
		}
		if len(lows) > 0 {
			fmt.Fprintln(file, "=== LOW SEVERITY ===")
			writeDetections(file, lows)
		}
	}

	// Write footer
	fmt.Fprintln(file)
	fmt.Fprintln(file, "================================================================================")
	fmt.Fprintf(file, "Report generated at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(file, "================================================================================")

	if !h.opts.Quiet && !h.opts.JSON {
		fmt.Printf("Detailed report: %s\n", fullPath)
	}
}

func filterBySeverity(detections []types.Detection, severity string) []types.Detection {
	var result []types.Detection
	for _, d := range detections {
		if d.Severity == severity {
			result = append(result, d)
		}
	}
	return result
}

func writeDetections(file *os.File, detections []types.Detection) {
	for i, d := range detections {
		fmt.Fprintf(file, "\n[%d] %s\n", i+1, d.Description)
		fmt.Fprintf(file, "    Type:       %s\n", d.Type)
		fmt.Fprintf(file, "    Severity:   %s\n", d.Severity)
		fmt.Fprintf(file, "    Confidence: %.0f%%\n", d.Confidence*100)
		fmt.Fprintf(file, "    Timestamp:  %s\n", d.Timestamp.Format("2006-01-02 15:04:05"))

		if d.Process != nil {
			fmt.Fprintln(file, "    Process Info:")
			fmt.Fprintf(file, "      - Name:        %s\n", d.Process.Name)
			fmt.Fprintf(file, "      - PID:         %d\n", d.Process.PID)
			fmt.Fprintf(file, "      - PPID:        %d\n", d.Process.PPID)
			if d.Process.ParentName != "" {
				fmt.Fprintf(file, "      - Parent:      %s\n", d.Process.ParentName)
			}
			if d.Process.Path != "" {
				fmt.Fprintf(file, "      - Path:        %s\n", d.Process.Path)
			}
			if d.Process.CommandLine != "" {
				fmt.Fprintf(file, "      - CommandLine: %s\n", d.Process.CommandLine)
			}
			if d.Process.User != "" {
				fmt.Fprintf(file, "      - User:        %s\n", d.Process.User)
			}
			fmt.Fprintf(file, "      - CreateTime:  %s\n", d.Process.CreateTime.Format("2006-01-02 15:04:05"))
		}

		if d.Network != nil {
			fmt.Fprintln(file, "    Network Info:")
			fmt.Fprintf(file, "      - Protocol:    %s\n", d.Network.Protocol)
			fmt.Fprintf(file, "      - Local:       %s:%d\n", d.Network.LocalAddr, d.Network.LocalPort)
			fmt.Fprintf(file, "      - Remote:      %s:%d\n", d.Network.RemoteAddr, d.Network.RemotePort)
			fmt.Fprintf(file, "      - State:       %s\n", d.Network.State)
			fmt.Fprintf(file, "      - OwningPID:   %d\n", d.Network.OwningPID)
		}

		if d.MITRE != nil {
			fmt.Fprintln(file, "    MITRE ATT&CK:")
			if len(d.MITRE.Tactics) > 0 {
				fmt.Fprintf(file, "      - Tactics:     %v\n", d.MITRE.Tactics)
			}
			if len(d.MITRE.Techniques) > 0 {
				fmt.Fprintf(file, "      - Techniques:  %v\n", d.MITRE.Techniques)
			}
		}

		if len(d.SigmaRules) > 0 {
			fmt.Fprintf(file, "    Sigma Rules: %v\n", d.SigmaRules)
		}

		if len(d.Details) > 0 {
			fmt.Fprintln(file, "    Additional Details:")
			for k, v := range d.Details {
				fmt.Fprintf(file, "      - %s: %v\n", k, v)
			}
		}

		fmt.Fprintln(file, "    ------------------------------------------------------------------------")
	}
	fmt.Fprintln(file)
}

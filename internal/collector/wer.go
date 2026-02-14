package collector

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// WERCollector collects Windows Error Reporting entries
type WERCollector struct{}

// NewWERCollector creates a new WER collector
func NewWERCollector() *WERCollector {
	return &WERCollector{}
}

// WER report directories
var werPaths = []string{
	`ProgramData\Microsoft\Windows\WER\ReportArchive`,
	`ProgramData\Microsoft\Windows\WER\ReportQueue`,
}

// Collect reads WER report metadata files
func (c *WERCollector) Collect() ([]types.WEREntry, error) {
	logger.Section("WER Collection")
	startTime := time.Now()

	var entries []types.WEREntry

	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	for _, werRelPath := range werPaths {
		werPath := filepath.Join(systemDrive+`\`, werRelPath)

		reportDirs, err := os.ReadDir(werPath)
		if err != nil {
			continue
		}

		for _, reportDir := range reportDirs {
			if !reportDir.IsDir() {
				continue
			}

			reportPath := filepath.Join(werPath, reportDir.Name())
			entry := c.parseWERReport(reportPath)
			if entry != nil {
				entries = append(entries, *entry)
			}

			if len(entries) >= 500 {
				break
			}
		}
	}

	logger.Timing("WERCollector.Collect", startTime)
	logger.Info("WER: %d crash reports collected", len(entries))

	return entries, nil
}

// parseWERReport parses a WER report.wer file
func (c *WERCollector) parseWERReport(reportDir string) *types.WEREntry {
	// Look for Report.wer file
	werFile := filepath.Join(reportDir, "Report.wer")
	data, err := os.ReadFile(werFile)
	if err != nil {
		return nil
	}

	content := string(data)
	entry := &types.WEREntry{
		ReportPath: reportDir,
	}

	// Parse key-value pairs from .wer file
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "EventType":
			entry.EventType = value
		case "Sig[0].Name":
			if value == "Application Name" {
				// Next Sig[0].Value will be the app name
			}
		case "Sig[0].Value":
			entry.FaultingApp = value
		case "DynamicSig[2].Value":
			// Often contains the faulting module path
			if entry.FaultingPath == "" {
				entry.FaultingPath = value
			}
		case "Sig[6].Value":
			entry.ExceptionCode = value
		}
	}

	// Parse report time from directory modification time
	info, err := os.Stat(reportDir)
	if err == nil {
		entry.ReportTime = info.ModTime()
	}

	// Also try to get app name from P1 line or AppPath
	for _, line := range lines {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "AppPath" {
			entry.FaultingPath = value
			if entry.FaultingApp == "" {
				entry.FaultingApp = filepath.Base(value)
			}
		}
	}

	if entry.FaultingApp == "" && entry.EventType == "" {
		return nil
	}

	return entry
}

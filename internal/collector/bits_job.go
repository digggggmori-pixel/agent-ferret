package collector

import (
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// BITSCollector collects Background Intelligent Transfer Service jobs
type BITSCollector struct{}

// NewBITSCollector creates a new BITS collector
func NewBITSCollector() *BITSCollector {
	return &BITSCollector{}
}

// Collect retrieves BITS transfer jobs using bitsadmin.exe (native Windows binary)
func (c *BITSCollector) Collect() ([]types.BITSJobInfo, error) {
	logger.Section("BITS Job Collection")
	startTime := time.Now()

	var entries []types.BITSJobInfo

	// Use bitsadmin.exe directly (no PowerShell)
	cmd := exec.Command("bitsadmin", "/list", "/allusers", "/verbose")
	output, err := cmd.Output()
	if err != nil {
		// Try without /allusers (non-admin)
		cmd2 := exec.Command("bitsadmin", "/list", "/verbose")
		output, err = cmd2.Output()
		if err != nil {
			logger.Debug("Cannot collect BITS jobs: %v", err)
			return entries, nil
		}
	}

	entries = c.parseBitsadminOutput(string(output))

	logger.Timing("BITSCollector.Collect", startTime)
	logger.Info("BITS: %d jobs collected", len(entries))

	return entries, nil
}

// parseBitsadminOutput parses verbose output from bitsadmin /list /verbose
func (c *BITSCollector) parseBitsadminOutput(output string) []types.BITSJobInfo {
	var entries []types.BITSJobInfo

	guidRe := regexp.MustCompile(`(?i)GUID\s*:\s*(.+)`)
	displayRe := regexp.MustCompile(`(?i)DISPLAY\s*:\s*(.+)`)
	typeRe := regexp.MustCompile(`(?i)TYPE\s*:\s*(.+)`)
	stateRe := regexp.MustCompile(`(?i)STATE\s*:\s*(.+)`)
	ownerRe := regexp.MustCompile(`(?i)OWNER\s*:\s*(.+)`)
	creationRe := regexp.MustCompile(`(?i)CREATION TIME\s*:\s*(.+)`)

	var current *types.BITSJobInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if m := guidRe.FindStringSubmatch(line); len(m) > 1 {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &types.BITSJobInfo{
				JobID: strings.TrimSpace(m[1]),
			}
		}

		if current == nil {
			continue
		}

		if m := displayRe.FindStringSubmatch(line); len(m) > 1 {
			current.DisplayName = strings.TrimSpace(m[1])
		}
		if m := typeRe.FindStringSubmatch(line); len(m) > 1 {
			current.JobType = strings.TrimSpace(m[1])
		}
		if m := stateRe.FindStringSubmatch(line); len(m) > 1 {
			current.State = strings.TrimSpace(m[1])
		}
		if m := ownerRe.FindStringSubmatch(line); len(m) > 1 {
			current.Owner = strings.TrimSpace(m[1])
		}
		if m := creationRe.FindStringSubmatch(line); len(m) > 1 {
			tsStr := strings.TrimSpace(m[1])
			current.CreatedAt, _ = time.Parse("1/2/2006 3:04:05 PM", tsStr)
			if current.CreatedAt.IsZero() {
				current.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", tsStr)
			}
		}
		// URL / remote file
		if strings.HasPrefix(strings.ToUpper(line), "REMOTE NAME") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				current.URL = strings.TrimSpace(parts[1])
			}
		}
		// Local file
		if strings.HasPrefix(strings.ToUpper(line), "LOCAL NAME") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				current.LocalFile = strings.TrimSpace(parts[1])
			}
		}
	}

	if current != nil {
		entries = append(entries, *current)
	}

	return entries
}

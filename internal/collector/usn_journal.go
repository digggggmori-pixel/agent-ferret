package collector

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// USNJournalCollector reads the USN Change Journal for file change history
type USNJournalCollector struct{}

// NewUSNJournalCollector creates a new USN Journal collector
func NewUSNJournalCollector() *USNJournalCollector {
	return &USNJournalCollector{}
}

// Collect reads recent USN Journal entries using fsutil directly
func (c *USNJournalCollector) Collect() ([]types.USNJournalEntry, error) {
	logger.Section("USN Journal Collection")
	startTime := time.Now()

	var entries []types.USNJournalEntry

	// Check if USN journal exists (requires admin)
	checkCmd := exec.Command("fsutil", "usn", "queryjournal", "C:")
	if err := checkCmd.Run(); err != nil {
		logger.Debug("Cannot query USN journal (admin required)")
		return entries, nil
	}

	// Enumerate USN records directly via fsutil (native Windows binary, no PS)
	// HighUsn must be large enough to cover the full USN range (not just 1)
	enumCmd := exec.Command("fsutil", "usn", "enumdata", "1", "0", "9223372036854775807", "C:")
	output, err := enumCmd.Output()
	if err != nil {
		logger.Debug("Cannot enumerate USN data: %v", err)
		return entries, nil
	}

	// Decode from OEM codepage (e.g. CP949 on Korean Windows) to UTF-8
	outputStr := decodeOEMOutput(output)

	// Log first 300 chars to help diagnose locale parsing issues
	peek := outputStr
	if len(peek) > 300 {
		peek = peek[:300]
	}
	logger.Debug("USN enumdata output (first 300 chars): %s", peek)

	entries = c.parseFsutilOutput(outputStr)

	logger.Timing("USNJournalCollector.Collect", startTime)
	logger.Info("USN Journal: %d entries collected", len(entries))

	return entries, nil
}

// parseFsutilOutput parses the text output from "fsutil usn enumdata"
// Supports both English and Korean locale field names.
func (c *USNJournalCollector) parseFsutilOutput(output string) []types.USNJournalEntry {
	var entries []types.USNJournalEntry

	// English and Korean field name patterns for fsutil output
	fileRefRe := regexp.MustCompile(`(?:File Ref#|파일 참조#|파일 Ref#)\s*:\s*(.+)`)
	parentRefRe := regexp.MustCompile(`(?:Parent File Ref#|부모 파일 참조#|상위 파일 Ref#)\s*:\s*(.+)`)
	usnRe := regexp.MustCompile(`(?:Usn|USN)\s*:\s*(\d+)`)
	fileNameRe := regexp.MustCompile(`(?:File Name|파일 이름|파일 명)\s*:\s*(.+)`)
	reasonRe := regexp.MustCompile(`(?:Reason|이유)\s*:\s*(.+)`)
	timeStampRe := regexp.MustCompile(`(?:Time Stamp|타임 스탬프|타임스탬프)\s*:\s*(.+)`)

	var currentFileName, currentReason string
	var currentUSN int64
	var currentFileRef, currentParentRef uint64

	lines := strings.Split(output, "\n")
	count := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if m := fileRefRe.FindStringSubmatch(line); len(m) > 1 {
			refStr := strings.TrimSpace(m[1])
			refStr = strings.TrimPrefix(refStr, "0x")
			currentFileRef, _ = strconv.ParseUint(refStr, 16, 64)
		}
		if m := parentRefRe.FindStringSubmatch(line); len(m) > 1 {
			refStr := strings.TrimSpace(m[1])
			refStr = strings.TrimPrefix(refStr, "0x")
			currentParentRef, _ = strconv.ParseUint(refStr, 16, 64)
		}
		if m := usnRe.FindStringSubmatch(line); len(m) > 1 {
			currentUSN, _ = strconv.ParseInt(strings.TrimSpace(m[1]), 10, 64)
		}
		if m := fileNameRe.FindStringSubmatch(line); len(m) > 1 {
			currentFileName = strings.TrimSpace(m[1])
		}
		if m := reasonRe.FindStringSubmatch(line); len(m) > 1 {
			currentReason = strings.TrimSpace(m[1])
		}
		// Time Stamp is the last field per record — emit entry when seen
		if m := timeStampRe.FindStringSubmatch(line); len(m) > 1 {
			tsStr := strings.TrimSpace(m[1])
			// Try multiple date formats (English and Korean locale variants)
			var ts time.Time
			for _, layout := range []string{
				"2006/01/02 15:04:05",
				"2006-01-02 15:04:05",
				time.RFC3339,
			} {
				if t, err := time.Parse(layout, tsStr); err == nil {
					ts = t
					break
				}
			}

			entries = append(entries, types.USNJournalEntry{
				USN:       currentUSN,
				FileName:  currentFileName,
				Reason:    currentReason,
				Timestamp: ts,
				FileRef:   currentFileRef,
				ParentRef: currentParentRef,
			})

			count++
			if count >= 5000 {
				break
			}
		}
	}

	return entries
}

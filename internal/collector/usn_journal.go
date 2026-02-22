package collector

import (
	"context"
	"os/exec"
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

	// Use context timeout to avoid long waits (fsutil enumdata can take 40+ seconds)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Enumerate USN records directly via fsutil (native Windows binary, no PS)
	enumCmd := exec.CommandContext(ctx, "fsutil", "usn", "enumdata", "1", "0", "9223372036854775807", "C:")
	output, err := enumCmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			if len(output) > 0 {
				logger.Debug("USN enumdata timed out after 15s, using partial output (%d bytes)", len(output))
			} else {
				logger.Debug("USN enumdata timed out after 15s with no output")
				return entries, nil
			}
		} else {
			logger.Debug("Cannot enumerate USN data: %v", err)
			return entries, nil
		}
	}

	// Decode from OEM codepage (e.g. CP949 on Korean Windows) to UTF-8
	outputStr := decodeOEMOutput(output)

	// Log first 500 chars to help diagnose locale parsing issues
	peek := outputStr
	if len(peek) > 500 {
		peek = peek[:500]
	}
	logger.Debug("USN enumdata output (first 500 chars): %s", peek)

	entries = c.parseFsutilOutput(outputStr)

	logger.Timing("USNJournalCollector.Collect", startTime)
	logger.Info("USN Journal: %d entries collected", len(entries))

	return entries, nil
}

// parseFsutilOutput parses the text output from "fsutil usn enumdata".
// Uses blank lines as record separators.
// Supports both English and Korean locale field names:
//
//	EN: File Ref#, Parent File Ref#, Usn, File Name, Reason, Time Stamp
//	KO: 파일 참조 번호, 부모 파일 참조 번호, USN, 이름(NNN), 이유, 타임 스탬프
func (c *USNJournalCollector) parseFsutilOutput(output string) []types.USNJournalEntry {
	var entries []types.USNJournalEntry

	var currentFileName, currentReason string
	var currentUSN int64
	var currentFileRef, currentParentRef uint64
	var currentTimestamp time.Time
	hasData := false
	count := 0

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Blank line = record boundary — emit current record
		if line == "" {
			if hasData && currentFileName != "" {
				entries = append(entries, types.USNJournalEntry{
					USN:       currentUSN,
					FileName:  currentFileName,
					Reason:    currentReason,
					Timestamp: currentTimestamp,
					FileRef:   currentFileRef,
					ParentRef: currentParentRef,
				})
				count++
				if count >= 5000 {
					break
				}
			}
			currentFileName = ""
			currentReason = ""
			currentUSN = 0
			currentFileRef = 0
			currentParentRef = 0
			currentTimestamp = time.Time{}
			hasData = false
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		keyLower := strings.ToLower(key)

		switch {
		// File Reference Number
		// EN: "File Ref#" / KO: "파일 참조 번호"
		case (strings.Contains(key, "파일") && strings.Contains(key, "참조") &&
			!strings.Contains(key, "부모") && !strings.Contains(key, "상위")) ||
			(strings.Contains(keyLower, "file ref") && !strings.Contains(keyLower, "parent")):
			currentFileRef = parseHexRef(value)
			hasData = true

		// Parent File Reference Number
		// EN: "Parent File Ref#" / KO: "부모 파일 참조 번호"
		case strings.Contains(key, "부모") || strings.Contains(key, "상위") ||
			strings.Contains(keyLower, "parent"):
			currentParentRef = parseHexRef(value)

		// USN (hex in KO, decimal in EN)
		case keyLower == "usn":
			currentUSN = parseHexOrDecimal(value)

		// File Name
		// EN: "File Name" / KO: "이름" (with optional "(NNN)" length suffix)
		case strings.HasPrefix(key, "이름") || strings.Contains(keyLower, "file name"):
			currentFileName = value

		// Reason (hex flags in both locales)
		// EN: "Reason" / KO: "이유"
		case key == "이유" || strings.Contains(keyLower, "reason"):
			currentReason = decodeUSNReason(value)

		// Time Stamp (may not exist in all locales / enumdata)
		// EN: "Time Stamp" / KO: "타임 스탬프" / "타임스탬프"
		case strings.Contains(keyLower, "time stamp") || strings.Contains(key, "타임"):
			for _, layout := range []string{
				"2006/01/02 15:04:05",
				"2006-01-02 15:04:05",
				time.RFC3339,
			} {
				if t, err := time.Parse(layout, value); err == nil {
					currentTimestamp = t
					break
				}
			}
		}
	}

	// Emit last record if no trailing blank line
	if hasData && currentFileName != "" {
		entries = append(entries, types.USNJournalEntry{
			USN:       currentUSN,
			FileName:  currentFileName,
			Reason:    currentReason,
			Timestamp: currentTimestamp,
			FileRef:   currentFileRef,
			ParentRef: currentParentRef,
		})
	}

	return entries
}

// parseHexRef parses a hex reference number (potentially 128-bit), returning the lower 64 bits.
func parseHexRef(value string) uint64 {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "0x")
	value = strings.TrimPrefix(value, "0X")
	// For 128-bit refs (32 hex chars), take the last 16 chars (lower 64 bits)
	if len(value) > 16 {
		value = value[len(value)-16:]
	}
	ref, _ := strconv.ParseUint(value, 16, 64)
	return ref
}

// parseHexOrDecimal parses a value that could be hex (0x...) or decimal.
func parseHexOrDecimal(value string) int64 {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		hex := value[2:]
		n, _ := strconv.ParseInt(hex, 16, 64)
		return n
	}
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}

// decodeUSNReason converts hex reason flags to a human-readable pipe-separated string.
func decodeUSNReason(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "0x") && !strings.HasPrefix(value, "0X") {
		return value
	}
	hex := value[2:]
	reason, _ := strconv.ParseUint(hex, 16, 32)
	if reason == 0 {
		return ""
	}

	reasonFlags := []struct {
		flag uint32
		name string
	}{
		{0x00000001, "DATA_OVERWRITE"},
		{0x00000002, "DATA_EXTEND"},
		{0x00000004, "DATA_TRUNCATION"},
		{0x00000010, "NAMED_DATA_OVERWRITE"},
		{0x00000020, "NAMED_DATA_EXTEND"},
		{0x00000040, "NAMED_DATA_TRUNCATION"},
		{0x00000100, "FILE_CREATE"},
		{0x00000200, "FILE_DELETE"},
		{0x00000400, "EA_CHANGE"},
		{0x00000800, "SECURITY_CHANGE"},
		{0x00001000, "RENAME_OLD_NAME"},
		{0x00002000, "RENAME_NEW_NAME"},
		{0x00004000, "INDEXABLE_CHANGE"},
		{0x00008000, "BASIC_INFO_CHANGE"},
		{0x00010000, "HARD_LINK_CHANGE"},
		{0x00020000, "COMPRESSION_CHANGE"},
		{0x00040000, "ENCRYPTION_CHANGE"},
		{0x00080000, "OBJECT_ID_CHANGE"},
		{0x00100000, "REPARSE_POINT_CHANGE"},
		{0x00200000, "STREAM_CHANGE"},
		{0x80000000, "CLOSE"},
	}

	var reasons []string
	for _, rf := range reasonFlags {
		if uint32(reason)&rf.flag != 0 {
			reasons = append(reasons, rf.name)
		}
	}

	if len(reasons) == 0 {
		return value
	}
	return strings.Join(reasons, "|")
}

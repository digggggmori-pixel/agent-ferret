package collector

import (
	"encoding/binary"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// BAMCollector parses Background Activity Moderator (BAM) / Desktop Activity Moderator (DAM) entries
// Available on Windows 10 1709+ (Build 16299+)
type BAMCollector struct{}

// NewBAMCollector creates a new BAM/DAM collector
func NewBAMCollector() *BAMCollector {
	return &BAMCollector{}
}

// BAM registry paths
var bamPaths = []string{
	`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`,
	`SYSTEM\CurrentControlSet\Services\dam\State\UserSettings`,
	// Older versions (pre-1809)
	`SYSTEM\CurrentControlSet\Services\bam\UserSettings`,
	`SYSTEM\CurrentControlSet\Services\dam\UserSettings`,
}

// Collect reads BAM/DAM entries from the registry
func (c *BAMCollector) Collect() ([]types.BAMEntry, error) {
	logger.Section("BAM/DAM Collection")
	startTime := time.Now()

	var entries []types.BAMEntry

	for _, bamPath := range bamPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, bamPath, registry.READ)
		if err != nil {
			continue
		}

		// Each subkey is a user SID
		subKeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, sid := range subKeys {
			userKey, err := registry.OpenKey(key, sid, registry.READ)
			if err != nil {
				continue
			}

			valueNames, err := userKey.ReadValueNames(-1)
			if err != nil {
				userKey.Close()
				continue
			}

			username := sidToUsername(sid)

			for _, valueName := range valueNames {
				// Skip non-path values (like Version and SequenceNumber)
				if valueName == "Version" || valueName == "SequenceNumber" {
					continue
				}

				data, _, err := userKey.GetBinaryValue(valueName)
				if err != nil || len(data) < 8 {
					continue
				}

				// BAM data format: 8 bytes FILETIME (last execution time)
				ft := binary.LittleEndian.Uint64(data[0:8])
				lastExec := filetimeToTime(ft)

				if lastExec.IsZero() {
					continue
				}

				entry := types.BAMEntry{
					Path:          valueName,
					LastExecution: lastExec,
					User:          username,
				}

				entries = append(entries, entry)
			}

			userKey.Close()

			if len(entries) >= 2000 {
				break
			}
		}

		key.Close()
	}

	logger.Timing("BAMCollector.Collect", startTime)
	logger.Info("BAM/DAM: %d entries collected", len(entries))

	return entries, nil
}

// sidToUsername attempts to convert a SID string to a username
func sidToUsername(sid string) string {
	// Try to resolve SID to username via registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid,
		registry.READ)
	if err != nil {
		return sid
	}
	defer key.Close()

	profilePath, _, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return sid
	}

	// Extract username from profile path (e.g., C:\Users\john → john)
	for i := len(profilePath) - 1; i >= 0; i-- {
		if profilePath[i] == '\\' {
			return profilePath[i+1:]
		}
	}
	return sid
}

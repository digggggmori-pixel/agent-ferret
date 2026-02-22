package collector

import (
	"encoding/binary"
	"time"
	"unicode/utf16"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// ShimcacheCollector parses AppCompatCache (Shimcache) from registry
type ShimcacheCollector struct{}

// NewShimcacheCollector creates a new Shimcache collector
func NewShimcacheCollector() *ShimcacheCollector {
	return &ShimcacheCollector{}
}

// Collect reads and parses the AppCompatCache registry value
func (c *ShimcacheCollector) Collect() ([]types.ShimcacheEntry, error) {
	logger.Section("Shimcache Collection")
	startTime := time.Now()

	var entries []types.ShimcacheEntry

	// Open the AppCompatCache registry key
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
		registry.READ)
	if err != nil {
		logger.Error("Cannot open AppCompatCache key: %v", err)
		return entries, nil
	}
	defer key.Close()

	// Read the binary value
	data, _, err := key.GetBinaryValue("AppCompatCache")
	if err != nil {
		logger.Error("Cannot read AppCompatCache value: %v", err)
		return entries, nil
	}

	if len(data) < 48 {
		logger.Error("AppCompatCache data too small: %d bytes", len(data))
		return entries, nil
	}

	// Parse header signature to determine format
	sig := binary.LittleEndian.Uint32(data[0:4])
	logger.Debug("Shimcache: signature=0x%x, dataLen=%d", sig, len(data))

	switch sig {
	case 0x30, 0x34:
		// Windows 10/11 format (signature 0x30 or 0x34)
		entries = parseWin10Shimcache(data)
	default:
		headerLen := len(data)
		if headerLen > 64 {
			headerLen = 64
		}
		logger.Debug("Unknown Shimcache signature: 0x%x, first %d bytes: %x", sig, headerLen, data[:headerLen])
		return entries, nil
	}

	logger.Timing("ShimcacheCollector.Collect", startTime)
	logger.Info("Shimcache: %d entries parsed", len(entries))

	return entries, nil
}

// parseWin10Shimcache parses Windows 10/11 AppCompatCache format
// Win10/11 format:
//   The signature value (0x30 or 0x34) equals the header size in bytes.
//   Entries start at offset = signature value:
//     Signature "10ts" (4 bytes)
//     Unknown (4 bytes)
//     DataSize (4 bytes)
//     PathSize (2 bytes)
//     Path (UTF-16LE, PathSize bytes)
//     LastModifiedTime (FILETIME, 8 bytes)
//     DataSize2 (4 bytes)
//     Data (DataSize2 bytes)
func parseWin10Shimcache(data []byte) []types.ShimcacheEntry {
	var entries []types.ShimcacheEntry
	// The first uint32 (signature) is also the header size: 0x30=48, 0x34=52
	sig := binary.LittleEndian.Uint32(data[0:4])
	offset := int(sig)
	order := 0

	for offset < len(data)-12 {
		// Check for entry signature "10ts"
		if string(data[offset:offset+4]) != "10ts" {
			if order == 0 {
				// First entry doesn't have expected magic — log for debugging
				peekLen := 16
				if offset+peekLen > len(data) {
					peekLen = len(data) - offset
				}
				logger.Debug("Shimcache: no '10ts' magic at offset %d, got: %x", offset, data[offset:offset+peekLen])
			}
			break
		}

		entryStart := offset
		offset += 4 // Skip signature

		// Unknown field
		offset += 4

		// Cache entry data size (total size of this entry minus the header)
		if offset+4 > len(data) {
			break
		}
		_ = binary.LittleEndian.Uint32(data[offset : offset+4]) // cache entry size (skip)
		offset += 4

		// Path size in bytes
		if offset+2 > len(data) {
			break
		}
		pathSize := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2

		// Read path (UTF-16LE)
		if offset+pathSize > len(data) {
			break
		}
		path := decodeUTF16LE(data[offset : offset+pathSize])
		offset += pathSize

		// Last modified time (FILETIME)
		var lastModified time.Time
		if offset+8 <= len(data) {
			ft := binary.LittleEndian.Uint64(data[offset : offset+8])
			lastModified = filetimeToTime(ft)
		}
		offset += 8

		// Data size
		var dataSize uint32
		if offset+4 <= len(data) {
			dataSize = binary.LittleEndian.Uint32(data[offset : offset+4])
		}
		offset += 4

		// Guard against corrupt data: shimcache data blobs should be small
		if dataSize > 65536 {
			break
		}

		// Skip data blob
		offset += int(dataSize)

		entry := types.ShimcacheEntry{
			Order:        order,
			Path:         path,
			LastModified: lastModified,
			DataSize:     dataSize,
		}

		entries = append(entries, entry)
		order++

		// Safety: ensure we're making progress
		if offset <= entryStart {
			break
		}

		// Reasonable limit
		if order >= 1024 {
			break
		}
	}

	return entries
}

// decodeUTF16LE decodes UTF-16LE bytes to a Go string
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}

	// Remove null terminator if present
	for len(u16s) > 0 && u16s[len(u16s)-1] == 0 {
		u16s = u16s[:len(u16s)-1]
	}

	return string(utf16.Decode(u16s))
}

// filetimeToTime converts a Windows FILETIME (100-nanosecond intervals since Jan 1, 1601) to time.Time
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME epoch is January 1, 1601
	// Unix epoch is January 1, 1970
	// Difference = 116444736000000000 (in 100-nanosecond intervals)
	const filetimeEpochDiff = 116444736000000000
	// Max reasonable FILETIME: year 2100 = ~157766880000000000
	const filetimeMax = 157766880000000000
	if ft < filetimeEpochDiff || ft > filetimeMax {
		return time.Time{}
	}
	nsec := (ft - filetimeEpochDiff) * 100
	return time.Unix(0, int64(nsec))
}

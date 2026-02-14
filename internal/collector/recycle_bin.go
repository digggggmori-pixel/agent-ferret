package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// RecycleBinCollector parses Recycle Bin $I files for deleted file metadata
type RecycleBinCollector struct{}

// NewRecycleBinCollector creates a new Recycle Bin collector
func NewRecycleBinCollector() *RecycleBinCollector {
	return &RecycleBinCollector{}
}

// Collect reads $I files from the Recycle Bin for all users
func (c *RecycleBinCollector) Collect() ([]types.RecycleBinEntry, error) {
	logger.Section("Recycle Bin Collection")
	startTime := time.Now()

	var entries []types.RecycleBinEntry

	// $Recycle.Bin is on the system drive
	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	recyclePath := filepath.Join(systemDrive+`\`, "$Recycle.Bin")

	// Enumerate SID directories
	sidDirs, err := os.ReadDir(recyclePath)
	if err != nil {
		logger.Debug("Cannot read Recycle Bin: %v", err)
		return entries, nil
	}

	for _, sidDir := range sidDirs {
		if !sidDir.IsDir() || !strings.HasPrefix(sidDir.Name(), "S-") {
			continue
		}

		sid := sidDir.Name()
		username := sidToUsername(sid)
		sidPath := filepath.Join(recyclePath, sid)

		files, err := os.ReadDir(sidPath)
		if err != nil {
			continue
		}

		for _, f := range files {
			if !strings.HasPrefix(f.Name(), "$I") {
				continue
			}

			iFilePath := filepath.Join(sidPath, f.Name())
			entry := c.parseIFile(iFilePath, username)
			if entry != nil {
				entries = append(entries, *entry)
			}

			if len(entries) >= 1000 {
				break
			}
		}

		if len(entries) >= 1000 {
			break
		}
	}

	logger.Timing("RecycleBinCollector.Collect", startTime)
	logger.Info("Recycle Bin: %d deleted file entries", len(entries))

	return entries, nil
}

// parseIFile parses a $I file (Vista+ format)
// Format:
//   Version (8 bytes) - 1 for Vista/7, 2 for Win10+
//   FileSize (8 bytes)
//   DeletedTime (8 bytes, FILETIME)
//   V1: PathLength (4 bytes) + Path (UTF-16LE, 520 bytes)
//   V2: PathLength (4 bytes) + Path (UTF-16LE, variable)
func (c *RecycleBinCollector) parseIFile(path, username string) *types.RecycleBinEntry {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 24 {
		return nil
	}

	version := binary.LittleEndian.Uint64(data[0:8])
	fileSize := int64(binary.LittleEndian.Uint64(data[8:16]))
	deletedFT := binary.LittleEndian.Uint64(data[16:24])
	deletedTime := filetimeToTime(deletedFT)

	var originalPath string

	switch version {
	case 1:
		// Vista/7: fixed 520 bytes for path (UTF-16LE)
		if len(data) >= 24+520 {
			originalPath = decodeUTF16LETerminated(data[24 : 24+520])
		}
	case 2:
		// Win10+: 4 bytes path length + variable path
		if len(data) >= 28 {
			pathLen := binary.LittleEndian.Uint32(data[24:28])
			if pathLen > 32768 {
				return nil
			}
			pathBytes := int(pathLen) * 2 // UTF-16LE
			if len(data) >= 28+pathBytes {
				originalPath = decodeUTF16LETerminated(data[28 : 28+pathBytes])
			}
		}
	default:
		return nil
	}

	if originalPath == "" {
		return nil
	}

	return &types.RecycleBinEntry{
		OriginalPath: originalPath,
		DeletedTime:  deletedTime,
		FileSize:     fileSize,
		User:         username,
	}
}

// decodeUTF16LETerminated decodes UTF-16LE bytes to a Go string, stopping at null terminator
func decodeUTF16LETerminated(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
		if u16s[i] == 0 {
			u16s = u16s[:i]
			break
		}
	}

	return string(utf16.Decode(u16s))
}


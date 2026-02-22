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

// JumplistCollector parses Jumplist (.automaticDestinations-ms) and .lnk files
type JumplistCollector struct{}

// NewJumplistCollector creates a new Jumplist collector
func NewJumplistCollector() *JumplistCollector {
	return &JumplistCollector{}
}

// Collect reads Jumplist and recent LNK files from all user profiles
func (c *JumplistCollector) Collect() ([]types.JumplistEntry, error) {
	logger.Section("Jumplist/LNK Collection")
	startTime := time.Now()

	var entries []types.JumplistEntry

	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err != nil {
		logger.Error("Cannot list user directories: %v", err)
		return entries, nil
	}

	for _, userDir := range userDirs {
		if !userDir.IsDir() || isSystemProfile(userDir.Name()) {
			continue
		}

		username := userDir.Name()
		userHome := filepath.Join(usersDir, username)

		// Recent items (LNK files)
		recentPath := filepath.Join(userHome, `AppData\Roaming\Microsoft\Windows\Recent`)
		entries = append(entries, c.collectLNKFiles(recentPath, username)...)

		// AutomaticDestinations (Jumplist)
		jumplistPath := filepath.Join(userHome, `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`)
		entries = append(entries, c.collectJumplists(jumplistPath, username)...)

		if len(entries) >= 2000 {
			break
		}
	}

	logger.Timing("JumplistCollector.Collect", startTime)
	logger.Info("Jumplist/LNK: %d entries collected", len(entries))

	return entries, nil
}

// collectLNKFiles parses .lnk files from a directory
func (c *JumplistCollector) collectLNKFiles(dir, username string) []types.JumplistEntry {
	var entries []types.JumplistEntry

	files, err := os.ReadDir(dir)
	if err != nil {
		return entries
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".lnk") {
			continue
		}

		lnkPath := filepath.Join(dir, f.Name())
		entry := c.parseLNKFile(lnkPath, username)
		if entry != nil {
			entries = append(entries, *entry)
		}

		if len(entries) >= 500 {
			break
		}
	}

	return entries
}

// parseLNKFile parses a Windows .lnk (Shell Link) file
// Ref: [MS-SHLLINK] Shell Link Binary File Format
func (c *JumplistCollector) parseLNKFile(path, username string) *types.JumplistEntry {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 76 {
		return nil
	}

	// Verify LNK header magic: 4C 00 00 00
	if data[0] != 0x4C || data[1] != 0x00 || data[2] != 0x00 || data[3] != 0x00 {
		return nil
	}

	// LinkFlags at offset 20 (4 bytes)
	linkFlags := binary.LittleEndian.Uint32(data[20:24])

	// Creation time at offset 28 (8 bytes, FILETIME)
	creationFT := binary.LittleEndian.Uint64(data[28:36])
	creationTime := filetimeToTime(creationFT)

	// Access time at offset 36 (8 bytes, FILETIME)
	accessFT := binary.LittleEndian.Uint64(data[36:44])
	accessTime := filetimeToTime(accessFT)

	entry := &types.JumplistEntry{
		AccessTime:   accessTime,
		CreationTime: creationTime,
		User:         username,
	}

	// Parse LinkTargetIDList if present (bit 0 of flags)
	offset := 76
	hasTargetIDList := linkFlags&0x01 != 0
	if hasTargetIDList {
		if offset+2 > len(data) {
			return entry
		}
		idListSize := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2 + idListSize
	}

	// Parse LinkInfo if present (bit 1 of flags)
	hasLinkInfo := linkFlags&0x02 != 0
	if hasLinkInfo && offset+4 <= len(data) {
		linkInfoSize := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if linkInfoSize >= 28 && offset+linkInfoSize <= len(data) {
			// LocalBasePath offset at LinkInfo+16
			localBasePathOffset := int(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
			if localBasePathOffset > 0 && offset+localBasePathOffset < len(data) {
				// Read null-terminated string
				pathStart := offset + localBasePathOffset
				pathEnd := pathStart
				for pathEnd < len(data) && data[pathEnd] != 0 {
					pathEnd++
				}
				entry.TargetPath = string(data[pathStart:pathEnd])
			}
		}
		offset += linkInfoSize
	}

	// Parse StringData: NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS
	hasName := linkFlags&0x04 != 0
	hasRelPath := linkFlags&0x08 != 0
	hasWorkingDir := linkFlags&0x10 != 0
	hasArguments := linkFlags&0x20 != 0
	isUnicode := linkFlags&0x80 != 0

	if hasName {
		offset = skipStringData(data, offset, isUnicode)
	}
	if hasRelPath {
		if entry.TargetPath == "" {
			s, newOffset := readStringData(data, offset, isUnicode)
			entry.TargetPath = s
			offset = newOffset
		} else {
			offset = skipStringData(data, offset, isUnicode)
		}
	}
	if hasWorkingDir {
		s, newOffset := readStringData(data, offset, isUnicode)
		entry.WorkingDir = s
		offset = newOffset
	}
	if hasArguments {
		s, _ := readStringData(data, offset, isUnicode)
		entry.Arguments = s
	}

	if entry.TargetPath == "" {
		return nil
	}

	return entry
}

// skipStringData skips a StringData entry and returns new offset
func skipStringData(data []byte, offset int, isUnicode bool) int {
	if offset+2 > len(data) {
		return len(data)
	}
	charCount := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if isUnicode {
		offset += charCount * 2
	} else {
		offset += charCount
	}
	return offset
}

// readStringData reads a StringData entry
func readStringData(data []byte, offset int, isUnicode bool) (string, int) {
	if offset+2 > len(data) {
		return "", len(data)
	}
	charCount := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if isUnicode {
		byteLen := charCount * 2
		if offset+byteLen > len(data) {
			return "", len(data)
		}
		u16s := make([]uint16, charCount)
		for i := 0; i < charCount; i++ {
			u16s[i] = binary.LittleEndian.Uint16(data[offset+i*2:])
		}
		return string(utf16.Decode(u16s)), offset + byteLen
	}

	if offset+charCount > len(data) {
		return "", len(data)
	}
	return string(data[offset : offset+charCount]), offset + charCount
}

// collectJumplists reads .automaticDestinations-ms files
// These are OLE Compound Documents containing embedded LNK streams
func (c *JumplistCollector) collectJumplists(dir, username string) []types.JumplistEntry {
	var entries []types.JumplistEntry

	files, err := os.ReadDir(dir)
	if err != nil {
		return entries
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".automaticdestinations-ms") {
			continue
		}

		// Extract AppID from filename (first part before the dot)
		appID := strings.Split(f.Name(), ".")[0]

		info, err := f.Info()
		if err != nil {
			continue
		}

		// For automaticDestinations files, we just record their existence and metadata
		// Full OLE parsing would be very complex
		entries = append(entries, types.JumplistEntry{
			AppID:      appID,
			TargetPath: filepath.Join(dir, f.Name()),
			AccessTime: info.ModTime(),
			User:       username,
		})
	}

	return entries
}

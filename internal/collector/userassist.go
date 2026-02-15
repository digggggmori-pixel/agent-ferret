package collector

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// UserAssistCollector parses UserAssist registry entries (ROT13 encoded program execution history)
type UserAssistCollector struct{}

// NewUserAssistCollector creates a new UserAssist collector
func NewUserAssistCollector() *UserAssistCollector {
	return &UserAssistCollector{}
}

// Known UserAssist GUIDs
var userAssistGUIDs = []string{
	"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", // Executable File Execution
	"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}", // Shortcut File Execution
}

// Collect reads UserAssist entries from all user profiles
func (c *UserAssistCollector) Collect() ([]types.UserAssistEntry, error) {
	logger.Section("UserAssist Collection")
	startTime := time.Now()

	var entries []types.UserAssistEntry

	// Enumerate user profiles via HKU
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
		userEntries := c.collectForUser(username)
		entries = append(entries, userEntries...)
	}

	// Also try current user via HKCU
	if len(entries) == 0 {
		entries = c.collectFromHKCU()
	}

	logger.Timing("UserAssistCollector.Collect", startTime)
	logger.Info("UserAssist: %d entries collected", len(entries))

	return entries, nil
}

func (c *UserAssistCollector) collectFromHKCU() []types.UserAssistEntry {
	var entries []types.UserAssistEntry

	for _, guid := range userAssistGUIDs {
		keyPath := fmt.Sprintf(`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\%s\Count`, guid)
		key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
		if err != nil {
			continue
		}

		valueNames, err := key.ReadValueNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, valueName := range valueNames {
			data, _, err := key.GetBinaryValue(valueName)
			if err != nil || len(data) < 16 {
				continue
			}

			decoded := rot13(valueName)
			entry := parseUserAssistData(decoded, data, "")
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
		key.Close()
	}

	return entries
}

// collectForUser loads another user's NTUSER.DAT via reg.exe and reads UserAssist keys
func (c *UserAssistCollector) collectForUser(username string) []types.UserAssistEntry {
	var entries []types.UserAssistEntry

	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	ntUserPath := filepath.Join(usersDir, username, "NTUSER.DAT")
	if _, err := os.Stat(ntUserPath); err != nil {
		return entries
	}

	tempKeyName := fmt.Sprintf("FERRET_UA_%s", username)

	// Load the user's registry hive (requires admin, fails for logged-in users)
	loadCmd := exec.Command("reg.exe", "load", `HKLM\`+tempKeyName, ntUserPath)
	if err := loadCmd.Run(); err != nil {
		return entries
	}
	defer func() {
		unloadCmd := exec.Command("reg.exe", "unload", `HKLM\`+tempKeyName)
		unloadCmd.Run()
	}()

	for _, guid := range userAssistGUIDs {
		keyPath := fmt.Sprintf(`%s\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\%s\Count`, tempKeyName, guid)
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
		if err != nil {
			continue
		}

		valueNames, err := key.ReadValueNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, valueName := range valueNames {
			data, _, err := key.GetBinaryValue(valueName)
			if err != nil || len(data) < 16 {
				continue
			}

			decoded := rot13(valueName)
			entry := parseUserAssistData(decoded, data, username)
			if entry != nil {
				entries = append(entries, *entry)
			}
		}
		key.Close()
	}

	return entries
}

// parseUserAssistData parses the binary data from a UserAssist registry value
// Win7+ format: 4 bytes session, 4 bytes run count, 4 bytes focus count, ... 8 bytes FILETIME (last execution)
func parseUserAssistData(name string, data []byte, user string) *types.UserAssistEntry {
	if len(data) < 72 {
		// Win7+ format is 72 bytes
		if len(data) < 16 {
			return nil
		}
	}

	var runCount uint32
	var lastExec time.Time

	if len(data) >= 72 {
		// Windows 7+ format (72 bytes)
		runCount = binary.LittleEndian.Uint32(data[4:8])
		ft := binary.LittleEndian.Uint64(data[60:68])
		lastExec = filetimeToTime(ft)
	} else if len(data) >= 16 {
		// Windows XP format (16 bytes) - unlikely but handle
		runCount = binary.LittleEndian.Uint32(data[4:8])
		ft := binary.LittleEndian.Uint64(data[8:16])
		lastExec = filetimeToTime(ft)
	}

	if runCount == 0 && lastExec.IsZero() {
		return nil
	}

	return &types.UserAssistEntry{
		Name:          name,
		RunCount:      runCount,
		LastExecution: lastExec,
		User:          user,
	}
}

// rot13 decodes a ROT13 encoded string (UserAssist uses ROT13 on value names)
func rot13(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z':
			result[i] = (c-'A'+13)%26 + 'A'
		case c >= 'a' && c <= 'z':
			result[i] = (c-'a'+13)%26 + 'a'
		default:
			result[i] = c
		}
	}
	return string(result)
}

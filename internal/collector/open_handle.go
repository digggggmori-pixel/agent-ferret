package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

// OpenHandleCollector detects processes with handles to LSASS
type OpenHandleCollector struct{}

// NewOpenHandleCollector creates a new open handle collector
func NewOpenHandleCollector() *OpenHandleCollector {
	return &OpenHandleCollector{}
}

// Collect enumerates processes with handles to LSASS (credential dump detection)
func (c *OpenHandleCollector) Collect() ([]types.HandleInfo, error) {
	logger.Section("Open Handle Collection")
	startTime := time.Now()

	var entries []types.HandleInfo

	// Find LSASS PID first
	lsassPID := findLsassPID()
	if lsassPID == 0 {
		logger.Debug("Could not find LSASS process")
		return entries, nil
	}

	entries = c.detectLSASSAccess(lsassPID)

	logger.Timing("OpenHandleCollector.Collect", startTime)
	logger.Info("Open handles: %d suspicious LSASS access entries", len(entries))

	return entries, nil
}

// findLsassPID finds the PID of lsass.exe
func findLsassPID() uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	for err == nil {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(name, "lsass.exe") {
			return pe.ProcessID
		}
		err = windows.Process32Next(snapshot, &pe)
	}
	return 0
}

// detectLSASSAccess checks for credential dump indicators using native Go
func (c *OpenHandleCollector) detectLSASSAccess(lsassPID uint32) []types.HandleInfo {
	var entries []types.HandleInfo

	// 1. Check for known credential dumping tool processes
	entries = append(entries, c.findSuspiciousProcesses(lsassPID)...)

	// 2. Check for recent LSASS dump files
	entries = append(entries, c.findDumpFiles(lsassPID)...)

	return entries
}

// findSuspiciousProcesses enumerates running processes looking for known cred-dump tools
func (c *OpenHandleCollector) findSuspiciousProcesses(lsassPID uint32) []types.HandleInfo {
	var entries []types.HandleInfo

	suspiciousNames := map[string]bool{
		"procdump":   true,
		"procdump64": true,
		"mimikatz":   true,
		"pypykatz":   true,
		"dumpert":    true,
		"nanodump":   true,
		"handlekatz": true,
		"lsassy":     true,
		"samdump":    true,
		"samdump2":   true,
	}
	sekurlsaPattern := regexp.MustCompile(`(?i)sekurlsa`)

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return entries
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	for err == nil {
		name := windows.UTF16ToString(pe.ExeFile[:])
		baseName := strings.ToLower(strings.TrimSuffix(name, ".exe"))

		if suspiciousNames[baseName] || sekurlsaPattern.MatchString(baseName) {
			processPath := ""
			if h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID); e == nil {
				var buf [windows.MAX_PATH]uint16
				pathLen := uint32(len(buf))
				if windows.QueryFullProcessImageName(h, 0, &buf[0], &pathLen) == nil {
					processPath = windows.UTF16ToString(buf[:pathLen])
				}
				windows.CloseHandle(h)
			}
			entries = append(entries, types.HandleInfo{
				ProcessPID:  pe.ProcessID,
				ProcessName: name,
				ProcessPath: processPath,
				TargetPID:   lsassPID,
				TargetName:  "lsass.exe",
				HandleType:  "process",
			})
		}
		err = windows.Process32Next(snapshot, &pe)
	}

	return entries
}

// findDumpFiles checks for recent LSASS minidump files
func (c *OpenHandleCollector) findDumpFiles(lsassPID uint32) []types.HandleInfo {
	var entries []types.HandleInfo

	cutoff := time.Now().AddDate(0, 0, -7)
	dumpPattern := regexp.MustCompile(`(?i)lsass|procdump|minidump`)

	searchDirs := []string{
		os.TempDir(),
		`C:\Windows\Temp`,
	}

	for _, dir := range searchDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			ext := strings.ToLower(filepath.Ext(name))

			// Check .dmp files or files matching lsass patterns
			if ext != ".dmp" && !dumpPattern.MatchString(name) {
				continue
			}

			info, err := f.Info()
			if err != nil || info.ModTime().Before(cutoff) {
				continue
			}

			if dumpPattern.MatchString(name) {
				entries = append(entries, types.HandleInfo{
					ProcessPID:  0,
					ProcessName: "lsass_dump_file",
					ProcessPath: filepath.Join(dir, name),
					TargetPID:   lsassPID,
					TargetName:  "lsass.exe",
					HandleType:  "process",
				})
			}
		}
	}

	return entries
}

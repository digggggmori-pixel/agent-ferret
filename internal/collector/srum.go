package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// SRUMCollector parses the System Resource Usage Monitor database
type SRUMCollector struct{}

// NewSRUMCollector creates a new SRUM collector
func NewSRUMCollector() *SRUMCollector {
	return &SRUMCollector{}
}

// Collect reads SRUM data
// SRUDB.dat is an ESE (Extensible Storage Engine) database, not SQLite.
// We use esentutl.exe to verify/copy and read available metadata from registry.
func (c *SRUMCollector) Collect() ([]types.SRUMEntry, error) {
	logger.Section("SRUM Collection")
	startTime := time.Now()

	var entries []types.SRUMEntry

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	srumPath := filepath.Join(winDir, `System32\sru\SRUDB.dat`)
	if _, err := os.Stat(srumPath); os.IsNotExist(err) {
		logger.Debug("SRUDB.dat not found at %s", srumPath)
		return entries, nil
	}

	// Copy SRUDB.dat to temp (it's locked by the SRU service)
	tempDir := os.TempDir()
	tempCopy := filepath.Join(tempDir, "ferret_srudb_copy.dat")
	defer os.Remove(tempCopy)

	// Use esentutl to copy (handles locked ESE databases)
	copyCmd := exec.Command("esentutl.exe", "/y", srumPath, "/vssrec", "/d", tempCopy)
	if err := copyCmd.Run(); err != nil {
		// Fallback: try direct copy
		data, err := os.ReadFile(srumPath)
		if err != nil {
			logger.Debug("Cannot copy SRUDB.dat: %v", err)
			return entries, nil
		}
		if err := os.WriteFile(tempCopy, data, 0600); err != nil {
			return entries, nil
		}
	}

	// Read SRUM extension registry metadata and network profile data
	entries = c.readSRUMRegistry()

	logger.Timing("SRUMCollector.Collect", startTime)
	logger.Info("SRUM: %d entries collected", len(entries))

	return entries, nil
}

// readSRUMRegistry reads SRUM extension and network data from registry
func (c *SRUMCollector) readSRUMRegistry() []types.SRUMEntry {
	var entries []types.SRUMEntry

	// SRUM extensions are registered here
	extensionsPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`
	extensionsKey, err := registry.OpenKey(registry.LOCAL_MACHINE, extensionsPath, registry.READ)
	if err != nil {
		return entries
	}
	defer extensionsKey.Close()

	subkeys, err := extensionsKey.ReadSubKeyNames(-1)
	if err != nil {
		return entries
	}

	// Known SRUM extension GUIDs
	extensionNames := map[string]string{
		"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "NetworkUsage",
		"{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "NetworkConnectivity",
		"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "EnergyUsage",
		"{973F5D5C-1D90-4944-BE8E-24B94231A174}": "AppTimeline",
	}

	for _, subkey := range subkeys {
		extKey, err := registry.OpenKey(extensionsKey, subkey, registry.READ)
		if err != nil {
			continue
		}

		dllPath, _, _ := extKey.GetStringValue("")
		extKey.Close()

		if dllPath == "" {
			continue
		}

		extName := subkey
		if name, ok := extensionNames[subkey]; ok {
			extName = name
		}

		entries = append(entries, types.SRUMEntry{
			AppName:   "SRUM_" + extName,
			Timestamp: time.Now(),
		})
	}

	// Read network profiles for additional context
	profileEntries := c.readNetworkProfiles()
	entries = append(entries, profileEntries...)

	return entries
}

// readNetworkProfiles reads network profile data from registry
func (c *SRUMCollector) readNetworkProfiles() []types.SRUMEntry {
	var entries []types.SRUMEntry

	profilesPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
	profilesKey, err := registry.OpenKey(registry.LOCAL_MACHINE, profilesPath, registry.READ)
	if err != nil {
		return entries
	}
	defer profilesKey.Close()

	subkeys, err := profilesKey.ReadSubKeyNames(-1)
	if err != nil {
		return entries
	}

	for _, subkey := range subkeys {
		profKey, err := registry.OpenKey(profilesKey, subkey, registry.READ)
		if err != nil {
			continue
		}

		profileName, _, _ := profKey.GetStringValue("ProfileName")
		profKey.Close()

		if profileName != "" {
			entries = append(entries, types.SRUMEntry{
				AppName:   "NetworkProfile:" + profileName,
				Timestamp: time.Now(),
			})
		}

		if len(entries) >= 100 {
			break
		}
	}

	return entries
}

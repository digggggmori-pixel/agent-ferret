package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// AmcacheCollector parses the Amcache.hve registry hive
type AmcacheCollector struct{}

// NewAmcacheCollector creates a new Amcache collector
func NewAmcacheCollector() *AmcacheCollector {
	return &AmcacheCollector{}
}

const amcacheTempKey = `FERRET_AMCACHE_TEMP`

// Collect reads Amcache.hve and returns application execution history
func (c *AmcacheCollector) Collect() ([]types.AmcacheEntry, error) {
	logger.Section("Amcache Collection")
	startTime := time.Now()

	var entries []types.AmcacheEntry

	// Strategy 1: Try to load hive via reg.exe (requires admin)
	entries = c.tryLoadHive()

	// Strategy 2: Fallback to PowerShell with compat flags registry
	if len(entries) == 0 {
		entries = c.tryPowerShellFallback()
	}

	logger.Timing("AmcacheCollector.Collect", startTime)
	logger.Info("Amcache: %d entries collected", len(entries))

	return entries, nil
}

func (c *AmcacheCollector) tryLoadHive() []types.AmcacheEntry {
	var entries []types.AmcacheEntry

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	amcachePath := filepath.Join(winDir, `appcompat\Programs\Amcache.hve`)

	// Check if file exists
	if _, err := os.Stat(amcachePath); os.IsNotExist(err) {
		logger.Debug("Amcache.hve not found at %s", amcachePath)
		return entries
	}

	// Copy to temp to avoid lock issues (use esentutl for locked files)
	tempDir := os.TempDir()
	tempCopy := filepath.Join(tempDir, "ferret_amcache_copy.hve")
	defer os.Remove(tempCopy)

	// Try esentutl first (can copy locked files)
	copyCmd := exec.Command("esentutl.exe", "/y", amcachePath, "/vssrec", "/d", tempCopy)
	if err := copyCmd.Run(); err != nil {
		// Fallback: simple copy (works if file isn't exclusively locked)
		data, err := os.ReadFile(amcachePath)
		if err != nil {
			logger.Debug("Cannot copy Amcache.hve: %v", err)
			return entries
		}
		if err := os.WriteFile(tempCopy, data, 0600); err != nil {
			return entries
		}
	}

	// Load the hive copy into a temporary registry location
	loadCmd := exec.Command("reg.exe", "load", `HKLM\`+amcacheTempKey, tempCopy)
	if err := loadCmd.Run(); err != nil {
		logger.Debug("Cannot load Amcache hive: %v (admin required)", err)
		return entries
	}

	// Ensure we unload the hive when done
	defer func() {
		unloadCmd := exec.Command("reg.exe", "unload", `HKLM\`+amcacheTempKey)
		unloadCmd.Run()
	}()

	// Read InventoryApplicationFile entries
	entries = c.readInventoryApplicationFile()

	return entries
}

func (c *AmcacheCollector) readInventoryApplicationFile() []types.AmcacheEntry {
	var entries []types.AmcacheEntry

	keyPath := amcacheTempKey + `\Root\InventoryApplicationFile`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		logger.Debug("Cannot open InventoryApplicationFile: %v", err)
		return entries
	}
	defer key.Close()

	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return entries
	}

	for _, subKeyName := range subKeys {
		subKey, err := registry.OpenKey(key, subKeyName, registry.READ)
		if err != nil {
			continue
		}

		entry := types.AmcacheEntry{}

		if val, _, err := subKey.GetStringValue("LowerCaseLongPath"); err == nil {
			entry.Path = val
		}
		if val, _, err := subKey.GetStringValue("Name"); err == nil {
			entry.Name = val
		}
		if val, _, err := subKey.GetStringValue("Publisher"); err == nil {
			entry.Publisher = val
		}
		if val, _, err := subKey.GetStringValue("Version"); err == nil {
			entry.Version = val
		}
		if val, _, err := subKey.GetStringValue("ProductName"); err == nil {
			entry.ProductName = val
		}
		if val, _, err := subKey.GetStringValue("BinaryType"); err == nil {
			entry.BinaryType = val
		}

		// FileId contains SHA1 hash (prefixed with "0000")
		if val, _, err := subKey.GetStringValue("FileId"); err == nil {
			sha1 := strings.TrimPrefix(val, "0000")
			if len(sha1) == 40 {
				entry.SHA1 = sha1
			}
		}

		// LinkDate (compile time)
		if val, _, err := subKey.GetStringValue("LinkDate"); err == nil && val != "" {
			if t, err := time.Parse("01/02/2006 15:04:05", val); err == nil {
				entry.LinkDate = t
			}
		}

		// Size
		if val, _, err := subKey.GetIntegerValue("Size"); err == nil {
			entry.Size = int64(val)
		}

		subKey.Close()

		if entry.Path != "" || entry.Name != "" {
			entries = append(entries, entry)
		}

		// Limit to avoid excessive data
		if len(entries) >= 2000 {
			break
		}
	}

	return entries
}

// amcachePSEntry matches PowerShell JSON output
type amcachePSEntry struct {
	Path       string `json:"LowerCaseLongPath"`
	Name       string `json:"Name"`
	Publisher  string `json:"Publisher"`
	Version    string `json:"Version"`
	ProductName string `json:"ProductName"`
	FileId     string `json:"FileId"`
	Size       int64  `json:"Size"`
}

func (c *AmcacheCollector) tryPowerShellFallback() []types.AmcacheEntry {
	// Use PowerShell to query Amcache via Get-ItemProperty on the hive
	// This is a lighter approach that queries program compatibility data
	psScript := fmt.Sprintf(`
$entries = @()
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
if (Test-Path $regPath) {
    $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    if ($props) {
        foreach ($name in $props.PSObject.Properties.Name) {
            if ($name -like '*\*' -and $name -notlike 'PS*') {
                $entries += @{Path=$name; Name=[System.IO.Path]::GetFileName($name)}
            }
        }
    }
}
$entries | Select-Object -First 500 | ConvertTo-Json -Compress
`)

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}

	var rawEntries []map[string]string
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse Amcache PS fallback: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single map[string]string
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	var entries []types.AmcacheEntry
	for _, raw := range rawEntries {
		entries = append(entries, types.AmcacheEntry{
			Path: raw["Path"],
			Name: raw["Name"],
		})
	}

	return entries
}

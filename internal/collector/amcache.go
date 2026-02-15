package collector

import (
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

	// Strategy 2: Fallback to native registry read of compat flags
	if len(entries) == 0 {
		entries = c.tryRegistryFallback()
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

// tryRegistryFallback reads program compatibility data directly from registry
func (c *AmcacheCollector) tryRegistryFallback() []types.AmcacheEntry {
	var entries []types.AmcacheEntry

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store`,
		registry.READ)
	if err != nil {
		return entries
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return entries
	}

	for _, name := range valueNames {
		if !strings.Contains(name, `\`) {
			continue
		}

		entries = append(entries, types.AmcacheEntry{
			Path: name,
			Name: filepath.Base(name),
		})
		if len(entries) >= 500 {
			break
		}
	}

	return entries
}

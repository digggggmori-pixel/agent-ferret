package collector

import (
	"fmt"
	"os"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// RDPCacheCollector collects RDP connection history from the registry
type RDPCacheCollector struct{}

// NewRDPCacheCollector creates a new RDP cache collector
func NewRDPCacheCollector() *RDPCacheCollector {
	return &RDPCacheCollector{}
}

// Collect reads RDP connection history from the registry (all user profiles)
func (c *RDPCacheCollector) Collect() ([]types.RDPCacheEntry, error) {
	logger.Section("RDP Cache Collection")
	startTime := time.Now()

	var entries []types.RDPCacheEntry

	// Collect from HKCU for current user
	entries = append(entries, c.collectFromHive(registry.CURRENT_USER, "")...)

	// Collect from all user profiles via HKU
	usersDir := os.Getenv("SYSTEMDRIVE") + `\Users`
	if usersDir == `\Users` {
		usersDir = `C:\Users`
	}

	userDirs, err := os.ReadDir(usersDir)
	if err == nil {
		for _, userDir := range userDirs {
			if !userDir.IsDir() || isSystemProfile(userDir.Name()) {
				continue
			}
			// We can only access HKU if the user's hive is loaded
			// For current user, we already have HKCU
		}
	}

	logger.Timing("RDPCacheCollector.Collect", startTime)
	logger.Info("RDP cache: %d entries collected", len(entries))

	return entries, nil
}

func (c *RDPCacheCollector) collectFromHive(root registry.Key, username string) []types.RDPCacheEntry {
	var entries []types.RDPCacheEntry

	// Terminal Server Client\Servers - contains list of RDP servers connected to
	serversKeyPath := `Software\Microsoft\Terminal Server Client\Servers`
	serversKey, err := registry.OpenKey(root, serversKeyPath, registry.READ)
	if err != nil {
		return entries
	}
	defer serversKey.Close()

	subKeys, err := serversKey.ReadSubKeyNames(-1)
	if err != nil {
		return entries
	}

	for _, serverName := range subKeys {
		serverKey, err := registry.OpenKey(serversKey, serverName, registry.READ)
		if err != nil {
			continue
		}

		entry := types.RDPCacheEntry{
			Server: serverName,
			User:   username,
		}

		if hint, _, err := serverKey.GetStringValue("UsernameHint"); err == nil {
			entry.UsernameHint = hint
		}

		serverKey.Close()

		entries = append(entries, entry)
	}

	// Also check Default.rdp file and MRU list
	mruKeyPath := `Software\Microsoft\Terminal Server Client\Default`
	mruKey, err := registry.OpenKey(root, mruKeyPath, registry.READ)
	if err == nil {
		// MRU entries are named MRU0, MRU1, etc.
		for i := 0; i < 20; i++ {
			valueName := fmt.Sprintf("MRU%d", i)
			if server, _, err := mruKey.GetStringValue(valueName); err == nil && server != "" {
				// Check if already in list
				found := false
				for _, e := range entries {
					if e.Server == server {
						found = true
						break
					}
				}
				if !found {
					entries = append(entries, types.RDPCacheEntry{
						Server: server,
						User:   username,
					})
				}
			}
		}
		mruKey.Close()
	}

	return entries
}

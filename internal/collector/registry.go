package collector

import (
	"fmt"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// PersistenceKeys are the 19 registry keys commonly used for persistence
var PersistenceKeys = []RegistryKeyDef{
	// HKLM Run keys
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, Category: "RunServices"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`, Category: "RunServicesOnce"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},

	// HKCU Run keys
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, Category: "RunServices"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`, Category: "RunServicesOnce"},

	// Winlogon
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, Category: "Winlogon"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`, Category: "WinlogonNotify"},

	// Image File Execution Options (debugger injection)
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "IFEO"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "IFEO"},

	// Services
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Services`, Category: "Services"},

	// Explorer
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, Category: "BHO"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, Category: "BHO"},

	// Shell extensions
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, Category: "ShellServiceObject"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, Category: "ShellServiceObject"},

	// ── Phase 1 추가 (16키) ──

	// AppInit_DLLs — DLL injection into all user-mode processes
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, Category: "AppInitDLLs"},

	// Logon script
	{Hive: registry.CURRENT_USER, Path: `Environment`, Category: "LogonScript"},

	// Print Monitors — malicious print monitor DLL
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Control\Print\Monitors`, Category: "PrintMonitors"},

	// LSA Authentication Packages
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Control\Lsa`, Category: "LSA"},

	// Time Providers — DLL hijacking via time service
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders`, Category: "TimeProviders"},

	// Active Setup — runs StubPath on user logon
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Active Setup\Installed Components`, Category: "ActiveSetup"},

	// Shell Folders / User Shell Folders — startup path redirection
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, Category: "ShellFolders"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, Category: "ShellFolders"},

	// BootExecute — pre-boot execution
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Control\Session Manager`, Category: "BootExecute"},

	// KnownDLLs — DLL hijacking
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`, Category: "KnownDLLs"},

	// Terminal Server Client — RDP connection history
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Terminal Server Client\Servers`, Category: "RDPHistory"},

	// USBSTOR — USB device history
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Enum\USBSTOR`, Category: "USBSTOR"},

	// Network profiles
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`, Category: "NetworkProfiles"},

	// User typed paths/URLs/RunMRU
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`, Category: "UserInput"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, Category: "UserInput"},

	// BAM — Background Activity Moderator (Win10 1709+)
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, Category: "BAM"},
}

// RegistryKeyDef defines a registry key to scan
type RegistryKeyDef struct {
	Hive     registry.Key
	Path     string
	Category string
}

// RegistryCollector collects registry entries for persistence analysis
type RegistryCollector struct{}

// NewRegistryCollector creates a new registry collector
func NewRegistryCollector() *RegistryCollector {
	return &RegistryCollector{}
}

// Collect gathers registry entries from persistence keys
func (c *RegistryCollector) Collect() ([]types.RegistryEntry, error) {
	logger.Section("Registry Collection")
	startTime := time.Now()
	logger.Info("Scanning %d persistence keys", len(PersistenceKeys))

	var entries []types.RegistryEntry
	keysScanned := 0
	keysFailed := 0

	for _, keyDef := range PersistenceKeys {
		fullPath := hiveName(keyDef.Hive) + "\\" + keyDef.Path
		logger.Debug("Scanning registry key: %s", fullPath)

		keyEntries, err := c.collectKey(keyDef)
		if err != nil {
			// Key might not exist, skip silently
			keysFailed++
			logger.Debug("Key not accessible: %s (%v)", fullPath, err)
			continue
		}
		keysScanned++
		if len(keyEntries) > 0 {
			logger.Debug("Found %d entries in %s", len(keyEntries), fullPath)
		}
		entries = append(entries, keyEntries...)
	}

	logger.Timing("RegistryCollector.Collect", startTime)
	logger.Info("Registry collection complete: %d entries from %d keys (%d inaccessible)",
		len(entries), keysScanned, keysFailed)

	// Log sample entries
	if len(entries) > 0 {
		logger.SubSection("Sample Registry Entries (first 10)")
		for i, entry := range entries {
			if i >= 10 {
				break
			}
			logger.Debug("Registry: %s\\%s = %s", entry.Key, entry.ValueName, truncateValue(entry.ValueData, 100))
		}
	}

	return entries, nil
}

func truncateValue(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (c *RegistryCollector) collectKey(keyDef RegistryKeyDef) ([]types.RegistryEntry, error) {
	key, err := registry.OpenKey(keyDef.Hive, keyDef.Path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	var entries []types.RegistryEntry

	// Get all value names
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	fullPath := hiveName(keyDef.Hive) + "\\" + keyDef.Path

	for _, valueName := range valueNames {
		// Read the value
		value, valueType, err := readRegistryValue(key, valueName)
		if err != nil {
			continue
		}

		entry := types.RegistryEntry{
			Key:       fullPath,
			ValueName: valueName,
			ValueData: value,
			ValueType: registryTypeToString(valueType),
		}
		entries = append(entries, entry)
	}

	// For some keys we need to enumerate subkeys
	subkeyCategories := map[string]bool{
		"Services": true, "IFEO": true, "PrintMonitors": true,
		"TimeProviders": true, "ActiveSetup": true, "RDPHistory": true,
		"USBSTOR": true, "NetworkProfiles": true, "BAM": true,
	}
	if subkeyCategories[keyDef.Category] {
		subkeyEntries, _ := c.collectSubkeys(keyDef)
		entries = append(entries, subkeyEntries...)
	}

	return entries, nil
}

func (c *RegistryCollector) collectSubkeys(keyDef RegistryKeyDef) ([]types.RegistryEntry, error) {
	key, err := registry.OpenKey(keyDef.Hive, keyDef.Path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	var entries []types.RegistryEntry

	// Get subkey names
	subkeyNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	fullPath := hiveName(keyDef.Hive) + "\\" + keyDef.Path

	// Limit to first 100 subkeys for performance
	limit := len(subkeyNames)
	if limit > 100 {
		limit = 100
	}

	for i := 0; i < limit; i++ {
		subkeyName := subkeyNames[i]
		subkeyPath := keyDef.Path + "\\" + subkeyName

		subkey, err := registry.OpenKey(keyDef.Hive, subkeyPath, registry.READ)
		if err != nil {
			continue
		}

		// For Services, get ImagePath
		if keyDef.Category == "Services" {
			if imagePath, _, err := subkey.GetStringValue("ImagePath"); err == nil {
				entry := types.RegistryEntry{
					Key:       fullPath + "\\" + subkeyName,
					ValueName: "ImagePath",
					ValueData: imagePath,
					ValueType: "REG_SZ",
				}
				entries = append(entries, entry)
			}
		}

		// For IFEO, get Debugger
		if keyDef.Category == "IFEO" {
			if debugger, _, err := subkey.GetStringValue("Debugger"); err == nil {
				entry := types.RegistryEntry{
					Key:       fullPath + "\\" + subkeyName,
					ValueName: "Debugger",
					ValueData: debugger,
					ValueType: "REG_SZ",
				}
				entries = append(entries, entry)
			}
		}

		// For Print Monitors, get Driver
		if keyDef.Category == "PrintMonitors" {
			if driver, _, err := subkey.GetStringValue("Driver"); err == nil {
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "Driver",
					ValueData: driver, ValueType: "REG_SZ",
				})
			}
		}

		// For TimeProviders, get DllName + Enabled
		if keyDef.Category == "TimeProviders" {
			if dll, _, err := subkey.GetStringValue("DllName"); err == nil {
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "DllName",
					ValueData: dll, ValueType: "REG_SZ",
				})
			}
		}

		// For Active Setup, get StubPath
		if keyDef.Category == "ActiveSetup" {
			if stub, _, err := subkey.GetStringValue("StubPath"); err == nil {
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "StubPath",
					ValueData: stub, ValueType: "REG_SZ",
				})
			}
		}

		// For RDP history, get UsernameHint
		if keyDef.Category == "RDPHistory" {
			if user, _, err := subkey.GetStringValue("UsernameHint"); err == nil {
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "UsernameHint",
					ValueData: user, ValueType: "REG_SZ",
				})
			} else {
				// Even without UsernameHint, record the server entry (subkey name = IP/hostname)
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "(server)",
					ValueData: subkeyName, ValueType: "REG_SZ",
				})
			}
		}

		// For USBSTOR, enumerate serial number subkeys for FriendlyName
		if keyDef.Category == "USBSTOR" {
			serialKeys, _ := subkey.ReadSubKeyNames(-1)
			for _, serial := range serialKeys {
				serialPath := keyDef.Path + "\\" + subkeyName + "\\" + serial
				if serialKey, err := registry.OpenKey(keyDef.Hive, serialPath, registry.READ); err == nil {
					if friendly, _, err := serialKey.GetStringValue("FriendlyName"); err == nil {
						entries = append(entries, types.RegistryEntry{
							Key: fullPath + "\\" + subkeyName + "\\" + serial, ValueName: "FriendlyName",
							ValueData: friendly, ValueType: "REG_SZ",
						})
					}
					serialKey.Close()
				}
			}
		}

		// For Network profiles, get ProfileName + DateCreated
		if keyDef.Category == "NetworkProfiles" {
			if name, _, err := subkey.GetStringValue("ProfileName"); err == nil {
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: "ProfileName",
					ValueData: name, ValueType: "REG_SZ",
				})
			}
		}

		// For BAM, enumerate all values (each value = executable path, data = FILETIME)
		if keyDef.Category == "BAM" {
			bamValues, _ := subkey.ReadValueNames(-1)
			for _, val := range bamValues {
				if val == "Version" || val == "SequenceNumber" {
					continue
				}
				data, valType, err := readRegistryValue(subkey, val)
				if err != nil {
					continue
				}
				entries = append(entries, types.RegistryEntry{
					Key: fullPath + "\\" + subkeyName, ValueName: val,
					ValueData: data, ValueType: registryTypeToString(valType),
				})
			}
		}

		subkey.Close()
	}

	return entries, nil
}

// CountByType counts entries by category
func (c *RegistryCollector) CountByType(entries []types.RegistryEntry) (run, runOnce, services int) {
	for _, entry := range entries {
		switch {
		case strings.Contains(entry.Key, "\\Run\\") || strings.HasSuffix(entry.Key, "\\Run"):
			run++
		case strings.Contains(entry.Key, "\\RunOnce"):
			runOnce++
		case strings.Contains(entry.Key, "\\Services\\"):
			services++
		}
	}
	return
}

func readRegistryValue(key registry.Key, valueName string) (string, uint32, error) {
	// Try string first
	value, valueType, err := key.GetStringValue(valueName)
	if err == nil {
		return value, valueType, nil
	}

	// Try DWORD
	dwordValue, valueType, err := key.GetIntegerValue(valueName)
	if err == nil {
		return fmt.Sprintf("%d", dwordValue), valueType, nil
	}

	// Try binary (return as hex)
	binValue, valueType, err := key.GetBinaryValue(valueName)
	if err == nil {
		return fmt.Sprintf("%x", binValue), valueType, nil
	}

	return "", 0, fmt.Errorf("failed to read value")
}

func hiveName(hive registry.Key) string {
	switch hive {
	case registry.CLASSES_ROOT:
		return "HKCR"
	case registry.CURRENT_USER:
		return "HKCU"
	case registry.LOCAL_MACHINE:
		return "HKLM"
	case registry.USERS:
		return "HKU"
	case registry.CURRENT_CONFIG:
		return "HKCC"
	default:
		return fmt.Sprintf("0x%x", hive)
	}
}

func registryTypeToString(valueType uint32) string {
	switch valueType {
	case registry.NONE:
		return "REG_NONE"
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "REG_LINK"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN(%d)", valueType)
	}
}

// FilterByCategory filters entries by category
func FilterByCategory(entries []types.RegistryEntry, category string) []types.RegistryEntry {
	var result []types.RegistryEntry
	for _, entry := range entries {
		if strings.Contains(entry.Key, category) {
			result = append(result, entry)
		}
	}
	return result
}

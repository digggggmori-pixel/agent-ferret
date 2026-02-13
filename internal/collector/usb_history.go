package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// USBHistoryCollector collects USB device connection history
type USBHistoryCollector struct{}

// NewUSBHistoryCollector creates a new USB history collector
func NewUSBHistoryCollector() *USBHistoryCollector {
	return &USBHistoryCollector{}
}

// Collect retrieves USB device connection history from registry and setupapi log
func (c *USBHistoryCollector) Collect() ([]types.USBDeviceInfo, error) {
	logger.Section("USB History Collection")
	startTime := time.Now()

	var devices []types.USBDeviceInfo

	// Read USBSTOR registry entries
	usbstorDevices := c.readUSBSTOR()
	devices = append(devices, usbstorDevices...)

	// Enrich with drive letter mappings from MountedDevices
	c.enrichDriveLetters(devices)

	// Enrich with timestamps from setupapi.dev.log
	c.enrichTimestamps(devices)

	logger.Timing("USBHistoryCollector.Collect", startTime)
	logger.Info("USB history: %d devices found", len(devices))

	return devices, nil
}

func (c *USBHistoryCollector) readUSBSTOR() []types.USBDeviceInfo {
	var devices []types.USBDeviceInfo

	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Enum\USBSTOR`, registry.READ)
	if err != nil {
		logger.Debug("Cannot open USBSTOR registry key: %v", err)
		return devices
	}
	defer key.Close()

	// Enumerate device class subkeys (e.g., Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00)
	classNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return devices
	}

	for _, className := range classNames {
		classKey, err := registry.OpenKey(key, className, registry.READ)
		if err != nil {
			continue
		}

		// Parse VID/PID from class name
		vendorID, productID := parseUSBSTORClass(className)

		// Enumerate serial number subkeys
		serialNames, err := classKey.ReadSubKeyNames(-1)
		if err != nil {
			classKey.Close()
			continue
		}

		for _, serialName := range serialNames {
			serialKey, err := registry.OpenKey(classKey, serialName, registry.READ)
			if err != nil {
				continue
			}

			device := types.USBDeviceInfo{
				DeviceID:     className + `\` + serialName,
				SerialNumber: serialName,
				VendorID:     vendorID,
				ProductID:    productID,
			}

			// Read FriendlyName
			if val, _, err := serialKey.GetStringValue("FriendlyName"); err == nil {
				device.FriendlyName = val
			}

			// Read ContainerID for correlation
			if device.FriendlyName == "" {
				device.FriendlyName = buildFriendlyName(className)
			}

			serialKey.Close()
			devices = append(devices, device)
		}

		classKey.Close()
	}

	return devices
}

// parseUSBSTORClass extracts vendor and product from USBSTOR class name
// Format: Disk&Ven_VENDOR&Prod_PRODUCT&Rev_REV
func parseUSBSTORClass(className string) (vendor, product string) {
	parts := strings.Split(className, "&")
	for _, part := range parts {
		if strings.HasPrefix(part, "Ven_") {
			vendor = strings.TrimPrefix(part, "Ven_")
		}
		if strings.HasPrefix(part, "Prod_") {
			product = strings.TrimPrefix(part, "Prod_")
		}
	}
	return
}

// buildFriendlyName constructs a name from the class name
func buildFriendlyName(className string) string {
	vendor, product := parseUSBSTORClass(className)
	if vendor != "" && product != "" {
		return vendor + " " + product
	}
	return className
}

// enrichDriveLetters maps USB devices to drive letters via MountedDevices
func (c *USBHistoryCollector) enrichDriveLetters(devices []types.USBDeviceInfo) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\MountedDevices`, registry.READ)
	if err != nil {
		return
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return
	}

	for _, name := range names {
		// Only look at drive letter mappings
		if !strings.HasPrefix(name, `\DosDevices\`) {
			continue
		}

		val, _, err := key.GetBinaryValue(name)
		if err != nil || len(val) < 4 {
			continue
		}

		// Convert binary value to string for matching
		valStr := string(val)
		driveLetter := strings.TrimPrefix(name, `\DosDevices\`)

		// Try to match with USBSTOR device IDs
		for i := range devices {
			if strings.Contains(valStr, "USBSTOR") &&
				strings.Contains(valStr, devices[i].SerialNumber) {
				devices[i].DriveLetter = driveLetter
			}
		}
	}
}

// enrichTimestamps parses setupapi.dev.log for USB install timestamps
func (c *USBHistoryCollector) enrichTimestamps(devices []types.USBDeviceInfo) {
	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	logPath := filepath.Join(winDir, "INF", "setupapi.dev.log")
	f, err := os.Open(logPath)
	if err != nil {
		logger.Debug("Cannot open setupapi.dev.log: %v", err)
		return
	}
	defer f.Close()

	// Parse log for USBSTOR entries with timestamps
	// Format: >>>  [Device Install (Hardware initiated) - USBSTOR\...]
	//         >>>  Section start 2024/01/15 14:30:22.123
	deviceInstallRe := regexp.MustCompile(`Device Install.*USBSTOR\\([^\]]+)`)
	timestampRe := regexp.MustCompile(`Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)

	scanner := bufio.NewScanner(f)
	var currentSerial string
	for scanner.Scan() {
		line := scanner.Text()

		if match := deviceInstallRe.FindStringSubmatch(line); match != nil {
			// Extract serial from the device path
			parts := strings.Split(match[1], `\`)
			if len(parts) >= 2 {
				currentSerial = parts[len(parts)-1]
			}
		}

		if currentSerial != "" {
			if match := timestampRe.FindStringSubmatch(line); match != nil {
				if t, err := time.Parse("2006/01/02 15:04:05", match[1]); err == nil {
					for i := range devices {
						if devices[i].SerialNumber == currentSerial {
							if devices[i].FirstInstall.IsZero() || t.Before(devices[i].FirstInstall) {
								devices[i].FirstInstall = t
							}
							if t.After(devices[i].LastConnect) {
								devices[i].LastConnect = t
							}
						}
					}
				}
				currentSerial = ""
			}
		}
	}
}

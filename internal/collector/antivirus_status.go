package collector

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// AntivirusCollector collects installed antivirus product status
type AntivirusCollector struct{}

// NewAntivirusCollector creates a new antivirus collector
func NewAntivirusCollector() *AntivirusCollector {
	return &AntivirusCollector{}
}

// Collect retrieves antivirus product information via WMI SecurityCenter2
func (c *AntivirusCollector) Collect() ([]types.AntivirusInfo, error) {
	logger.Section("Antivirus Status Collection")
	startTime := time.Now()

	var products []types.AntivirusInfo

	// Use PowerShell to query WMI SecurityCenter2 — avoids complex COM interop
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName + '|' + $_.instanceGuid + '|' + $_.productState.ToString() + '|' + $_.pathToSignedProductExe }`)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Error("Failed to query antivirus status: %v (stderr: %s)", err, stderr.String())
		return products, nil
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 3 {
			continue
		}

		productState, _ := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 32)
		state := uint32(productState)

		pathToExe := ""
		if len(parts) >= 4 {
			pathToExe = strings.TrimSpace(parts[3])
		}

		product := types.AntivirusInfo{
			ProductName:  strings.TrimSpace(parts[0]),
			InstanceGUID: strings.TrimSpace(parts[1]),
			ProductState: state,
			IsEnabled:    decodeAVEnabled(state),
			IsUpToDate:   decodeAVUpToDate(state),
			PathToExe:    pathToExe,
		}

		products = append(products, product)
		logger.Debug("AV Product: %s (enabled=%v, upToDate=%v)", product.ProductName, product.IsEnabled, product.IsUpToDate)
	}

	logger.Timing("AntivirusCollector.Collect", startTime)
	logger.Info("Antivirus: %d products found", len(products))

	return products, nil
}

// decodeAVEnabled decodes the productState bitmask for enabled/disabled status
// Byte 2 (bits 12-15): 0x10 = enabled, 0x00 or 0x01 = disabled
func decodeAVEnabled(state uint32) bool {
	return (state>>12)&0xF == 1
}

// decodeAVUpToDate decodes the productState bitmask for definition update status
// Byte 3 (bits 4-7): 0x00 = up to date, 0x10 = out of date
func decodeAVUpToDate(state uint32) bool {
	return (state>>4)&0xF == 0
}

package collector

import (
	"strconv"
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

	// Use native WMI COM query via go-ole (no PowerShell)
	rows, err := WMIQueryFields(`root\SecurityCenter2`,
		"SELECT displayName, instanceGuid, productState, pathToSignedProductExe FROM AntiVirusProduct",
		[]string{"displayName", "instanceGuid", "productState", "pathToSignedProductExe"})
	if err != nil {
		logger.Error("Failed to query antivirus status: %v", err)
		return products, nil
	}

	for _, row := range rows {
		stateStr := row["productState"]
		state64, _ := strconv.ParseUint(stateStr, 10, 32)
		state := uint32(state64)

		product := types.AntivirusInfo{
			ProductName:  row["displayName"],
			InstanceGUID: row["instanceGuid"],
			ProductState: state,
			IsEnabled:    decodeAVEnabled(state),
			IsUpToDate:   decodeAVUpToDate(state),
			PathToExe:    row["pathToSignedProductExe"],
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

package collector

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ARPCollector collects the ARP table
type ARPCollector struct{}

// NewARPCollector creates a new ARP collector
func NewARPCollector() *ARPCollector {
	return &ARPCollector{}
}

// Note: modiphlpapi is declared in network.go (same package)
var (
	procGetIpNetTable = modiphlpapi.NewProc("GetIpNetTable")
)

// MIB_IPNETROW represents a single ARP table entry
type MIB_IPNETROW struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32 // IPv4 address in network byte order
	Type        uint32
}

const (
	arpTypeOther   = 1
	arpTypeInvalid = 2
	arpTypeDynamic = 3
	arpTypeStatic  = 4
)

// Collect retrieves the ARP table using GetIpNetTable
func (c *ARPCollector) Collect() ([]types.ARPEntry, error) {
	logger.Section("ARP Table Collection")
	startTime := time.Now()

	var entries []types.ARPEntry

	// First call to get buffer size
	var size uint32
	procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	if size == 0 {
		logger.Debug("ARP table empty or API unavailable")
		return entries, nil
	}

	buf := make([]byte, size)
	ret, _, _ := procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // sorted
	)

	if ret != 0 {
		logger.Debug("GetIpNetTable failed: %d", ret)
		return entries, nil
	}

	// Parse MIB_IPNETTABLE structure
	// First 4 bytes = number of entries
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(MIB_IPNETROW{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*MIB_IPNETROW)(unsafe.Pointer(&buf[offset]))

		// Convert IPv4 address from uint32 to string
		ip := fmt.Sprintf("%d.%d.%d.%d",
			byte(row.Addr), byte(row.Addr>>8),
			byte(row.Addr>>16), byte(row.Addr>>24))

		// Convert MAC address
		mac := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			row.PhysAddr[0], row.PhysAddr[1], row.PhysAddr[2],
			row.PhysAddr[3], row.PhysAddr[4], row.PhysAddr[5])

		var arpType string
		switch row.Type {
		case arpTypeDynamic:
			arpType = "dynamic"
		case arpTypeStatic:
			arpType = "static"
		case arpTypeInvalid:
			arpType = "invalid"
		default:
			arpType = "other"
		}

		entries = append(entries, types.ARPEntry{
			IPAddress:    ip,
			MACAddress:   mac,
			InterfaceIdx: row.Index,
			Type:         arpType,
		})
	}

	logger.Timing("ARPCollector.Collect", startTime)
	logger.Info("ARP table: %d entries collected", len(entries))

	return entries, nil
}

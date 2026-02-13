package collector

import (
	"syscall"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	modDnsapi                = syscall.NewLazyDLL("dnsapi.dll")
	procDnsGetCacheDataTable = modDnsapi.NewProc("DnsGetCacheDataTable")
)

// Note: DnsGetCacheDataTable is an undocumented API that returns pointers into
// the DNS resolver's internal cache structures. The caller does NOT own this
// memory and must not free it. Calling DnsFree on these entries would corrupt
// the resolver's internal state.

// DNS_CACHE_ENTRY represents a single DNS cache entry (linked list node)
type DNS_CACHE_ENTRY struct {
	Next       *DNS_CACHE_ENTRY
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
}

// DNSCacheCollector collects DNS cache entries
type DNSCacheCollector struct{}

// NewDNSCacheCollector creates a new DNS cache collector
func NewDNSCacheCollector() *DNSCacheCollector {
	return &DNSCacheCollector{}
}

// Collect retrieves the DNS resolver cache
func (c *DNSCacheCollector) Collect() ([]types.DNSCacheEntry, error) {
	logger.Section("DNS Cache Collection")
	startTime := time.Now()

	var entries []types.DNSCacheEntry

	var head *DNS_CACHE_ENTRY
	ret, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if ret == 0 || head == nil {
		logger.Info("DNS cache empty or API unavailable")
		return entries, nil
	}

	seen := make(map[string]bool)
	for entry := head; entry != nil; entry = entry.Next {
		if entry.Name == nil {
			continue
		}

		name := windows.UTF16PtrToString(entry.Name)
		if name == "" {
			continue
		}

		// Deduplicate by name (same name can appear with different record types)
		key := name + dnsTypeName(entry.Type)
		if seen[key] {
			continue
		}
		seen[key] = true

		entries = append(entries, types.DNSCacheEntry{
			Name:       name,
			Type:       entry.Type,
			DataLength: entry.DataLength,
			Section:    dnsTypeName(entry.Type),
		})
	}

	logger.Timing("DNSCacheCollector.Collect", startTime)
	logger.Info("DNS cache: %d unique entries", len(entries))

	return entries, nil
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 28:
		return "AAAA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 33:
		return "SRV"
	case 6:
		return "SOA"
	case 16:
		return "TXT"
	default:
		return "OTHER"
	}
}

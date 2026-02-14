package collector

import (
	"strings"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

// SharedFolderCollector enumerates network shares
type SharedFolderCollector struct{}

// NewSharedFolderCollector creates a new shared folder collector
func NewSharedFolderCollector() *SharedFolderCollector {
	return &SharedFolderCollector{}
}

var (
	procNetShareEnum = modnetapi32.NewProc("NetShareEnum")
)

// Collect enumerates network shares using NetShareEnum
func (c *SharedFolderCollector) Collect() ([]types.SharedFolderInfo, error) {
	logger.Section("Shared Folder Collection")
	startTime := time.Now()

	var entries []types.SharedFolderInfo

	var buf uintptr
	var entriesRead, totalEntries, resumeHandle uint32

	ret, _, _ := procNetShareEnum.Call(
		0, // local server
		2, // level 2 (SHARE_INFO_2)
		uintptr(unsafe.Pointer(&buf)),
		0xFFFFFFFF, // MAX_PREFERRED_LENGTH
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)

	if ret != 0 || buf == 0 {
		logger.Debug("NetShareEnum failed: %d", ret)
		return entries, nil
	}
	defer procNetApiBufferFree.Call(buf)

	type SHARE_INFO_2 struct {
		Netname     *uint16
		Type        uint32
		Remark      *uint16
		Permissions uint32
		MaxUses     uint32
		CurrentUses uint32
		Path        *uint16
		Passwd      *uint16
	}

	size := unsafe.Sizeof(SHARE_INFO_2{})
	for i := uint32(0); i < entriesRead; i++ {
		share := (*SHARE_INFO_2)(unsafe.Pointer(buf + uintptr(i)*size))

		name := ""
		if share.Netname != nil {
			name = windows.UTF16PtrToString(share.Netname)
		}

		path := ""
		if share.Path != nil {
			path = windows.UTF16PtrToString(share.Path)
		}

		remark := ""
		if share.Remark != nil {
			remark = windows.UTF16PtrToString(share.Remark)
		}

		entry := types.SharedFolderInfo{
			Name:        name,
			Path:        path,
			Description: remark,
			ShareType:   share.Type,
			IsHidden:    strings.HasSuffix(name, "$"),
		}

		entries = append(entries, entry)
	}

	logger.Timing("SharedFolderCollector.Collect", startTime)
	logger.Info("Shared folders: %d shares found", len(entries))

	return entries, nil
}

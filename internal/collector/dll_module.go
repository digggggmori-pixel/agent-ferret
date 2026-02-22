package collector

import (
	"strings"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

// DLLModuleCollector collects loaded DLL modules per process
type DLLModuleCollector struct{}

// NewDLLModuleCollector creates a new DLL module collector
func NewDLLModuleCollector() *DLLModuleCollector {
	return &DLLModuleCollector{}
}

// MODULEENTRY32W structure for Module32First/Next
type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

const (
	thSnapModule   = 0x00000008
	thSnapModule32 = 0x00000010
)

var (
	modKernel32       = windows.NewLazyDLL("kernel32.dll")
	procModule32First = modKernel32.NewProc("Module32FirstW")
	procModule32Next  = modKernel32.NewProc("Module32NextW")
)

// Collect retrieves loaded DLL modules for interesting processes
func (c *DLLModuleCollector) Collect(processes []types.ProcessInfo) ([]types.DLLModuleInfo, error) {
	logger.Section("DLL Module Collection")
	startTime := time.Now()

	var modules []types.DLLModuleInfo

	// Only scan non-system processes to reduce noise and time
	for _, proc := range processes {
		if shouldSkipProcess(proc) {
			continue
		}

		procModules, err := c.getProcessModules(proc.PID, proc.Name)
		if err != nil {
			continue // Skip processes we can't access
		}

		modules = append(modules, procModules...)
	}

	logger.Timing("DLLModuleCollector.Collect", startTime)
	logger.Info("DLL modules: %d modules from non-system processes", len(modules))

	return modules, nil
}

func (c *DLLModuleCollector) getProcessModules(pid uint32, processName string) ([]types.DLLModuleInfo, error) {
	// Skip System/Idle
	if pid == 0 || pid == 4 {
		return nil, nil
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(thSnapModule|thSnapModule32, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var me moduleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	ret, _, err := procModule32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return nil, err
	}

	var modules []types.DLLModuleInfo

	for {
		moduleName := windows.UTF16ToString(me.Module[:])
		modulePath := windows.UTF16ToString(me.ExePath[:])

		// Skip the process exe itself (first module is always the exe)
		if !strings.EqualFold(moduleName, processName) {
			modules = append(modules, types.DLLModuleInfo{
				ProcessPID:  pid,
				ProcessName: processName,
				ModuleName:  moduleName,
				ModulePath:  modulePath,
				BaseAddress: uint64(me.ModBaseAddr),
				Size:        me.ModBaseSize,
			})
		}

		me.Size = uint32(unsafe.Sizeof(me))
		ret, _, err = procModule32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return modules, nil
}

// shouldSkipProcess returns true for system processes that should not be scanned for DLLs
func shouldSkipProcess(proc types.ProcessInfo) bool {
	if proc.PID == 0 || proc.PID == 4 {
		return true
	}

	// Skip well-known system processes to reduce noise
	nameLower := strings.ToLower(proc.Name)
	systemProcesses := map[string]bool{
		"system":          true,
		"smss.exe":        true,
		"csrss.exe":       true,
		"wininit.exe":     true,
		"winlogon.exe":    true,
		"services.exe":    true,
		"lsass.exe":       true,
		"svchost.exe":     true,
		"fontdrvhost.exe": true,
		"dwm.exe":         true,
		"memory compression": true,
		"registry":        true,
	}

	return systemProcesses[nameLower]
}

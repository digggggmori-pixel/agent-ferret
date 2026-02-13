// Package types defines the core data structures for Agent Lite
package types

import (
	"strings"
	"time"
)

// ProcessInfo represents a running process
type ProcessInfo struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"cmdline,omitempty"`
	CreateTime  time.Time `json:"create_time"`
	User        string    `json:"user,omitempty"`
	ParentName  string    `json:"parent_name,omitempty"`
	ParentPath  string    `json:"parent_path,omitempty"`
}

// NetworkConnection represents a TCP/UDP connection
type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   uint16 `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  uint16 `json:"remote_port"`
	State       string `json:"state"`
	OwningPID   uint32 `json:"owning_pid"`
	ProcessName string `json:"process_name"`
}

// ServiceInfo represents a Windows service
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	BinaryPath  string `json:"binary_path"`
}

// RegistryEntry represents a registry key/value
type RegistryEntry struct {
	Key       string `json:"key"`
	ValueName string `json:"value_name"`
	ValueData string `json:"value_data"`
	ValueType string `json:"value_type"`
}

// StartupEntry represents a file in the startup folder
type StartupEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
	IsHidden   bool      `json:"is_hidden"`
	Scope      string    `json:"scope"` // "user" or "common"
	User       string    `json:"user,omitempty"`
}

// PowerShellHistoryEntry represents a line from PowerShell history
type PowerShellHistoryEntry struct {
	User       string `json:"user"`
	Command    string `json:"command"`
	LineNumber int    `json:"line_number"`
	FilePath   string `json:"file_path"`
}

// DNSCacheEntry represents a cached DNS record
type DNSCacheEntry struct {
	Name       string `json:"name"`
	Type       uint16 `json:"type"`
	TTL        uint32 `json:"ttl"`
	DataLength uint16 `json:"data_length"`
	Section    string `json:"section"`
}

// UserAccountInfo represents a Windows user account
type UserAccountInfo struct {
	Name        string        `json:"name"`
	FullName    string        `json:"full_name,omitempty"`
	Comment     string        `json:"comment,omitempty"`
	Flags       uint32        `json:"flags"`
	IsAdmin     bool          `json:"is_admin"`
	IsDisabled  bool          `json:"is_disabled"`
	IsLocked    bool          `json:"is_locked"`
	PasswordAge time.Duration `json:"password_age"`
	LastLogon   time.Time     `json:"last_logon"`
	NumLogons   uint32        `json:"num_logons"`
	BadPWCount  uint32        `json:"bad_pw_count"`
}

// AntivirusInfo represents an installed antivirus product
type AntivirusInfo struct {
	ProductName string `json:"product_name"`
	InstanceGUID string `json:"instance_guid,omitempty"`
	ProductState uint32 `json:"product_state"`
	IsEnabled   bool   `json:"is_enabled"`
	IsUpToDate  bool   `json:"is_up_to_date"`
	PathToExe   string `json:"path_to_exe,omitempty"`
}

// ScheduledTaskInfo represents a Windows scheduled task
type ScheduledTaskInfo struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	State       string    `json:"state"`
	LastRunTime time.Time `json:"last_run_time,omitempty"`
	NextRunTime time.Time `json:"next_run_time,omitempty"`
	ActionPath  string    `json:"action_path,omitempty"`
	ActionArgs  string    `json:"action_args,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	Author      string    `json:"author,omitempty"`
	Description string    `json:"description,omitempty"`
	IsHidden    bool      `json:"is_hidden"`
}

// PrefetchInfo represents a parsed Windows Prefetch file
type PrefetchInfo struct {
	ExecutableName string      `json:"executable_name"`
	PrefetchPath   string      `json:"prefetch_path"`
	RunCount       uint32      `json:"run_count"`
	LastRunTimes   []time.Time `json:"last_run_times"`
	FilesLoaded    []string    `json:"files_loaded,omitempty"`
	FileSize       int64       `json:"file_size"`
}

// ShimcacheEntry represents a Shimcache (AppCompatCache) entry
type ShimcacheEntry struct {
	Order        int       `json:"order"`
	Path         string    `json:"path"`
	LastModified time.Time `json:"last_modified"`
	DataSize     uint32    `json:"data_size"`
}

// AmcacheEntry represents an Amcache entry
type AmcacheEntry struct {
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	Publisher   string    `json:"publisher,omitempty"`
	Version     string    `json:"version,omitempty"`
	SHA1        string    `json:"sha1,omitempty"`
	BinaryType  string    `json:"binary_type,omitempty"`
	ProductName string    `json:"product_name,omitempty"`
	LinkDate    time.Time `json:"link_date,omitempty"`
	Size        int64     `json:"size"`
}

// DLLModuleInfo represents a loaded DLL module in a process
type DLLModuleInfo struct {
	ProcessPID  uint32 `json:"process_pid"`
	ProcessName string `json:"process_name"`
	ModuleName  string `json:"module_name"`
	ModulePath  string `json:"module_path"`
	BaseAddress uint64 `json:"base_address"`
	Size        uint32 `json:"size"`
}

// WMIPersistenceInfo represents a WMI event subscription persistence
type WMIPersistenceInfo struct {
	FilterName   string `json:"filter_name"`
	FilterQuery  string `json:"filter_query"`
	ConsumerName string `json:"consumer_name"`
	ConsumerType string `json:"consumer_type"`
	ConsumerData string `json:"consumer_data"`
	BindingPath  string `json:"binding_path,omitempty"`
	CreatorSID   string `json:"creator_sid,omitempty"`
}

// BrowserHistoryEntry represents a browser history entry
type BrowserHistoryEntry struct {
	Browser    string    `json:"browser"`
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	VisitCount int       `json:"visit_count"`
	LastVisited time.Time `json:"last_visited"`
	User       string    `json:"user"`
}

// USBDeviceInfo represents a USB device connection history entry
type USBDeviceInfo struct {
	DeviceID     string    `json:"device_id"`
	SerialNumber string    `json:"serial_number"`
	FriendlyName string    `json:"friendly_name"`
	VendorID     string    `json:"vendor_id,omitempty"`
	ProductID    string    `json:"product_id,omitempty"`
	FirstInstall time.Time `json:"first_install"`
	LastConnect  time.Time `json:"last_connect"`
	DriveLetter  string    `json:"drive_letter,omitempty"`
}

// EventLogEntry represents a Windows event log entry
type EventLogEntry struct {
	Channel   string                 `json:"channel"`
	Provider  string                 `json:"provider"`
	EventID   uint32                 `json:"event_id"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Detection represents a security detection
type Detection struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Confidence      float64                `json:"confidence"`
	Timestamp       time.Time              `json:"timestamp"`
	Description     string                 `json:"description"`
	UserDescription string                 `json:"user_description,omitempty"`
	Recommendation  string                 `json:"recommendation,omitempty"`
	Process         *ProcessInfo           `json:"process,omitempty"`
	Network         *NetworkConnection     `json:"network,omitempty"`
	Registry        *RegistryEntry         `json:"registry,omitempty"`
	MITRE           *MITREMapping          `json:"mitre,omitempty"`
	SigmaRules      []string               `json:"sigma_rules,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty"`
}

// MITREMapping represents MITRE ATT&CK mapping
type MITREMapping struct {
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}

// HostInfo represents the host system information
type HostInfo struct {
	Hostname    string   `json:"hostname"`
	Domain      string   `json:"domain,omitempty"`
	OSVersion   string   `json:"os_version"`
	Arch        string   `json:"arch"`
	IPAddresses []string `json:"ip_addresses"`
}

// ScanSummary represents the summary of a scan
type ScanSummary struct {
	TotalProcesses   int            `json:"total_processes"`
	TotalConnections int            `json:"total_connections"`
	TotalServices    int            `json:"total_services"`
	TotalEvents      int            `json:"total_events"`
	Detections       DetectionCount `json:"detections"`
}

// DetectionCount represents detection counts by severity
type DetectionCount struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// IOCCollection represents collected Indicators of Compromise
type IOCCollection struct {
	IPs   []IOCEntry `json:"ips,omitempty"`
	URLs  []IOCEntry `json:"urls,omitempty"`
	Files []IOCEntry `json:"files,omitempty"`
}

// IOCEntry represents a single IOC
type IOCEntry struct {
	Value   string `json:"value"`
	Context string `json:"context"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	AgentVersion   string         `json:"agent_version"`
	ScanID         string         `json:"scan_id"`
	ScanTime       time.Time      `json:"scan_time"`
	ScanDurationMs int64          `json:"scan_duration_ms"`
	Host           HostInfo       `json:"host"`
	Summary        ScanSummary    `json:"summary"`
	Detections     []Detection    `json:"detections"`
	IOCs           IOCCollection  `json:"iocs"`
}

// Severity constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "informational"
)

// Detection type constants
const (
	DetectionTypeLOLBin          = "lolbin_execution"
	DetectionTypeChain           = "suspicious_chain"
	DetectionTypePort            = "suspicious_port"
	DetectionTypePath            = "path_anomaly"
	DetectionTypeTyposquat       = "typosquatting"
	DetectionTypeSigma           = "sigma_match"
	DetectionTypePersistence     = "persistence"
	DetectionTypeServiceVendor   = "service_vendor_typosquat"
	DetectionTypeServiceName     = "service_name_typosquat"
	DetectionTypeServicePath     = "service_path_anomaly"
	DetectionTypeUnsignedProcess = "unsigned_critical_process"
	DetectionTypeSuspiciousDomain = "suspicious_domain"
	DetectionTypeEncodedCommand  = "encoded_command"

	// Phase 1 detection types
	DetectionTypeSuspiciousStartup    = "suspicious_startup"
	DetectionTypeSuspiciousPowerShell = "suspicious_powershell"
	DetectionTypeSuspiciousDNS        = "suspicious_dns_cache"
	DetectionTypeSuspiciousAccount    = "suspicious_account"
	DetectionTypeAntivirusIssue       = "antivirus_issue"
	DetectionTypeSuspiciousTask       = "suspicious_scheduled_task"

	// Phase 2 detection types
	DetectionTypePrefetchAnomaly  = "prefetch_anomaly"
	DetectionTypeShimcacheAnomaly = "shimcache_anomaly"
	DetectionTypeAmcacheAnomaly   = "amcache_anomaly"
	DetectionTypeDLLAnomaly       = "dll_anomaly"
	DetectionTypeWMIPersistence   = "wmi_persistence"
	DetectionTypeSuspiciousBrowsing = "suspicious_browsing"
	DetectionTypeSuspiciousUSB    = "suspicious_usb"
)

// NormalizeTactic converts MITRE tactic names to Title Case.
// e.g. "defense_evasion" → "Defense Evasion", "persistence" → "Persistence"
// Already Title-Cased values pass through unchanged.
func NormalizeTactic(s string) string {
	if len(s) == 0 {
		return s
	}
	// Already starts with uppercase — assume correct
	if s[0] >= 'A' && s[0] <= 'Z' {
		return s
	}
	words := strings.Split(s, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// NormalizeTactics normalizes a slice of MITRE tactic names.
func NormalizeTactics(tactics []string) []string {
	out := make([]string, len(tactics))
	for i, t := range tactics {
		out[i] = NormalizeTactic(t)
	}
	return out
}

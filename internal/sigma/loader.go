package sigma

import (
	"fmt"
	"strings"
)

// GetCategoryForLogsource returns the category name for a logsource
func GetCategoryForLogsource(logsource Logsource) string {
	// Build category name from logsource
	if logsource.Category != "" {
		return fmt.Sprintf("windows_%s", logsource.Category)
	}
	if logsource.Service != "" {
		return fmt.Sprintf("windows_%s", logsource.Service)
	}
	return "windows_general"
}

// ChannelToCategory maps Windows Event Log channels to Sigma categories
var ChannelToCategory = map[string]string{
	"Security":                                                 "windows_security",
	"System":                                                   "windows_system",
	"Application":                                              "windows_application",
	"Microsoft-Windows-PowerShell/Operational":                 "windows_ps_script",
	"PowerShellCore/Operational":                               "windows_ps_script",
	"Microsoft-Windows-Sysmon/Operational":                     "windows_sysmon",
	"Microsoft-Windows-Windows Defender/Operational":           "windows_windefend",
	"Microsoft-Windows-TaskScheduler/Operational":              "windows_taskscheduler",
	"Microsoft-Windows-Bits-Client/Operational":                "windows_bits_client",
	"Microsoft-Windows-DNS-Client/Operational":                 "windows_dns_client",
	"Microsoft-Windows-DriverFrameworks-UserMode/Operational":  "windows_driver_framework",
	"Microsoft-Windows-CodeIntegrity/Operational":              "windows_codeintegrity_operational",
	"Microsoft-Windows-AppLocker/EXE and DLL":                  "windows_applocker",
	"Microsoft-Windows-AppLocker/MSI and Script":               "windows_applocker",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": "windows_firewall_as",
	"Microsoft-Windows-WMI-Activity/Operational":               "windows_wmi_event",
	"Microsoft-Windows-NTLM/Operational":                       "windows_ntlm",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "windows_terminalservices_localsessionmanager",
}

// EventIDCategories maps specific Event IDs in Security channel to Sigma categories
var EventIDCategories = map[uint32]string{
	// Process events (Security)
	4688: "windows_process_creation",
	4689: "windows_process_termination",

	// Logon events
	4624: "windows_security", // Logon success
	4625: "windows_security", // Logon failure
	4672: "windows_security", // Special privileges

	// Account management
	4720: "windows_security", // Account created
	4722: "windows_security", // Account enabled
	4726: "windows_security", // Account deleted
	4738: "windows_security", // Account changed
	4781: "windows_security", // Account renamed

	// Directory services
	5136: "windows_security", // Directory object modified

	// Service events (System)
	7045: "windows_system", // Service installed
	7034: "windows_system", // Service crashed

	// Log events
	104:  "windows_system",   // Log cleared
	1102: "windows_security", // Audit log cleared
}

// SysmonEventCategories maps Sysmon Event IDs to Sigma categories
// This enables full Sigma rule coverage when Sysmon is installed
var SysmonEventCategories = map[uint32]string{
	1:  "windows_process_creation",     // Process Create - 1,156 rules
	2:  "windows_file_change",          // File creation time changed
	3:  "windows_network_connection",   // Network connection - 51 rules
	4:  "windows_sysmon_status",        // Sysmon service state changed
	5:  "windows_process_termination",  // Process terminated
	6:  "windows_driver_load",          // Driver loaded - 10 rules
	7:  "windows_image_load",           // Image loaded - 99 rules
	8:  "windows_create_remote_thread", // CreateRemoteThread - 11 rules
	9:  "windows_raw_access_thread",    // RawAccessRead
	10: "windows_process_access",       // ProcessAccess - 23 rules
	11: "windows_file_event",           // FileCreate - 162 rules
	12: "windows_registry_event",       // RegistryEvent (Object create/delete) - 32 rules
	13: "windows_registry_set",         // RegistryEvent (Value Set) - 199 rules
	14: "windows_registry_event",       // RegistryEvent (Key/Value Rename)
	15: "windows_create_stream_hash",   // FileCreateStreamHash - 9 rules
	16: "windows_sysmon",               // Sysmon config state changed
	17: "windows_pipe_created",         // PipeEvent (Pipe Created) - 17 rules
	18: "windows_pipe_created",         // PipeEvent (Pipe Connected)
	19: "windows_wmi_event",            // WmiEvent (WmiEventFilter) - 3 rules
	20: "windows_wmi_event",            // WmiEvent (WmiEventConsumer)
	21: "windows_wmi_event",            // WmiEvent (WmiEventConsumerToFilter)
	22: "windows_dns_query",            // DNSEvent (DNS query) - 21 rules
	23: "windows_file_delete",          // FileDelete (File Delete archived) - 12 rules
	24: "windows_clipboard_change",     // ClipboardChange
	25: "windows_process_tampering",    // ProcessTampering - 1 rule
	26: "windows_file_delete",          // FileDeleteDetected
	27: "windows_file_block_executable", // FileBlockExecutable
	28: "windows_file_block_shredding", // FileBlockShredding
	29: "windows_file_executable_detected", // FileExecutableDetected
}

// GetCategoryForEvent determines the Sigma category for a Windows event
func GetCategoryForEvent(channel string, eventID uint32, provider string) string {
	// Check Sysmon channel with Event ID-specific mapping
	// This is critical for full Sigma rule coverage
	if channel == "Microsoft-Windows-Sysmon/Operational" {
		if cat, ok := SysmonEventCategories[eventID]; ok {
			return cat
		}
		return "windows_sysmon"
	}

	// Check EventID-specific categories for Security channel
	if channel == "Security" {
		if cat, ok := EventIDCategories[eventID]; ok {
			return cat
		}
		return "windows_security"
	}

	// Check EventID-specific categories for System channel
	if channel == "System" {
		if cat, ok := EventIDCategories[eventID]; ok {
			return cat
		}
		return "windows_system"
	}

	// Use channel mapping
	if cat, ok := ChannelToCategory[channel]; ok {
		return cat
	}

	// Fallback based on provider patterns
	providerLower := strings.ToLower(provider)
	if strings.Contains(providerLower, "powershell") {
		return "windows_ps_script"
	}
	if strings.Contains(providerLower, "sysmon") {
		return "windows_sysmon"
	}
	if strings.Contains(providerLower, "defender") {
		return "windows_windefend"
	}

	return "windows_general"
}

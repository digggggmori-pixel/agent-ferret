// Package rules provides embedded Sigma rules
package rules

import (
	"embed"
)

// EmbeddedRules contains all compiled Sigma rules
// The rules are embedded at compile time for single-binary distribution
//
//go:embed *.json
var EmbeddedRules embed.FS

// Categories lists all available rule categories based on the embedded files
// This is populated at runtime by reading the _index.json file
var Categories = []string{
	"windows_application",
	"windows_applocker",
	"windows_appmodel_runtime",
	"windows_appxdeployment_server",
	"windows_appxpackaging_om",
	"windows_bits_client",
	"windows_capi2",
	"windows_certificateservicesclient_lifecycle_system",
	"windows_codeintegrity_operational",
	"windows_create_remote_thread",
	"windows_create_stream_hash",
	"windows_diagnosis_scripted",
	"windows_dns_client",
	"windows_dns_query",
	"windows_dns_server",
	"windows_driver_framework",
	"windows_driver_load",
	"windows_file_access",
	"windows_file_change",
	"windows_file_delete",
	"windows_file_event",
	"windows_file_executable_detected",
	"windows_file_rename",
	"windows_firewall_as",
	"windows_general",
	"windows_iis_configuration",
	"windows_image_load",
	"windows_ldap",
	"windows_lsa_server",
	"windows_microsoft_servicebus_client",
	"windows_msexchange_management",
	"windows_network_connection",
	"windows_ntlm",
	"windows_openssh",
	"windows_pipe_created",
	"windows_powershell_classic",
	"windows_process_access",
	"windows_process_creation",
	"windows_process_tampering",
	"windows_ps_classic_provider_start",
	"windows_ps_classic_start",
	"windows_ps_module",
	"windows_ps_script",
	"windows_raw_access_thread",
	"windows_registry_add",
	"windows_registry_delete",
	"windows_registry_event",
	"windows_registry_set",
	"windows_security",
	"windows_security_mitigations",
	"windows_shell_core",
	"windows_smbclient_security",
	"windows_smbserver_connectivity",
	"windows_sysmon",
	"windows_sysmon_error",
	"windows_sysmon_status",
	"windows_system",
	"windows_taskscheduler",
	"windows_terminalservices_localsessionmanager",
	"windows_windefend",
	"windows_wmi",
	"windows_wmi_event",
}

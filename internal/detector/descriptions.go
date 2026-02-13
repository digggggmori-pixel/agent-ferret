package detector

import (
	"fmt"

	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// GenerateUserDescription creates a plain English explanation of the detection
func GenerateUserDescription(d *types.Detection) string {
	switch d.Type {
	case types.DetectionTypeLOLBin:
		name := ""
		if d.Process != nil {
			name = d.Process.Name
		}
		return fmt.Sprintf("'%s' was executed. This is a built-in Windows tool that attackers commonly abuse to run malicious commands.", name)

	case types.DetectionTypeChain:
		if d.Process != nil {
			parent := d.Process.ParentName
			child := d.Process.Name
			if parent != "" {
				return fmt.Sprintf("'%s' launched '%s'. This execution pattern is commonly seen in malware activity.", parent, child)
			}
		}
		return "A suspicious process execution chain was detected. This pattern is commonly used by malware."

	case types.DetectionTypePort:
		if d.Network != nil {
			if d.Network.State == "LISTEN" {
				return fmt.Sprintf("Listening on suspicious port %d. This port is commonly associated with hacking tools or unauthorized remote access.", d.Network.LocalPort)
			}
			return fmt.Sprintf("Outbound connection detected on port %d. This port is commonly associated with hacking tools or command-and-control servers.", d.Network.RemotePort)
		}
		return "A connection to a suspicious port was detected."

	case types.DetectionTypePath:
		if d.Process != nil && d.Process.Path != "" {
			return fmt.Sprintf("'%s' is running from an unusual location. Legitimate software typically runs from standard system directories.", d.Process.Name)
		}
		return "A program is running from an unusual location. Legitimate software typically runs from standard directories."

	case types.DetectionTypeTyposquat:
		if d.Process != nil {
			return fmt.Sprintf("'%s' has a name very similar to a known Windows system process. Attackers often disguise malware with lookalike names.", d.Process.Name)
		}
		return "A process with a name suspiciously similar to a system process was detected."

	case types.DetectionTypeSigma:
		if desc, ok := d.Details["description"]; ok {
			if s, ok := desc.(string); ok && s != "" {
				return s
			}
		}
		return d.Description

	case types.DetectionTypePersistence:
		return "A persistence mechanism was found. This allows a program to run automatically when your computer starts."

	case types.DetectionTypeServiceVendor:
		if word, ok := d.Details["typosquat_word"]; ok {
			if vendor, ok2 := d.Details["legitimate_name"]; ok2 {
				return fmt.Sprintf("A service has a vendor name '%s' similar to '%s'. This may indicate a disguised malicious service.", word, vendor)
			}
		}
		return "A service has a vendor name similar to a well-known company. This may be a disguised malicious service."

	case types.DetectionTypeServiceName:
		if svcName, ok := d.Details["service_name"]; ok {
			if systemSvc, ok2 := d.Details["system_service"]; ok2 {
				return fmt.Sprintf("Service '%s' closely resembles the system service '%s'. This may be an attempt to hide malicious software.", svcName, systemSvc)
			}
		}
		return "A service name closely resembles a Windows system service. This may be an attempt to hide malware."

	case types.DetectionTypeServicePath:
		return "A Windows service is running from a suspicious location. Legitimate services typically run from system directories."

	case types.DetectionTypeUnsignedProcess:
		if d.Process != nil {
			return fmt.Sprintf("Critical system process '%s' is running from an unexpected path. This may indicate process masquerading by malware.", d.Process.Name)
		}
		return "A critical system process is running from an unexpected path."

	case types.DetectionTypeSuspiciousDomain:
		if domain, ok := d.Details["domain"]; ok {
			return fmt.Sprintf("A connection to suspicious domain '%s' was detected. This may indicate communication with a malicious server.", domain)
		}
		return "A connection to a suspicious domain was detected."

	case types.DetectionTypeEncodedCommand:
		return "An encoded or obfuscated command was detected. Attackers use encoding to hide malicious commands from security tools."

	case types.DetectionTypeSuspiciousStartup:
		if name, ok := d.Details["file_name"]; ok {
			return fmt.Sprintf("File '%s' was found in a startup folder. Programs in this folder run automatically when you log in.", name)
		}
		return "A suspicious file was found in a startup folder. Programs placed here run automatically at login."

	case types.DetectionTypeSuspiciousPowerShell:
		if desc, ok := d.Details["pattern"]; ok {
			return fmt.Sprintf("A suspicious PowerShell command matching '%s' was found in command history. This pattern is commonly used by attackers.", desc)
		}
		return "A suspicious PowerShell command was found in command history."

	case types.DetectionTypeSuspiciousDNS:
		if domain, ok := d.Details["domain"]; ok {
			return fmt.Sprintf("Domain '%s' was found in the DNS cache. This domain has suspicious characteristics that may indicate malware communication.", domain)
		}
		return "A suspicious domain was found in the DNS cache."

	case types.DetectionTypeSuspiciousAccount:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "hidden_account":
				return fmt.Sprintf("A hidden user account '%s' was detected. Attackers create hidden accounts to maintain persistent access.", d.Details["account_name"])
			case "brute_force_attempt":
				return fmt.Sprintf("Account '%s' has many failed login attempts, which may indicate a brute-force attack.", d.Details["account_name"])
			case "default_account_enabled":
				return fmt.Sprintf("The default '%s' account is enabled. Default accounts are common attack targets and should be disabled.", d.Details["account_name"])
			case "non_expiring_password":
				return fmt.Sprintf("Admin account '%s' has a password that never expires. This weakens security posture.", d.Details["account_name"])
			}
		}
		return "A suspicious user account configuration was detected."

	case types.DetectionTypeAntivirusIssue:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "no_av_installed":
				return "No antivirus software was detected on this system. Your computer is unprotected against malware."
			case "av_disabled":
				return fmt.Sprintf("Antivirus '%s' is disabled. Your computer is not actively protected. Attackers often disable antivirus before deploying malware.", d.Details["product_name"])
			case "av_outdated":
				return fmt.Sprintf("Antivirus '%s' definitions are out of date. New threats may not be detected.", d.Details["product_name"])
			}
		}
		return "An issue with antivirus protection was detected."

	case types.DetectionTypeSuspiciousTask:
		if name, ok := d.Details["task_name"]; ok {
			return fmt.Sprintf("Scheduled task '%s' has suspicious characteristics. Attackers use scheduled tasks to maintain persistence and execute commands.", name)
		}
		return "A suspicious scheduled task was detected."

	// Phase 2 detection types

	case types.DetectionTypePrefetchAnomaly:
		if exe, ok := d.Details["executable"]; ok {
			if reason, ok2 := d.Details["reason"]; ok2 {
				switch reason {
				case "lolbin_history":
					return fmt.Sprintf("Windows Prefetch shows '%s' was executed on this system. This is a tool commonly abused by attackers.", exe)
				case "recent_first_execution":
					return fmt.Sprintf("A program '%s' was recently executed for the first time. This may indicate a newly introduced tool.", exe)
				}
			}
		}
		return "A suspicious entry was found in Windows Prefetch, indicating past program execution."

	case types.DetectionTypeShimcacheAnomaly:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "lolbin_unusual_path":
				if path, ok2 := d.Details["path"]; ok2 {
					return fmt.Sprintf("Shimcache records a system tool executed from an unusual location: %s. This may indicate a copied or disguised tool.", path)
				}
			case "suspicious_path":
				if path, ok2 := d.Details["path"]; ok2 {
					return fmt.Sprintf("Shimcache records a program that existed at a suspicious location: %s. Even if deleted, this indicates past activity.", path)
				}
			}
		}
		return "A suspicious entry was found in the Application Compatibility Cache, indicating past program presence."

	case types.DetectionTypeAmcacheAnomaly:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "lolbin_history":
				if name, ok2 := d.Details["name"]; ok2 {
					return fmt.Sprintf("Amcache records tool '%s' was executed from a non-standard location. This may indicate attacker tool usage.", name)
				}
			case "unsigned_suspicious_path":
				if name, ok2 := d.Details["name"]; ok2 {
					return fmt.Sprintf("An unsigned program '%s' was executed from a suspicious location according to Amcache records.", name)
				}
			}
		}
		return "A suspicious entry was found in Amcache, indicating past program execution."

	case types.DetectionTypeDLLAnomaly:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "suspicious_dll_path":
				if modName, ok2 := d.Details["module_name"]; ok2 {
					if procName, ok3 := d.Details["process_name"]; ok3 {
						return fmt.Sprintf("DLL '%s' is loaded from a suspicious location into process '%s'. Malware often places DLLs in temp/download folders.", modName, procName)
					}
				}
			case "dll_typosquatting":
				if modName, ok2 := d.Details["module_name"]; ok2 {
					if knownDLL, ok3 := d.Details["known_dll"]; ok3 {
						return fmt.Sprintf("DLL '%s' has a name very similar to system DLL '%s' but is loaded from a non-system path. This is a common DLL hijacking technique.", modName, knownDLL)
					}
				}
			}
		}
		return "A suspicious DLL module was detected loaded in a process."

	case types.DetectionTypeWMIPersistence:
		if consType, ok := d.Details["consumer_type"]; ok {
			if consName, ok2 := d.Details["consumer_name"]; ok2 {
				return fmt.Sprintf("A WMI event subscription '%s' (%s type) was found. WMI persistence allows code to execute automatically in response to system events. This technique is commonly used by advanced malware.", consName, consType)
			}
		}
		return "A WMI event subscription was found. This is a persistence mechanism that allows automatic code execution."

	case types.DetectionTypeSuspiciousBrowsing:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "suspicious_url":
				if url, ok2 := d.Details["url"]; ok2 {
					return fmt.Sprintf("Browser history contains a visit to a suspicious site: %s. This type of site is sometimes used for hosting malicious payloads.", url)
				}
			case "dangerous_download":
				if url, ok2 := d.Details["url"]; ok2 {
					return fmt.Sprintf("Browser history shows a potentially dangerous file was downloaded: %s", url)
				}
			case "high_risk_tld":
				if domain, ok2 := d.Details["domain"]; ok2 {
					return fmt.Sprintf("Browser history contains a visit to a high-risk domain: %s", domain)
				}
			}
		}
		return "Suspicious browsing activity was detected in browser history."

	case types.DetectionTypeSuspiciousUSB:
		if reason, ok := d.Details["reason"]; ok {
			switch reason {
			case "recent_usb":
				if name, ok2 := d.Details["friendly_name"]; ok2 {
					return fmt.Sprintf("USB storage device '%s' was connected recently. USB devices can be used to introduce malware or exfiltrate data.", name)
				}
			case "usb_audit":
				if name, ok2 := d.Details["friendly_name"]; ok2 {
					return fmt.Sprintf("USB storage device '%s' has been connected to this computer. Recorded for audit purposes.", name)
				}
			}
		}
		return "USB device activity was recorded."

	default:
		return d.Description
	}
}

// GenerateRecommendation creates actionable guidance based on severity
func GenerateRecommendation(d *types.Detection) string {
	switch d.Severity {
	case types.SeverityCritical:
		return "Immediate attention required. Get a BRIQA AI analysis to assess the exact risk level."
	case types.SeverityHigh:
		return "Attention needed. Verify whether you recognize this program or activity."
	case types.SeverityMedium:
		return "Worth noting. This could be normal activity, but verify if anything seems unfamiliar."
	case types.SeverityLow:
		return "Low risk. Most likely normal activity, noted for your reference."
	case types.SeverityInfo:
		return "Informational finding. Normal system activity recorded for context."
	default:
		return "Review this finding for additional context."
	}
}

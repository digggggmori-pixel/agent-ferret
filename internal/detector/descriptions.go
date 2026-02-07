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
	default:
		return "Review this finding for additional context."
	}
}

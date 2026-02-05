package detector

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-lite/internal/logger"
	"github.com/digggggmori-pixel/agent-lite/pkg/types"
)

// Compiled regex patterns for domain analysis
var (
	dgaPatternCompiled      = regexp.MustCompile(`^[a-z0-9]{20,}\.[a-z]{2,4}$`)
	punycodePatternCompiled = regexp.MustCompile(`^xn--`)
	ipPatternCompiled       = regexp.MustCompile(`\d{1,3}[-_]\d{1,3}[-_]\d{1,3}`)
)

// Detector is the main detection engine
type Detector struct {
	pathPatterns []*regexp.Regexp
}

// New creates a new Detector instance
func New() *Detector {
	d := &Detector{
		pathPatterns: make([]*regexp.Regexp, 0, len(PathAnomalyPatterns)),
	}

	// Compile path anomaly patterns
	for _, pattern := range PathAnomalyPatterns {
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			d.pathPatterns = append(d.pathPatterns, re)
		}
	}

	return d
}

// DetectLOLBins detects LOLBin execution
func (d *Detector) DetectLOLBins(processes []types.ProcessInfo) []types.Detection {
	logger.SubSection("LOLBin Detection")
	logger.Debug("Scanning %d processes for LOLBin patterns", len(processes))
	var detections []types.Detection

	for i := range processes {
		proc := processes[i] // Copy to avoid pointer issues
		nameLower := strings.ToLower(proc.Name)

		if AllLOLBins[nameLower] {
			// Skip common Windows shell processes running normally
			// Only flag when there's suspicious context
			if isNormalWindowsShell(nameLower, proc.Path, proc.CommandLine, proc.ParentName) {
				continue
			}

			category := LOLBinCategory(nameLower)
			severity := determineLOLBinSeverity(nameLower, proc.CommandLine)

			procCopy := proc // Make a copy for the pointer
			detection := types.Detection{
				ID:          fmt.Sprintf("lolbin-%d-%d", proc.PID, time.Now().UnixNano()),
				Type:        types.DetectionTypeLOLBin,
				Severity:    severity,
				Confidence:  0.7,
				Timestamp:   proc.CreateTime,
				Description: fmt.Sprintf("LOLBin %s (%s) executed", proc.Name, category),
				Process:     &procCopy,
				MITRE:       getLOLBinMITRE(category),
			}

			// Increase confidence based on suspicious command line
			if hasSuspiciousArgs(proc.CommandLine) {
				detection.Confidence = 0.9
				detection.Severity = types.SeverityHigh
			}

			logger.DetectionInfo(types.DetectionTypeLOLBin, detection.Severity, detection.Description)
			detections = append(detections, detection)
		}
	}

	logger.Debug("LOLBin detection complete: %d detections", len(detections))
	return detections
}

// isNormalWindowsShell checks if a LOLBin is running as a normal Windows shell process
// Returns true if it should be skipped (normal operation)
func isNormalWindowsShell(name, path, cmdline, parentName string) bool {
	nameLower := strings.ToLower(name)
	pathLower := strings.ToLower(path)
	parentLower := strings.ToLower(parentName)

	// Common Windows shell processes that run normally
	shellProcesses := map[string]bool{
		"explorer.exe":   true,
		"cmd.exe":        true,
		"powershell.exe": true,
		"pwsh.exe":       true,
	}

	if !shellProcesses[nameLower] {
		return false // Not a shell process, don't skip
	}

	// Check if running from legitimate Windows paths
	legitimatePaths := []string{
		`c:\windows\`,
		`c:\windows\system32\`,
		`c:\windows\syswow64\`,
		`c:\program files\powershell\`,
	}

	isLegitPath := false
	for _, legitPath := range legitimatePaths {
		if strings.HasPrefix(pathLower, legitPath) {
			isLegitPath = true
			break
		}
	}

	if !isLegitPath {
		return false // Non-standard path, flag it
	}

	// If command line has suspicious patterns, don't skip
	if hasSuspiciousArgs(cmdline) {
		return false
	}

	// Normal parents for shell processes
	normalParents := map[string]bool{
		"":                    true, // No parent info
		"explorer.exe":        true,
		"windowsterminal.exe": true,
		"code.exe":            true,
		"conhost.exe":         true,
		"cmd.exe":             true,
		"powershell.exe":      true,
		"pwsh.exe":            true,
		"svchost.exe":         true,
		"services.exe":        true,
		"userinit.exe":        true,
		"winlogon.exe":        true,
	}

	// For explorer.exe, it's almost always normal when from Windows path
	if nameLower == "explorer.exe" && isLegitPath {
		return true
	}

	// For cmd/powershell, check if parent is normal
	if normalParents[parentLower] {
		return true
	}

	return false
}

// DetectChains detects suspicious parent-child process chains
func (d *Detector) DetectChains(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		parentName := strings.ToLower(proc.ParentName)
		childName := strings.ToLower(proc.Name)

		if suspiciousChildren, exists := SuspiciousChains[parentName]; exists {
			for _, suspChild := range suspiciousChildren {
				if childName == suspChild {
					// Check if this is a developer-friendly chain that should be reduced severity
					severity := types.SeverityHigh
					confidence := 0.85

					if isDeveloperFriendlyChain(parentName, childName, proc.ParentPath) {
						severity = types.SeverityLow
						confidence = 0.4
					}

					procCopy := proc
					detection := types.Detection{
						ID:          fmt.Sprintf("chain-%d-%d", proc.PID, time.Now().UnixNano()),
						Type:        types.DetectionTypeChain,
						Severity:    severity,
						Confidence:  confidence,
						Timestamp:   proc.CreateTime,
						Description: fmt.Sprintf("Suspicious chain: %s → %s", proc.ParentName, proc.Name),
						Process:     &procCopy,
						MITRE:       getChainMITRE(parentName),
					}

					detections = append(detections, detection)
					break
				}
			}
		}
	}

	return detections
}

// isDeveloperFriendlyChain checks if a chain is likely from legitimate developer activity
func isDeveloperFriendlyChain(parent, child, parentPath string) bool {
	parentLower := strings.ToLower(parent)
	parentPathLower := strings.ToLower(parentPath)

	// Developer tools that commonly spawn cmd/powershell
	developerParents := map[string]bool{
		"python.exe":  true,
		"python3.exe": true,
		"node.exe":    true,
		"ruby.exe":    true,
		"php.exe":     true,
		"java.exe":    true,
		"javaw.exe":   true,
	}

	if developerParents[parentLower] {
		// Check if running from legitimate development paths
		legitDevPaths := []string{
			`\programs\python`,
			`\python`,
			`\nodejs\`,
			`\program files\`,
			`\appdata\local\programs\`,
		}

		for _, path := range legitDevPaths {
			if strings.Contains(parentPathLower, path) {
				return true
			}
		}
	}

	return false
}

// DetectSuspiciousPorts detects connections to suspicious ports
func (d *Detector) DetectSuspiciousPorts(connections []types.NetworkConnection) []types.Detection {
	var detections []types.Detection

	for i := range connections {
		conn := connections[i]

		// Check remote port for outbound connections
		if conn.State == "ESTABLISHED" && conn.RemotePort > 0 {
			if description, suspicious := SuspiciousPorts[conn.RemotePort]; suspicious {
				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("port-%d-%d", conn.OwningPID, time.Now().UnixNano()),
					Type:        types.DetectionTypePort,
					Severity:    determinPortSeverity(conn.RemotePort),
					Confidence:  0.75,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Connection to suspicious port %d (%s)", conn.RemotePort, description),
					Network:     &connCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control"},
						Techniques: []string{"T1071"},
					},
				}

				detections = append(detections, detection)
			}
		}

		// Check local port for listening services
		if conn.State == "LISTEN" {
			if description, suspicious := SuspiciousPorts[conn.LocalPort]; suspicious {
				// Skip standard Windows services (System process PID 4)
				if isStandardWindowsService(conn.LocalPort, conn.OwningPID) {
					continue
				}

				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("listen-%d-%d", conn.OwningPID, time.Now().UnixNano()),
					Type:        types.DetectionTypePort,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Listening on suspicious port %d (%s)", conn.LocalPort, description),
					Network:     &connCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control", "Persistence"},
						Techniques: []string{"T1571"},
					},
				}

				detections = append(detections, detection)
			}
		}
	}

	return detections
}

// isStandardWindowsService checks if a port is a standard Windows service
// that should not be flagged (e.g., SMB, NetBIOS from System process)
func isStandardWindowsService(port uint16, pid uint32) bool {
	// Standard Windows ports from System process (PID 4)
	standardPorts := map[uint16]bool{
		139: true, // NetBIOS Session Service
		445: true, // SMB (Server Message Block)
		137: true, // NetBIOS Name Service
		138: true, // NetBIOS Datagram Service
	}

	// These ports are normal when from System (PID 4) or smss/lsass
	if standardPorts[port] && (pid == 4 || pid == 0) {
		return true
	}

	return false
}

// DetectPathAnomalies detects suspicious process paths
func (d *Detector) DetectPathAnomalies(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		if proc.Path == "" {
			continue
		}

		// Skip known legitimate temp folder applications
		if isLegitTempApplication(proc.Path) {
			continue
		}

		for j, pattern := range d.pathPatterns {
			if pattern.MatchString(proc.Path) {
				procCopy := proc
				detection := types.Detection{
					ID:          fmt.Sprintf("path-%d-%d", proc.PID, time.Now().UnixNano()),
					Type:        types.DetectionTypePath,
					Severity:    types.SeverityMedium,
					Confidence:  0.7,
					Timestamp:   proc.CreateTime,
					Description: fmt.Sprintf("Suspicious path pattern: %s", getPathPatternDescription(j)),
					Process:     &procCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1036"},
					},
				}

				detections = append(detections, detection)
				break // Only report first matching pattern
			}
		}
	}

	return detections
}

// DetectTyposquatting detects typosquatted process names
func (d *Detector) DetectTyposquatting(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		nameLower := strings.ToLower(proc.Name)
		pathLower := strings.ToLower(proc.Path)

		// Skip if this process is itself a known system process (prevents system process vs system process false positives)
		// e.g., smss.exe should not be flagged as similar to lsass.exe or csrss.exe
		if _, isKnownSystem := TyposquatTargets[proc.Name]; isKnownSystem {
			continue
		}
		if _, isKnownSystem := TyposquatTargets[strings.ToLower(proc.Name)]; isKnownSystem {
			continue
		}

		// Skip if running from legitimate software paths (reduces false positives)
		if isLegitimateInstallPath(proc.Path) {
			continue
		}

		for targetName, expectedPath := range TyposquatTargets {
			targetLower := strings.ToLower(targetName)

			// Check if name is similar but not exact
			// Only flag if: 1) name similar AND 2) path is suspicious (not in Program Files, etc.)
			if nameLower != targetLower && isSimilar(nameLower, targetLower) {
				// Additional check: only flag if path looks suspicious
				if proc.Path != "" && !isSuspiciousPath(proc.Path) {
					continue // Skip if path is legitimate
				}

				procCopy := proc
				detection := types.Detection{
					ID:          fmt.Sprintf("typo-%d-%d", proc.PID, time.Now().UnixNano()),
					Type:        types.DetectionTypeTyposquat,
					Severity:    types.SeverityHigh,
					Confidence:  0.85,
					Timestamp:   proc.CreateTime,
					Description: fmt.Sprintf("Possible typosquatting: %s (similar to %s)", proc.Name, targetName),
					Process:     &procCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1036.005"},
					},
				}

				detections = append(detections, detection)
			}

			// Check if name matches but path doesn't (masquerading detection)
			// Skip if path is empty (couldn't read path != wrong path)
			if proc.Path == "" {
				continue
			}

			if nameLower == targetLower && !strings.EqualFold(pathLower, expectedPath) {
				// Verify it's not just a different valid path
				if !isValidSystemPath(proc.Path, targetName) {
					procCopy := proc
					detection := types.Detection{
						ID:          fmt.Sprintf("masq-%d-%d", proc.PID, time.Now().UnixNano()),
						Type:        types.DetectionTypeTyposquat,
						Severity:    types.SeverityCritical,
						Confidence:  0.95,
						Timestamp:   proc.CreateTime,
						Description: fmt.Sprintf("Process masquerading: %s running from unexpected path", proc.Name),
						Process:     &procCopy,
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Defense Evasion"},
							Techniques: []string{"T1036.005"},
						},
						Details: map[string]interface{}{
							"expected_path": expectedPath,
							"actual_path":   proc.Path,
						},
					}

					detections = append(detections, detection)
				}
			}
		}
	}

	return detections
}

// Helper functions

func determineLOLBinSeverity(name, cmdline string) string {
	// High severity LOLBins
	highSeverity := map[string]bool{
		"certutil.exe": true, "bitsadmin.exe": true, "mshta.exe": true,
		"regsvr32.exe": true, "rundll32.exe": true, "msbuild.exe": true,
		"cmstp.exe": true, "installutil.exe": true,
	}

	if highSeverity[name] {
		return types.SeverityHigh
	}

	// Check for suspicious command line patterns
	if hasSuspiciousArgs(cmdline) {
		return types.SeverityHigh
	}

	return types.SeverityMedium
}

func hasSuspiciousArgs(cmdline string) bool {
	if cmdline == "" {
		return false
	}

	cmdLower := strings.ToLower(cmdline)
	suspiciousPatterns := []string{
		"-encodedcommand", "-enc ", "-e ", "-ec ",
		"downloadstring", "downloadfile", "invoke-webrequest",
		"iex(", "invoke-expression",
		"-urlcache", "-split",
		"http://", "https://", "ftp://",
		"bypass", "-nop", "-noprofile", "-w hidden",
		"frombase64", "tobase64",
		"-exec bypass", "unrestricted",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	return false
}

func getLOLBinMITRE(category string) *types.MITREMapping {
	mapping := &types.MITREMapping{}

	switch category {
	case "Execute":
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	case "Download":
		mapping.Tactics = []string{"Command and Control"}
		mapping.Techniques = []string{"T1105"}
	case "Bypass":
		mapping.Tactics = []string{"Defense Evasion"}
		mapping.Techniques = []string{"T1218"}
	case "Recon":
		mapping.Tactics = []string{"Discovery"}
		mapping.Techniques = []string{"T1082", "T1083"}
	case "Persist":
		mapping.Tactics = []string{"Persistence"}
		mapping.Techniques = []string{"T1053", "T1543"}
	case "Credential Access":
		mapping.Tactics = []string{"Credential Access"}
		mapping.Techniques = []string{"T1003"}
	case "Lateral Movement":
		mapping.Tactics = []string{"Lateral Movement"}
		mapping.Techniques = []string{"T1021"}
	case "Compile":
		mapping.Tactics = []string{"Defense Evasion"}
		mapping.Techniques = []string{"T1027.004"}
	default:
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	}

	return mapping
}

func getChainMITRE(parentName string) *types.MITREMapping {
	mapping := &types.MITREMapping{}

	switch {
	case strings.Contains(parentName, "w3wp") || strings.Contains(parentName, "httpd") ||
		strings.Contains(parentName, "tomcat") || strings.Contains(parentName, "java"):
		mapping.Tactics = []string{"Initial Access", "Execution"}
		mapping.Techniques = []string{"T1190", "T1059"}
	case strings.Contains(parentName, "word") || strings.Contains(parentName, "excel") ||
		strings.Contains(parentName, "outlook"):
		mapping.Tactics = []string{"Initial Access", "Execution"}
		mapping.Techniques = []string{"T1566", "T1204"}
	case strings.Contains(parentName, "wmiprvse"):
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1047"}
	default:
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	}

	return mapping
}

func determinPortSeverity(port uint16) string {
	// Critical ports (common C2/reverse shell)
	criticalPorts := map[uint16]bool{
		4444: true, 5555: true, 6666: true, 1337: true, 31337: true,
	}

	if criticalPorts[port] {
		return types.SeverityCritical
	}

	// High severity ports
	highPorts := map[uint16]bool{
		8080: true, 8443: true, 4443: true, 6667: true, 9001: true,
	}

	if highPorts[port] {
		return types.SeverityHigh
	}

	return types.SeverityMedium
}

func getPathPatternDescription(index int) string {
	descriptions := []string{
		"UNC path (remote execution)",
		"Alternate Data Stream",
		"Double extension",
		"Numeric filename",
		"Fake system path",
		"Temp folder executable",
		"AppData executable (non-standard location)",
		"Public folder executable",
		"ProgramData executable",
		"Recycle bin execution",
	}

	if index < len(descriptions) {
		return descriptions[index]
	}
	return "Unknown pattern"
}

// isSimilar checks if two strings are similar (Levenshtein distance 1-2)
func isSimilar(a, b string) bool {
	distance := levenshteinDistance(a, b)
	return distance > 0 && distance <= 2
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func isValidSystemPath(path, processName string) bool {
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(processName)

	// Check for valid Windows system paths
	validPaths := []string{
		`c:\windows\system32\`,
		`c:\windows\syswow64\`,
		`c:\windows\`,
		`c:\windows\system32\wbem\`,
	}

	for _, validPath := range validPaths {
		if strings.HasPrefix(pathLower, validPath) && strings.HasSuffix(pathLower, nameLower) {
			return true
		}
	}

	return false
}

// isLegitimateInstallPath checks if a path is a legitimate software installation path
func isLegitimateInstallPath(path string) bool {
	if path == "" {
		return false
	}

	pathLower := strings.ToLower(path)

	// Legitimate installation paths
	legitimatePaths := []string{
		`c:\program files\`,
		`c:\program files (x86)\`,
		`c:\windows\`,
		`\appdata\local\programs\`,
		`\appdata\local\microsoft\`,
		`\appdata\local\google\`,
		`\appdata\local\slack\`,
		`\appdata\local\discord\`,
	}

	for _, legitPath := range legitimatePaths {
		if strings.Contains(pathLower, legitPath) {
			return true
		}
	}

	return false
}

// isLegitTempApplication checks if a temp folder executable is a known legitimate application
func isLegitTempApplication(path string) bool {
	if path == "" {
		return false
	}

	pathLower := strings.ToLower(path)

	// Known legitimate temp folder applications
	legitTempPatterns := []string{
		`\temp\vscode-`,           // VSCode auto-updater
		`\temp\chrome_`,           // Chrome installer/updater
		`\temp\discord`,           // Discord updater
		`\temp\slack`,             // Slack updater
		`\temp\teams`,             // Teams updater
		`\temp\\.net\`,            // .NET runtime
		`\temp\go-build`,          // Go build cache
		`\temp\pip-`,              // Python pip
		`\temp\npm-`,              // npm cache
		`\temp\yarn-`,             // Yarn cache
	}

	for _, pattern := range legitTempPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	return false
}

// isSuspiciousPath checks if a path is typically used by malware
func isSuspiciousPath(path string) bool {
	if path == "" {
		return true // No path = suspicious
	}

	pathLower := strings.ToLower(path)

	// Suspicious paths commonly used by malware
	suspiciousPaths := []string{
		`\temp\`,
		`\tmp\`,
		`\users\public\`,
		`\programdata\`,
		`\appdata\roaming\`,
		`\recycler\`,
		`\$recycle.bin\`,
		`\downloads\`,
		`\desktop\`,
	}

	for _, suspPath := range suspiciousPaths {
		if strings.Contains(pathLower, suspPath) {
			return true
		}
	}

	// If path doesn't start with common legitimate prefixes, it's suspicious
	legitimatePrefixes := []string{
		`c:\program files`,
		`c:\windows`,
	}

	hasLegitimatePrefix := false
	for _, prefix := range legitimatePrefixes {
		if strings.HasPrefix(pathLower, prefix) {
			hasLegitimatePrefix = true
			break
		}
	}

	// AppData\Local\Programs is legitimate
	if strings.Contains(pathLower, `\appdata\local\programs\`) {
		hasLegitimatePrefix = true
	}

	return !hasLegitimatePrefix
}

// DetectServiceVendorTyposquatting detects typosquatted vendor names in service display names
func (d *Detector) DetectServiceVendorTyposquatting(services []types.ServiceInfo) []types.Detection {
	var detections []types.Detection

	for _, svc := range services {
		displayLower := strings.ToLower(svc.DisplayName)

		for _, vendor := range TrustedVendors {
			vendorLower := strings.ToLower(vendor)

			// Skip short vendor names (too many false positives)
			if len(vendorLower) < 4 {
				continue
			}

			// Check if display name contains something similar but not exact
			words := strings.Fields(displayLower)
			for _, word := range words {
				// Skip if it's the exact match
				if word == vendorLower {
					continue
				}

				// Skip common English words that cause false positives
				if CommonEnglishWords[word] {
					continue
				}

				// Skip very short words (3 chars or less)
				if len(word) <= 3 {
					continue
				}

				// Check Levenshtein distance
				distance := levenshteinDistance(word, vendorLower)

				// Only flag distance 1 to reduce false positives
				// Word must be close in length to vendor name
				if distance == 1 && len(word) >= len(vendorLower)-1 && len(word) <= len(vendorLower)+1 {
					detection := types.Detection{
						ID:          fmt.Sprintf("svc-vendor-%s-%d", svc.Name, time.Now().UnixNano()),
						Type:        types.DetectionTypeServiceVendor,
						Severity:    types.SeverityHigh,
						Confidence:  0.85,
						Timestamp:   time.Now(),
						Description: fmt.Sprintf("Service vendor typosquatting: '%s' similar to '%s' in service '%s'", word, vendor, svc.DisplayName),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Defense Evasion", "Persistence"},
							Techniques: []string{"T1036.005", "T1543.003"},
						},
						Details: map[string]interface{}{
							"service_name":    svc.Name,
							"display_name":    svc.DisplayName,
							"typosquat_word":  word,
							"legitimate_name": vendor,
							"distance":        distance,
						},
					}
					detections = append(detections, detection)
					break // Only one detection per service
				}
			}
		}
	}

	return detections
}

// DetectServiceNameTyposquatting detects typosquatted system service names
func (d *Detector) DetectServiceNameTyposquatting(services []types.ServiceInfo) []types.Detection {
	var detections []types.Detection

	for _, svc := range services {
		nameLower := strings.ToLower(svc.Name)

		// Skip if this is a known Microsoft service (whitelist)
		if MicrosoftServiceWhitelist[nameLower] {
			continue
		}

		// Skip if binary path is from Windows system directory (trusted)
		pathLower := strings.ToLower(svc.BinaryPath)
		if strings.Contains(pathLower, `\windows\system32\`) ||
			strings.Contains(pathLower, `\windows\syswow64\`) ||
			strings.Contains(pathLower, `\program files\`) ||
			strings.Contains(pathLower, `\program files (x86)\`) {
			continue
		}

		for _, systemSvc := range SystemServices {
			// Skip exact match
			if nameLower == systemSvc {
				continue
			}

			distance := levenshteinDistance(nameLower, systemSvc)

			// Only flag distance 1 (stricter) and require similar length
			if distance == 1 && len(nameLower) >= len(systemSvc)-1 && len(nameLower) <= len(systemSvc)+1 {
				detection := types.Detection{
					ID:          fmt.Sprintf("svc-name-%s-%d", svc.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeServiceName,
					Severity:    types.SeverityHigh,
					Confidence:  0.9,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Service name typosquatting: '%s' similar to system service '%s'", svc.Name, systemSvc),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion", "Persistence"},
						Techniques: []string{"T1036.005", "T1543.003"},
					},
					Details: map[string]interface{}{
						"service_name":   svc.Name,
						"display_name":   svc.DisplayName,
						"system_service": systemSvc,
						"distance":       distance,
						"binary_path":    svc.BinaryPath,
					},
				}
				detections = append(detections, detection)
				break
			}
		}
	}

	return detections
}

// DetectServicePathAnomalies detects services running from suspicious paths
func (d *Detector) DetectServicePathAnomalies(services []types.ServiceInfo) []types.Detection {
	var detections []types.Detection

	for _, svc := range services {
		if svc.BinaryPath == "" {
			continue
		}

		pathLower := strings.ToLower(svc.BinaryPath)

		// Skip known Microsoft paths (whitelist)
		isMicrosoftPath := false
		for _, msPath := range MicrosoftPathPrefixes {
			if strings.Contains(pathLower, msPath) {
				isMicrosoftPath = true
				break
			}
		}
		if isMicrosoftPath {
			continue
		}

		// Skip if it's a known Microsoft service running from system paths
		nameLower := strings.ToLower(svc.Name)
		if MicrosoftServiceWhitelist[nameLower] {
			continue
		}

		// Check for dangerous paths
		for _, dangerPath := range DangerousPaths {
			if strings.Contains(pathLower, dangerPath) {
				detection := types.Detection{
					ID:          fmt.Sprintf("svc-path-%s-%d", svc.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeServicePath,
					Severity:    types.SeverityHigh,
					Confidence:  0.85,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Service running from suspicious path: %s", svc.BinaryPath),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence", "Defense Evasion"},
						Techniques: []string{"T1543.003", "T1036"},
					},
					Details: map[string]interface{}{
						"service_name":   svc.Name,
						"display_name":   svc.DisplayName,
						"binary_path":    svc.BinaryPath,
						"dangerous_path": dangerPath,
					},
				}
				detections = append(detections, detection)
				break
			}
		}

		// Check if service runs cmd.exe or powershell.exe directly
		shellBinaries := []string{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
		for _, shell := range shellBinaries {
			if strings.Contains(pathLower, shell) {
				detection := types.Detection{
					ID:          fmt.Sprintf("svc-shell-%s-%d", svc.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeServicePath,
					Severity:    types.SeverityCritical,
					Confidence:  0.9,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Service executes shell binary: %s", shell),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence", "Execution"},
						Techniques: []string{"T1543.003", "T1059"},
					},
					Details: map[string]interface{}{
						"service_name": svc.Name,
						"display_name": svc.DisplayName,
						"binary_path":  svc.BinaryPath,
						"shell":        shell,
					},
				}
				detections = append(detections, detection)
				break
			}
		}
	}

	return detections
}

// DetectUnsignedCriticalProcesses detects critical system processes running from unexpected paths
func (d *Detector) DetectUnsignedCriticalProcesses(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for _, proc := range processes {
		nameLower := strings.ToLower(proc.Name)
		pathLower := strings.ToLower(proc.Path)

		// Check if this is a critical process
		expectedPath, isCritical := CriticalProcesses[nameLower]
		if !isCritical {
			continue
		}

		// Skip if path is empty (we can't verify without path)
		if proc.Path == "" {
			continue
		}

		// Check if running from expected path
		if pathLower != expectedPath {
			// Allow SysWOW64 for 32-bit processes
			if strings.Contains(pathLower, `\windows\syswow64\`) && strings.Contains(expectedPath, `\windows\system32\`) {
				continue
			}

			detection := types.Detection{
				ID:          fmt.Sprintf("unsigned-%d-%d", proc.PID, time.Now().UnixNano()),
				Type:        types.DetectionTypeUnsignedProcess,
				Severity:    types.SeverityCritical,
				Confidence:  0.95,
				Timestamp:   proc.CreateTime,
				Description: fmt.Sprintf("Critical process %s running from unexpected path", proc.Name),
				Process:     &proc,
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion"},
					Techniques: []string{"T1036.005"},
				},
				Details: map[string]interface{}{
					"expected_path": expectedPath,
					"actual_path":   proc.Path,
				},
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// DetectSuspiciousDomains detects connections to suspicious domains
func (d *Detector) DetectSuspiciousDomains(connections []types.NetworkConnection) []types.Detection {
	var detections []types.Detection

	for _, conn := range connections {
		if conn.RemoteAddr == "" || conn.State != "ESTABLISHED" {
			continue
		}

		// Skip local/private IPs
		if isPrivateIP(conn.RemoteAddr) {
			continue
		}

		domain := conn.RemoteAddr
		domainLower := strings.ToLower(domain)

		var reason string
		var severity string = types.SeverityMedium

		// Check high-risk TLDs
		for _, tld := range HighRiskTLDs {
			if strings.HasSuffix(domainLower, "."+tld) {
				reason = fmt.Sprintf("High-risk TLD: .%s", tld)
				severity = types.SeverityHigh
				break
			}
		}

		// Check DGA pattern
		if reason == "" && dgaPatternCompiled.MatchString(domainLower) {
			reason = "DGA-like domain pattern"
			severity = types.SeverityCritical
		}

		// Check Punycode
		if reason == "" && punycodePatternCompiled.MatchString(domainLower) {
			reason = "Punycode IDN domain (potential homograph attack)"
			severity = types.SeverityHigh
		}

		// Check IP pattern in domain
		if reason == "" && ipPatternCompiled.MatchString(domainLower) {
			reason = "IP-like pattern in domain"
			severity = types.SeverityMedium
		}

		// Check for malicious keywords
		if reason == "" {
			for _, keyword := range MaliciousKeywords {
				if strings.Contains(domainLower, keyword) {
					reason = fmt.Sprintf("Malicious keyword: %s", keyword)
					severity = types.SeverityHigh
					break
				}
			}
		}

		// Check .onion domain
		if reason == "" && strings.HasSuffix(domainLower, ".onion") {
			reason = "Tor .onion domain"
			severity = types.SeverityCritical
		}

		if reason != "" {
			connCopy := conn
			detection := types.Detection{
				ID:          fmt.Sprintf("domain-%d-%d", conn.OwningPID, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousDomain,
				Severity:    severity,
				Confidence:  0.8,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Suspicious domain: %s (%s)", domain, reason),
				Network:     &connCopy,
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Command and Control"},
					Techniques: []string{"T1071", "T1568"},
				},
				Details: map[string]interface{}{
					"domain":       domain,
					"reason":       reason,
					"remote_port":  conn.RemotePort,
					"process_name": conn.ProcessName,
				},
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// DetectEncodedCommands detects encoded/obfuscated command lines
func (d *Detector) DetectEncodedCommands(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for _, proc := range processes {
		if proc.CommandLine == "" {
			continue
		}

		cmdLower := strings.ToLower(proc.CommandLine)

		for _, pattern := range EncodedCommandPatterns {
			if strings.Contains(cmdLower, pattern) {
				procCopy := proc
				detection := types.Detection{
					ID:          fmt.Sprintf("encoded-%d-%d", proc.PID, time.Now().UnixNano()),
					Type:        types.DetectionTypeEncodedCommand,
					Severity:    types.SeverityHigh,
					Confidence:  0.85,
					Timestamp:   proc.CreateTime,
					Description: fmt.Sprintf("Encoded/obfuscated command detected: %s", pattern),
					Process:     &procCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion", "Execution"},
						Techniques: []string{"T1027", "T1059.001"},
					},
					Details: map[string]interface{}{
						"pattern":      pattern,
						"command_line": truncateString(proc.CommandLine, 500),
					},
				}
				detections = append(detections, detection)
				break // Only one detection per process
			}
		}
	}

	return detections
}

// ExtractIOCs extracts Indicators of Compromise from scan results
func (d *Detector) ExtractIOCs(result *types.ScanResult) types.IOCCollection {
	iocs := types.IOCCollection{
		IPs:   make([]types.IOCEntry, 0),
		URLs:  make([]types.IOCEntry, 0),
		Files: make([]types.IOCEntry, 0),
	}

	seenIPs := make(map[string]bool)
	seenFiles := make(map[string]bool)

	for _, detection := range result.Detections {
		// Extract IPs from network detections
		if detection.Network != nil {
			ip := detection.Network.RemoteAddr
			if ip != "" && !seenIPs[ip] && !isPrivateIP(ip) {
				seenIPs[ip] = true
				iocs.IPs = append(iocs.IPs, types.IOCEntry{
					Value:   ip,
					Context: fmt.Sprintf("Port:%d Process:%s", detection.Network.RemotePort, detection.Network.ProcessName),
				})
			}
		}

		// Extract file paths from process detections
		if detection.Process != nil {
			path := detection.Process.Path
			if path != "" && !seenFiles[path] {
				seenFiles[path] = true
				iocs.Files = append(iocs.Files, types.IOCEntry{
					Value:   path,
					Context: fmt.Sprintf("Detection:%s", detection.Type),
				})
			}
		}

		// Extract from Details map
		if details, ok := detection.Details["binary_path"]; ok {
			if path, ok := details.(string); ok && path != "" && !seenFiles[path] {
				seenFiles[path] = true
				iocs.Files = append(iocs.Files, types.IOCEntry{
					Value:   path,
					Context: fmt.Sprintf("Service:%s", detection.Type),
				})
			}
		}
	}

	return iocs
}

// Helper functions

func isPrivateIP(ip string) bool {
	// Simple check for private/local IPs
	privatePatterns := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.", "127.", "0.0.0.0",
		"::1", "fe80:", "fc00:", "fd00:",
	}

	for _, prefix := range privatePatterns {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

package detector

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/internal/rulestore"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// Compiled regex patterns for domain analysis
var (
	dgaPatternCompiled      = regexp.MustCompile(`^[a-z0-9]{20,}\.[a-z]{2,4}$`)
	punycodePatternCompiled = regexp.MustCompile(`^xn--`)
	ipPatternCompiled       = regexp.MustCompile(`\d{1,3}[-_]\d{1,3}[-_]\d{1,3}`)
)

// Detector is the main detection engine
type Detector struct {
	rules        *rulestore.DetectionRules
	pathPatterns []*regexp.Regexp
}

// New creates a new Detector instance with injected detection rules
func New(rules *rulestore.DetectionRules) *Detector {
	d := &Detector{rules: rules}
	if rules != nil {
		d.pathPatterns = rules.PathAnomalyRegexps
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

		if d.rules.AllLOLBins[nameLower] {
			// Skip common Windows shell processes running normally
			// Only flag when there's suspicious context
			if isNormalWindowsShell(nameLower, proc.Path, proc.CommandLine, proc.ParentName) {
				continue
			}

			category := d.rules.LOLBinCategory(nameLower)
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

	// Common Windows shell/installer processes that run normally
	shellProcesses := map[string]bool{
		"explorer.exe":   true,
		"cmd.exe":        true,
		"powershell.exe": true,
		"pwsh.exe":       true,
		"msiexec.exe":    true,
		"mmc.exe":        true,
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
		// Developer tools
		"wails.exe":           true,
		"go.exe":              true,
		"npm.exe":             true,
		"node.exe":            true,
		"cargo.exe":           true,
		"python.exe":          true,
		"python3.exe":         true,
		"idea64.exe":          true,
		"devenv.exe":          true,
		"goland64.exe":        true,
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

		if suspiciousChildren, exists := d.rules.SuspiciousChains[parentName]; exists {
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
		"wails.exe":   true,
		"go.exe":      true,
		"npm.exe":     true,
		"cargo.exe":   true,
		"gradle.exe":  true,
		"maven.exe":   true,
		"dotnet.exe":  true,
	}

	if developerParents[parentLower] {
		// Check if running from legitimate development paths
		legitDevPaths := []string{
			`\programs\python`,
			`\python`,
			`\nodejs\`,
			`\program files\`,
			`\appdata\local\programs\`,
			`\go\bin\`,
			`\cargo\bin\`,
			`\npm\`,
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
			if description, suspicious := d.rules.SuspiciousPorts[conn.RemotePort]; suspicious {
				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("port-%d-%d-%d", conn.RemotePort, conn.OwningPID, time.Now().UnixNano()),
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
			if description, suspicious := d.rules.SuspiciousPorts[conn.LocalPort]; suspicious {
				// Skip standard Windows services (System process PID 4)
				if isStandardWindowsService(conn.LocalPort, conn.OwningPID) {
					continue
				}

				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("listen-%d-%d-%d", conn.LocalPort, conn.OwningPID, time.Now().UnixNano()),
					Type:        types.DetectionTypePort,
					Severity:    types.SeverityLow,
					Confidence:  0.5,
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
		if _, isKnownSystem := d.rules.TyposquatTargets[proc.Name]; isKnownSystem {
			continue
		}
		if _, isKnownSystem := d.rules.TyposquatTargets[strings.ToLower(proc.Name)]; isKnownSystem {
			continue
		}

		// Skip if running from legitimate software paths (reduces false positives)
		if isLegitimateInstallPath(proc.Path) {
			continue
		}

		for targetName, expectedPath := range d.rules.TyposquatTargets {
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

		for _, vendor := range d.rules.TrustedVendors {
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
				if d.rules.CommonEnglishWords[word] {
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
		if d.rules.MicrosoftServiceWhitelist[nameLower] {
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

		for _, systemSvc := range d.rules.SystemServices {
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
		for _, msPath := range d.rules.MicrosoftPathPrefixes {
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
		if d.rules.MicrosoftServiceWhitelist[nameLower] {
			continue
		}

		// Check for dangerous paths
		for _, dangerPath := range d.rules.DangerousPaths {
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
		expectedPath, isCritical := d.rules.CriticalProcesses[nameLower]
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

			procCopy := proc
			detection := types.Detection{
				ID:          fmt.Sprintf("unsigned-%d-%d", proc.PID, time.Now().UnixNano()),
				Type:        types.DetectionTypeUnsignedProcess,
				Severity:    types.SeverityCritical,
				Confidence:  0.95,
				Timestamp:   proc.CreateTime,
				Description: fmt.Sprintf("Critical process %s running from unexpected path", proc.Name),
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
		for _, tld := range d.rules.HighRiskTLDs {
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
			for _, keyword := range d.rules.MaliciousKeywords {
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

		for _, pattern := range d.rules.EncodedCommandPatterns {
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

// ── Phase 1 Detection Methods ──

// DetectSuspiciousStartup detects suspicious files in startup folders
func (d *Detector) DetectSuspiciousStartup(entries []types.StartupEntry) []types.Detection {
	var detections []types.Detection

	executableExts := map[string]bool{
		".exe": true, ".bat": true, ".cmd": true, ".ps1": true,
		".vbs": true, ".js": true, ".wsf": true, ".scr": true,
		".com": true, ".pif": true, ".hta": true,
	}

	for _, entry := range entries {
		ext := strings.ToLower(getExtension(entry.Name))

		// Skip non-executable LNK shortcuts (normal in startup)
		if ext == ".lnk" || ext == ".ini" || ext == ".url" {
			continue
		}

		severity := types.SeverityMedium
		confidence := 0.7
		reason := ""

		if executableExts[ext] {
			reason = fmt.Sprintf("Executable file in startup folder: %s", entry.Name)
			severity = types.SeverityHigh
			confidence = 0.8

			// Recently created = higher severity
			if !entry.CreatedAt.IsZero() && time.Since(entry.CreatedAt) < 7*24*time.Hour {
				severity = types.SeverityHigh
				confidence = 0.9
				reason += " (created within last 7 days)"
			}
		} else {
			reason = fmt.Sprintf("Unknown file in startup folder: %s", entry.Name)
		}

		if entry.IsHidden {
			severity = types.SeverityHigh
			confidence = 0.85
			reason += " [hidden]"
		}

		if reason != "" {
			detection := types.Detection{
				ID:          fmt.Sprintf("startup-%s-%d", entry.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousStartup,
				Severity:    severity,
				Confidence:  confidence,
				Timestamp:   time.Now(),
				Description: reason,
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence"},
					Techniques: []string{"T1547.001"},
				},
				Details: map[string]interface{}{
					"file_name":  entry.Name,
					"file_path":  entry.Path,
					"file_size":  entry.Size,
					"scope":      entry.Scope,
					"user":       entry.User,
					"created_at": entry.CreatedAt.Format(time.RFC3339),
					"is_hidden":  entry.IsHidden,
				},
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// DetectSuspiciousPowerShell detects suspicious commands in PowerShell history
func (d *Detector) DetectSuspiciousPowerShell(entries []types.PowerShellHistoryEntry) []types.Detection {
	var detections []types.Detection

	suspiciousPatterns := []struct {
		pattern  string
		severity string
		desc     string
	}{
		{"invoke-mimikatz", types.SeverityCritical, "Mimikatz credential dump"},
		{"get-credential", types.SeverityHigh, "Credential harvesting"},
		{"set-mppreference -disablerealtimemonitoring", types.SeverityCritical, "Disabling Defender real-time protection"},
		{"set-mppreference -disableioavprotection", types.SeverityCritical, "Disabling Defender IO/AV protection"},
		{"add-mppreference -exclusionpath", types.SeverityHigh, "Adding Defender exclusion"},
		{"net user", types.SeverityMedium, "User account manipulation"},
		{"net localgroup administrators", types.SeverityHigh, "Local admin group change"},
		{"-encodedcommand", types.SeverityHigh, "Encoded command execution"},
		{"-enc ", types.SeverityHigh, "Encoded command execution"},
		{"frombase64string", types.SeverityHigh, "Base64 decode (possible payload)"},
		{"downloadstring", types.SeverityHigh, "Remote script download"},
		{"downloadfile", types.SeverityHigh, "Remote file download"},
		{"invoke-webrequest", types.SeverityMedium, "Web request (possible download)"},
		{"start-process", types.SeverityLow, "Process execution"},
		{"invoke-expression", types.SeverityHigh, "Dynamic code execution (IEX)"},
		{"new-object net.webclient", types.SeverityHigh, "WebClient download"},
		{"bypass", types.SeverityMedium, "Execution policy bypass"},
		{"reg add", types.SeverityMedium, "Registry modification"},
		{"schtasks /create", types.SeverityMedium, "Scheduled task creation"},
		{"certutil -urlcache", types.SeverityHigh, "File download via certutil"},
		{"bitsadmin /transfer", types.SeverityHigh, "File download via BITS"},
	}

	for _, entry := range entries {
		cmdLower := strings.ToLower(entry.Command)

		for _, p := range suspiciousPatterns {
			if strings.Contains(cmdLower, p.pattern) {
				detection := types.Detection{
					ID:          fmt.Sprintf("pshist-%s-%d-%d", entry.User, entry.LineNumber, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousPowerShell,
					Severity:    p.severity,
					Confidence:  0.85,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Suspicious PowerShell command: %s (user: %s)", p.desc, entry.User),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1059.001"},
					},
					Details: map[string]interface{}{
						"user":        entry.User,
						"command":     truncateString(entry.Command, 500),
						"line_number": entry.LineNumber,
						"file_path":   entry.FilePath,
						"pattern":     p.pattern,
					},
				}
				detections = append(detections, detection)
				break // One detection per command
			}
		}
	}

	return detections
}

// DetectSuspiciousDNSCache detects suspicious domains in DNS cache
func (d *Detector) DetectSuspiciousDNSCache(entries []types.DNSCacheEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		domainLower := strings.ToLower(entry.Name)

		var reason string
		severity := types.SeverityMedium

		// Reuse existing domain detection logic
		for _, tld := range d.rules.HighRiskTLDs {
			if strings.HasSuffix(domainLower, "."+tld) {
				reason = fmt.Sprintf("High-risk TLD: .%s", tld)
				severity = types.SeverityHigh
				break
			}
		}

		if reason == "" && dgaPatternCompiled.MatchString(domainLower) {
			reason = "DGA-like domain pattern"
			severity = types.SeverityCritical
		}

		if reason == "" && punycodePatternCompiled.MatchString(domainLower) {
			reason = "Punycode IDN domain"
			severity = types.SeverityHigh
		}

		if reason == "" && strings.HasSuffix(domainLower, ".onion") {
			reason = "Tor .onion domain"
			severity = types.SeverityCritical
		}

		if reason == "" {
			for _, keyword := range d.rules.MaliciousKeywords {
				if strings.Contains(domainLower, keyword) {
					reason = fmt.Sprintf("Malicious keyword: %s", keyword)
					severity = types.SeverityHigh
					break
				}
			}
		}

		// DNS tunneling: unusually long subdomain
		if reason == "" {
			parts := strings.Split(domainLower, ".")
			for _, part := range parts {
				if len(part) > 50 {
					reason = "Extremely long subdomain (possible DNS tunneling)"
					severity = types.SeverityHigh
					break
				}
			}
		}

		if reason != "" {
			detection := types.Detection{
				ID:          fmt.Sprintf("dns-%s-%d", entry.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousDNS,
				Severity:    severity,
				Confidence:  0.75,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Suspicious DNS cache entry: %s (%s)", entry.Name, reason),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Command and Control"},
					Techniques: []string{"T1071.004"},
				},
				Details: map[string]interface{}{
					"domain":      entry.Name,
					"record_type": entry.Section,
					"reason":      reason,
				},
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// DetectSuspiciousAccounts detects suspicious user accounts
func (d *Detector) DetectSuspiciousAccounts(accounts []types.UserAccountInfo) []types.Detection {
	var detections []types.Detection

	for _, account := range accounts {
		// Hidden account (name ends with $)
		if strings.HasSuffix(account.Name, "$") && !strings.EqualFold(account.Name, "DefaultAccount$") {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("acct-hidden-%s-%d", account.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousAccount,
				Severity:    types.SeverityHigh,
				Confidence:  0.9,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Hidden user account detected: %s", account.Name),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence"},
					Techniques: []string{"T1136.001"},
				},
				Details: map[string]interface{}{
					"account_name": account.Name,
					"is_admin":     account.IsAdmin,
					"reason":       "hidden_account",
				},
			})
		}

		// Active admin account with password that never expires
		if account.IsAdmin && !account.IsDisabled && account.Flags&0x10000 != 0 { // UF_DONT_EXPIRE_PASSWD
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("acct-noexpire-%s-%d", account.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousAccount,
				Severity:    types.SeverityMedium,
				Confidence:  0.6,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Admin account with non-expiring password: %s", account.Name),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence"},
					Techniques: []string{"T1098"},
				},
				Details: map[string]interface{}{
					"account_name": account.Name,
					"is_admin":     true,
					"reason":       "non_expiring_password",
				},
			})
		}

		// Enabled default accounts (Administrator, Guest)
		nameLower := strings.ToLower(account.Name)
		if (nameLower == "administrator" || nameLower == "guest") && !account.IsDisabled {
			severity := types.SeverityMedium
			if nameLower == "guest" {
				severity = types.SeverityHigh
			}
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("acct-default-%s-%d", account.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousAccount,
				Severity:    severity,
				Confidence:  0.7,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Default account '%s' is enabled", account.Name),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence"},
					Techniques: []string{"T1078.001"},
				},
				Details: map[string]interface{}{
					"account_name": account.Name,
					"is_admin":     account.IsAdmin,
					"reason":       "default_account_enabled",
				},
			})
		}

		// High number of failed login attempts
		if account.BadPWCount > 10 {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("acct-bruteforce-%s-%d", account.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousAccount,
				Severity:    types.SeverityHigh,
				Confidence:  0.8,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Account '%s' has %d failed login attempts", account.Name, account.BadPWCount),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Credential Access"},
					Techniques: []string{"T1110"},
				},
				Details: map[string]interface{}{
					"account_name":    account.Name,
					"bad_pw_count":    account.BadPWCount,
					"reason":          "brute_force_attempt",
				},
			})
		}
	}

	return detections
}

// DetectAntivirusIssues detects problems with antivirus protection
func (d *Detector) DetectAntivirusIssues(products []types.AntivirusInfo) []types.Detection {
	var detections []types.Detection

	if len(products) == 0 {
		detections = append(detections, types.Detection{
			ID:          fmt.Sprintf("av-none-%d", time.Now().UnixNano()),
			Type:        types.DetectionTypeAntivirusIssue,
			Severity:    types.SeverityCritical,
			Confidence:  0.95,
			Timestamp:   time.Now(),
			Description: "No antivirus product detected on this system",
			MITRE: &types.MITREMapping{
				Tactics:    []string{"Defense Evasion"},
				Techniques: []string{"T1562.001"},
			},
			Details: map[string]interface{}{
				"reason": "no_av_installed",
			},
		})
		return detections
	}

	for _, product := range products {
		if !product.IsEnabled {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("av-disabled-%s-%d", product.ProductName, time.Now().UnixNano()),
				Type:        types.DetectionTypeAntivirusIssue,
				Severity:    types.SeverityCritical,
				Confidence:  0.95,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Antivirus '%s' is disabled", product.ProductName),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion"},
					Techniques: []string{"T1562.001"},
				},
				Details: map[string]interface{}{
					"product_name":  product.ProductName,
					"product_state": product.ProductState,
					"reason":        "av_disabled",
				},
			})
		}

		if !product.IsUpToDate {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("av-outdated-%s-%d", product.ProductName, time.Now().UnixNano()),
				Type:        types.DetectionTypeAntivirusIssue,
				Severity:    types.SeverityHigh,
				Confidence:  0.9,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Antivirus '%s' definitions are out of date", product.ProductName),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion"},
					Techniques: []string{"T1562.001"},
				},
				Details: map[string]interface{}{
					"product_name":  product.ProductName,
					"product_state": product.ProductState,
					"reason":        "av_outdated",
				},
			})
		}
	}

	return detections
}

// DetectSuspiciousScheduledTasks detects suspicious scheduled tasks
func (d *Detector) DetectSuspiciousScheduledTasks(tasks []types.ScheduledTaskInfo) []types.Detection {
	var detections []types.Detection

	for _, task := range tasks {
		pathLower := strings.ToLower(task.ActionPath)
		argsLower := strings.ToLower(task.ActionArgs)

		// Encoded commands in task arguments
		encodedPatterns := []string{"-enc ", "-encodedcommand", "frombase64string", "iex(", "invoke-expression"}
		for _, pattern := range encodedPatterns {
			if strings.Contains(argsLower, pattern) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("task-encoded-%s-%d", task.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousTask,
					Severity:    types.SeverityCritical,
					Confidence:  0.9,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Scheduled task with encoded command: %s", task.Name),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence", "Execution"},
						Techniques: []string{"T1053.005", "T1059.001"},
					},
					Details: map[string]interface{}{
						"task_name":   task.Name,
						"action_path": task.ActionPath,
						"action_args": truncateString(task.ActionArgs, 500),
						"principal":   task.Principal,
						"reason":      "encoded_command",
					},
				})
				break
			}
		}

		// Tasks running from suspicious paths
		suspiciousPaths := []string{`\temp\`, `\tmp\`, `\users\public\`, `\downloads\`, `\appdata\`}
		for _, sp := range suspiciousPaths {
			if strings.Contains(pathLower, sp) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("task-path-%s-%d", task.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousTask,
					Severity:    types.SeverityHigh,
					Confidence:  0.8,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Scheduled task running from suspicious path: %s", task.Name),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence"},
						Techniques: []string{"T1053.005"},
					},
					Details: map[string]interface{}{
						"task_name":   task.Name,
						"action_path": task.ActionPath,
						"principal":   task.Principal,
						"reason":      "suspicious_path",
					},
				})
				break
			}
		}

		// Tasks executing shell binaries directly
		shellBinaries := []string{"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
		for _, shell := range shellBinaries {
			if strings.Contains(pathLower, shell) {
				// Check if it's a SYSTEM-level shell task
				severity := types.SeverityMedium
				if strings.EqualFold(task.Principal, "SYSTEM") || strings.EqualFold(task.Principal, "NT AUTHORITY\\SYSTEM") {
					severity = types.SeverityHigh
				}
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("task-shell-%s-%d", task.Name, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousTask,
					Severity:    severity,
					Confidence:  0.7,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Scheduled task executes %s: %s", shell, task.Name),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence", "Execution"},
						Techniques: []string{"T1053.005", "T1059"},
					},
					Details: map[string]interface{}{
						"task_name":   task.Name,
						"action_path": task.ActionPath,
						"action_args": truncateString(task.ActionArgs, 500),
						"principal":   task.Principal,
						"shell":       shell,
						"reason":      "shell_execution",
					},
				})
				break
			}
		}

		// Hidden tasks (GUID names)
		if task.IsHidden {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("task-hidden-%s-%d", task.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousTask,
				Severity:    types.SeverityMedium,
				Confidence:  0.65,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Hidden scheduled task (GUID name): %s", task.Name),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence", "Defense Evasion"},
					Techniques: []string{"T1053.005"},
				},
				Details: map[string]interface{}{
					"task_name":   task.Name,
					"action_path": task.ActionPath,
					"principal":   task.Principal,
					"reason":      "hidden_task",
				},
			})
		}
	}

	return detections
}

func getExtension(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i:]
		}
	}
	return ""
}

// ── Phase 2 Detection Methods ──

// DetectPrefetchAnomalies detects suspicious Prefetch entries
func (d *Detector) DetectPrefetchAnomalies(entries []types.PrefetchInfo) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		nameLower := strings.ToLower(entry.ExecutableName)

		// LOLBin execution history in Prefetch
		if d.rules.AllLOLBins[nameLower] {
			severity := types.SeverityMedium
			confidence := 0.6
			if entry.RunCount > 10 {
				severity = types.SeverityHigh
				confidence = 0.75
			}

			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("pf-lolbin-%s-%d", nameLower, time.Now().UnixNano()),
				Type:        types.DetectionTypePrefetchAnomaly,
				Severity:    severity,
				Confidence:  confidence,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("LOLBin '%s' has Prefetch evidence (run %d times)", entry.ExecutableName, entry.RunCount),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Execution"},
					Techniques: []string{"T1059"},
				},
				Details: map[string]interface{}{
					"executable":    entry.ExecutableName,
					"prefetch_path": entry.PrefetchPath,
					"run_count":     entry.RunCount,
					"reason":        "lolbin_history",
				},
			})
		}

		// Recent first-time execution (single last run time, low run count)
		if len(entry.LastRunTimes) == 1 && entry.RunCount <= 2 {
			lastRun := entry.LastRunTimes[0]
			if !lastRun.IsZero() && time.Since(lastRun) < 7*24*time.Hour {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("pf-recent-%s-%d", nameLower, time.Now().UnixNano()),
					Type:        types.DetectionTypePrefetchAnomaly,
					Severity:    types.SeverityLow,
					Confidence:  0.5,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Recently executed program '%s' (run %d times, last: %s)", entry.ExecutableName, entry.RunCount, lastRun.Format("2006-01-02")),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1204"},
					},
					Details: map[string]interface{}{
						"executable": entry.ExecutableName,
						"run_count":  entry.RunCount,
						"last_run":   lastRun.Format(time.RFC3339),
						"reason":     "recent_first_execution",
					},
				})
			}
		}
	}

	return detections
}

// DetectShimcacheAnomalies detects suspicious Shimcache entries
func (d *Detector) DetectShimcacheAnomalies(entries []types.ShimcacheEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		pathLower := strings.ToLower(entry.Path)
		fileName := filepath.Base(pathLower)

		// LOLBin from unusual path
		if d.rules.AllLOLBins[fileName] {
			if !strings.Contains(pathLower, `\windows\system32\`) &&
				!strings.Contains(pathLower, `\windows\syswow64\`) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("shim-lolbin-%d-%d", entry.Order, time.Now().UnixNano()),
					Type:        types.DetectionTypeShimcacheAnomaly,
					Severity:    types.SeverityHigh,
					Confidence:  0.8,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("LOLBin '%s' in Shimcache from unusual path", fileName),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution", "Defense Evasion"},
						Techniques: []string{"T1059", "T1036"},
					},
					Details: map[string]interface{}{
						"path":          entry.Path,
						"order":         entry.Order,
						"last_modified": entry.LastModified.Format(time.RFC3339),
						"reason":        "lolbin_unusual_path",
					},
				})
			}
		}

		// Executables from suspicious directories
		suspDirs := []string{`\temp\`, `\tmp\`, `\users\public\`, `\downloads\`, `\$recycle.bin\`}
		for _, dir := range suspDirs {
			if strings.Contains(pathLower, dir) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("shim-path-%d-%d", entry.Order, time.Now().UnixNano()),
					Type:        types.DetectionTypeShimcacheAnomaly,
					Severity:    types.SeverityMedium,
					Confidence:  0.7,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Shimcache entry from suspicious path: %s", entry.Path),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1204"},
					},
					Details: map[string]interface{}{
						"path":          entry.Path,
						"order":         entry.Order,
						"last_modified": entry.LastModified.Format(time.RFC3339),
						"reason":        "suspicious_path",
					},
				})
				break
			}
		}
	}

	return detections
}

// DetectAmcacheAnomalies detects suspicious Amcache entries
func (d *Detector) DetectAmcacheAnomalies(entries []types.AmcacheEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		pathLower := strings.ToLower(entry.Path)
		nameLower := strings.ToLower(entry.Name)

		// LOLBin from unusual path
		if d.rules.AllLOLBins[nameLower] && pathLower != "" {
			if !strings.Contains(pathLower, `\windows\system32\`) &&
				!strings.Contains(pathLower, `\windows\syswow64\`) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("amc-lolbin-%s-%d", nameLower, time.Now().UnixNano()),
					Type:        types.DetectionTypeAmcacheAnomaly,
					Severity:    types.SeverityHigh,
					Confidence:  0.75,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("LOLBin '%s' in Amcache from unusual path", entry.Name),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1059"},
					},
					Details: map[string]interface{}{
						"path":      entry.Path,
						"name":      entry.Name,
						"publisher": entry.Publisher,
						"sha1":      entry.SHA1,
						"reason":    "lolbin_history",
					},
				})
			}
		}

		// Unsigned executables from suspicious locations
		if entry.Publisher == "" && pathLower != "" {
			suspDirs := []string{`\temp\`, `\tmp\`, `\users\public\`, `\downloads\`, `\appdata\`}
			for _, dir := range suspDirs {
				if strings.Contains(pathLower, dir) {
					detections = append(detections, types.Detection{
						ID:          fmt.Sprintf("amc-unsigned-%s-%d", nameLower, time.Now().UnixNano()),
						Type:        types.DetectionTypeAmcacheAnomaly,
						Severity:    types.SeverityMedium,
						Confidence:  0.65,
						Timestamp:   time.Now(),
						Description: fmt.Sprintf("Unsigned executable '%s' in Amcache from suspicious path", entry.Name),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Execution", "Defense Evasion"},
							Techniques: []string{"T1204", "T1036"},
						},
						Details: map[string]interface{}{
							"path":   entry.Path,
							"name":   entry.Name,
							"sha1":   entry.SHA1,
							"size":   entry.Size,
							"reason": "unsigned_suspicious_path",
						},
					})
					break
				}
			}
		}
	}

	return detections
}

// DetectDLLAnomalies detects suspicious DLL modules loaded in processes
func (d *Detector) DetectDLLAnomalies(modules []types.DLLModuleInfo) []types.Detection {
	var detections []types.Detection

	for _, mod := range modules {
		pathLower := strings.ToLower(mod.ModulePath)
		nameLower := strings.ToLower(mod.ModuleName)

		// DLL from suspicious paths
		suspDirs := []string{`\temp\`, `\tmp\`, `\downloads\`, `\users\public\`, `\$recycle.bin\`}
		for _, dir := range suspDirs {
			if strings.Contains(pathLower, dir) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("dll-path-%d-%s-%d", mod.ProcessPID, nameLower, time.Now().UnixNano()),
					Type:        types.DetectionTypeDLLAnomaly,
					Severity:    types.SeverityHigh,
					Confidence:  0.8,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("DLL '%s' loaded from suspicious path in process '%s'", mod.ModuleName, mod.ProcessName),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Persistence", "Defense Evasion"},
						Techniques: []string{"T1574.001"},
					},
					Details: map[string]interface{}{
						"process_name": mod.ProcessName,
						"process_pid":  mod.ProcessPID,
						"module_name":  mod.ModuleName,
						"module_path":  mod.ModulePath,
						"reason":       "suspicious_dll_path",
					},
				})
				break
			}
		}

		// DLL name typosquatting
		knownDLLs := []string{
			"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
			"ws2_32.dll", "crypt32.dll", "msvcrt.dll", "ole32.dll",
			"shell32.dll", "gdi32.dll", "comctl32.dll", "comdlg32.dll",
		}
		for _, knownDLL := range knownDLLs {
			if nameLower != knownDLL && isSimilar(nameLower, knownDLL) {
				if !strings.Contains(pathLower, `\windows\system32\`) &&
					!strings.Contains(pathLower, `\windows\syswow64\`) {
					detections = append(detections, types.Detection{
						ID:          fmt.Sprintf("dll-typo-%d-%s-%d", mod.ProcessPID, nameLower, time.Now().UnixNano()),
						Type:        types.DetectionTypeDLLAnomaly,
						Severity:    types.SeverityCritical,
						Confidence:  0.9,
						Timestamp:   time.Now(),
						Description: fmt.Sprintf("DLL '%s' similar to system DLL '%s' from non-system path", mod.ModuleName, knownDLL),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Persistence", "Defense Evasion"},
							Techniques: []string{"T1574.001", "T1036.005"},
						},
						Details: map[string]interface{}{
							"process_name": mod.ProcessName,
							"process_pid":  mod.ProcessPID,
							"module_name":  mod.ModuleName,
							"module_path":  mod.ModulePath,
							"known_dll":    knownDLL,
							"reason":       "dll_typosquatting",
						},
					})
					break
				}
			}
		}
	}

	return detections
}

// DetectWMIPersistence detects WMI event subscription based persistence
func (d *Detector) DetectWMIPersistence(entries []types.WMIPersistenceInfo) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		severity := types.SeverityHigh
		confidence := 0.85

		consumerTypeLower := strings.ToLower(entry.ConsumerType)

		// CommandLine and ActiveScript consumers are almost always malicious
		if consumerTypeLower == "commandline" || consumerTypeLower == "activescript" {
			severity = types.SeverityCritical
			confidence = 0.95
		}

		// Suspicious patterns in consumer data
		dataLower := strings.ToLower(entry.ConsumerData)
		if strings.Contains(dataLower, "powershell") ||
			strings.Contains(dataLower, "cmd.exe") ||
			strings.Contains(dataLower, "-enc") ||
			strings.Contains(dataLower, "downloadstring") ||
			strings.Contains(dataLower, "invoke-expression") {
			severity = types.SeverityCritical
			confidence = 0.95
		}

		desc := fmt.Sprintf("WMI persistence: %s consumer '%s'", entry.ConsumerType, entry.ConsumerName)
		if entry.FilterName != "" {
			desc += fmt.Sprintf(" (filter: %s)", entry.FilterName)
		}

		detections = append(detections, types.Detection{
			ID:          fmt.Sprintf("wmi-%s-%d", entry.ConsumerName, time.Now().UnixNano()),
			Type:        types.DetectionTypeWMIPersistence,
			Severity:    severity,
			Confidence:  confidence,
			Timestamp:   time.Now(),
			Description: desc,
			MITRE: &types.MITREMapping{
				Tactics:    []string{"Persistence", "Execution"},
				Techniques: []string{"T1546.003"},
			},
			Details: map[string]interface{}{
				"filter_name":   entry.FilterName,
				"filter_query":  entry.FilterQuery,
				"consumer_name": entry.ConsumerName,
				"consumer_type": entry.ConsumerType,
				"consumer_data": truncateString(entry.ConsumerData, 500),
				"creator_sid":   entry.CreatorSID,
			},
		})
	}

	return detections
}

// DetectSuspiciousBrowsing detects suspicious URLs in browser history
func (d *Detector) DetectSuspiciousBrowsing(entries []types.BrowserHistoryEntry) []types.Detection {
	var detections []types.Detection

	suspiciousPatterns := []struct {
		pattern  string
		severity string
		desc     string
	}{
		{"pastebin.com", types.SeverityMedium, "Paste service (common payload hosting)"},
		{"hastebin.com", types.SeverityMedium, "Paste service"},
		{"ghostbin.", types.SeverityMedium, "Paste service"},
		{"raw.githubusercontent.com", types.SeverityLow, "Raw GitHub content"},
		{".onion.", types.SeverityCritical, "Tor hidden service"},
		{"exploit-db.com", types.SeverityMedium, "Exploit database"},
		{"shodan.io", types.SeverityLow, "Network scanner service"},
	}

	dangerousExts := []string{".exe", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".scr", ".msi"}

	for _, entry := range entries {
		urlLower := strings.ToLower(entry.URL)

		// Check suspicious URL patterns
		for _, sp := range suspiciousPatterns {
			if strings.Contains(urlLower, sp.pattern) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("browse-%s-%d", entry.Browser, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousBrowsing,
					Severity:    sp.severity,
					Confidence:  0.65,
					Timestamp:   entry.LastVisited,
					Description: fmt.Sprintf("Suspicious browsing: %s (%s)", sp.desc, entry.Browser),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control", "Execution"},
						Techniques: []string{"T1105"},
					},
					Details: map[string]interface{}{
						"url":         truncateString(entry.URL, 300),
						"title":       entry.Title,
						"browser":     entry.Browser,
						"user":        entry.User,
						"visit_count": entry.VisitCount,
						"reason":      "suspicious_url",
					},
				})
				break
			}
		}

		// Dangerous file downloads
		for _, ext := range dangerousExts {
			if strings.Contains(urlLower, ext) &&
				(strings.Contains(urlLower, "download") || strings.HasSuffix(urlLower, ext)) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("browse-dl-%s-%d", entry.Browser, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousBrowsing,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entry.LastVisited,
					Description: fmt.Sprintf("Potential dangerous file download via %s", entry.Browser),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Initial Access"},
						Techniques: []string{"T1189"},
					},
					Details: map[string]interface{}{
						"url":     truncateString(entry.URL, 300),
						"browser": entry.Browser,
						"user":    entry.User,
						"reason":  "dangerous_download",
					},
				})
				break
			}
		}

		// High-risk TLD domains
		domain := extractDomainFromURL(urlLower)
		if domain == "" {
			continue
		}
		for _, tld := range d.rules.HighRiskTLDs {
			if strings.HasSuffix(domain, "."+tld) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("browse-tld-%s-%d", entry.Browser, time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousBrowsing,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entry.LastVisited,
					Description: fmt.Sprintf("Browser visited high-risk TLD domain: .%s (%s)", tld, entry.Browser),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control"},
						Techniques: []string{"T1071"},
					},
					Details: map[string]interface{}{
						"url":     truncateString(entry.URL, 300),
						"domain":  domain,
						"browser": entry.Browser,
						"user":    entry.User,
						"reason":  "high_risk_tld",
					},
				})
				break
			}
		}
	}

	return detections
}

// DetectSuspiciousUSB detects suspicious USB device activity
func (d *Detector) DetectSuspiciousUSB(devices []types.USBDeviceInfo) []types.Detection {
	var detections []types.Detection

	for _, device := range devices {
		// Recently connected USB storage
		if !device.LastConnect.IsZero() && time.Since(device.LastConnect) < 7*24*time.Hour {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("usb-recent-%s-%d", device.SerialNumber, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousUSB,
				Severity:    types.SeverityInfo,
				Confidence:  0.5,
				Timestamp:   device.LastConnect,
				Description: fmt.Sprintf("USB storage device '%s' connected within last 7 days", device.FriendlyName),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Initial Access", "Exfiltration"},
					Techniques: []string{"T1091", "T1052.001"},
				},
				Details: map[string]interface{}{
					"device_id":     device.DeviceID,
					"serial_number": device.SerialNumber,
					"friendly_name": device.FriendlyName,
					"first_install": device.FirstInstall.Format(time.RFC3339),
					"last_connect":  device.LastConnect.Format(time.RFC3339),
					"drive_letter":  device.DriveLetter,
					"reason":        "recent_usb",
				},
			})
		}

		// All USB devices for audit
		if device.LastConnect.IsZero() && device.FirstInstall.IsZero() {
			continue
		}
		detections = append(detections, types.Detection{
			ID:          fmt.Sprintf("usb-audit-%s-%d", device.SerialNumber, time.Now().UnixNano()),
			Type:        types.DetectionTypeSuspiciousUSB,
			Severity:    types.SeverityInfo,
			Confidence:  0.3,
			Timestamp:   time.Now(),
			Description: fmt.Sprintf("USB storage device history: '%s' (S/N: %s)", device.FriendlyName, device.SerialNumber),
			MITRE: &types.MITREMapping{
				Tactics:    []string{"Initial Access"},
				Techniques: []string{"T1091"},
			},
			Details: map[string]interface{}{
				"device_id":     device.DeviceID,
				"serial_number": device.SerialNumber,
				"friendly_name": device.FriendlyName,
				"first_install": device.FirstInstall.Format(time.RFC3339),
				"last_connect":  device.LastConnect.Format(time.RFC3339),
				"drive_letter":  device.DriveLetter,
				"reason":        "usb_audit",
			},
		})
	}

	return detections
}

// ═══════════════════════════════════════════════════════════
// Phase 3 Detection Engines
// ═══════════════════════════════════════════════════════════

// DetectUnsignedDrivers detects unsigned or suspicious kernel drivers
func (d *Detector) DetectUnsignedDrivers(drivers []types.DriverInfo) []types.Detection {
	var detections []types.Detection

	for _, drv := range drivers {
		drvCopy := drv

		// Unsigned running driver
		if !drvCopy.IsSigned && drvCopy.State == "Running" {
			severity := types.SeverityHigh
			confidence := 0.8

			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("driver-unsigned-%s-%d", drvCopy.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeUnsignedDriver,
				Severity:    severity,
				Confidence:  confidence,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Unsigned kernel driver '%s' is running (path: %s)", drvCopy.Name, drvCopy.Path),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence", "Privilege Escalation"},
					Techniques: []string{"T1543.003", "T1068"},
				},
				Details: map[string]interface{}{
					"driver_name":  drvCopy.Name,
					"display_name": drvCopy.DisplayName,
					"path":         drvCopy.Path,
					"state":        drvCopy.State,
					"start_mode":   drvCopy.StartMode,
					"reason":       "unsigned_driver",
				},
			})
		}

		// Driver from suspicious path
		pathLower := strings.ToLower(drvCopy.Path)
		suspiciousPath := false
		if drvCopy.State == "Running" {
			for _, dp := range d.rules.DangerousPaths {
				if strings.Contains(pathLower, dp) {
					suspiciousPath = true
					break
				}
			}
		}
		if suspiciousPath {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("driver-path-%s-%d", drvCopy.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeUnsignedDriver,
				Severity:    types.SeverityCritical,
				Confidence:  0.9,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Kernel driver '%s' loaded from suspicious path: %s", drvCopy.Name, drvCopy.Path),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Persistence", "Defense Evasion"},
					Techniques: []string{"T1543.003", "T1014"},
				},
				Details: map[string]interface{}{
					"driver_name": drvCopy.Name,
					"path":        drvCopy.Path,
					"reason":      "suspicious_driver_path",
				},
			})
		}
	}

	return detections
}

// DetectFirewallAnomalies detects suspicious firewall rules
func (d *Detector) DetectFirewallAnomalies(rules []types.FirewallRuleInfo) []types.Detection {
	var detections []types.Detection

	for _, rule := range rules {
		ruleCopy := rule
		programLower := strings.ToLower(ruleCopy.Program)

		// Rules allowing suspicious programs
		suspicious := false
		if programLower != "" && ruleCopy.Enabled {
			for _, sp := range d.rules.SuspiciousFirewallPrograms {
				if strings.Contains(programLower, sp) {
					suspicious = true
					break
				}
			}

			// Programs from suspicious paths
			for _, dp := range d.rules.DangerousPaths {
				if strings.Contains(programLower, dp) {
					suspicious = true
					break
				}
			}
		}

		// Rules allowing Any/All remote addresses on sensitive ports
		if ruleCopy.Enabled && ruleCopy.RemoteAddr == "Any" {
			if ruleCopy.LocalPort != "" && ruleCopy.LocalPort != "Any" {
				// Check for well-known attack ports
				var port uint16
				if _, err := fmt.Sscanf(ruleCopy.LocalPort, "%d", &port); err == nil {
					if _, known := d.rules.SuspiciousPorts[port]; known {
						suspicious = true
					}
				}
			}
		}

		if suspicious {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("firewall-%s-%d", ruleCopy.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeFirewallAnomaly,
				Severity:    types.SeverityMedium,
				Confidence:  0.7,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Suspicious firewall allow rule '%s' (program: %s, port: %s)", ruleCopy.DisplayName, ruleCopy.Program, ruleCopy.LocalPort),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion", "Command and Control"},
					Techniques: []string{"T1562.004"},
				},
				Details: map[string]interface{}{
					"rule_name":   ruleCopy.DisplayName,
					"direction":   ruleCopy.Direction,
					"program":     ruleCopy.Program,
					"local_port":  ruleCopy.LocalPort,
					"remote_addr": ruleCopy.RemoteAddr,
					"reason":      "suspicious_firewall_rule",
				},
			})
		}
	}

	return detections
}

// DetectSuspiciousCertificates detects suspicious certificates in the store
func (d *Detector) DetectSuspiciousCertificates(certs []types.CertificateInfo) []types.Detection {
	var detections []types.Detection

	for _, cert := range certs {
		certCopy := cert

		// Self-signed root certificates (not from well-known CAs)
		if certCopy.IsSelfSigned && strings.Contains(certCopy.Store, "Root") {
			// Check if it's a known legitimate self-signed cert
			subjectLower := strings.ToLower(certCopy.Subject)
			knownSelfSigned := false
			for _, issuer := range d.rules.TrustedCertificateAuthorities {
				if strings.Contains(subjectLower, issuer) {
					knownSelfSigned = true
					break
				}
			}

			if !knownSelfSigned {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("cert-%s-%d", certCopy.Thumbprint[:8], time.Now().UnixNano()),
					Type:        types.DetectionTypeSuspiciousCert,
					Severity:    types.SeverityMedium,
					Confidence:  0.7,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Unknown self-signed certificate in Root store: %s", certCopy.Subject),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1553.004"},
					},
					Details: map[string]interface{}{
						"subject":     certCopy.Subject,
						"issuer":      certCopy.Issuer,
						"thumbprint":  certCopy.Thumbprint,
						"store":       certCopy.Store,
						"not_after":   certCopy.NotAfter.Format(time.RFC3339),
						"reason":      "unknown_root_cert",
					},
				})
			}
		}

		// Certificates in CurrentUser Root store (potential MITM proxy)
		if strings.Contains(certCopy.Store, "CurrentUser-Root") && certCopy.IsSelfSigned {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("cert-user-%s-%d", certCopy.Thumbprint[:8], time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousCert,
				Severity:    types.SeverityMedium,
				Confidence:  0.6,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Self-signed certificate in CurrentUser Root store: %s (potential MITM)", certCopy.Subject),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Credential Access", "Collection"},
					Techniques: []string{"T1557.002"},
				},
				Details: map[string]interface{}{
					"subject":    certCopy.Subject,
					"thumbprint": certCopy.Thumbprint,
					"store":      certCopy.Store,
					"reason":     "user_root_cert",
				},
			})
		}
	}

	return detections
}

// DetectSuspiciousShares detects suspicious network shares
func (d *Detector) DetectSuspiciousShares(shares []types.SharedFolderInfo) []types.Detection {
	var detections []types.Detection

	for _, share := range shares {
		shareCopy := share
		nameLower := strings.ToLower(shareCopy.Name)

		// Non-default hidden shares ($ suffix but not C$, D$, ADMIN$, IPC$, PRINT$)
		if shareCopy.IsHidden && !d.rules.DefaultHiddenShares[nameLower] {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("share-hidden-%s-%d", shareCopy.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousShare,
				Severity:    types.SeverityMedium,
				Confidence:  0.7,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Non-default hidden share found: %s (path: %s)", shareCopy.Name, shareCopy.Path),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Lateral Movement", "Collection"},
					Techniques: []string{"T1021.002", "T1039"},
				},
				Details: map[string]interface{}{
					"share_name": shareCopy.Name,
					"path":       shareCopy.Path,
					"reason":     "non_default_hidden_share",
				},
			})
		}

		// Shares pointing to user directories or sensitive paths
		pathLower := strings.ToLower(shareCopy.Path)
		if !shareCopy.IsHidden && (strings.Contains(pathLower, `\users\`) ||
			strings.Contains(pathLower, `\windows\`) ||
			strings.Contains(pathLower, `\temp`)) {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("share-path-%s-%d", shareCopy.Name, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousShare,
				Severity:    types.SeverityLow,
				Confidence:  0.5,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Share '%s' exposes sensitive directory: %s", shareCopy.Name, shareCopy.Path),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Collection"},
					Techniques: []string{"T1039"},
				},
				Details: map[string]interface{}{
					"share_name": shareCopy.Name,
					"path":       shareCopy.Path,
					"reason":     "sensitive_path_share",
				},
			})
		}
	}

	return detections
}

// DetectLSASSAccess detects processes accessing LSASS (credential dumping)
func (d *Detector) DetectLSASSAccess(handles []types.HandleInfo) []types.Detection {
	var detections []types.Detection

	for _, h := range handles {
		hCopy := h

		detections = append(detections, types.Detection{
			ID:          fmt.Sprintf("lsass-%d-%s-%d", hCopy.ProcessPID, hCopy.ProcessName, time.Now().UnixNano()),
			Type:        types.DetectionTypeLSASSAccess,
			Severity:    types.SeverityCritical,
			Confidence:  0.9,
			Timestamp:   time.Now(),
			Description: fmt.Sprintf("Process '%s' (PID: %d) has handle/access to LSASS (credential dump indicator)", hCopy.ProcessName, hCopy.ProcessPID),
			MITRE: &types.MITREMapping{
				Tactics:    []string{"Credential Access"},
				Techniques: []string{"T1003.001"},
			},
			Details: map[string]interface{}{
				"process_pid":  hCopy.ProcessPID,
				"process_name": hCopy.ProcessName,
				"process_path": hCopy.ProcessPath,
				"target_pid":   hCopy.TargetPID,
				"target_name":  hCopy.TargetName,
				"reason":       "lsass_access",
			},
		})
	}

	return detections
}

// DetectSuspiciousBITS detects suspicious BITS transfer jobs
func (d *Detector) DetectSuspiciousBITS(jobs []types.BITSJobInfo) []types.Detection {
	var detections []types.Detection

	for _, job := range jobs {
		jobCopy := job
		urlLower := strings.ToLower(jobCopy.URL)
		localLower := strings.ToLower(jobCopy.LocalFile)

		suspicious := false
		reason := ""

		// Suspicious URLs (raw IPs, high-risk TLDs)
		if strings.Contains(urlLower, "http://") && !strings.Contains(urlLower, "microsoft.com") {
			for _, tld := range d.rules.HighRiskTLDs {
				if strings.HasSuffix(urlLower, tld) {
					suspicious = true
					reason = "high_risk_tld"
					break
				}
			}
		}

		// Download to suspicious locations
		for _, dp := range d.rules.DangerousPaths {
			if strings.Contains(localLower, dp) {
				suspicious = true
				if reason == "" {
					reason = "suspicious_download_path"
				}
				break
			}
		}

		// Executable downloads
		for _, ext := range d.rules.SuspiciousFileExtensions {
			if strings.HasSuffix(localLower, ext) || strings.HasSuffix(urlLower, ext) {
				suspicious = true
				if reason == "" {
					reason = "executable_download"
				}
				break
			}
		}

		if suspicious {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("bits-%s-%d", jobCopy.JobID, time.Now().UnixNano()),
				Type:        types.DetectionTypeSuspiciousBITS,
				Severity:    types.SeverityMedium,
				Confidence:  0.7,
				Timestamp:   jobCopy.CreatedAt,
				Description: fmt.Sprintf("Suspicious BITS job '%s': %s → %s", jobCopy.DisplayName, jobCopy.URL, jobCopy.LocalFile),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion", "Persistence"},
					Techniques: []string{"T1197"},
				},
				Details: map[string]interface{}{
					"job_id":      jobCopy.JobID,
					"display_name": jobCopy.DisplayName,
					"url":         jobCopy.URL,
					"local_file":  jobCopy.LocalFile,
					"owner":       jobCopy.Owner,
					"state":       jobCopy.State,
					"reason":      reason,
				},
			})
		}
	}

	return detections
}

// DetectUserAssistAnomalies detects suspicious program execution from UserAssist
func (d *Detector) DetectUserAssistAnomalies(entries []types.UserAssistEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry
		nameLower := strings.ToLower(entryCopy.Name)

		// Check for LOLBin execution
		for _, lolbin := range d.rules.LOLBinCategories {
			for binName := range lolbin {
				if strings.Contains(nameLower, strings.ToLower(binName)) {
					detections = append(detections, types.Detection{
						ID:          fmt.Sprintf("userassist-lolbin-%d", time.Now().UnixNano()),
						Type:        types.DetectionTypeUserAssistAnomaly,
						Severity:    types.SeverityMedium,
						Confidence:  0.6,
						Timestamp:   entryCopy.LastExecution,
						Description: fmt.Sprintf("UserAssist shows LOLBin execution: %s (run count: %d)", entryCopy.Name, entryCopy.RunCount),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Execution", "Defense Evasion"},
							Techniques: []string{"T1218"},
						},
						Details: map[string]interface{}{
							"program":        entryCopy.Name,
							"run_count":      entryCopy.RunCount,
							"last_execution": entryCopy.LastExecution.Format(time.RFC3339),
							"user":           entryCopy.User,
							"reason":         "lolbin_userassist",
						},
					})
					break
				}
			}
		}

		// Programs from suspicious paths
		suspiciousUA := false
		for _, dp := range d.rules.DangerousPaths {
			if strings.Contains(nameLower, dp) {
				suspiciousUA = true
				break
			}
		}
		if suspiciousUA {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("userassist-path-%d", time.Now().UnixNano()),
				Type:        types.DetectionTypeUserAssistAnomaly,
				Severity:    types.SeverityLow,
				Confidence:  0.5,
				Timestamp:   entryCopy.LastExecution,
				Description: fmt.Sprintf("UserAssist shows execution from suspicious path: %s", entryCopy.Name),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Execution"},
					Techniques: []string{"T1204.002"},
				},
				Details: map[string]interface{}{
					"program":        entryCopy.Name,
					"run_count":      entryCopy.RunCount,
					"last_execution": entryCopy.LastExecution.Format(time.RFC3339),
					"reason":         "suspicious_path_userassist",
				},
			})
		}
	}

	return detections
}

// DetectBAMAnomalies detects suspicious execution from BAM/DAM entries
func (d *Detector) DetectBAMAnomalies(entries []types.BAMEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry
		pathLower := strings.ToLower(entryCopy.Path)

		// Check for LOLBin execution
		for binName := range d.rules.AllLOLBins {
			if strings.HasSuffix(pathLower, strings.ToLower(binName)) ||
				strings.Contains(pathLower, `\`+strings.ToLower(binName)) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("bam-lolbin-%d", time.Now().UnixNano()),
					Type:        types.DetectionTypeBAMAnomaly,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entryCopy.LastExecution,
					Description: fmt.Sprintf("BAM shows LOLBin execution: %s", entryCopy.Path),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution", "Defense Evasion"},
						Techniques: []string{"T1218"},
					},
					Details: map[string]interface{}{
						"path":           entryCopy.Path,
						"last_execution": entryCopy.LastExecution.Format(time.RFC3339),
						"user":           entryCopy.User,
						"reason":         "lolbin_bam",
					},
				})
				break
			}
		}

		// Execution from suspicious paths
		suspiciousBAM := false
		for _, dp := range d.rules.DangerousPaths {
			if strings.Contains(pathLower, dp) {
				suspiciousBAM = true
				break
			}
		}
		if suspiciousBAM {
			if !entryCopy.LastExecution.IsZero() && time.Since(entryCopy.LastExecution) < 30*24*time.Hour {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("bam-path-%d", time.Now().UnixNano()),
					Type:        types.DetectionTypeBAMAnomaly,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entryCopy.LastExecution,
					Description: fmt.Sprintf("Recent execution from suspicious path: %s", entryCopy.Path),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1204.002"},
					},
					Details: map[string]interface{}{
						"path":           entryCopy.Path,
						"last_execution": entryCopy.LastExecution.Format(time.RFC3339),
						"user":           entryCopy.User,
						"reason":         "suspicious_path_bam",
					},
				})
			}
		}
	}

	return detections
}

// DetectRDPAnomalies detects suspicious RDP connection history
func (d *Detector) DetectRDPAnomalies(entries []types.RDPCacheEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry

		// All RDP connections are noteworthy for security audit
		severity := types.SeverityInfo
		confidence := 0.4

		// Internal IP connections (lateral movement indicator)
		if isPrivateIP(entryCopy.Server) {
			severity = types.SeverityLow
			confidence = 0.5
		}

		detections = append(detections, types.Detection{
			ID:          fmt.Sprintf("rdp-%s-%d", entryCopy.Server, time.Now().UnixNano()),
			Type:        types.DetectionTypeRDPAnomaly,
			Severity:    severity,
			Confidence:  confidence,
			Timestamp:   time.Now(),
			Description: fmt.Sprintf("RDP connection history: %s (username hint: %s)", entryCopy.Server, entryCopy.UsernameHint),
			MITRE: &types.MITREMapping{
				Tactics:    []string{"Lateral Movement"},
				Techniques: []string{"T1021.001"},
			},
			Details: map[string]interface{}{
				"server":        entryCopy.Server,
				"username_hint": entryCopy.UsernameHint,
				"local_user":    entryCopy.User,
				"reason":        "rdp_connection",
			},
		})
	}

	return detections
}

// DetectRecycleBinAnomalies detects suspicious files in the Recycle Bin
func (d *Detector) DetectRecycleBinAnomalies(entries []types.RecycleBinEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry
		pathLower := strings.ToLower(entryCopy.OriginalPath)

		// Check for deleted security tools or LOLBins
		for binName := range d.rules.AllLOLBins {
			if strings.HasSuffix(pathLower, strings.ToLower(binName)) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("recbin-lolbin-%d", time.Now().UnixNano()),
					Type:        types.DetectionTypeRecycleBinAnomaly,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entryCopy.DeletedTime,
					Description: fmt.Sprintf("Deleted LOLBin/tool found in Recycle Bin: %s", entryCopy.OriginalPath),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1070.004"},
					},
					Details: map[string]interface{}{
						"original_path": entryCopy.OriginalPath,
						"deleted_time":  entryCopy.DeletedTime.Format(time.RFC3339),
						"file_size":     entryCopy.FileSize,
						"user":          entryCopy.User,
						"reason":        "deleted_lolbin",
					},
				})
				break
			}
		}

		// Suspicious file types deleted recently
		for _, ext := range d.rules.SuspiciousFileExtensions {
			if strings.HasSuffix(pathLower, ext) {
				if !entryCopy.DeletedTime.IsZero() && time.Since(entryCopy.DeletedTime) < 7*24*time.Hour {
					detections = append(detections, types.Detection{
						ID:          fmt.Sprintf("recbin-recent-%d", time.Now().UnixNano()),
						Type:        types.DetectionTypeRecycleBinAnomaly,
						Severity:    types.SeverityLow,
						Confidence:  0.4,
						Timestamp:   entryCopy.DeletedTime,
						Description: fmt.Sprintf("Recently deleted executable: %s (%s)", entryCopy.OriginalPath, ext),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Defense Evasion"},
							Techniques: []string{"T1070.004"},
						},
						Details: map[string]interface{}{
							"original_path": entryCopy.OriginalPath,
							"deleted_time":  entryCopy.DeletedTime.Format(time.RFC3339),
							"file_size":     entryCopy.FileSize,
							"reason":        "recently_deleted_executable",
						},
					})
				}
				break
			}
		}
	}

	return detections
}

// DetectWERAnomalies detects suspicious crash reports (e.g., LSASS crashes from credential dumping)
func (d *Detector) DetectWERAnomalies(entries []types.WEREntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry
		appLower := strings.ToLower(entryCopy.FaultingApp)
		pathLower := strings.ToLower(entryCopy.FaultingPath)

		// LSASS crash - strong credential dump indicator
		if strings.Contains(appLower, "lsass") {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("wer-lsass-%d", time.Now().UnixNano()),
				Type:        types.DetectionTypeWERAnomaly,
				Severity:    types.SeverityHigh,
				Confidence:  0.85,
				Timestamp:   entryCopy.ReportTime,
				Description: fmt.Sprintf("LSASS crash report found (potential credential dump attempt): %s", entryCopy.FaultingApp),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Credential Access"},
					Techniques: []string{"T1003.001"},
				},
				Details: map[string]interface{}{
					"faulting_app":   entryCopy.FaultingApp,
					"faulting_path":  entryCopy.FaultingPath,
					"exception_code": entryCopy.ExceptionCode,
					"report_time":   entryCopy.ReportTime.Format(time.RFC3339),
					"reason":        "lsass_crash",
				},
			})
		}

		// Security process crashes (skip lsass - handled above with higher severity)
		for _, proc := range d.rules.CriticalSecurityProcesses {
			if proc == "lsass" {
				continue
			}
			if strings.Contains(appLower, proc) || strings.Contains(pathLower, proc) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("wer-security-%d", time.Now().UnixNano()),
					Type:        types.DetectionTypeWERAnomaly,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   entryCopy.ReportTime,
					Description: fmt.Sprintf("Security process crash report: %s", entryCopy.FaultingApp),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1562.001"},
					},
					Details: map[string]interface{}{
						"faulting_app":  entryCopy.FaultingApp,
						"faulting_path": entryCopy.FaultingPath,
						"report_time":  entryCopy.ReportTime.Format(time.RFC3339),
						"reason":       "security_process_crash",
					},
				})
				break
			}
		}
	}

	return detections
}

// DetectTimestomping detects timestamp manipulation by comparing $SI and $FN timestamps in MFT
func (d *Detector) DetectTimestomping(entries []types.MFTEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry

		// Skip entries without both timestamps
		if entryCopy.SICreated.IsZero() || entryCopy.FNCreated.IsZero() {
			continue
		}

		// $STANDARD_INFORMATION timestamps can be modified by user-mode programs
		// $FILE_NAME timestamps can only be modified by the kernel
		// If $SI is significantly earlier than $FN, timestomping is likely
		siToFN := entryCopy.FNCreated.Sub(entryCopy.SICreated)
		if siToFN > time.Duration(d.rules.TimestompingThresholdHours)*time.Hour {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("timestomp-%d-%d", entryCopy.RecordNumber, time.Now().UnixNano()),
				Type:        types.DetectionTypeTimestomping,
				Severity:    types.SeverityHigh,
				Confidence:  0.85,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Timestamp manipulation detected on '%s': $SI created %s but $FN created %s (diff: %s)", entryCopy.FileName, entryCopy.SICreated.Format("2006-01-02"), entryCopy.FNCreated.Format("2006-01-02"), siToFN),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Defense Evasion"},
					Techniques: []string{"T1070.006"},
				},
				Details: map[string]interface{}{
					"file_name":     entryCopy.FileName,
					"record_number": entryCopy.RecordNumber,
					"si_created":    entryCopy.SICreated.Format(time.RFC3339),
					"fn_created":    entryCopy.FNCreated.Format(time.RFC3339),
					"si_modified":   entryCopy.SIModified.Format(time.RFC3339),
					"difference":    siToFN.String(),
					"reason":        "timestomping",
				},
			})
		}
	}

	return detections
}

// DetectEvidenceDestruction detects signs of evidence destruction from Recycle Bin and USN Journal
func (d *Detector) DetectEvidenceDestruction(recycleBin []types.RecycleBinEntry, usnJournal []types.USNJournalEntry) []types.Detection {
	var detections []types.Detection

	// Check Recycle Bin for deleted evidence files
	for _, entry := range recycleBin {
		entryCopy := entry
		nameLower := strings.ToLower(filepath.Base(entryCopy.OriginalPath))

		for _, ext := range d.rules.EvidenceFileExtensions {
			if strings.HasSuffix(nameLower, ext) {
				severity := types.SeverityMedium
				confidence := 0.65
				technique := "T1070.004"
				if ext == ".evtx" {
					severity = types.SeverityHigh
					confidence = 0.8
					technique = "T1070.001"
				}
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("evidence-recycle-%s-%d", ext[1:], time.Now().UnixNano()),
					Type:        types.DetectionTypeEvidenceDestruction,
					Severity:    severity,
					Confidence:  confidence,
					Timestamp:   entryCopy.DeletedTime,
					Description: fmt.Sprintf("Evidence file found in Recycle Bin: %s", entryCopy.OriginalPath),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{technique},
					},
					Details: map[string]interface{}{
						"original_path": entryCopy.OriginalPath,
						"extension":     ext,
						"deleted_time":  entryCopy.DeletedTime.Format(time.RFC3339),
						"file_size":     entryCopy.FileSize,
						"user":          entryCopy.User,
						"source":        "recycle_bin",
					},
				})
				break
			}
		}
	}

	// Check USN journal for log deletion
	for _, entry := range usnJournal {
		entryCopy := entry
		nameLower := strings.ToLower(entryCopy.FileName)
		reasonLower := strings.ToLower(entryCopy.Reason)

		// Evidence file deletion (event logs, prefetch, etc.)
		if strings.Contains(reasonLower, "delete") {
			for _, ext := range d.rules.EvidenceFileExtensions {
				if strings.HasSuffix(nameLower, ext) {
					severity := types.SeverityMedium
					confidence := 0.7
					technique := "T1070.004"
					// Event log deletion is higher severity than other evidence files
					if ext == ".evtx" {
						severity = types.SeverityHigh
						confidence = 0.85
						technique = "T1070.001"
					}
					detections = append(detections, types.Detection{
						ID:          fmt.Sprintf("evidence-%s-%d", ext[1:], time.Now().UnixNano()),
						Type:        types.DetectionTypeEvidenceDestruction,
						Severity:    severity,
						Confidence:  confidence,
						Timestamp:   entryCopy.Timestamp,
						Description: fmt.Sprintf("Evidence file deleted: %s", entryCopy.FileName),
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Defense Evasion"},
							Techniques: []string{technique},
						},
						Details: map[string]interface{}{
							"file_name": entryCopy.FileName,
							"extension": ext,
							"reason":    entryCopy.Reason,
							"timestamp": entryCopy.Timestamp.Format(time.RFC3339),
							"usn":       entryCopy.USN,
							"source":    "usn_journal",
						},
					})
					break
				}
			}
		}
	}

	return detections
}

// DetectBeaconing detects periodic communication patterns (C2 beaconing)
func (d *Detector) DetectBeaconing(connections []types.NetworkConnection) []types.Detection {
	var detections []types.Detection

	// Group connections by remote endpoint
	endpointCounts := make(map[string]int)
	for _, conn := range connections {
		if conn.RemoteAddr != "" && !isPrivateIP(conn.RemoteAddr) && conn.State == "ESTABLISHED" {
			key := fmt.Sprintf("%s:%d", conn.RemoteAddr, conn.RemotePort)
			endpointCounts[key]++
		}
	}

	// Multiple established connections to the same external endpoint is suspicious
	for endpoint, count := range endpointCounts {
		if count >= d.rules.BeaconingThreshold {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("beacon-%s-%d", endpoint, time.Now().UnixNano()),
				Type:        types.DetectionTypeBeaconing,
				Severity:    types.SeverityMedium,
				Confidence:  0.5,
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("Multiple connections (%d) to external endpoint %s (potential beaconing)", count, endpoint),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Command and Control"},
					Techniques: []string{"T1071", "T1573"},
				},
				Details: map[string]interface{}{
					"endpoint":         endpoint,
					"connection_count": count,
					"reason":           "multiple_connections",
				},
			})
		}
	}

	return detections
}

// DetectJumplistAnomalies detects suspicious entries in Jumplist/LNK files
func (d *Detector) DetectJumplistAnomalies(entries []types.JumplistEntry) []types.Detection {
	var detections []types.Detection

	for _, entry := range entries {
		entryCopy := entry
		targetLower := strings.ToLower(entryCopy.TargetPath)

		// LOLBin targets in jumplist
		for binName := range d.rules.AllLOLBins {
			if strings.HasSuffix(targetLower, strings.ToLower(binName)) {
				detections = append(detections, types.Detection{
					ID:          fmt.Sprintf("jumplist-lolbin-%d", time.Now().UnixNano()),
					Type:        types.DetectionTypeJumplistAnomaly,
					Severity:    types.SeverityLow,
					Confidence:  0.5,
					Timestamp:   entryCopy.AccessTime,
					Description: fmt.Sprintf("Jumplist/LNK shows LOLBin access: %s", entryCopy.TargetPath),
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Execution"},
						Techniques: []string{"T1218"},
					},
					Details: map[string]interface{}{
						"target_path":  entryCopy.TargetPath,
						"arguments":    entryCopy.Arguments,
						"access_time":  entryCopy.AccessTime.Format(time.RFC3339),
						"user":         entryCopy.User,
						"reason":       "lolbin_jumplist",
					},
				})
				break
			}
		}

		// Remote path access (UNC paths)
		if strings.HasPrefix(targetLower, `\\`) {
			detections = append(detections, types.Detection{
				ID:          fmt.Sprintf("jumplist-unc-%d", time.Now().UnixNano()),
				Type:        types.DetectionTypeJumplistAnomaly,
				Severity:    types.SeverityLow,
				Confidence:  0.5,
				Timestamp:   entryCopy.AccessTime,
				Description: fmt.Sprintf("Jumplist shows remote path access: %s", entryCopy.TargetPath),
				MITRE: &types.MITREMapping{
					Tactics:    []string{"Lateral Movement"},
					Techniques: []string{"T1021.002"},
				},
				Details: map[string]interface{}{
					"target_path": entryCopy.TargetPath,
					"access_time": entryCopy.AccessTime.Format(time.RFC3339),
					"user":        entryCopy.User,
					"reason":      "remote_path_access",
				},
			})
		}
	}

	return detections
}

// extractDomainFromURL extracts the domain from a URL string
func extractDomainFromURL(url string) string {
	if idx := strings.Index(url, "://"); idx >= 0 {
		url = url[idx+3:]
	}
	if idx := strings.IndexAny(url, "/?#"); idx >= 0 {
		url = url[:idx]
	}
	if idx := strings.LastIndex(url, ":"); idx >= 0 {
		url = url[:idx]
	}
	if idx := strings.Index(url, "@"); idx >= 0 {
		url = url[idx+1:]
	}
	return url
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

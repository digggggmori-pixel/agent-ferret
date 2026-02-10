// Package rulestore manages external rule bundle loading and hot-reloading.
// Rules are loaded from a single rules.json file placed next to the executable.
package rulestore

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/digggggmori-pixel/agent-ferret/internal/sigma"
)

// BundleFile represents the on-disk rules.json structure
type BundleFile struct {
	Version    string                 `json:"version"`
	CompiledAt string                 `json:"compiled_at"`
	Sigma      SigmaBundleSection     `json:"sigma"`
	Detection  DetectionBundleSection `json:"detection"`
}

// SigmaBundleSection contains sigma rules organized by category
type SigmaBundleSection struct {
	Metadata SigmaBundleMetadata               `json:"metadata"`
	Files    map[string]SigmaBundleCategoryFile `json:"files"`
}

// SigmaBundleMetadata contains sigma metadata
type SigmaBundleMetadata struct {
	TotalRules int `json:"total_rules"`
}

// SigmaBundleCategoryFile contains rules for a single sigma category
type SigmaBundleCategoryFile struct {
	RuleCount int              `json:"rule_count"`
	Rules     []sigma.SigmaRule `json:"rules"`
}

// DetectionBundleSection contains all detection constants
type DetectionBundleSection struct {
	LOLBins                   map[string][]string   `json:"lolbins"`
	Chains                    map[string][]string   `json:"chains"`
	SuspiciousPorts           map[string]string     `json:"suspicious_ports"`
	PathAnomalyPatterns       []string              `json:"path_anomaly_patterns"`
	LegitimateAppDataPaths    []string              `json:"legitimate_appdata_paths"`
	TyposquatTargets          map[string]string     `json:"typosquat_targets"`
	TrustedVendors            []string              `json:"trusted_vendors"`
	SystemServices            []string              `json:"system_services"`
	HighRiskTLDs              []string              `json:"high_risk_tlds"`
	DangerousPaths            []string              `json:"dangerous_paths"`
	CriticalProcesses         map[string]string     `json:"critical_processes"`
	EncodedCommandPatterns    []string              `json:"encoded_command_patterns"`
	MaliciousKeywords         []string              `json:"malicious_keywords"`
	CommonEnglishWords        []string              `json:"common_english_words"`
	MicrosoftServiceWhitelist []string              `json:"microsoft_service_whitelist"`
	MicrosoftPathPrefixes     []string              `json:"microsoft_path_prefixes"`
}

// RuleBundle is the in-memory representation of a loaded rule bundle.
// It contains a ready-to-use Sigma engine and parsed detection rules.
type RuleBundle struct {
	Version    string
	CompiledAt string
	Sigma      *sigma.Engine
	Detection  *DetectionRules
}

// DetectionRules holds all detection constants in memory-efficient form
type DetectionRules struct {
	// LOLBins
	AllLOLBins       map[string]bool
	LOLBinCategories map[string]map[string]bool // category name → set of binary names

	// Process chain detection
	SuspiciousChains map[string][]string

	// Network detection
	SuspiciousPorts map[uint16]string

	// Path anomaly detection
	PathAnomalyPatterns    []string
	PathAnomalyRegexps     []*regexp.Regexp
	LegitimateAppDataPaths []string

	// Typosquatting detection
	TyposquatTargets map[string]string

	// Vendor/Service detection
	TrustedVendors            []string
	SystemServices            []string
	CommonEnglishWords        map[string]bool
	MicrosoftServiceWhitelist map[string]bool
	MicrosoftPathPrefixes     []string

	// Domain detection
	HighRiskTLDs      []string
	MaliciousKeywords []string

	// Path/Process detection
	DangerousPaths         []string
	CriticalProcesses      map[string]string
	EncodedCommandPatterns []string
}

// LoadBundleFromFile loads a rule bundle from a JSON file on disk
func LoadBundleFromFile(path string) (*RuleBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}
	return LoadBundleFromBytes(data)
}

// LoadBundleFromBytes parses a rule bundle from raw JSON bytes
func LoadBundleFromBytes(data []byte) (*RuleBundle, error) {
	var bf BundleFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("failed to parse rules bundle: %w", err)
	}

	bundle := &RuleBundle{
		Version:    bf.Version,
		CompiledAt: bf.CompiledAt,
	}

	// Build Sigma engine from bundle
	sigmaEngine, err := buildSigmaEngine(&bf.Sigma)
	if err != nil {
		return nil, fmt.Errorf("failed to build sigma engine: %w", err)
	}
	bundle.Sigma = sigmaEngine

	// Build detection rules from bundle
	detRules, err := buildDetectionRules(&bf.Detection)
	if err != nil {
		return nil, fmt.Errorf("failed to build detection rules: %w", err)
	}
	bundle.Detection = detRules

	return bundle, nil
}

// buildSigmaEngine creates a Sigma engine from the bundle's sigma section
func buildSigmaEngine(s *SigmaBundleSection) (*sigma.Engine, error) {
	engine, err := sigma.NewEngine()
	if err != nil {
		return nil, err
	}

	rulesByCategory := make(map[string][]*sigma.SigmaRule)
	totalRules := 0

	for category, catFile := range s.Files {
		rules := make([]*sigma.SigmaRule, len(catFile.Rules))
		for i := range catFile.Rules {
			rules[i] = &catFile.Rules[i]
		}
		rulesByCategory[category] = rules
		totalRules += len(rules)
	}

	engine.LoadFromBundle(rulesByCategory, totalRules)

	return engine, nil
}

// buildDetectionRules converts the JSON detection section into in-memory DetectionRules
func buildDetectionRules(d *DetectionBundleSection) (*DetectionRules, error) {
	rules := &DetectionRules{
		AllLOLBins:       make(map[string]bool),
		LOLBinCategories: make(map[string]map[string]bool),
		SuspiciousChains: d.Chains,
		SuspiciousPorts:  make(map[uint16]string),

		PathAnomalyPatterns:    d.PathAnomalyPatterns,
		LegitimateAppDataPaths: d.LegitimateAppDataPaths,
		TyposquatTargets:       d.TyposquatTargets,
		TrustedVendors:         d.TrustedVendors,
		SystemServices:         d.SystemServices,
		HighRiskTLDs:           d.HighRiskTLDs,
		DangerousPaths:         d.DangerousPaths,
		CriticalProcesses:      d.CriticalProcesses,
		EncodedCommandPatterns: d.EncodedCommandPatterns,
		MaliciousKeywords:      d.MaliciousKeywords,
		MicrosoftPathPrefixes:  d.MicrosoftPathPrefixes,

		CommonEnglishWords:        make(map[string]bool),
		MicrosoftServiceWhitelist: make(map[string]bool),
	}

	// Build LOLBins maps
	for category, names := range d.LOLBins {
		catMap := make(map[string]bool, len(names))
		for _, name := range names {
			catMap[name] = true
			rules.AllLOLBins[name] = true
		}
		rules.LOLBinCategories[category] = catMap
	}

	// Parse suspicious ports (JSON keys are strings, we need uint16)
	for portStr, desc := range d.SuspiciousPorts {
		var port uint16
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			rules.SuspiciousPorts[port] = desc
		}
	}

	// Compile path anomaly regexps
	rules.PathAnomalyRegexps = make([]*regexp.Regexp, 0, len(d.PathAnomalyPatterns))
	for _, pattern := range d.PathAnomalyPatterns {
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			rules.PathAnomalyRegexps = append(rules.PathAnomalyRegexps, re)
		}
	}

	// Build set maps from slices
	for _, w := range d.CommonEnglishWords {
		rules.CommonEnglishWords[w] = true
	}
	for _, svc := range d.MicrosoftServiceWhitelist {
		rules.MicrosoftServiceWhitelist[svc] = true
	}

	return rules, nil
}

// LOLBinCategory returns the category of a LOLBin binary name
func (r *DetectionRules) LOLBinCategory(name string) string {
	categoryOrder := []string{
		"execute", "download", "bypass", "recon",
		"persist", "creds", "lateral", "compile", "misc",
	}
	for _, cat := range categoryOrder {
		if r.LOLBinCategories[cat][name] {
			return categoryDisplayName(cat)
		}
	}
	return "Unknown"
}

func categoryDisplayName(cat string) string {
	switch cat {
	case "execute":
		return "Execute"
	case "download":
		return "Download"
	case "bypass":
		return "Bypass"
	case "recon":
		return "Recon"
	case "persist":
		return "Persist"
	case "creds":
		return "Credential Access"
	case "lateral":
		return "Lateral Movement"
	case "compile":
		return "Compile"
	case "misc":
		return "Misc"
	default:
		return "Unknown"
	}
}

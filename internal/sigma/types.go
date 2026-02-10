// Package sigma provides Sigma rule matching engine for Windows event logs
package sigma

import (
	"encoding/json"
	"time"
)

// SigmaEvent represents a normalized event for Sigma matching
// Field names follow Sigma specification for compatibility
type SigmaEvent struct {
	Category  string                 `json:"category"`   // e.g., "windows_security", "windows_ps_script"
	Channel   string                 `json:"channel"`    // Original Windows channel
	Provider  string                 `json:"provider"`   // Event provider name
	EventID   uint32                 `json:"event_id"`   // Windows Event ID
	Timestamp time.Time              `json:"timestamp"`
	Computer  string                 `json:"computer"`   // Host name
	Fields    map[string]interface{} `json:"fields"`     // Event-specific fields using Sigma naming
}

// SigmaRule represents a compiled Sigma rule
type SigmaRule struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Status      string       `json:"status"`
	Description string       `json:"description"`
	Level       string       `json:"level"` // critical, high, medium, low, informational
	Tags        []string     `json:"tags"`
	Logsource   Logsource    `json:"logsource"`
	Detection   Detection    `json:"detection"`
	MITRE       MITREMapping `json:"mitre"`
	Meta        RuleMeta     `json:"meta"`
}

// Logsource defines where the rule applies
type Logsource struct {
	Category string `json:"category"` // process_creation, network_connection, etc.
	Product  string `json:"product"`  // windows
	Service  string `json:"service"`  // security, system, etc.
}

// Detection contains the rule's detection logic
type Detection struct {
	Selections      map[string]Selection `json:"selections"`
	Filters         map[string]Selection `json:"filters"`
	Condition       string               `json:"condition"`
	ConditionParsed ConditionNode        `json:"condition_parsed"`
}

// Selection represents a detection selection block
type Selection struct {
	Type     string             `json:"type"` // "field_match", "or_list", "keywords"
	Matchers map[string]Matcher `json:"matchers,omitempty"`
	Items    []Selection        `json:"items,omitempty"`
	Keywords []string           `json:"keywords,omitempty"`
}

// Matcher represents a single field matcher
type Matcher struct {
	Field     string      `json:"field"`
	Value     interface{} `json:"value"` // string, number, or []interface{}
	Modifiers []string    `json:"modifiers"` // contains, startswith, endswith, re, cidr, all
	IsList    bool        `json:"is_list"`
	Negated   bool        `json:"negated"`
}

// ConditionNode represents a parsed condition tree
type ConditionNode struct {
	Op        string          `json:"op"` // single, and, or, not, 1_of, all_of, and_not
	Selection string          `json:"selection,omitempty"`
	Pattern   string          `json:"pattern,omitempty"`
	Operands  []ConditionNode `json:"operands,omitempty"`
	Include   string          `json:"include,omitempty"`
	Exclude   string          `json:"exclude,omitempty"`
}

// UnmarshalJSON handles both object and string forms of ConditionNode.
// String operands like "selection1" are converted to {op:"single", selection:"<name>"}.
func (c *ConditionNode) UnmarshalJSON(data []byte) error {
	// Try string first (e.g. "selection1" in operands array)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		c.Op = OpSingle
		c.Selection = s
		return nil
	}

	// Otherwise parse as object (use alias to avoid infinite recursion)
	type Alias ConditionNode
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = ConditionNode(a)
	return nil
}

// MITREMapping represents MITRE ATT&CK mapping
type MITREMapping struct {
	Techniques []string `json:"techniques"`
	Tactics    []string `json:"tactics"`
}

// RuleMeta contains rule metadata
type RuleMeta struct {
	Author         string   `json:"author"`
	Date           string   `json:"date"`
	Modified       string   `json:"modified"`
	References     []string `json:"references"`
	FalsePositives []string `json:"falsepositives"`
	SourceFile     string   `json:"source_file"`
}

// SigmaMatch represents a rule that matched an event
type SigmaMatch struct {
	RuleID       string                 `json:"rule_id"`
	RuleName     string                 `json:"rule_name"`
	Description  string                 `json:"description"`
	Severity     string                 `json:"severity"`
	Timestamp    time.Time              `json:"timestamp"`
	Category     string                 `json:"category"`
	Channel      string                 `json:"channel"`
	EventID      uint32                 `json:"event_id"`
	MatchedEvent map[string]interface{} `json:"matched_event"`
	MITRE        MITREMapping           `json:"mitre"`
	Tags         []string               `json:"tags"`
}

// RuleFile represents the structure of a compiled rules JSON file
type RuleFile struct {
	Metadata RuleFileMetadata `json:"metadata"`
	Rules    []SigmaRule      `json:"rules"`
}

// RuleFileMetadata contains metadata about the rule file
type RuleFileMetadata struct {
	Logsource   string `json:"logsource"`
	RuleCount   int    `json:"rule_count"`
	CompiledAt  string `json:"compiled_at"`
	Version     string `json:"version"`
}

// IndexFile represents the _index.json structure
type IndexFile struct {
	Metadata IndexMetadata          `json:"metadata"`
	Files    map[string]IndexEntry  `json:"files"`
}

// IndexMetadata contains index metadata
type IndexMetadata struct {
	CompiledAt string `json:"compiled_at"`
	TotalRules int    `json:"total_rules"`
	SourceDir  string `json:"source_dir"`
}

// IndexEntry represents a single category entry in the index
type IndexEntry struct {
	Path      string `json:"path"`
	RuleCount int    `json:"rule_count"`
}

// Severity constants matching Sigma levels
const (
	SeverityCritical      = "critical"
	SeverityHigh          = "high"
	SeverityMedium        = "medium"
	SeverityLow           = "low"
	SeverityInformational = "informational"
)

// ConditionOp constants for condition evaluation
const (
	OpSingle = "single"
	OpAnd    = "and"
	OpOr     = "or"
	OpNot    = "not"
	Op1Of    = "1_of"
	OpAllOf  = "all_of"
	OpAndNot = "and_not"
)

// SelectionType constants
const (
	SelectionTypeFieldMatch = "field_match"
	SelectionTypeOrList     = "or_list"
	SelectionTypeKeywords   = "keywords"
)

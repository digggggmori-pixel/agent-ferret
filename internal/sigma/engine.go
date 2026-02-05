package sigma

import (
	"embed"
	"fmt"
	"sync"
	"time"
)

// Engine is the main Sigma rule matching engine
type Engine struct {
	rulesByCategory map[string][]*SigmaRule // O(1) category lookup
	allRules        []*SigmaRule            // All rules for iteration
	totalRules      int
	mu              sync.RWMutex
}

// NewEngine creates a new Sigma engine with embedded rules
func NewEngine() (*Engine, error) {
	engine := &Engine{
		rulesByCategory: make(map[string][]*SigmaRule),
		allRules:        make([]*SigmaRule, 0),
	}

	return engine, nil
}

// NewEngineWithRules creates a new Sigma engine with the given embedded rules
func NewEngineWithRules(rulesFS embed.FS) (*Engine, error) {
	engine := &Engine{
		rulesByCategory: make(map[string][]*SigmaRule),
		allRules:        make([]*SigmaRule, 0),
	}

	// Load rules from embedded filesystem
	rulesByCategory, totalRules, err := LoadRulesFromFS(rulesFS)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	engine.rulesByCategory = rulesByCategory
	engine.totalRules = totalRules

	// Build allRules slice
	for _, rules := range rulesByCategory {
		engine.allRules = append(engine.allRules, rules...)
	}

	return engine, nil
}

// LoadRules loads rules from an embedded filesystem
func (e *Engine) LoadRules(rulesFS embed.FS) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rulesByCategory, totalRules, err := LoadRulesFromFS(rulesFS)
	if err != nil {
		return err
	}

	e.rulesByCategory = rulesByCategory
	e.totalRules = totalRules

	// Build allRules slice
	e.allRules = make([]*SigmaRule, 0, totalRules)
	for _, rules := range rulesByCategory {
		e.allRules = append(e.allRules, rules...)
	}

	return nil
}

// TotalRules returns the total number of loaded rules
func (e *Engine) TotalRules() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.totalRules
}

// Categories returns all available rule categories
func (e *Engine) Categories() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	categories := make([]string, 0, len(e.rulesByCategory))
	for cat := range e.rulesByCategory {
		categories = append(categories, cat)
	}
	return categories
}

// RulesForCategory returns rules for a specific category
func (e *Engine) RulesForCategory(category string) []*SigmaRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rulesByCategory[category]
}

// Match finds all rules matching the given event
func (e *Engine) Match(event *SigmaEvent) []*SigmaMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []*SigmaMatch

	// Get rules for this category (O(1))
	rules := e.rulesByCategory[event.Category]
	if len(rules) == 0 {
		return matches
	}

	// Evaluate each rule
	for _, rule := range rules {
		if e.matchRule(rule, event) {
			matches = append(matches, createMatch(rule, event))
		}
	}

	return matches
}

// MatchAll matches event against all rules regardless of category
// This is useful when the event category is unknown
func (e *Engine) MatchAll(event *SigmaEvent) []*SigmaMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []*SigmaMatch

	for _, rule := range e.allRules {
		if e.matchRule(rule, event) {
			matches = append(matches, createMatch(rule, event))
		}
	}

	return matches
}

// matchRule performs full condition evaluation on a single rule
func (e *Engine) matchRule(rule *SigmaRule, event *SigmaEvent) bool {
	// Evaluate the rule condition
	return EvaluateRuleCondition(rule, event)
}

// createMatch creates a SigmaMatch from a rule and event
func createMatch(rule *SigmaRule, event *SigmaEvent) *SigmaMatch {
	return &SigmaMatch{
		RuleID:       rule.ID,
		RuleName:     rule.Title,
		Description:  rule.Description,
		Severity:     normalizeSeverity(rule.Level),
		Timestamp:    event.Timestamp,
		Category:     event.Category,
		Channel:      event.Channel,
		EventID:      event.EventID,
		MatchedEvent: event.Fields,
		MITRE:        rule.MITRE,
		Tags:         rule.Tags,
	}
}

// normalizeSeverity converts Sigma level to standard severity
func normalizeSeverity(level string) string {
	switch level {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "informational", "info":
		return SeverityInformational
	default:
		return SeverityLow
	}
}

// ConvertToDetection converts a SigmaMatch to a types.Detection
// This is a helper for integration with the main detection system
func (m *SigmaMatch) ToDetectionFields() map[string]interface{} {
	return map[string]interface{}{
		"rule_id":     m.RuleID,
		"rule_name":   m.RuleName,
		"description": m.Description,
		"category":    m.Category,
		"channel":     m.Channel,
		"event_id":    m.EventID,
		"tags":        m.Tags,
	}
}

// GetMITRETechniques returns MITRE techniques as strings
func (m *SigmaMatch) GetMITRETechniques() []string {
	return m.MITRE.Techniques
}

// GetMITRETactics returns MITRE tactics as strings
func (m *SigmaMatch) GetMITRETactics() []string {
	return m.MITRE.Tactics
}

// EngineStats holds engine statistics
type EngineStats struct {
	TotalRules     int            `json:"total_rules"`
	RulesByLevel   map[string]int `json:"rules_by_level"`
	CategoryCounts map[string]int `json:"category_counts"`
}

// Stats returns statistics about loaded rules
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := EngineStats{
		TotalRules:     e.totalRules,
		RulesByLevel:   make(map[string]int),
		CategoryCounts: make(map[string]int),
	}

	for category, rules := range e.rulesByCategory {
		stats.CategoryCounts[category] = len(rules)
		for _, rule := range rules {
			stats.RulesByLevel[rule.Level]++
		}
	}

	return stats
}

// ScanProgress represents scan progress information
type ScanProgress struct {
	Channel     string
	Current     int64
	Total       int64
	Matches     int
	StartTime   time.Time
	ElapsedMs   int64
}

// ProgressCallback is called during scanning to report progress
type ProgressCallback func(progress ScanProgress)

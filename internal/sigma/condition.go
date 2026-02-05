package sigma

import (
	"path/filepath"
	"strings"
)

// EvaluateCondition evaluates a parsed condition node against selection results
func EvaluateCondition(cond *ConditionNode, selections map[string]bool, filters map[string]bool) bool {
	switch cond.Op {
	case OpSingle:
		// Single selection reference
		return selections[cond.Selection]

	case OpAnd:
		// All operands must be true
		for _, operand := range cond.Operands {
			if !EvaluateCondition(&operand, selections, filters) {
				return false
			}
		}
		return len(cond.Operands) > 0

	case OpOr:
		// At least one operand must be true
		for _, operand := range cond.Operands {
			if EvaluateCondition(&operand, selections, filters) {
				return true
			}
		}
		return false

	case OpNot:
		// Negate the operand
		if len(cond.Operands) > 0 {
			return !EvaluateCondition(&cond.Operands[0], selections, filters)
		}
		return true

	case Op1Of:
		// At least one matching selection must be true
		return evaluateNOf(1, cond.Pattern, selections)

	case OpAllOf:
		// All matching selections must be true
		return evaluateAllOf(cond.Pattern, selections)

	case OpAndNot:
		// Include must be true AND Exclude must be false
		// This handles "selection and not filter" patterns
		includeResult := getResult(cond.Include, selections, filters)
		excludeResult := getResult(cond.Exclude, selections, filters)
		return includeResult && !excludeResult

	default:
		// Unknown operator - try to match as selection name
		if cond.Selection != "" {
			return selections[cond.Selection]
		}
		return false
	}
}

// evaluateNOf checks if at least N selections matching pattern are true
func evaluateNOf(n int, pattern string, selections map[string]bool) bool {
	count := 0
	glob := normalizePattern(pattern)

	for name, result := range selections {
		if result && matchGlob(glob, name) {
			count++
			if count >= n {
				return true
			}
		}
	}
	return false
}

// evaluateAllOf checks if all selections matching pattern are true
func evaluateAllOf(pattern string, selections map[string]bool) bool {
	glob := normalizePattern(pattern)
	matched := false

	for name, result := range selections {
		if matchGlob(glob, name) {
			matched = true
			if !result {
				return false
			}
		}
	}
	return matched
}

// getResult gets the result from either selections or filters map
func getResult(name string, selections, filters map[string]bool) bool {
	// Check selections first
	if result, ok := selections[name]; ok {
		return result
	}
	// Then check filters
	if result, ok := filters[name]; ok {
		return result
	}
	// If name contains wildcard, treat as pattern
	if strings.ContainsAny(name, "*?") {
		// Check if any matching selection is true
		for selName, result := range selections {
			if matchGlob(name, selName) && result {
				return true
			}
		}
		for filterName, result := range filters {
			if matchGlob(name, filterName) && result {
				return true
			}
		}
	}
	return false
}

// normalizePattern ensures pattern has wildcard suffix for matching
func normalizePattern(pattern string) string {
	// Handle special patterns
	switch pattern {
	case "them":
		return "*" // Match all
	case "selection*", "selection_*":
		return "selection*"
	case "filter*", "filter_*":
		return "filter*"
	}

	// If pattern doesn't end with wildcard, add one for prefix matching
	if !strings.HasSuffix(pattern, "*") && !strings.HasSuffix(pattern, "?") {
		// Check if it looks like a base name pattern
		if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
			return pattern + "*"
		}
	}
	return pattern
}

// matchGlob performs simple glob-style pattern matching
func matchGlob(pattern, name string) bool {
	// Handle special case: pattern is exactly the name
	if pattern == name {
		return true
	}

	// Handle "them" which matches everything
	if pattern == "them" || pattern == "*" {
		return true
	}

	// Use filepath.Match for glob matching
	matched, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
	if err != nil {
		return false
	}
	return matched
}

// EvaluateRuleCondition evaluates a rule's full condition
func EvaluateRuleCondition(rule *SigmaRule, event *SigmaEvent) bool {
	// Evaluate all selections
	selectionResults := make(map[string]bool)
	for name, selection := range rule.Detection.Selections {
		selectionResults[name] = EvaluateSelection(&selection, event)
	}

	// Evaluate all filters
	filterResults := make(map[string]bool)
	for name, filter := range rule.Detection.Filters {
		filterResults[name] = EvaluateSelection(&filter, event)
	}

	// Evaluate the parsed condition
	return EvaluateCondition(&rule.Detection.ConditionParsed, selectionResults, filterResults)
}

// ParseConditionString parses a simple condition string (for fallback)
// This handles basic conditions like "selection", "selection and not filter"
func ParseConditionString(condition string) ConditionNode {
	condition = strings.TrimSpace(strings.ToLower(condition))

	// Handle "selection and not filter" pattern
	if strings.Contains(condition, " and not ") {
		parts := strings.SplitN(condition, " and not ", 2)
		if len(parts) == 2 {
			return ConditionNode{
				Op:      OpAndNot,
				Include: strings.TrimSpace(parts[0]),
				Exclude: strings.TrimSpace(parts[1]),
			}
		}
	}

	// Handle "1 of selection*" pattern
	if strings.HasPrefix(condition, "1 of ") {
		pattern := strings.TrimPrefix(condition, "1 of ")
		return ConditionNode{
			Op:      Op1Of,
			Pattern: strings.TrimSpace(pattern),
		}
	}

	// Handle "all of selection*" pattern
	if strings.HasPrefix(condition, "all of ") {
		pattern := strings.TrimPrefix(condition, "all of ")
		return ConditionNode{
			Op:      OpAllOf,
			Pattern: strings.TrimSpace(pattern),
		}
	}

	// Handle "selection or filter" pattern
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		operands := make([]ConditionNode, 0, len(parts))
		for _, part := range parts {
			operands = append(operands, ConditionNode{
				Op:        OpSingle,
				Selection: strings.TrimSpace(part),
			})
		}
		return ConditionNode{
			Op:       OpOr,
			Operands: operands,
		}
	}

	// Handle "selection and filter" pattern
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		operands := make([]ConditionNode, 0, len(parts))
		for _, part := range parts {
			operands = append(operands, ConditionNode{
				Op:        OpSingle,
				Selection: strings.TrimSpace(part),
			})
		}
		return ConditionNode{
			Op:       OpAnd,
			Operands: operands,
		}
	}

	// Handle "not selection" pattern
	if strings.HasPrefix(condition, "not ") {
		selection := strings.TrimPrefix(condition, "not ")
		return ConditionNode{
			Op: OpNot,
			Operands: []ConditionNode{{
				Op:        OpSingle,
				Selection: strings.TrimSpace(selection),
			}},
		}
	}

	// Default: single selection
	return ConditionNode{
		Op:        OpSingle,
		Selection: condition,
	}
}

package sigma

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// EvaluateSelection evaluates a selection against an event
func EvaluateSelection(sel *Selection, event *SigmaEvent) bool {
	switch sel.Type {
	case SelectionTypeFieldMatch:
		return evaluateFieldMatchers(sel.Matchers, event)
	case SelectionTypeOrList:
		return evaluateOrList(sel.Items, event)
	case SelectionTypeKeywords:
		return evaluateKeywords(sel.Keywords, event)
	default:
		return false
	}
}

// evaluateFieldMatchers evaluates all matchers (AND logic)
func evaluateFieldMatchers(matchers map[string]Matcher, event *SigmaEvent) bool {
	if len(matchers) == 0 {
		return false
	}

	for _, matcher := range matchers {
		if !evaluateMatcher(&matcher, event) {
			return false
		}
	}
	return true
}

// evaluateOrList evaluates items with OR logic
func evaluateOrList(items []Selection, event *SigmaEvent) bool {
	for _, item := range items {
		if EvaluateSelection(&item, event) {
			return true
		}
	}
	return false
}

// evaluateKeywords searches for keywords in all event fields
func evaluateKeywords(keywords []string, event *SigmaEvent) bool {
	// Build searchable text from all fields
	searchText := buildSearchText(event)

	// All keywords must be present (AND logic)
	for _, keyword := range keywords {
		if !strings.Contains(searchText, strings.ToLower(keyword)) {
			return false
		}
	}
	return len(keywords) > 0
}

// buildSearchText creates a lowercase searchable string from event fields
func buildSearchText(event *SigmaEvent) string {
	var sb strings.Builder

	for _, v := range event.Fields {
		switch val := v.(type) {
		case string:
			sb.WriteString(strings.ToLower(val))
			sb.WriteByte(' ')
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					sb.WriteString(strings.ToLower(s))
					sb.WriteByte(' ')
				}
			}
		default:
			sb.WriteString(fmt.Sprint(val))
			sb.WriteByte(' ')
		}
	}

	return sb.String()
}

// evaluateMatcher evaluates a single field matcher
func evaluateMatcher(m *Matcher, event *SigmaEvent) bool {
	eventValue := getEventValue(event, m.Field)

	// Handle case where field is absent
	if eventValue == nil {
		// Negated matcher succeeds if field is absent (not contains X when X doesn't exist)
		return m.Negated
	}

	var result bool

	if m.IsList {
		// OR logic for list values
		values, ok := m.Value.([]interface{})
		if !ok {
			return m.Negated
		}
		for _, v := range values {
			if matchValue(eventValue, v, m.Modifiers) {
				result = true
				break
			}
		}
	} else {
		result = matchValue(eventValue, m.Value, m.Modifiers)
	}

	if m.Negated {
		return !result
	}
	return result
}

// matchValue compares event value against expected value with modifiers
func matchValue(eventValue, expected interface{}, modifiers []string) bool {
	// Handle CIDR modifier for IP matching
	if contains(modifiers, "cidr") {
		return matchCIDR(toString(eventValue), toString(expected))
	}

	// Handle regex modifier
	if contains(modifiers, "re") {
		return matchRegex(toString(eventValue), toString(expected))
	}

	// Handle base64 modifier
	if contains(modifiers, "base64") || contains(modifiers, "base64offset") {
		// For base64 matching, search in the raw value
		return strings.Contains(toString(eventValue), toString(expected))
	}

	// Handle numeric comparison (EventID, etc.)
	if expNum, ok := toNumber(expected); ok {
		if evtNum, ok := toNumber(eventValue); ok {
			return evtNum == expNum
		}
	}

	// String comparison (case-insensitive by default)
	eventStr := strings.ToLower(toString(eventValue))
	expectedStr := strings.ToLower(toString(expected))

	// Check for "all" modifier first (requires all items in list to match)
	if contains(modifiers, "all") {
		// The expected value should be treated as multiple items to check
		// This is typically used with "contains|all"
		if contains(modifiers, "contains") {
			// Each item in expected (if list) must be contained
			return containsAll(eventStr, expectedStr)
		}
	}

	// Standard modifier-based matching
	if contains(modifiers, "contains") {
		return strings.Contains(eventStr, expectedStr)
	}

	if contains(modifiers, "startswith") {
		return strings.HasPrefix(eventStr, expectedStr)
	}

	if contains(modifiers, "endswith") {
		return strings.HasSuffix(eventStr, expectedStr)
	}

	// Wildcard matching (if expected contains wildcards)
	if strings.ContainsAny(expectedStr, "*?") {
		return matchWildcard(eventStr, expectedStr)
	}

	// Exact match (case-insensitive)
	return eventStr == expectedStr
}

// getEventValue retrieves field value from event (case-insensitive lookup)
func getEventValue(event *SigmaEvent, fieldName string) interface{} {
	// Direct lookup first
	if v, ok := event.Fields[fieldName]; ok {
		return v
	}

	// Case-insensitive lookup
	fieldLower := strings.ToLower(fieldName)
	for k, v := range event.Fields {
		if strings.ToLower(k) == fieldLower {
			return v
		}
	}

	// Handle special fields
	switch strings.ToLower(fieldName) {
	case "eventid":
		return event.EventID
	case "channel":
		return event.Channel
	case "provider", "provider_name":
		return event.Provider
	case "computer", "computername":
		return event.Computer
	}

	return nil
}

// matchCIDR checks if IP is within CIDR range
func matchCIDR(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Handle plain IP (not CIDR)
	if !strings.Contains(cidrStr, "/") {
		targetIP := net.ParseIP(cidrStr)
		return targetIP != nil && ip.Equal(targetIP)
	}

	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

// matchRegex performs regex matching
func matchRegex(value, pattern string) bool {
	// Add case-insensitive flag if not present
	if !strings.HasPrefix(pattern, "(?i)") && !strings.HasPrefix(pattern, "(?-i)") {
		pattern = "(?i)" + pattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// matchWildcard performs glob-style wildcard matching
func matchWildcard(value, pattern string) bool {
	// Convert wildcard pattern to regex
	regexPattern := "^"
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			regexPattern += ".*"
		case '?':
			regexPattern += "."
		case '.', '+', '^', '$', '[', ']', '(', ')', '{', '}', '|', '\\':
			regexPattern += "\\" + string(pattern[i])
		default:
			regexPattern += string(pattern[i])
		}
	}
	regexPattern += "$"

	re, err := regexp.Compile("(?i)" + regexPattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// containsAll checks if all parts of expected are contained in value
func containsAll(value, expected string) bool {
	// Split expected by common delimiters
	parts := strings.FieldsFunc(expected, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(value, part) {
			return false
		}
	}
	return len(parts) > 0
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case uint32:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%.0f", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
}

func toNumber(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint32:
		return float64(val), true
	case float64:
		return val, true
	case string:
		// Try to parse string as number
		var num float64
		_, err := fmt.Sscanf(val, "%f", &num)
		return num, err == nil
	default:
		return 0, false
	}
}

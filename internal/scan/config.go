package scan

// Config holds scan configuration
type Config struct {
	QuickMode            bool // Scan only last 24 hours of event logs
	IncludeInformational bool // Include informational severity detections (default: false)
}

// DefaultConfig returns the default scan configuration
func DefaultConfig() Config {
	return Config{
		QuickMode:            false,
		IncludeInformational: false,
	}
}

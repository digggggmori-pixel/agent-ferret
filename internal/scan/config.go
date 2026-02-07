package scan

// Config holds scan configuration
type Config struct {
	QuickMode bool // Scan only last 24 hours of event logs
}

// DefaultConfig returns the default scan configuration
func DefaultConfig() Config {
	return Config{
		QuickMode: false,
	}
}

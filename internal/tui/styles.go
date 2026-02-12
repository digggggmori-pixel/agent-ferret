package tui

import "github.com/charmbracelet/lipgloss"

// ── Color Palette (muted, professional, 2-accent system) ──

var (
	// Background surfaces
	ColorBG      = lipgloss.Color("#0c0c14")
	ColorSurface = lipgloss.Color("#161624")
	ColorBorder  = lipgloss.Color("#2a2a3d")

	// Text hierarchy
	ColorText      = lipgloss.Color("#c8c8d4")
	ColorTextDim   = lipgloss.Color("#6b6b7b")
	ColorTextMuted = lipgloss.Color("#3e3e50")

	// Single accent color
	ColorAccent    = lipgloss.Color("#5eead4")
	ColorAccentDim = lipgloss.Color("#2d6a5e")

	// Severity (softer tones)
	ColorCritical      = lipgloss.Color("#ef4444")
	ColorHigh          = lipgloss.Color("#f59e0b")
	ColorMedium        = lipgloss.Color("#eab308")
	ColorLow           = lipgloss.Color("#22c55e")
	ColorInformational = lipgloss.Color("#06b6d4")

	// Semantic
	ColorSuccess = lipgloss.Color("#22c55e")
	ColorError   = lipgloss.Color("#ef4444")
)

// ── Reusable Styles ──

var (
	// Main border frame
	FrameStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1)

	// Title banner
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true)

	// Subtitle
	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorTextDim)

	// Info box
	InfoBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2)

	// Active button (reverse video)
	ButtonStyle = lipgloss.NewStyle().
			Foreground(ColorBG).
			Background(ColorAccent).
			Bold(true).
			Padding(0, 3)

	// Disabled button
	ButtonDisabledStyle = lipgloss.NewStyle().
				Foreground(ColorTextMuted).
				Background(ColorSurface).
				Padding(0, 3)

	// Severity badge styles
	CriticalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(ColorCritical).
			Bold(true).
			Padding(0, 1)

	HighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(ColorHigh).
			Bold(true).
			Padding(0, 1)

	MediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(ColorMedium).
			Padding(0, 1)

	LowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(ColorLow).
			Padding(0, 1)

	InfoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(ColorInformational).
			Padding(0, 1)

	// Detection list item
	DetectionStyle = lipgloss.NewStyle().
			Foreground(ColorText)

	// Selected detection
	DetectionSelectedStyle = lipgloss.NewStyle().
				Foreground(ColorAccent)

	// Hint / help text
	HintStyle = lipgloss.NewStyle().
			Foreground(ColorTextDim)

	// Scan stage box
	StageStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder)

	// Step indicator styles
	StepDone    = lipgloss.NewStyle().Foreground(ColorTextDim)
	StepActive  = lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	StepPending = lipgloss.NewStyle().Foreground(ColorTextMuted)

	// Alert / error
	AlertStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	// Module badge
	BadgeStyle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Background(ColorAccentDim).
			Padding(0, 1)

	// Separator line
	SeparatorStyle = lipgloss.NewStyle().
			Foreground(ColorBorder)

	// Label (right-aligned in info box)
	LabelStyle = lipgloss.NewStyle().
			Foreground(ColorTextDim).
			Width(8).
			Align(lipgloss.Right)

	// Value (info box)
	ValueStyle = lipgloss.NewStyle().
			Foreground(ColorText)
)

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return CriticalStyle
	case "high":
		return HighStyle
	case "medium":
		return MediumStyle
	case "low":
		return LowStyle
	case "informational":
		return InfoStyle
	default:
		return lipgloss.NewStyle().Foreground(ColorTextDim)
	}
}

// Truncate truncates a string to maxLen runes, adding "..." if needed.
func Truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

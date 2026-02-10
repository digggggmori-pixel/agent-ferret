package tui

import "github.com/charmbracelet/lipgloss"

// ── Color Palette ──

var (
	// Neon cyberpunk accent colors
	ColorCyan    = lipgloss.Color("#00ffff")
	ColorPink    = lipgloss.Color("#ff69b4")
	ColorGreen   = lipgloss.Color("#39ff14")
	ColorRed     = lipgloss.Color("#ff3333")
	ColorYellow  = lipgloss.Color("#ffff00")
	ColorOrange  = lipgloss.Color("#ff8c00")
	ColorWhite   = lipgloss.Color("#ffffff")
	ColorGray    = lipgloss.Color("#666666")
	ColorDimGray = lipgloss.Color("#444444")
	ColorDark    = lipgloss.Color("#1a1a2e")
	ColorBG      = lipgloss.Color("#0a0a1a")

	// Severity colors
	ColorCritical = lipgloss.Color("#ff3333")
	ColorHigh     = lipgloss.Color("#ff8c00")
	ColorMedium   = lipgloss.Color("#ffff00")
	ColorLow      = lipgloss.Color("#39ff14")
)

// ── Reusable Styles ──

var (
	// Main border frame
	FrameStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorCyan).
			Padding(0, 1)

	// Title banner
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	// Subtitle
	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	// Info box
	InfoBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorDimGray).
			Padding(0, 1)

	// Button
	ButtonStyle = lipgloss.NewStyle().
			Foreground(ColorGreen).
			Bold(true)

	// Progress bar filled
	ProgressFilled = lipgloss.NewStyle().
			Foreground(ColorCyan)

	// Progress bar empty
	ProgressEmpty = lipgloss.NewStyle().
			Foreground(ColorDimGray)

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

	// Detection list item
	DetectionStyle = lipgloss.NewStyle().
			Foreground(ColorWhite)

	// Hint / help text
	HintStyle = lipgloss.NewStyle().
			Foreground(ColorGray)

	// Scan stage box
	StageStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorDimGray)

	// Step indicator styles
	StepDone    = lipgloss.NewStyle().Foreground(ColorGreen)
	StepActive  = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
	StepPending = lipgloss.NewStyle().Foreground(ColorDimGray)

	// Alert popup
	AlertStyle = lipgloss.NewStyle().
			Foreground(ColorRed).
			Bold(true)
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
	default:
		return lipgloss.NewStyle()
	}
}

// RenderProgressBar renders a text progress bar of a given width.
func RenderProgressBar(percent, width int) string {
	filled := width * percent / 100
	if filled > width {
		filled = width
	}
	empty := width - filled
	bar := ProgressFilled.Render(repeatChar("█", filled)) +
		ProgressEmpty.Render(repeatChar("░", empty))
	return bar
}

func repeatChar(ch string, n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += ch
	}
	return s
}

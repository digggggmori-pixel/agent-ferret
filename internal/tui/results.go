package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ResultsModel represents the scan results screen.
type ResultsModel struct {
	width, height int

	result   *types.ScanResult
	duration time.Duration
	hostName string

	// scrolling
	offset     int
	maxVisible int

	// filtering
	filter string // "", "critical", "high", "medium", "low"

	// animation
	tickCount int

	// export status
	exportPath string
}

func NewResultsModel() ResultsModel {
	return ResultsModel{
		maxVisible: 10,
		filter:     "",
	}
}

func (m ResultsModel) Init() tea.Cmd {
	return nil
}

func (m ResultsModel) Update(msg tea.Msg) (ResultsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.maxVisible = m.height - 18
		if m.maxVisible < 3 {
			m.maxVisible = 3
		}
	case tickMsg:
		m.tickCount++
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.offset > 0 {
				m.offset--
			}
		case "down", "j":
			filtered := m.filteredDetections()
			if m.offset < len(filtered)-m.maxVisible {
				m.offset++
			}
		case "1":
			m.filter = "critical"
			m.offset = 0
		case "2":
			m.filter = "high"
			m.offset = 0
		case "3":
			m.filter = "medium"
			m.offset = 0
		case "4":
			m.filter = "low"
			m.offset = 0
		case "a":
			m.filter = ""
			m.offset = 0
		}
	case exportDoneMsg:
		m.exportPath = string(msg)
	}
	return m, nil
}

func (m ResultsModel) filteredDetections() []types.Detection {
	if m.result == nil {
		return nil
	}
	if m.filter == "" {
		return m.result.Detections
	}
	var filtered []types.Detection
	for _, d := range m.result.Detections {
		if d.Severity == m.filter {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

func (m ResultsModel) View() string {
	w := m.width
	if w < 40 {
		w = 60
	}

	if m.result == nil {
		return "No results available"
	}

	var b strings.Builder

	// Header
	header := fmt.Sprintf("  SCAN COMPLETE    Duration: %s    Host: %s",
		formatDuration(m.duration), m.hostName)
	b.WriteString(TitleStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDimGray).Render(strings.Repeat("═", w)))
	b.WriteString("\n\n")

	// Ferret happy pose + message
	ferret := RenderPose(PoseHappy)
	totalDet := len(m.result.Detections)
	var message string
	if totalDet == 0 {
		message = SpeechBubble("All clear!")
	} else {
		message = SpeechBubble(fmt.Sprintf("%d threats found", totalDet))
	}
	ferretSection := lipgloss.JoinHorizontal(lipgloss.Top, ferret, "  ", message)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, ferretSection))
	b.WriteString("\n\n")

	// Threat score bar
	score := m.calculateThreatScore()
	scoreLabel := "SAFE"
	scoreColor := ColorGreen
	if score >= 70 {
		scoreLabel = "CRITICAL"
		scoreColor = ColorRed
	} else if score >= 40 {
		scoreLabel = "WARNING"
		scoreColor = ColorOrange
	} else if score > 0 {
		scoreLabel = "CAUTION"
		scoreColor = ColorYellow
	}

	scoreLine := fmt.Sprintf("  Threat Score: %d/100  %s  %s",
		score,
		RenderProgressBar(score, 20),
		lipgloss.NewStyle().Foreground(scoreColor).Bold(true).Render(scoreLabel),
	)
	b.WriteString(scoreLine)
	b.WriteString("\n\n")

	// Severity summary
	summary := m.result.Summary.Detections
	sumLine := fmt.Sprintf("  %s: %d    %s: %d    %s: %d    %s: %d",
		CriticalStyle.Render("CRITICAL"), summary.Critical,
		HighStyle.Render("HIGH"), summary.High,
		MediumStyle.Render("MEDIUM"), summary.Medium,
		LowStyle.Render("LOW"), summary.Low,
	)
	b.WriteString(sumLine)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDimGray).Render("  " + strings.Repeat("─", w-4)))
	b.WriteString("\n\n")

	// Filter indicator
	if m.filter != "" {
		b.WriteString(fmt.Sprintf("  Filter: %s  (press A to show all)\n\n",
			lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render(strings.ToUpper(m.filter))))
	}

	// Detection list
	detections := m.filteredDetections()
	if len(detections) == 0 {
		if m.filter != "" {
			b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center,
				HintStyle.Render("No detections with this severity")))
		} else {
			b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center,
				lipgloss.NewStyle().Foreground(ColorGreen).Render("No threats detected!")))
		}
	} else {
		end := m.offset + m.maxVisible
		if end > len(detections) {
			end = len(detections)
		}
		visible := detections[m.offset:end]

		for _, d := range visible {
			b.WriteString(m.renderDetection(d))
			b.WriteString("\n")
		}

		// Scroll indicator
		if len(detections) > m.maxVisible {
			scrollInfo := fmt.Sprintf("  Showing %d-%d of %d", m.offset+1, end, len(detections))
			b.WriteString(HintStyle.Render(scrollInfo))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	// Export status
	if m.exportPath != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorGreen).Render(
			fmt.Sprintf("  Exported to: %s", m.exportPath)))
		b.WriteString("\n")
	}

	// Help line
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDimGray).Render("  " + strings.Repeat("─", w-4)))
	b.WriteString("\n")
	help := "  ↑↓ Scroll  •  1-4 Filter  •  A All  •  E Export  •  R Rescan  •  Q Quit"
	b.WriteString(HintStyle.Render(help))

	return b.String()
}

func (m ResultsModel) renderDetection(d types.Detection) string {
	badge := SeverityStyle(d.Severity).Render(strings.ToUpper(d.Severity))

	desc := d.Description
	if len(desc) > 60 {
		desc = desc[:57] + "..."
	}

	line := fmt.Sprintf("  %s %s", badge, DetectionStyle.Render(d.Type+": "+desc))

	// MITRE info
	if d.MITRE != nil && len(d.MITRE.Techniques) > 0 {
		mitre := HintStyle.Render(fmt.Sprintf("    MITRE: %s", strings.Join(d.MITRE.Techniques, ", ")))
		line += "\n" + mitre
	}

	return line
}

func (m ResultsModel) calculateThreatScore() int {
	if m.result == nil {
		return 0
	}
	s := m.result.Summary.Detections
	score := s.Critical*25 + s.High*10 + s.Medium*3 + s.Low*1
	if score > 100 {
		score = 100
	}
	return score
}

// exportDoneMsg is sent when JSON export completes
type exportDoneMsg string

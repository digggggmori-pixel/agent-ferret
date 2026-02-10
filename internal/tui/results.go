package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/viewport"
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

	// selection & scrolling
	selected int
	expanded bool
	vp       viewport.Model
	vpReady  bool

	// filtering
	filter string // "", "critical", "high", "medium", "low"

	// animation
	tickCount int

	// export status
	exportPath string

	// error from scan
	errMsg string

	// score progress bar
	scoreProg progress.Model
}

func NewResultsModel() ResultsModel {
	sp := progress.New(
		progress.WithScaledGradient(string(ColorSuccess), string(ColorError)),
		progress.WithoutPercentage(),
	)
	sp.Width = 20
	return ResultsModel{
		filter:    "",
		scoreProg: sp,
	}
}

func (m ResultsModel) Init() tea.Cmd {
	return nil
}

func (m ResultsModel) Update(msg tea.Msg) (ResultsModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.initViewport()

	case tickMsg:
		m.tickCount++

	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.selected > 0 {
				m.selected--
				m.expanded = false
				m.updateViewportContent()
			}
		case "down", "j":
			filtered := m.filteredDetections()
			if m.selected < len(filtered)-1 {
				m.selected++
				m.expanded = false
				m.updateViewportContent()
			}
		case "enter":
			m.expanded = !m.expanded
			m.updateViewportContent()
		case "1":
			m.filter = "critical"
			m.selected = 0
			m.expanded = false
			m.updateViewportContent()
		case "2":
			m.filter = "high"
			m.selected = 0
			m.expanded = false
			m.updateViewportContent()
		case "3":
			m.filter = "medium"
			m.selected = 0
			m.expanded = false
			m.updateViewportContent()
		case "4":
			m.filter = "low"
			m.selected = 0
			m.expanded = false
			m.updateViewportContent()
		case "a":
			m.filter = ""
			m.selected = 0
			m.expanded = false
			m.updateViewportContent()
		}
	case exportDoneMsg:
		m.exportPath = string(msg)
	}

	// Forward to viewport for scroll
	if m.vpReady {
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *ResultsModel) initViewport() {
	headerHeight := 12
	footerHeight := 4
	vpHeight := m.height - headerHeight - footerHeight
	if vpHeight < 5 {
		vpHeight = 5
	}
	vpWidth := m.width - 4
	if vpWidth < 20 {
		vpWidth = 20
	}
	m.vp = viewport.New(vpWidth, vpHeight)
	m.vp.Style = lipgloss.NewStyle()
	m.vpReady = true
	m.updateViewportContent()
}

func (m *ResultsModel) updateViewportContent() {
	if !m.vpReady {
		return
	}
	content := m.renderDetectionList()
	m.vp.SetContent(content)

	// Scroll to keep selected item visible
	// Each item is ~2-3 lines (1 main + optional MITRE + optional expanded)
	targetLine := m.selected * 2
	if m.vp.YOffset > targetLine {
		m.vp.SetYOffset(targetLine)
	} else if targetLine >= m.vp.YOffset+m.vp.Height-2 {
		m.vp.SetYOffset(targetLine - m.vp.Height + 3)
	}
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
		w = 80
	}

	if m.result == nil {
		return m.renderErrorView(w)
	}

	var b strings.Builder

	// Header
	left := TitleStyle.Render("  RESULTS")
	info := HintStyle.Render(fmt.Sprintf("Duration: %s  Host: %s  ", formatDuration(m.duration), m.hostName))
	spacerW := w - lipgloss.Width(left) - lipgloss.Width(info)
	if spacerW < 1 {
		spacerW = 1
	}
	b.WriteString(left + strings.Repeat(" ", spacerW) + info)
	b.WriteString("\n")
	b.WriteString(SeparatorStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n\n")

	// Threat score
	score := m.calculateThreatScore()
	scoreLabel := "SAFE"
	scoreColor := ColorSuccess
	if score >= 70 {
		scoreLabel = "CRITICAL"
		scoreColor = ColorError
	} else if score >= 40 {
		scoreLabel = "WARNING"
		scoreColor = ColorHigh
	} else if score > 0 {
		scoreLabel = "CAUTION"
		scoreColor = ColorMedium
	}

	m.scoreProg.Width = 20
	scoreLine := fmt.Sprintf("  Threat Score: %d/100  %s  %s",
		score,
		m.scoreProg.ViewAs(float64(score)/100.0),
		lipgloss.NewStyle().Foreground(scoreColor).Bold(true).Render(scoreLabel),
	)
	b.WriteString(scoreLine)
	b.WriteString("\n\n")

	// Severity summary with filter indicators
	summary := m.result.Summary.Detections
	b.WriteString(m.renderSeveritySummary(summary))
	b.WriteString("\n")
	b.WriteString(SeparatorStyle.Render("  " + strings.Repeat("─", w-4)))
	b.WriteString("\n")

	// Filter indicator
	if m.filter != "" {
		b.WriteString(fmt.Sprintf("  Filter: %s  ",
			lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(strings.ToUpper(m.filter))))
		b.WriteString(HintStyle.Render("(A = show all)"))
		b.WriteString("\n")
	}

	// Detection list via viewport
	if m.vpReady {
		b.WriteString(m.vp.View())
	}
	b.WriteString("\n")

	// Export status
	if m.exportPath != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorSuccess).Render(
			fmt.Sprintf("  Exported: %s", m.exportPath)))
		b.WriteString("\n")
	}

	// Footer
	b.WriteString(SeparatorStyle.Render(strings.Repeat("─", w)))
	b.WriteString("\n")

	// Scroll info + help
	scrollInfo := ""
	detections := m.filteredDetections()
	if len(detections) > 0 {
		scrollInfo = HintStyle.Render(fmt.Sprintf("  %d/%d  ", m.selected+1, len(detections)))
	}
	help := HintStyle.Render("↑↓ Select  ENTER Detail  1-4 Filter  A All  E Export  R Rescan  Q Quit")
	b.WriteString(scrollInfo + help)

	return b.String()
}

func (m ResultsModel) renderErrorView(w int) string {
	var b strings.Builder
	b.WriteString("\n\n")
	errText := "Scan failed"
	if m.errMsg != "" {
		errText = m.errMsg
	}
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center,
		AlertStyle.Render("[!] "+errText)))
	b.WriteString("\n\n")
	ferret := RenderPose(PoseSleep)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, ferret))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center,
		HintStyle.Render("R rescan  •  Q quit")))
	return b.String()
}

func (m ResultsModel) renderSeveritySummary(s types.DetectionCount) string {
	parts := []string{
		m.renderSummaryBadge("CRITICAL", s.Critical, "critical"),
		m.renderSummaryBadge("HIGH", s.High, "high"),
		m.renderSummaryBadge("MEDIUM", s.Medium, "medium"),
		m.renderSummaryBadge("LOW", s.Low, "low"),
	}
	return "  " + strings.Join(parts, "  ")
}

func (m ResultsModel) renderSummaryBadge(label string, count int, severity string) string {
	style := SeverityStyle(severity)
	countStr := fmt.Sprintf(" %s: %d ", label, count)
	if m.filter == severity {
		return style.Underline(true).Render(countStr)
	}
	return style.Render(countStr)
}

func (m ResultsModel) renderDetectionList() string {
	detections := m.filteredDetections()
	if len(detections) == 0 {
		if m.filter != "" {
			return lipgloss.PlaceHorizontal(m.width, lipgloss.Center,
				HintStyle.Render("No detections with this severity"))
		}
		return lipgloss.PlaceHorizontal(m.width, lipgloss.Center,
			lipgloss.NewStyle().Foreground(ColorSuccess).Render("No threats detected!"))
	}

	var b strings.Builder
	for i, d := range detections {
		isSelected := (i == m.selected)
		b.WriteString(m.renderDetection(d, isSelected))
		b.WriteString("\n")
	}
	return b.String()
}

func (m ResultsModel) renderDetection(d types.Detection, isSelected bool) string {
	descWidth := m.width - 24
	if descWidth < 30 {
		descWidth = 30
	}

	badge := SeverityStyle(d.Severity).Render(fmt.Sprintf(" %-8s", strings.ToUpper(d.Severity)))
	desc := Truncate(d.Description, descWidth)

	var line string
	if isSelected {
		// Selected: accent arrow + accent text
		indicator := lipgloss.NewStyle().Foreground(ColorAccent).Render("")
		descText := DetectionSelectedStyle.Render(d.Type + ": " + desc)
		line = fmt.Sprintf(" %s %s %s", indicator, badge, descText)

		// Show MITRE only for selected
		if d.MITRE != nil && len(d.MITRE.Techniques) > 0 {
			mitre := HintStyle.Render("     MITRE: " + strings.Join(d.MITRE.Techniques, ", "))
			line += "\n" + mitre
		}

		// Expanded detail view
		if m.expanded {
			if d.UserDescription != "" {
				detail := lipgloss.NewStyle().
					Foreground(ColorText).
					Width(m.width - 10).
					PaddingLeft(5).
					Render(d.UserDescription)
				line += "\n" + detail
			}
			if d.Recommendation != "" {
				rec := lipgloss.NewStyle().
					Foreground(ColorAccent).
					Width(m.width - 10).
					PaddingLeft(5).
					Render("Rec: " + d.Recommendation)
				line += "\n" + rec
			}
		}
	} else {
		descText := DetectionStyle.Render(d.Type + ": " + desc)
		line = fmt.Sprintf("   %s %s", badge, descText)
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

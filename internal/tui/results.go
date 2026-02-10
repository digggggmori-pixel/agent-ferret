package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
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
	selected  int
	listTop   int // first visible item index
	listHeight int // visible item count

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

	// viewport initialized flag
	vpReady bool
}

// Fixed layout constants
const (
	resultHeaderLines = 7 // title + sep + score/CTA + blank + badges/filter + help + sep
	resultDetailLines = 7 // separator + detail panel (6 lines)
	resultFooterLines = 0 // help moved into header
)

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
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalcLayout()

	case tickMsg:
		m.tickCount++

	case tea.KeyMsg:
		filtered := m.filteredDetections()
		switch msg.String() {
		case "up", "k", "K":
			if m.selected > 0 {
				m.selected--
				m.ensureVisible()
			}
		case "down", "j", "J":
			if m.selected < len(filtered)-1 {
				m.selected++
				m.ensureVisible()
			}
		case "1":
			m.filter = "critical"
			m.selected = 0
			m.listTop = 0
		case "2":
			m.filter = "high"
			m.selected = 0
			m.listTop = 0
		case "3":
			m.filter = "medium"
			m.selected = 0
			m.listTop = 0
		case "4":
			m.filter = "low"
			m.selected = 0
			m.listTop = 0
		case "a", "A":
			m.filter = ""
			m.selected = 0
			m.listTop = 0
		}
	case exportDoneMsg:
		m.exportPath = string(msg)
	}

	return m, nil
}

func (m *ResultsModel) initViewport() {
	m.recalcLayout()
	m.vpReady = true
}

func (m *ResultsModel) recalcLayout() {
	m.listHeight = m.height - resultHeaderLines - resultDetailLines - resultFooterLines
	if m.listHeight < 1 {
		m.listHeight = 1
	}
}

func (m *ResultsModel) ensureVisible() {
	if m.selected < m.listTop {
		m.listTop = m.selected
	} else if m.selected >= m.listTop+m.listHeight {
		m.listTop = m.selected - m.listHeight + 1
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

// View builds the results screen as a fixed-height line array.
func (m ResultsModel) View() string {
	w := m.width
	if w < 40 {
		w = 80
	}
	h := m.height
	if h < 12 {
		h = 12
	}

	if m.result == nil {
		return m.renderErrorView(w)
	}

	lines := make([]string, 0, h)

	// ── Header section (6 lines) ──

	// Line 1: Title + info
	left := TitleStyle.Render("  RESULTS")
	info := HintStyle.Render(fmt.Sprintf("Duration: %s  Host: %s  ", formatDuration(m.duration), m.hostName))
	spacerW := w - lipgloss.Width(left) - lipgloss.Width(info)
	if spacerW < 1 {
		spacerW = 1
	}
	lines = append(lines, left+strings.Repeat(" ", spacerW)+info)

	// Line 2: Separator
	lines = append(lines, SeparatorStyle.Render(strings.Repeat("─", w)))

	// Line 3: Threat score + CTA
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
	scoreStr := fmt.Sprintf("  Threat Score: %d/100  %s  %s",
		score,
		m.scoreProg.ViewAs(float64(score)/100.0),
		lipgloss.NewStyle().Foreground(scoreColor).Bold(true).Render(scoreLabel))
	cta := lipgloss.NewStyle().
		Background(lipgloss.Color("#f59e0b")).
		Foreground(lipgloss.Color("#000000")).
		Bold(true).
		Padding(0, 2).
		Render("▶ D  Full Analysis")
	ctaSpacer := w - lipgloss.Width(scoreStr) - lipgloss.Width(cta) - 1
	if ctaSpacer < 1 {
		ctaSpacer = 1
	}
	lines = append(lines, scoreStr+strings.Repeat(" ", ctaSpacer)+cta)

	// Line 4: Blank
	lines = append(lines, "")

	// Line 5: Severity badges + scroll/filter info
	summary := m.result.Summary.Detections
	badgeStr := m.renderSeveritySummary(summary)
	detections := m.filteredDetections()
	var rightParts []string
	if len(detections) > 0 {
		rightParts = append(rightParts, fmt.Sprintf("%d/%d", m.selected+1, len(detections)))
	}
	if m.filter != "" {
		rightParts = append(rightParts, lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(strings.ToUpper(m.filter)))
	} else {
		rightParts = append(rightParts, HintStyle.Render(fmt.Sprintf("%d detections", len(detections))))
	}
	if m.exportPath != "" {
		rightParts = append(rightParts, lipgloss.NewStyle().Foreground(ColorSuccess).Render("Exported"))
	}
	rightStr := strings.Join(rightParts, "  ") + "  "
	badgeSpacer := w - lipgloss.Width(badgeStr) - lipgloss.Width(rightStr)
	if badgeSpacer < 1 {
		badgeSpacer = 1
	}
	lines = append(lines, badgeStr+strings.Repeat(" ", badgeSpacer)+rightStr)

	// Line 6: Help shortcuts
	lines = append(lines, HintStyle.Render("  ↑↓ Navigate  1-4 Filter  A All  E Export  D Analyze  R Rescan  Q Quit"))

	// Line 7: Separator
	lines = append(lines, SeparatorStyle.Render(strings.Repeat("─", w)))

	// ── Detection list section ──
	listLines := m.renderList(detections, w)
	lines = append(lines, listLines...)

	// ── Detail panel section (separator is inside renderDetailPanel) ──
	detailLines := m.renderDetailPanel(detections, w)
	lines = append(lines, detailLines...)

	// Cap each line to prevent wrapping on Windows terminals
	capStyle := lipgloss.NewStyle().MaxWidth(w)
	for i, line := range lines {
		lines[i] = capStyle.Render(line)
	}

	// Pad to exact height
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}

	return strings.Join(lines, "\n")
}

// renderList renders the detection list with exactly listHeight lines.
func (m ResultsModel) renderList(detections []types.Detection, w int) []string {
	lines := make([]string, m.listHeight)

	if len(detections) == 0 {
		for i := range lines {
			lines[i] = ""
		}
		msg := lipgloss.NewStyle().Foreground(ColorSuccess).Render("  No threats detected!")
		if m.filter != "" {
			msg = HintStyle.Render("  No detections with this severity")
		}
		if m.listHeight > 1 {
			lines[1] = msg
		}
		return lines
	}

	// Line format: prefix(3) + badge(8) + space(1) + content
	// Badge has Padding(0,1) = 6ch content + 2ch padding = 8 visual chars
	contentWidth := w - 12 // 3 + 8 + 1 = 12 chars overhead
	if contentWidth < 20 {
		contentWidth = 20
	}

	for i := 0; i < m.listHeight; i++ {
		idx := m.listTop + i
		if idx >= len(detections) {
			lines[i] = ""
			continue
		}

		d := detections[idx]
		isSelected := (idx == m.selected)

		// Severity badge (short)
		sevShort := strings.ToUpper(d.Severity)
		if len(sevShort) > 4 {
			sevShort = sevShort[:4]
		}
		badge := SeverityStyle(d.Severity).Render(fmt.Sprintf(" %-4s ", sevShort))

		// Truncate combined type + description to fit in available width
		content := Truncate(d.Type+": "+d.Description, contentWidth)

		if isSelected {
			// Selected row: accent indicator + highlighted text
			indicator := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(" ▸ ")
			text := lipgloss.NewStyle().Foreground(ColorAccent).Render(content)
			lines[i] = indicator + badge + " " + text
		} else {
			// Normal row
			text := lipgloss.NewStyle().Foreground(ColorText).Render(content)
			lines[i] = "   " + badge + " " + text
		}
	}

	return lines
}

// renderDetailPanel renders the detail panel for the selected detection.
// Always returns exactly resultDetailLines lines.
// Line 0 is the separator; lines 1-6 are detail content.
func (m ResultsModel) renderDetailPanel(detections []types.Detection, w int) []string {
	lines := make([]string, resultDetailLines)
	lines[0] = SeparatorStyle.Render(strings.Repeat("─", w))
	for i := 1; i < resultDetailLines; i++ {
		lines[i] = ""
	}

	if len(detections) == 0 || m.selected >= len(detections) {
		if resultDetailLines > 2 {
			lines[2] = HintStyle.Render("  Select a detection to view details")
		}
		return lines
	}

	d := detections[m.selected]
	contentW := w - 6
	if contentW < 30 {
		contentW = 30
	}

	lineIdx := 1 // start after separator

	// Type + Severity header
	sevBadge := SeverityStyle(d.Severity).Render(fmt.Sprintf(" %s ", strings.ToUpper(d.Severity)))
	typeText := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(d.Type)
	lines[lineIdx] = "  " + sevBadge + "  " + typeText
	lineIdx++

	// Full description
	if d.Description != "" && lineIdx < resultDetailLines {
		lines[lineIdx] = "  " + lipgloss.NewStyle().Foreground(ColorText).Render(Truncate(d.Description, contentW))
		lineIdx++
	}

	// User description (explanation)
	if d.UserDescription != "" && lineIdx < resultDetailLines {
		lines[lineIdx] = "  " + lipgloss.NewStyle().Foreground(ColorTextDim).Render(Truncate(d.UserDescription, contentW))
		lineIdx++
	}

	// Recommendation
	if d.Recommendation != "" && lineIdx < resultDetailLines {
		recLabel := lipgloss.NewStyle().Foreground(ColorAccent).Render("Rec:")
		recText := lipgloss.NewStyle().Foreground(ColorText).Render(" " + Truncate(d.Recommendation, contentW-5))
		lines[lineIdx] = "  " + recLabel + recText
		lineIdx++
	}

	// MITRE
	if d.MITRE != nil && len(d.MITRE.Techniques) > 0 && lineIdx < resultDetailLines {
		mitreLabel := lipgloss.NewStyle().Foreground(ColorTextDim).Render("MITRE: ")
		techniques := strings.Join(d.MITRE.Techniques, ", ")
		lines[lineIdx] = "  " + mitreLabel + lipgloss.NewStyle().Foreground(ColorText).Render(Truncate(techniques, contentW-7))
		lineIdx++
	}

	// Process info
	if d.Process != nil && lineIdx < resultDetailLines {
		procLabel := lipgloss.NewStyle().Foreground(ColorTextDim).Render("Process: ")
		procInfo := fmt.Sprintf("%s (PID:%d)", d.Process.Name, d.Process.PID)
		if d.Process.Path != "" {
			procInfo += "  " + d.Process.Path
		}
		lines[lineIdx] = "  " + procLabel + lipgloss.NewStyle().Foreground(ColorText).Render(Truncate(procInfo, contentW-9))
		lineIdx++
	}

	// Network info
	if d.Network != nil && lineIdx < resultDetailLines {
		netLabel := lipgloss.NewStyle().Foreground(ColorTextDim).Render("Net: ")
		netInfo := fmt.Sprintf("%s:%d → %s:%d (%s)",
			d.Network.LocalAddr, d.Network.LocalPort,
			d.Network.RemoteAddr, d.Network.RemotePort,
			d.Network.ProcessName)
		lines[lineIdx] = "  " + netLabel + lipgloss.NewStyle().Foreground(ColorText).Render(Truncate(netInfo, contentW-5))
		lineIdx++
	}

	// Sigma rules
	if len(d.SigmaRules) > 0 && lineIdx < resultDetailLines {
		sigLabel := lipgloss.NewStyle().Foreground(ColorTextDim).Render("Sigma: ")
		lines[lineIdx] = "  " + sigLabel + lipgloss.NewStyle().Foreground(ColorText).Render(Truncate(strings.Join(d.SigmaRules, ", "), contentW-7))
		lineIdx++
	}

	return lines
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
		m.renderSummaryBadge("CRIT", s.Critical, "critical"),
		m.renderSummaryBadge("HIGH", s.High, "high"),
		m.renderSummaryBadge("MED", s.Medium, "medium"),
		m.renderSummaryBadge("LOW", s.Low, "low"),
	}
	return "  " + strings.Join(parts, "  ")
}

func (m ResultsModel) renderSummaryBadge(label string, count int, severity string) string {
	style := SeverityStyle(severity)
	countStr := fmt.Sprintf(" %s:%d ", label, count)
	if m.filter == severity {
		return style.Underline(true).Render(countStr)
	}
	return style.Render(countStr)
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

func min4(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// exportDoneMsg is sent when JSON export completes
type exportDoneMsg string

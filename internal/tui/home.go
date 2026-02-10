package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// HomeModel represents the home/start screen.
type HomeModel struct {
	width, height int
	hostName      string
	osVersion     string
	ipAddresses   []string
	isAdmin       bool
	ruleVersion   string
	rulesLoaded   bool
	sigmaCount    int

	// animation
	tailFrame int // 0 or 1
	tickCount int
}

func NewHomeModel() HomeModel {
	return HomeModel{
		sigmaCount: 2363,
	}
}

func (m HomeModel) Init() tea.Cmd {
	return nil
}

func (m HomeModel) Update(msg tea.Msg) (HomeModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.tickCount++
		if m.tickCount%6 == 0 { // ~600ms cycle
			m.tailFrame = 1 - m.tailFrame
		}
	}
	return m, nil
}

func (m HomeModel) View() string {
	w := m.width
	if w < 40 {
		w = 60
	}

	var b strings.Builder

	// Title
	title := TitleStyle.Render("██▓▒░  FERRET  ░▒▓██")
	subtitle := SubtitleStyle.Render("BRIQA Security Scanner v1.0.0")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, title))
	b.WriteString("\n")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, subtitle))
	b.WriteString("\n\n")

	// Ferret mascot (idle pose)
	ferret := RenderPose(PoseIdle)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, ferret))
	b.WriteString("\n\n")

	// Host info box
	adminStr := "No"
	adminColor := ColorRed
	if m.isAdmin {
		adminStr = "Yes"
		adminColor = ColorGreen
	}

	rulesStr := "Not loaded"
	rulesColor := ColorRed
	if m.rulesLoaded {
		rulesStr = fmt.Sprintf("%s (%d sigma)", m.ruleVersion, m.sigmaCount)
		rulesColor = ColorGreen
	}

	ip := "N/A"
	if len(m.ipAddresses) > 0 {
		ip = m.ipAddresses[0]
	}

	info := fmt.Sprintf(
		"  Host:  %s\n"+
			"  OS:    %s\n"+
			"  IP:    %s\n"+
			"  Admin: %s\n"+
			"  Rules: %s",
		lipgloss.NewStyle().Foreground(ColorWhite).Render(m.hostName),
		lipgloss.NewStyle().Foreground(ColorWhite).Render(m.osVersion),
		lipgloss.NewStyle().Foreground(ColorWhite).Render(ip),
		lipgloss.NewStyle().Foreground(adminColor).Render(adminStr),
		lipgloss.NewStyle().Foreground(rulesColor).Render(rulesStr),
	)

	infoBox := InfoBoxStyle.Width(42).Render(info)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, infoBox))
	b.WriteString("\n\n")

	// Scan modules indicator
	modules := fmt.Sprintf("Scan: %s  %s  %s  %s  %s  %s",
		lipgloss.NewStyle().Foreground(ColorCyan).Render("PROC"),
		lipgloss.NewStyle().Foreground(ColorCyan).Render("NET"),
		lipgloss.NewStyle().Foreground(ColorCyan).Render("SVC"),
		lipgloss.NewStyle().Foreground(ColorCyan).Render("REG"),
		lipgloss.NewStyle().Foreground(ColorCyan).Render("SIGMA"),
		lipgloss.NewStyle().Foreground(ColorCyan).Render("LOGS"),
	)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, modules))
	b.WriteString("\n\n")

	// Start button
	btn := ButtonStyle.Render("[ ▶  START SCAN ]")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, btn))
	b.WriteString("\n\n")

	// Hint
	hint := HintStyle.Render("Press ENTER to start  •  Q to quit")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, hint))

	return b.String()
}

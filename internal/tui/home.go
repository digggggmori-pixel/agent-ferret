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

	// error message (shown when scan can't start)
	errorMsg string
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
	switch msg.(type) {
	case tickMsg:
		m.tickCount++
		if m.tickCount%6 == 0 {
			m.tailFrame = 1 - m.tailFrame
		}
	}
	return m, nil
}

func (m HomeModel) View() string {
	w := m.width
	if w < 40 {
		w = 80
	}

	var b strings.Builder

	// Title
	title := TitleStyle.Render("██▓▒░  FERRET  ░▒▓██")
	subtitle := SubtitleStyle.Render("BRIQA Security Scanner v1.0.0")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, title))
	b.WriteString("\n")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, subtitle))
	b.WriteString("\n\n")

	// Ferret mascot (subtle idle animation)
	pose := PoseIdle
	if m.tailFrame == 1 {
		pose = PoseSniff
	}
	ferret := RenderPose(pose)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, ferret))
	b.WriteString("\n\n")

	// Host info box — responsive width
	boxWidth := w * 2 / 3
	if boxWidth > 56 {
		boxWidth = 56
	}
	if boxWidth < 36 {
		boxWidth = 36
	}

	adminStr := "No"
	adminColor := ColorError
	if m.isAdmin {
		adminStr = "Yes"
		adminColor = ColorSuccess
	}

	rulesStr := "Not loaded"
	rulesColor := ColorError
	if m.rulesLoaded {
		rulesStr = fmt.Sprintf("%s (%d sigma)", m.ruleVersion, m.sigmaCount)
		rulesColor = ColorSuccess
	}

	ip := "N/A"
	if len(m.ipAddresses) > 0 {
		ip = m.ipAddresses[0]
	}

	info := strings.Join([]string{
		LabelStyle.Render("Host") + "  " + ValueStyle.Render(m.hostName),
		LabelStyle.Render("OS") + "  " + ValueStyle.Render(m.osVersion),
		LabelStyle.Render("IP") + "  " + ValueStyle.Render(ip),
		LabelStyle.Render("Admin") + "  " + lipgloss.NewStyle().Foreground(adminColor).Render(adminStr),
		LabelStyle.Render("Rules") + "  " + lipgloss.NewStyle().Foreground(rulesColor).Render(rulesStr),
	}, "\n")

	infoBox := InfoBoxStyle.Width(boxWidth).Render(info)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, infoBox))
	b.WriteString("\n\n")

	// Module badges
	modules := lipgloss.JoinHorizontal(lipgloss.Center,
		BadgeStyle.Render("PROC"), " ",
		BadgeStyle.Render("NET"), " ",
		BadgeStyle.Render("SVC"), " ",
		BadgeStyle.Render("REG"), " ",
		BadgeStyle.Render("SIGMA"), " ",
		BadgeStyle.Render("LOGS"),
	)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, modules))
	b.WriteString("\n\n")

	// Error message
	if m.errorMsg != "" {
		errBox := lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true).
			Width(w - 8).
			Render("[!] " + m.errorMsg)
		b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, errBox))
		b.WriteString("\n\n")
	} else if !m.rulesLoaded {
		b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center,
			AlertStyle.Render("[!] rules.json not found")))
		b.WriteString("\n\n")
	}

	// Start button
	if m.rulesLoaded {
		btn := ButtonStyle.Render("START SCAN")
		b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, btn))
	} else {
		btn := ButtonDisabledStyle.Render("START SCAN")
		b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, btn))
	}
	b.WriteString("\n\n")

	// Hint
	hint := HintStyle.Render("ENTER start  •  Q quit")
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, hint))

	return b.String()
}

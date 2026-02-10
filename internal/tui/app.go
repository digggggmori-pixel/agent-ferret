package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digggggmori-pixel/agent-ferret/internal/rulestore"
	"github.com/digggggmori-pixel/agent-ferret/internal/scan"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ── Page enum ──

type page int

const (
	pageHome page = iota
	pageScanning
	pageResults
)

// ── Custom messages ──

type tickMsg time.Time

type progressMsg scan.Progress

type detectionMsg int

type scanDoneMsg struct {
	result *types.ScanResult
	err    string
}

// ── Main App Model ──

type AppModel struct {
	page         page
	width        int
	height       int
	home         HomeModel
	scanning     ScanningModel
	results      ResultsModel
	ruleStore    *rulestore.RuleStore
	scanner      *scan.Service
	lastResult   *types.ScanResult
	progressChan chan scan.Progress
	quitting     bool
}

func NewAppModel(rs *rulestore.RuleStore) AppModel {
	progressCh := make(chan scan.Progress, 16)
	svc := scan.NewServiceWithChannel(context.Background(), rs, progressCh)

	home := NewHomeModel()
	// Populate host info
	hostInfo := svc.GetHostInfo()
	home.hostName = hostInfo.Hostname
	home.osVersion = hostInfo.OSVersion
	home.ipAddresses = hostInfo.IPAddresses
	home.isAdmin = svc.IsAdmin()
	home.rulesLoaded = rs.IsLoaded()
	home.ruleVersion = rs.Version()

	return AppModel{
		page:         pageHome,
		home:         home,
		scanning:     NewScanningModel(),
		results:      NewResultsModel(),
		ruleStore:    rs,
		scanner:      svc,
		progressChan: progressCh,
	}
}

func (m AppModel) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.WindowSize())
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// listenProgress creates a command that reads from the progress channel.
func listenProgress(ch chan scan.Progress) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-ch
		if !ok {
			return nil
		}
		return progressMsg(p)
	}
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Propagate content dimensions to all child models
		cw := m.width - 4  // frame border (2) + padding (2)
		ch := m.height - 2 // frame border (2)
		m.home.width = cw
		m.home.height = ch
		m.scanning.width = cw
		m.scanning.height = ch
		m.results.width = cw
		m.results.height = ch

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			if m.page == pageHome {
				if !m.ruleStore.IsLoaded() {
					// Can't scan without rules
					m.home.errorMsg = "rules.json not found! Place it next to ferret.exe"
					break
				}
				// Start scan
				m.page = pageScanning
				m.scanning = NewScanningModel()
				m.scanning.width = m.width - 4
				m.scanning.height = m.height - 2
				m.scanning.updateStageDimensions()
				cmds = append(cmds, m.startScan(), listenProgress(m.progressChan))
			}

		case "r":
			if m.page == pageResults {
				// Rescan
				m.progressChan = make(chan scan.Progress, 16)
				m.scanner = scan.NewServiceWithChannel(context.Background(), m.ruleStore, m.progressChan)
				m.page = pageScanning
				m.scanning = NewScanningModel()
				m.scanning.width = m.width - 4
				m.scanning.height = m.height - 2
				m.scanning.updateStageDimensions()
				cmds = append(cmds, m.startScan(), listenProgress(m.progressChan))
			}

		case "e":
			if m.page == pageResults && m.lastResult != nil {
				cmds = append(cmds, m.exportJSON())
			}
		}

	case tickMsg:
		cmds = append(cmds, tickCmd())

	case progressMsg:
		p := scan.Progress(msg)
		if !p.Done {
			cmds = append(cmds, listenProgress(m.progressChan))
		}

	case scanDoneMsg:
		m.lastResult = msg.result
		m.results = NewResultsModel()
		m.results.result = msg.result
		m.results.errMsg = msg.err
		m.results.hostName = m.home.hostName
		if msg.result != nil {
			m.results.duration = time.Duration(msg.result.ScanDurationMs) * time.Millisecond
		}
		m.results.width = m.width - 4
		m.results.height = m.height - 2
		m.results.initViewport()
		m.page = pageResults
	}

	// Forward to active page
	switch m.page {
	case pageHome:
		var cmd tea.Cmd
		m.home, cmd = m.home.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case pageScanning:
		var cmd tea.Cmd
		m.scanning, cmd = m.scanning.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case pageResults:
		var cmd tea.Cmd
		m.results, cmd = m.results.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m AppModel) View() string {
	if m.quitting {
		return "\n  Goodbye!\n\n"
	}

	var content string
	switch m.page {
	case pageHome:
		content = m.home.View()
	case pageScanning:
		content = m.scanning.View()
	case pageResults:
		content = m.results.View()
	}

	w := m.width
	h := m.height
	if w < 40 {
		w = 80
	}
	if h < 10 {
		h = 20
	}

	// Content area: inside border(2 cols) + horizontal padding(2 cols)
	cw := w - 4
	ch := h - 2

	// Hard-crop content to exact frame dimensions — no lipgloss wrapping
	srcLines := strings.Split(content, "\n")
	capStyle := lipgloss.NewStyle().MaxWidth(cw)
	cropped := make([]string, ch)
	for i := 0; i < ch; i++ {
		if i < len(srcLines) {
			cropped[i] = capStyle.Render(srcLines[i])
		}
		// Right-pad to exact content width so every row is identical width
		if vis := lipgloss.Width(cropped[i]); vis < cw {
			cropped[i] += strings.Repeat(" ", cw-vis)
		}
	}

	// Build frame manually — guarantees exactly h lines × w visual chars
	borderFg := lipgloss.NewStyle().Foreground(ColorBorder)
	hBar := strings.Repeat("─", w-2)
	vBar := borderFg.Render("│")

	out := make([]string, 0, h)
	out = append(out, borderFg.Render("╭"+hBar+"╮"))
	for _, line := range cropped {
		out = append(out, vBar+" "+line+" "+vBar)
	}
	out = append(out, borderFg.Render("╰"+hBar+"╯"))

	return strings.Join(out, "\n")
}

// startScan runs the scan in a goroutine and sends a scanDoneMsg when complete.
func (m AppModel) startScan() tea.Cmd {
	scanner := m.scanner
	return func() tea.Msg {
		result, err := scanner.Execute()
		if err != nil {
			return scanDoneMsg{result: nil, err: err.Error()}
		}
		return scanDoneMsg{result: result}
	}
}

// exportJSON exports the scan result to a JSON file.
func (m AppModel) exportJSON() tea.Cmd {
	result := m.lastResult
	return func() tea.Msg {
		if result == nil {
			return exportDoneMsg("No result to export")
		}
		filename := fmt.Sprintf("ferret_scan_%s.json", time.Now().Format("2006-01-02_150405"))

		homeDir, err := os.UserHomeDir()
		var savePath string
		if err == nil {
			desktopDir := filepath.Join(homeDir, "Desktop")
			if _, statErr := os.Stat(desktopDir); statErr == nil {
				savePath = filepath.Join(desktopDir, filename)
			}
		}
		if savePath == "" {
			savePath = filename
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return exportDoneMsg(fmt.Sprintf("Error: %v", err))
		}

		if err := os.WriteFile(savePath, data, 0644); err != nil {
			return exportDoneMsg(fmt.Sprintf("Error: %v", err))
		}

		return exportDoneMsg(savePath)
	}
}

// Run starts the Bubble Tea program.
func Run(rs *rulestore.RuleStore) error {
	return RunWithError(rs, "")
}

// RunWithError starts the Bubble Tea program with an optional startup error to display.
func RunWithError(rs *rulestore.RuleStore, loadErr string) error {
	model := NewAppModel(rs)
	if loadErr != "" {
		model.home.errorMsg = loadErr
	}
	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ── Title Banner ──

func TitleBanner() string {
	banner := `
 ███████╗███████╗██████╗ ██████╗ ███████╗████████╗
 ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
 █████╗  █████╗  ██████╔╝██████╔╝█████╗     ██║
 ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██╔══╝     ██║
 ██║     ███████╗██║  ██║██║  ██║███████╗   ██║
 ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝`
	return lipgloss.NewStyle().Foreground(ColorAccent).Render(banner)
}

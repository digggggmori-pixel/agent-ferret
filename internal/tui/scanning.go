package tui

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digggggmori-pixel/agent-ferret/internal/scan"
)

// ── Roaming State Machine ──

type roamPhase int

const (
	roamIdle roamPhase = iota
	roamRunning
	roamSniffing
	roamFound
	roamDone
)

type footprint struct {
	x, y    int
	created time.Time
}

// Step names for display
var stepNames = []string{"Proc", "Net", "Svc", "Reg", "Detect", "Sigma", "Logs", "Done"}

// ScanningModel represents the scan-in-progress screen with ferret roaming animation.
type ScanningModel struct {
	width, height int

	// scan progress (from channel)
	progress   scan.Progress
	startTime  time.Time
	detections int

	// ferret roaming
	phase     roamPhase
	posX      float64
	posY      float64
	targetX   float64
	targetY   float64
	facingR   bool
	runFrame  int
	sniffTime int
	foundTime int

	// stage dimensions (in chars)
	stageW int
	stageH int

	// footprints
	footprints []footprint

	// alerts
	alertText string
	alertTime int

	// animation
	tickCount int

	// detection count tracking
	lastDetCount int

	// done flag
	done bool

	// progress bar component
	progressBar progress.Model
}

func NewScanningModel() ScanningModel {
	prog := progress.New(
		progress.WithGradient(string(ColorAccentDim), string(ColorAccent)),
		progress.WithoutPercentage(),
	)

	return ScanningModel{
		stageW:  52,
		stageH:  10,
		posX:    5,
		posY:    4,
		targetX: 5,
		targetY: 4,
		facingR: true,
		phase:   roamIdle,
		progress: scan.Progress{
			Step:     0,
			Total:    8,
			StepName: "Initializing...",
		},
		startTime:   time.Now(),
		progressBar: prog,
	}
}

func (m ScanningModel) Init() tea.Cmd {
	return nil
}

func (m ScanningModel) Update(msg tea.Msg) (ScanningModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateStageDimensions()

	case tickMsg:
		m.tickCount++
		m = m.updateRoaming()
		m = m.updateAlerts()

	case progressMsg:
		m.progress = scan.Progress(msg)
		if m.progress.Done {
			m.done = true
			m.phase = roamDone
		}
	case detectionMsg:
		m.detections = int(msg)
		if m.detections > m.lastDetCount {
			m.lastDetCount = m.detections
			m.phase = roamFound
			m.foundTime = 0
			m.alertText = fmt.Sprintf("! %d detected", m.detections)
			m.alertTime = 20
		}
	}

	// Forward to progress bar for animation
	var cmd tea.Cmd
	var progModel tea.Model
	progModel, cmd = m.progressBar.Update(msg)
	m.progressBar = progModel.(progress.Model)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// Fixed overhead lines outside of stage area:
// header(1) + separator(1) + blank(1) + step(1) + bar(1) + blank(1) + [stage] + blank(1) + steps(1) + det(1) = 9
const scanOverhead = 9

func (m *ScanningModel) updateStageDimensions() {
	m.stageW = m.width - 4
	if m.stageW > 70 {
		m.stageW = 70
	}
	if m.stageW < 30 {
		m.stageW = 30
	}
	m.stageH = m.height - scanOverhead
	if m.stageH > 14 {
		m.stageH = 14
	}
	if m.stageH < 4 {
		m.stageH = 4
	}
}

// updateRoaming handles the ferret movement state machine.
func (m ScanningModel) updateRoaming() ScanningModel {
	switch m.phase {
	case roamIdle:
		m.targetX = float64(4 + rand.Intn(max(m.stageW-8, 1)))
		m.targetY = float64(2 + rand.Intn(max(m.stageH-4, 1)))
		m.phase = roamRunning
		m.addFootprint(int(m.posX), int(m.posY))

	case roamRunning:
		if m.tickCount%3 == 0 {
			m.runFrame = 1 - m.runFrame
		}
		dx := m.targetX - m.posX
		dy := m.targetY - m.posY
		dist := abs(dx) + abs(dy)
		if dist < 1.5 {
			m.posX = m.targetX
			m.posY = m.targetY
			m.phase = roamSniffing
			m.sniffTime = 0
		} else {
			speed := 1.2
			if dist > 0 {
				m.posX += (dx / dist) * speed
				m.posY += (dy / dist) * speed
			}
			m.facingR = dx > 0
		}

	case roamSniffing:
		m.sniffTime++
		if m.sniffTime > 8+rand.Intn(10) {
			m.phase = roamIdle
		}

	case roamFound:
		m.foundTime++
		if m.foundTime > 15 {
			m.phase = roamIdle
		}

	case roamDone:
		centerX := float64(m.stageW / 2)
		centerY := float64(m.stageH / 2)
		dx := centerX - m.posX
		dy := centerY - m.posY
		dist := abs(dx) + abs(dy)
		if dist > 1.5 {
			speed := 1.0
			m.posX += (dx / dist) * speed
			m.posY += (dy / dist) * speed
		}
	}

	// Expire old footprints
	now := time.Now()
	alive := m.footprints[:0]
	for _, fp := range m.footprints {
		if now.Sub(fp.created) < 5*time.Second {
			alive = append(alive, fp)
		}
	}
	m.footprints = alive

	return m
}

func (m *ScanningModel) addFootprint(x, y int) {
	m.footprints = append(m.footprints, footprint{x: x, y: y, created: time.Now()})
	if len(m.footprints) > 15 {
		m.footprints = m.footprints[1:]
	}
}

func (m ScanningModel) updateAlerts() ScanningModel {
	if m.alertTime > 0 {
		m.alertTime--
	}
	return m
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// View builds a fixed-height output that never exceeds m.height lines.
func (m ScanningModel) View() string {
	w := m.width
	if w < 40 {
		w = 80
	}
	h := m.height
	if h < 20 {
		h = 20
	}

	// Build output as fixed-height line array
	lines := make([]string, 0, h)

	// Line 1: Header
	elapsed := formatDuration(time.Since(m.startTime))
	left := TitleStyle.Render("  SCANNING")
	right := HintStyle.Render("Elapsed: " + elapsed + "  ")
	spacerW := w - lipgloss.Width(left) - lipgloss.Width(right)
	if spacerW < 1 {
		spacerW = 1
	}
	lines = append(lines, left+strings.Repeat(" ", spacerW)+right)

	// Line 2: Separator
	lines = append(lines, SeparatorStyle.Render(strings.Repeat("─", w)))

	// Line 3: Blank
	lines = append(lines, "")

	// Line 4: Step info
	stepInfo := fmt.Sprintf("  Step %d/%d: %s", m.progress.Step, m.progress.Total, m.progress.StepName)
	lines = append(lines, lipgloss.NewStyle().Foreground(ColorText).Render(stepInfo))

	// Line 5: Progress bar
	barWidth := w - 16
	if barWidth < 20 {
		barWidth = 20
	}
	if barWidth > 60 {
		barWidth = 60
	}
	m.progressBar.Width = barWidth
	pct := float64(m.progress.Percent) / 100.0
	if pct > 1 {
		pct = 1
	}
	lines = append(lines, "  "+m.progressBar.ViewAs(pct)+fmt.Sprintf("  %d%%", m.progress.Percent))

	// Line 6: Blank
	lines = append(lines, "")

	// Lines 7..7+stageH-1: Stage content (no border wrapping)
	stageLines := strings.Split(m.renderStage(), "\n")
	lines = append(lines, stageLines...)

	// Blank after stage
	lines = append(lines, "")

	// Step indicators
	steps := m.renderStepIndicators()
	lines = append(lines, lipgloss.PlaceHorizontal(w, lipgloss.Center, steps))

	// Detection count
	detLine := m.renderDetectionCount()
	lines = append(lines, lipgloss.PlaceHorizontal(w, lipgloss.Center, detLine))

	// Pad to exact height (screen never shifts)
	for len(lines) < h {
		lines = append(lines, "")
	}
	// Truncate if somehow too tall
	if len(lines) > h {
		lines = lines[:h]
	}

	return strings.Join(lines, "\n")
}

func (m ScanningModel) renderStage() string {
	// Build a plain rune grid (no ANSI codes)
	bg := make([][]rune, m.stageH)
	for y := 0; y < m.stageH; y++ {
		bg[y] = make([]rune, m.stageW)
		for x := 0; x < m.stageW; x++ {
			bg[y][x] = ' '
		}
	}

	// Place footprints
	for _, fp := range m.footprints {
		if fp.x >= 0 && fp.x < m.stageW && fp.y >= 0 && fp.y < m.stageH {
			bg[fp.y][fp.x] = '·'
		}
	}

	// Determine ferret pose
	var pose string
	switch m.phase {
	case roamRunning:
		if m.runFrame == 0 {
			pose = PoseRun1
		} else {
			pose = PoseRun2
		}
	case roamSniffing:
		pose = PoseSniff
	case roamFound:
		pose = PoseFound
	case roamDone:
		pose = PoseHappy
	default:
		pose = PoseIdle
	}

	// Render ferret sprite
	var ferretArt string
	if m.facingR {
		ferretArt = RenderPose(pose)
	} else {
		ferretArt = RenderPoseFlipped(pose)
	}

	pw, ph := PoseSize(pose)
	fx := int(m.posX)
	fy := int(m.posY)

	// Clamp to stage bounds
	if fx < 0 {
		fx = 0
	}
	if fx+pw > m.stageW {
		fx = m.stageW - pw
	}
	if fy < 0 {
		fy = 0
	}
	if fy+ph > m.stageH {
		fy = m.stageH - ph
	}
	// Ensure fy doesn't go negative after clamp
	if fy < 0 {
		fy = 0
	}

	ferretLines := strings.Split(ferretArt, "\n")
	footprintStyle := lipgloss.NewStyle().Foreground(ColorTextMuted)

	// Compose lines: bg-prefix + ferret-line + bg-suffix
	lines := make([]string, m.stageH)
	for y := 0; y < m.stageH; y++ {
		ferretIdx := y - fy
		if ferretIdx >= 0 && ferretIdx < len(ferretLines) && ferretIdx < ph {
			prefix := styleBgRunes(bg[y][:fx], footprintStyle)
			suffix := ""
			afterFerret := fx + pw
			if afterFerret < m.stageW {
				suffix = styleBgRunes(bg[y][afterFerret:], footprintStyle)
			}
			lines[y] = prefix + ferretLines[ferretIdx] + suffix
		} else {
			lines[y] = styleBgRunes(bg[y], footprintStyle)
		}
	}

	// Alert overlay
	if m.alertTime > 0 && m.alertText != "" {
		alertRow := fy - 1
		if alertRow < 0 {
			alertRow = 0
		}
		if alertRow < m.stageH {
			alert := AlertStyle.Render(m.alertText)
			alertX := fx + pw + 1
			if alertX+len(m.alertText) < m.stageW {
				// Rebuild line with alert
				prefix := styleBgRunes(bg[alertRow][:alertX], footprintStyle)
				lines[alertRow] = prefix + alert
			}
		}
	}

	return strings.Join(lines, "\n")
}

// styleBgRunes converts a rune slice into a styled string (footprints as dim dots).
func styleBgRunes(runes []rune, dotStyle lipgloss.Style) string {
	var b strings.Builder
	for _, r := range runes {
		if r == '·' {
			b.WriteString(dotStyle.Render("·"))
		} else {
			b.WriteRune(' ')
		}
	}
	return b.String()
}

func (m ScanningModel) renderStepIndicators() string {
	var parts []string
	for i := 0; i < 8; i++ {
		step := i + 1
		name := stepNames[i]
		if step < m.progress.Step {
			parts = append(parts, StepDone.Render("  "+name))
		} else if step == m.progress.Step {
			parts = append(parts, StepActive.Render(" "+name))
		} else {
			parts = append(parts, StepPending.Render("  "+name))
		}
	}
	return strings.Join(parts, " ")
}

func (m ScanningModel) renderDetectionCount() string {
	if m.detections == 0 {
		return HintStyle.Render("Detections: 0")
	}
	return lipgloss.NewStyle().Foreground(ColorHigh).Render(
		fmt.Sprintf("Detections: %d", m.detections),
	)
}

func formatDuration(d time.Duration) string {
	min := int(d.Minutes())
	sec := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", min, sec)
}

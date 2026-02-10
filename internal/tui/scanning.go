package tui

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

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

// ScanningModel represents the scan-in-progress screen with ferret roaming animation.
type ScanningModel struct {
	width, height int

	// scan progress (from channel)
	progress   scan.Progress
	startTime  time.Time
	detections int

	// ferret roaming
	phase     roamPhase
	posX      float64 // current position (fractional)
	posY      float64
	targetX   float64
	targetY   float64
	facingR   bool // true = facing right
	runFrame  int  // 0 or 1
	sniffTime int  // ticks spent sniffing
	foundTime int  // ticks spent in found pose

	// stage dimensions (in chars)
	stageW int
	stageH int

	// footprints
	footprints []footprint

	// alerts to show
	alertText string
	alertTime int // ticks remaining

	// animation
	tickCount int

	// detection count tracking
	lastDetCount int

	// done flag
	done bool
}

func NewScanningModel() ScanningModel {
	return ScanningModel{
		stageW:    52,
		stageH:    10,
		posX:      5,
		posY:      4,
		targetX:   5,
		targetY:   4,
		facingR:   true,
		phase:     roamIdle,
		startTime: time.Now(),
	}
}

func (m ScanningModel) Init() tea.Cmd {
	return nil
}

func (m ScanningModel) Update(msg tea.Msg) (ScanningModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.tickCount++
		m = m.updateRoaming()
		m = m.updateAlerts()

	case progressMsg:
		m.progress = scan.Progress(msg)
		// Count detections
		if m.progress.Done {
			m.done = true
			m.phase = roamDone
		}
	case detectionMsg:
		m.detections = int(msg)
		if m.detections > m.lastDetCount {
			m.lastDetCount = m.detections
			// Trigger found pose
			m.phase = roamFound
			m.foundTime = 0
			m.alertText = fmt.Sprintf("! %d detected", m.detections)
			m.alertTime = 20 // 2 seconds at 10fps
		}
	}
	return m, nil
}

// updateRoaming handles the ferret movement state machine.
func (m ScanningModel) updateRoaming() ScanningModel {
	switch m.phase {
	case roamIdle:
		// Pick a random target and start running
		m.targetX = float64(4 + rand.Intn(m.stageW-8))
		m.targetY = float64(2 + rand.Intn(m.stageH-4))
		m.phase = roamRunning
		// Leave footprint at start
		m.addFootprint(int(m.posX), int(m.posY))

	case roamRunning:
		// Alternate run frames every 3 ticks (300ms)
		if m.tickCount%3 == 0 {
			m.runFrame = 1 - m.runFrame
		}
		// Move toward target
		dx := m.targetX - m.posX
		dy := m.targetY - m.posY
		dist := abs(dx) + abs(dy)
		if dist < 1.5 {
			// Arrived — switch to sniffing
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
		// Sniff for 8-18 ticks (800-1800ms)
		if m.sniffTime > 8+rand.Intn(10) {
			m.phase = roamIdle
		}

	case roamFound:
		m.foundTime++
		if m.foundTime > 15 { // 1.5 seconds
			m.phase = roamIdle
		}

	case roamDone:
		// Move to center for happy pose
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

func (m ScanningModel) View() string {
	w := m.width
	if w < 40 {
		w = 60
	}

	var b strings.Builder

	// Header
	elapsed := time.Since(m.startTime)
	header := fmt.Sprintf("  SCANNING...%sElapsed: %s",
		strings.Repeat(" ", 30),
		formatDuration(elapsed),
	)
	b.WriteString(TitleStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDimGray).Render(strings.Repeat("═", w)))
	b.WriteString("\n\n")

	// Step info + progress bar
	stepInfo := fmt.Sprintf("  Step %d/%d: %s", m.progress.Step, m.progress.Total, m.progress.StepName)
	b.WriteString(lipgloss.NewStyle().Foreground(ColorWhite).Render(stepInfo))
	b.WriteString("\n")
	bar := "  " + RenderProgressBar(m.progress.Percent, 30) + fmt.Sprintf("  %d%%", m.progress.Percent)
	b.WriteString(bar)
	b.WriteString("\n\n")

	// Scan stage with ferret
	stage := m.renderStage()
	stageBox := StageStyle.Render(stage)
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, stageBox))
	b.WriteString("\n\n")

	// Step indicators
	steps := m.renderStepIndicators()
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, steps))
	b.WriteString("\n")

	// Detection count
	detLine := m.renderDetectionCount()
	b.WriteString(lipgloss.PlaceHorizontal(w, lipgloss.Center, detLine))
	b.WriteString("\n")

	return b.String()
}

func (m ScanningModel) renderStage() string {
	// Build a char grid for the stage
	grid := make([][]rune, m.stageH)
	for y := 0; y < m.stageH; y++ {
		grid[y] = make([]rune, m.stageW)
		for x := 0; x < m.stageW; x++ {
			grid[y][x] = ' '
		}
	}

	// Place footprints
	for _, fp := range m.footprints {
		if fp.x >= 0 && fp.x < m.stageW && fp.y >= 0 && fp.y < m.stageH {
			grid[fp.y][fp.x] = '·'
		}
	}

	// Convert grid to string lines
	lines := make([]string, m.stageH)
	for y := 0; y < m.stageH; y++ {
		lines[y] = string(grid[y])
	}

	// Determine ferret pose and render
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

	// Get pose dimensions
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

	// Overlay ferret art onto the stage lines
	ferretLines := strings.Split(ferretArt, "\n")
	for i, fl := range ferretLines {
		row := fy + i
		if row >= 0 && row < m.stageH {
			// Place ferret line at position fx
			prefix := ""
			if fx > 0 {
				if fx < len(lines[row]) {
					prefix = lines[row][:fx]
				} else {
					prefix = lines[row] + strings.Repeat(" ", fx-len(lines[row]))
				}
			}
			suffix := ""
			afterFerret := fx + pw
			if afterFerret < m.stageW {
				if afterFerret < len(lines[row]) {
					suffix = lines[row][afterFerret:]
				}
			}
			lines[row] = prefix + fl + suffix
		}
	}

	// Add alert text if active
	if m.alertTime > 0 && m.alertText != "" {
		alertRow := fy - 1
		if alertRow < 0 {
			alertRow = 0
		}
		if alertRow < m.stageH {
			alert := AlertStyle.Render(m.alertText)
			alertX := fx + pw + 1
			if alertX < m.stageW-len(m.alertText) {
				if alertX < len(lines[alertRow]) {
					lines[alertRow] = lines[alertRow][:alertX] + alert
				}
			}
		}
	}

	return strings.Join(lines, "\n")
}

func (m ScanningModel) renderStepIndicators() string {
	var parts []string
	for i := 1; i <= 8; i++ {
		if i < m.progress.Step {
			parts = append(parts, StepDone.Render(fmt.Sprintf("✓%d", i)))
		} else if i == m.progress.Step {
			parts = append(parts, StepActive.Render(fmt.Sprintf("▶%d", i)))
		} else {
			parts = append(parts, StepPending.Render(fmt.Sprintf("○%d", i)))
		}
	}
	return strings.Join(parts, " ")
}

func (m ScanningModel) renderDetectionCount() string {
	if m.detections == 0 {
		return HintStyle.Render("Detections: 0")
	}
	return lipgloss.NewStyle().Foreground(ColorYellow).Render(
		fmt.Sprintf("Detections: %d", m.detections),
	)
}

func formatDuration(d time.Duration) string {
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", m, s)
}

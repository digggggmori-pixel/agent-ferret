package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// pixel represents a single pixel with foreground color.
// Background is always transparent (empty string = no pixel).
type pixel struct {
	color string // hex color, e.g. "#b8834e"; empty = transparent
}

// ── Ferret Color Palette (from ferretPixelArt.js) ──

const (
	cBody     = "#b8834e"
	cBodyDk   = "#9a6b38"
	cBelly    = "#e8d0a8"
	cMask     = "#3a2010"
	cEye      = "#00ffff"
	cEyeHi    = "#ffffff"
	cNose     = "#ff69b4"
	cBlush    = "#ff8888"
	cHandle   = "#8B7355"
	cHandleDk = "#6b5535"
	cRim      = "#d0d0d0"
	cRimHi    = "#f0f0f0"
	cLens     = "#7ab8e8"
	cLensHi   = "#a8dbff"
	cGlint    = "#ffffff"
	cAlert    = "#00ffff"
	cSpark1   = "#00ffff"
	cSpark2   = "#ff69b4"
	cZzz      = "#6a7080"
)

// pixelSpec is [x, y, color] from JS data
type pixelSpec struct {
	x, y  int
	color string
}

// magGlass returns 5x5 magnifying glass pixels at offset (ox, oy)
func magGlass(ox, oy int) []pixelSpec {
	return []pixelSpec{
		{ox + 1, oy, cRimHi}, {ox + 2, oy, cRimHi}, {ox + 3, oy, cRim},
		{ox, oy + 1, cRim}, {ox + 4, oy + 1, cRim},
		{ox, oy + 2, cRim}, {ox + 4, oy + 2, cRim},
		{ox, oy + 3, cRim}, {ox + 4, oy + 3, cRim},
		{ox + 1, oy + 4, cRim}, {ox + 2, oy + 4, cRim}, {ox + 3, oy + 4, cRim},
		{ox + 1, oy + 1, cGlint}, {ox + 2, oy + 1, cLensHi}, {ox + 3, oy + 1, cLensHi},
		{ox + 1, oy + 2, cLensHi}, {ox + 2, oy + 2, cLensHi}, {ox + 3, oy + 2, cLens},
		{ox + 1, oy + 3, cLens}, {ox + 2, oy + 3, cLens}, {ox + 3, oy + 3, cLens},
	}
}

// ── Pose Data (ported from ferretPixelArt.js) ──

func idlePixels() []pixelSpec {
	ps := []pixelSpec{
		{8, 0, cBody}, {9, 0, cBelly}, {12, 0, cBelly}, {13, 0, cBody},
		{7, 1, cBody}, {8, 1, cBody}, {9, 1, cBody}, {10, 1, cBody}, {11, 1, cBody}, {12, 1, cBody}, {13, 1, cBody}, {14, 1, cBody},
		{7, 2, cBody}, {8, 2, cMask}, {9, 2, cEyeHi}, {10, 2, cEye}, {11, 2, cMask}, {12, 2, cEyeHi}, {13, 2, cEye}, {14, 2, cBody},
		{7, 3, cBody}, {8, 3, cMask}, {9, 3, cEye}, {10, 3, cEye}, {11, 3, cMask}, {12, 3, cEye}, {13, 3, cEye}, {14, 3, cBody},
		{7, 4, cBody}, {8, 4, cBlush}, {9, 4, cBody}, {10, 4, cNose}, {11, 4, cBody}, {12, 4, cBody}, {13, 4, cBlush}, {14, 4, cBody},
		{8, 5, cBody}, {9, 5, cBelly}, {10, 5, cBelly}, {11, 5, cBelly}, {12, 5, cBelly}, {13, 5, cBody},
		{8, 6, cBody}, {9, 6, cBody}, {10, 6, cBelly}, {11, 6, cBelly}, {12, 6, cBody}, {13, 6, cBody},
		{9, 7, cBody}, {10, 7, cBelly}, {11, 7, cBody}, {12, 7, cBody},
		{8, 8, cBodyDk}, {9, 8, cBodyDk}, {11, 8, cBodyDk}, {12, 8, cBodyDk},
		// tail
		{13, 6, cBody}, {14, 5, cBody}, {15, 4, cBody}, {15, 3, cBodyDk},
		// handle
		{5, 6, cHandle}, {6, 7, cHandle}, {7, 8, cHandleDk},
	}
	ps = append(ps, magGlass(0, 2)...)
	return ps
}

func sniffPixels() []pixelSpec {
	ps := []pixelSpec{
		{5, 4, cHandle}, {6, 5, cHandle},
		{9, 0, cBody}, {10, 0, cBelly}, {13, 0, cBelly}, {14, 0, cBody},
		{8, 1, cBody}, {9, 1, cBody}, {10, 1, cBody}, {11, 1, cBody}, {12, 1, cBody}, {13, 1, cBody}, {14, 1, cBody}, {15, 1, cBody},
		{8, 2, cBody}, {9, 2, cMask}, {10, 2, cEyeHi}, {11, 2, cEye}, {12, 2, cMask}, {13, 2, cEyeHi}, {14, 2, cEye}, {15, 2, cBody},
		{8, 3, cBody}, {9, 3, cMask}, {10, 3, cEye}, {11, 3, cEye}, {12, 3, cMask}, {13, 3, cEye}, {14, 3, cEye}, {15, 3, cBody},
		{8, 4, cBody}, {9, 4, cBlush}, {10, 4, cBody}, {11, 4, cNose}, {12, 4, cBody}, {13, 4, cBody}, {14, 4, cBlush}, {15, 4, cBody},
		{7, 5, cBodyDk}, {8, 5, cBody},
		{9, 5, cBody}, {10, 5, cBelly}, {11, 5, cBelly}, {12, 5, cBelly}, {13, 5, cBody},
		{9, 6, cBody}, {10, 6, cBody}, {11, 6, cBelly}, {12, 6, cBelly}, {13, 6, cBody}, {14, 6, cBody},
		{10, 7, cBody}, {11, 7, cBelly}, {12, 7, cBody}, {13, 7, cBody},
		{9, 8, cBodyDk}, {10, 8, cBodyDk}, {12, 8, cBodyDk}, {13, 8, cBodyDk},
		// tail
		{14, 5, cBody}, {15, 4, cBody}, {16, 3, cBody}, {16, 2, cBodyDk},
	}
	ps = append(ps, magGlass(0, 0)...)
	return ps
}

func runFrame1Pixels() []pixelSpec {
	return []pixelSpec{
		{5, 0, cBody}, {6, 0, cBelly},
		{4, 1, cBody}, {5, 1, cBody}, {6, 1, cBody}, {7, 1, cBody}, {8, 1, cBody},
		{4, 2, cBody}, {5, 2, cMask}, {6, 2, cEyeHi}, {7, 2, cEye}, {8, 2, cBody},
		{4, 3, cBody}, {5, 3, cNose}, {6, 3, cBody}, {7, 3, cBody}, {8, 3, cBody}, {9, 3, cBody},
		{5, 4, cBody}, {6, 4, cBelly}, {7, 4, cBelly}, {8, 4, cBelly}, {9, 4, cBody}, {10, 4, cBody},
		{5, 5, cBody}, {6, 5, cBelly}, {7, 5, cBelly}, {8, 5, cBelly}, {9, 5, cBody}, {10, 5, cBody}, {11, 5, cBody},
		// legs
		{3, 6, cBodyDk}, {4, 6, cBodyDk}, {9, 6, cBodyDk},
		// tail
		{11, 4, cBody}, {12, 3, cBody}, {12, 2, cBodyDk},
		// small magnifying glass
		{9, 1, cRim}, {10, 1, cRim},
		{8, 2, cRim}, {11, 2, cRim},
		{9, 2, cLens}, {10, 2, cLensHi},
		{9, 3, cRim}, {10, 3, cRim},
		{9, 1, cGlint},
		{8, 3, cHandle},
	}
}

func runFrame2Pixels() []pixelSpec {
	return []pixelSpec{
		{5, 0, cBody}, {6, 0, cBelly},
		{4, 1, cBody}, {5, 1, cBody}, {6, 1, cBody}, {7, 1, cBody}, {8, 1, cBody},
		{4, 2, cBody}, {5, 2, cMask}, {6, 2, cEyeHi}, {7, 2, cEye}, {8, 2, cBody},
		{4, 3, cBody}, {5, 3, cNose}, {6, 3, cBody}, {7, 3, cBody}, {8, 3, cBody}, {9, 3, cBody},
		{5, 4, cBody}, {6, 4, cBelly}, {7, 4, cBelly}, {8, 4, cBelly}, {9, 4, cBody}, {10, 4, cBody},
		{5, 5, cBody}, {6, 5, cBelly}, {7, 5, cBelly}, {8, 5, cBelly}, {9, 5, cBody}, {10, 5, cBody}, {11, 5, cBody},
		// legs (different from frame1)
		{5, 6, cBodyDk}, {9, 6, cBodyDk}, {10, 6, cBodyDk},
		// tail (slightly different)
		{11, 4, cBody}, {12, 4, cBody}, {12, 3, cBodyDk},
		// small magnifying glass
		{9, 1, cRim}, {10, 1, cRim},
		{8, 2, cRim}, {11, 2, cRim},
		{9, 2, cLens}, {10, 2, cLensHi},
		{9, 3, cRim}, {10, 3, cRim},
		{9, 1, cGlint},
		{8, 3, cHandle},
	}
}

func foundPixels() []pixelSpec {
	ps := []pixelSpec{
		// alert indicator
		{10, 0, cAlert}, {10, 1, cAlert}, {10, 2, cAlert},
		{10, 4, cAlert},
		// ears
		{8, 5, cBody}, {9, 5, cBelly}, {12, 5, cBelly}, {13, 5, cBody},
		// head
		{7, 6, cBody}, {8, 6, cBody}, {9, 6, cBody}, {10, 6, cBody}, {11, 6, cBody}, {12, 6, cBody}, {13, 6, cBody}, {14, 6, cBody},
		{7, 7, cBody}, {8, 7, cMask}, {9, 7, cEyeHi}, {10, 7, cEye}, {11, 7, cMask}, {12, 7, cEyeHi}, {13, 7, cEye}, {14, 7, cBody},
		{7, 8, cBody}, {8, 8, cMask}, {9, 8, cEye}, {10, 8, cEye}, {11, 8, cMask}, {12, 8, cEye}, {13, 8, cEye}, {14, 8, cBody},
		// face
		{7, 9, cBody}, {8, 9, cBlush}, {9, 9, cBody}, {10, 9, cNose}, {11, 9, cBody}, {12, 9, cBody}, {13, 9, cBlush}, {14, 9, cBody},
		// body
		{8, 10, cBody}, {9, 10, cBelly}, {10, 10, cBelly}, {11, 10, cBelly}, {12, 10, cBelly}, {13, 10, cBody},
		{8, 11, cBody}, {9, 11, cBody}, {10, 11, cBelly}, {11, 11, cBelly}, {12, 11, cBody}, {13, 11, cBody},
		// feet
		{8, 12, cBodyDk}, {9, 12, cBodyDk}, {11, 12, cBodyDk}, {12, 12, cBodyDk},
		// tail
		{13, 10, cBody}, {14, 9, cBody}, {15, 8, cBodyDk},
		// handle
		{5, 7, cHandle}, {6, 8, cHandle}, {7, 9, cHandleDk},
	}
	ps = append(ps, magGlass(0, 3)...)
	return ps
}

func happyPixels() []pixelSpec {
	ps := []pixelSpec{
		// sparkles
		{1, 0, cSpark1}, {14, 1, cSpark2}, {0, 5, cSpark1}, {15, 4, cSpark2}, {2, 9, cSpark1},
		// ears
		{8, 1, cBody}, {9, 1, cBelly}, {12, 1, cBelly}, {13, 1, cBody},
		// head
		{7, 2, cBody}, {8, 2, cBody}, {9, 2, cBody}, {10, 2, cBody}, {11, 2, cBody}, {12, 2, cBody}, {13, 2, cBody}, {14, 2, cBody},
		// closed eyes (happy expression)
		{7, 3, cBody}, {8, 3, cMask}, {9, 3, cBody}, {10, 3, cBody}, {11, 3, cMask}, {12, 3, cBody}, {13, 3, cBody}, {14, 3, cMask},
		// face
		{7, 4, cBody}, {8, 4, cBlush}, {9, 4, cBody}, {10, 4, cNose}, {11, 4, cBody}, {12, 4, cBody}, {13, 4, cBlush}, {14, 4, cBody},
		// body
		{8, 5, cBody}, {9, 5, cBelly}, {10, 5, cBelly}, {11, 5, cBelly}, {12, 5, cBelly}, {13, 5, cBody},
		{7, 6, cBody}, {8, 6, cBody}, {9, 6, cBelly}, {10, 6, cBelly}, {11, 6, cBelly}, {12, 6, cBody}, {13, 6, cBody},
		{8, 7, cBody}, {9, 7, cBelly}, {10, 7, cBelly}, {11, 7, cBody}, {12, 7, cBody},
		// feet
		{8, 8, cBodyDk}, {9, 8, cBodyDk}, {11, 8, cBodyDk}, {12, 8, cBodyDk},
		// tail
		{13, 6, cBody}, {14, 5, cBody}, {14, 4, cBodyDk},
		// handle
		{5, 7, cHandle}, {6, 8, cHandle}, {7, 8, cHandleDk},
	}
	ps = append(ps, magGlass(0, 3)...)
	return ps
}

func sleepPixels() []pixelSpec {
	ps := []pixelSpec{
		// zzZ
		{10, 0, cZzz}, {11, 0, cZzz}, {12, 0, cZzz},
		{12, 1, cZzz},
		{11, 2, cZzz},
		{10, 3, cZzz}, {11, 3, cZzz}, {12, 3, cZzz},
		{13, 1, cZzz}, {14, 1, cZzz},
		{14, 2, cZzz},
		{13, 3, cZzz}, {14, 3, cZzz},
		// head
		{3, 5, cBody}, {4, 5, cBody},
		{3, 6, cMask}, {4, 6, cBody},
		{3, 7, cNose},
		// body
		{5, 4, cBody}, {6, 4, cBody}, {7, 4, cBody}, {8, 4, cBody}, {9, 4, cBody}, {10, 4, cBody},
		{4, 5, cBody}, {5, 5, cBody}, {6, 5, cBelly}, {7, 5, cBelly}, {8, 5, cBelly}, {9, 5, cBody}, {10, 5, cBody}, {11, 5, cBody},
		{4, 6, cBody}, {5, 6, cBody}, {6, 6, cBelly}, {7, 6, cBelly}, {8, 6, cBelly}, {9, 6, cBody}, {10, 6, cBody}, {11, 6, cBody},
		{5, 7, cBody}, {6, 7, cBody}, {7, 7, cBody}, {8, 7, cBody}, {9, 7, cBody}, {10, 7, cBody},
		// tail
		{11, 5, cBody}, {12, 5, cBodyDk}, {12, 4, cBodyDk},
		// handle
		{13, 8, cHandle}, {13, 9, cHandle},
	}
	ps = append(ps, magGlass(13, 4)...)
	return ps
}

// ── Pose Registry ──

// Pose names
const (
	PoseIdle  = "idle"
	PoseSniff = "sniff"
	PoseRun1  = "run1"
	PoseRun2  = "run2"
	PoseFound = "found"
	PoseHappy = "happy"
	PoseSleep = "sleep"
)

// GetPosePixels returns the pixel data for a given pose name.
func GetPosePixels(pose string) []pixelSpec {
	switch pose {
	case PoseIdle:
		return idlePixels()
	case PoseSniff:
		return sniffPixels()
	case PoseRun1:
		return runFrame1Pixels()
	case PoseRun2:
		return runFrame2Pixels()
	case PoseFound:
		return foundPixels()
	case PoseHappy:
		return happyPixels()
	case PoseSleep:
		return sleepPixels()
	default:
		return idlePixels()
	}
}

// ── Half-Block Renderer ──
//
// Uses ▀ (upper half block) with fg=top pixel, bg=bottom pixel
// to render 2 vertical pixels per character cell.
// This gives us high-res pixel art in the terminal.

// Pose cache: avoid re-rendering identical pixel art every 100ms tick.
var (
	poseCache        = make(map[string]string)
	poseFlippedCache = make(map[string]string)
)

// RenderPose renders a ferret pose as a string using half-block characters.
// The result can be placed in a lipgloss layout.
func RenderPose(pose string) string {
	if cached, ok := poseCache[pose]; ok {
		return cached
	}
	pixels := GetPosePixels(pose)
	rendered := renderPixels(pixels)
	poseCache[pose] = rendered
	return rendered
}

// RenderPoseFlipped renders a ferret pose horizontally flipped.
func RenderPoseFlipped(pose string) string {
	if cached, ok := poseFlippedCache[pose]; ok {
		return cached
	}
	pixels := GetPosePixels(pose)
	// Find max X to flip
	maxX := 0
	for _, p := range pixels {
		if p.x > maxX {
			maxX = p.x
		}
	}
	flipped := make([]pixelSpec, len(pixels))
	for i, p := range pixels {
		flipped[i] = pixelSpec{x: maxX - p.x, y: p.y, color: p.color}
	}
	rendered := renderPixels(flipped)
	poseFlippedCache[pose] = rendered
	return rendered
}

func renderPixels(pixels []pixelSpec) string {
	if len(pixels) == 0 {
		return ""
	}

	// Find bounds
	maxX, maxY := 0, 0
	for _, p := range pixels {
		if p.x > maxX {
			maxX = p.x
		}
		if p.y > maxY {
			maxY = p.y
		}
	}
	w := maxX + 1
	h := maxY + 1

	// Build 2D grid
	grid := make([][]string, h)
	for y := 0; y < h; y++ {
		grid[y] = make([]string, w)
	}
	for _, p := range pixels {
		grid[p.y][p.x] = p.color
	}

	// Render using background-colored spaces.
	// Each pair of pixel rows (0,1), (2,3), etc. becomes one terminal row.
	// Uses space + background color instead of ▀/▄ half-blocks to avoid
	// East Asian Ambiguous width issues on CJK terminals (▀▄ may render
	// as 2 cells instead of 1, breaking layout).
	var lines []string
	for y := 0; y < h; y += 2 {
		var line strings.Builder
		for x := 0; x < w; x++ {
			top := grid[y][x]
			bottom := ""
			if y+1 < h {
				bottom = grid[y+1][x]
			}

			if top == "" && bottom == "" {
				line.WriteRune(' ')
			} else if top != "" && bottom != "" {
				// Both pixels: show top color as background
				style := lipgloss.NewStyle().Background(lipgloss.Color(top))
				line.WriteString(style.Render(" "))
			} else if top != "" {
				// Only top pixel
				style := lipgloss.NewStyle().Background(lipgloss.Color(top))
				line.WriteString(style.Render(" "))
			} else {
				// Only bottom pixel
				style := lipgloss.NewStyle().Background(lipgloss.Color(bottom))
				line.WriteString(style.Render(" "))
			}
		}
		lines = append(lines, line.String())
	}

	return strings.Join(lines, "\n")
}

// ── Pose Dimensions ──

// PoseSize returns the width (chars) and height (rows) of a rendered pose.
func PoseSize(pose string) (w, h int) {
	pixels := GetPosePixels(pose)
	maxX, maxY := 0, 0
	for _, p := range pixels {
		if p.x > maxX {
			maxX = p.x
		}
		if p.y > maxY {
			maxY = p.y
		}
	}
	w = maxX + 1
	h = (maxY + 2) / 2 // half-block = 2 pixels per row
	return
}

// ── Simple speech bubble ──

func SpeechBubble(text string) string {
	w := len(text) + 2
	top := "╭" + strings.Repeat("─", w) + "╮"
	mid := fmt.Sprintf("│ %s │", text)
	bot := "╰" + strings.Repeat("─", w) + "╯"
	pointer := strings.Repeat(" ", 3) + "╰──"
	return lipgloss.NewStyle().Foreground(ColorAccent).Render(
		strings.Join([]string{top, mid, bot, pointer}, "\n"),
	)
}

// Package scan provides the scan service that bridges Wails UI with collectors/detectors.
// Refactored from cmd/main.go runScan() - CLI output replaced with Wails event emission.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/collector"
	"github.com/digggggmori-pixel/agent-ferret/internal/detector"
	"github.com/digggggmori-pixel/agent-ferret/internal/sigma"
	"github.com/digggggmori-pixel/agent-ferret/internal/sigma/rules"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"github.com/google/uuid"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Service manages the scan lifecycle
type Service struct {
	ctx    context.Context
	config Config
}

// Progress represents scan progress sent to the frontend via events
type Progress struct {
	Step     int    `json:"step"`
	Total    int    `json:"total"`
	StepName string `json:"stepName"`
	Percent  int    `json:"percent"`
	Detail   string `json:"detail"`
	Done     bool   `json:"done"`
}

// NewService creates a new scan service
func NewService(ctx context.Context) *Service {
	return &Service{
		ctx:    ctx,
		config: DefaultConfig(),
	}
}

// IsAdmin checks if running with administrator privileges
func (s *Service) IsAdmin() bool {
	return collector.IsRunningAsAdmin()
}

// GetHostInfo returns host system information
func (s *Service) GetHostInfo() types.HostInfo {
	return collector.GetHostInfo()
}

// emitProgress sends a progress update to the frontend
func (s *Service) emitProgress(step int, name string, percent int, detail string) {
	wailsRuntime.EventsEmit(s.ctx, "scan:progress", Progress{
		Step:     step,
		Total:    8,
		StepName: name,
		Percent:  percent,
		Detail:   detail,
		Done:     false,
	})
}

// Execute runs the full 8-step scan pipeline.
// This is a direct refactoring of cmd/main.go runScan().
// Changes: CLI output → Wails events, all collector/detector calls unchanged.
func (s *Service) Execute() (*types.ScanResult, error) {
	startTime := time.Now()

	// Get host info
	hostInfo := collector.GetHostInfo()

	// Initialize result
	result := &types.ScanResult{
		AgentVersion: "1.0.0",
		ScanID:       uuid.New().String(),
		ScanTime:     startTime,
		Host:         hostInfo,
		Detections:   make([]types.Detection, 0),
	}

	// Initialize detector
	det := detector.New()

	// ── Step 1: Collect processes ──
	s.emitProgress(1, "프로세스 수집 중...", 0, "")
	processCollector := collector.NewProcessCollector()
	processes, err := processCollector.Collect()
	if err != nil {
		processes = []types.ProcessInfo{}
	}
	result.Summary.TotalProcesses = len(processes)
	s.emitProgress(1, "프로세스 수집 완료", 12, fmt.Sprintf("%d개 프로세스", len(processes)))

	// ── Step 2: Collect network connections ──
	s.emitProgress(2, "네트워크 연결 수집 중...", 12, "")
	networkCollector := collector.NewNetworkCollector()
	connections, err := networkCollector.Collect()
	if err != nil {
		connections = []types.NetworkConnection{}
	}
	result.Summary.TotalConnections = len(connections)
	s.emitProgress(2, "네트워크 연결 수집 완료", 25, fmt.Sprintf("%d개 연결", len(connections)))

	// ── Step 3: Collect services ──
	s.emitProgress(3, "서비스 수집 중...", 25, "")
	serviceCollector := collector.NewServiceCollector()
	services, err := serviceCollector.Collect()
	if err != nil {
		services = []types.ServiceInfo{}
	}
	result.Summary.TotalServices = len(services)
	s.emitProgress(3, "서비스 수집 완료", 37, fmt.Sprintf("%d개 서비스", len(services)))

	// ── Step 4: Scan registry ──
	s.emitProgress(4, "레지스트리 스캔 중...", 37, "19개 Persistence 키 검사")
	registryCollector := collector.NewRegistryCollector()
	registryCollector.Collect() // Entries used for persistence detection
	s.emitProgress(4, "레지스트리 스캔 완료", 50, "")

	// ── Step 5: Run detection engine (11 detectors) ──
	s.emitProgress(5, "탐지 엔진 실행 중...", 50, "12종 탐지 엔진")

	result.Detections = append(result.Detections, det.DetectLOLBins(processes)...)
	result.Detections = append(result.Detections, det.DetectChains(processes)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousPorts(connections)...)
	result.Detections = append(result.Detections, det.DetectPathAnomalies(processes)...)
	result.Detections = append(result.Detections, det.DetectTyposquatting(processes)...)
	result.Detections = append(result.Detections, det.DetectServiceVendorTyposquatting(services)...)
	result.Detections = append(result.Detections, det.DetectServiceNameTyposquatting(services)...)
	result.Detections = append(result.Detections, det.DetectServicePathAnomalies(services)...)
	result.Detections = append(result.Detections, det.DetectUnsignedCriticalProcesses(processes)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousDomains(connections)...)
	result.Detections = append(result.Detections, det.DetectEncodedCommands(processes)...)

	detCount := len(result.Detections)
	s.emitProgress(5, "탐지 엔진 완료", 62, fmt.Sprintf("%d건 탐지", detCount))

	// ── Step 6: Live Sigma matching ──
	s.emitProgress(6, "Sigma 룰 매칭 중...", 62, "")
	sigmaEngine, err := sigma.NewEngineWithRules(rules.EmbeddedRules)
	if err == nil {
		// Live process matching
		liveProcessMatches := sigma.ScanLiveProcesses(sigmaEngine, processes)
		for _, match := range liveProcessMatches {
			result.Detections = append(result.Detections, sigma.ConvertSigmaMatchToDetection(match, "live_process"))
		}

		// Live network matching
		processMap := sigma.BuildProcessMap(processes)
		liveNetworkMatches := sigma.ScanLiveNetwork(sigmaEngine, connections, processMap)
		for _, match := range liveNetworkMatches {
			result.Detections = append(result.Detections, sigma.ConvertSigmaMatchToDetection(match, "live_network"))
		}

		s.emitProgress(6, "Sigma 라이브 매칭 완료", 75,
			fmt.Sprintf("%d룰, 프로세스 %d건 + 네트워크 %d건",
				sigmaEngine.TotalRules(), len(liveProcessMatches), len(liveNetworkMatches)))
	} else {
		s.emitProgress(6, "Sigma 엔진 초기화 실패", 75, err.Error())
	}

	// ── Step 7: Event log Sigma scan ──
	s.emitProgress(7, "이벤트 로그 분석 중...", 75, "")
	if sigmaEngine != nil {
		progressCB := func(progress sigma.ScanProgress) {
			s.emitProgress(7, "이벤트 로그 분석 중...", 75,
				fmt.Sprintf("[%s] %d 이벤트, %d 매칭", progress.Channel, progress.Current, progress.Matches))
		}

		eventCollector := collector.NewEventLogCollector(
			collector.WithQuickMode(s.config.QuickMode),
			collector.WithProgress(progressCB),
		)

		accessibleChannels := collector.GetAccessibleChannels()
		if len(accessibleChannels) > 0 {
			sigmaDetections, err := eventCollector.Scan(sigmaEngine)
			if err == nil {
				result.Detections = append(result.Detections, sigmaDetections...)
				result.Summary.TotalEvents = int(eventCollector.TotalScanned())
			}
		}
	}
	s.emitProgress(7, "이벤트 로그 분석 완료", 87, "")

	// ── Step 8: Aggregate results ──
	s.emitProgress(8, "결과 집계 중...", 87, "")

	// Count by severity
	for _, d := range result.Detections {
		switch d.Severity {
		case types.SeverityCritical:
			result.Summary.Detections.Critical++
		case types.SeverityHigh:
			result.Summary.Detections.High++
		case types.SeverityMedium:
			result.Summary.Detections.Medium++
		case types.SeverityLow:
			result.Summary.Detections.Low++
		}
	}

	// Deduplicate
	result.Detections = deduplicateDetections(result.Detections)

	// Extract IOCs
	result.IOCs = det.ExtractIOCs(result)

	// Calculate duration
	result.ScanDurationMs = time.Since(startTime).Milliseconds()

	// Emit completion
	wailsRuntime.EventsEmit(s.ctx, "scan:progress", Progress{
		Step:     8,
		Total:    8,
		StepName: "스캔 완료",
		Percent:  100,
		Detail:   fmt.Sprintf("총 %d건 탐지, %.1f초 소요", len(result.Detections), time.Since(startTime).Seconds()),
		Done:     true,
	})

	return result, nil
}

// deduplicateDetections removes duplicate detections based on type+description+timestamp
func deduplicateDetections(detections []types.Detection) []types.Detection {
	seen := make(map[string]bool)
	result := make([]types.Detection, 0)

	for _, d := range detections {
		key := fmt.Sprintf("%s-%s-%s", d.Type, d.Description, d.Timestamp.Format(time.RFC3339))
		if !seen[key] {
			seen[key] = true
			result = append(result, d)
		}
	}

	return result
}

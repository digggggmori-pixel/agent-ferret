// Package scan provides the scan service that orchestrates collectors and detectors.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/collector"
	"github.com/digggggmori-pixel/agent-ferret/internal/detector"
	"github.com/digggggmori-pixel/agent-ferret/internal/rulestore"
	"github.com/digggggmori-pixel/agent-ferret/internal/sigma"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"github.com/google/uuid"
)

// Service manages the scan lifecycle
type Service struct {
	ctx        context.Context
	config     Config
	ruleStore  *rulestore.RuleStore
	progressCh chan Progress
}

// Progress represents scan progress sent via channel
type Progress struct {
	Step     int    `json:"step"`
	Total    int    `json:"total"`
	StepName string `json:"stepName"`
	Percent  int    `json:"percent"`
	Detail   string `json:"detail"`
	Done     bool   `json:"done"`
}

// NewService creates a new scan service (no progress channel).
func NewService(ctx context.Context, rs *rulestore.RuleStore) *Service {
	return &Service{
		ctx:       ctx,
		config:    DefaultConfig(),
		ruleStore: rs,
	}
}

// NewServiceWithChannel creates a new scan service with a progress channel for TUI.
func NewServiceWithChannel(ctx context.Context, rs *rulestore.RuleStore, ch chan Progress) *Service {
	return &Service{
		ctx:        ctx,
		config:     DefaultConfig(),
		ruleStore:  rs,
		progressCh: ch,
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

const totalSteps = 21

// emitProgress sends a progress update via channel (if set).
func (s *Service) emitProgress(step int, name string, percent int, detail string) {
	if s.progressCh != nil {
		s.progressCh <- Progress{
			Step:     step,
			Total:    totalSteps,
			StepName: name,
			Percent:  percent,
			Detail:   detail,
			Done:     false,
		}
	}
}

// Execute runs the full 21-step scan pipeline.
// Steps 1-10: Phase 1 snapshot collectors
// Steps 11-17: Phase 2 forensic collectors (DLL, Prefetch, Shimcache, Amcache, WMI, Browser, USB)
// Step 18: Detection engines (24 detectors)
// Steps 19-20: Sigma matching (live + event log)
// Step 21: Aggregation
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

	// Get rule bundle
	bundle := s.ruleStore.GetBundle()
	if bundle == nil {
		return nil, fmt.Errorf("rules not loaded: place rules.json next to ferret.exe")
	}

	// Initialize detector with loaded rules
	det := detector.New(bundle.Detection)

	// ── Step 1: Collect processes ──
	s.emitProgress(1, "Collecting processes...", 0, "")
	processCollector := collector.NewProcessCollector()
	processes, err := processCollector.Collect()
	if err != nil {
		processes = []types.ProcessInfo{}
	}
	result.Summary.TotalProcesses = len(processes)
	s.emitProgress(1, "Processes collected", 7, fmt.Sprintf("%d processes", len(processes)))

	// ── Step 2: Collect network connections ──
	s.emitProgress(2, "Collecting network connections...", 7, "")
	networkCollector := collector.NewNetworkCollector()
	connections, err := networkCollector.Collect()
	if err != nil {
		connections = []types.NetworkConnection{}
	}
	result.Summary.TotalConnections = len(connections)
	s.emitProgress(2, "Network connections collected", 14, fmt.Sprintf("%d connections", len(connections)))

	// ── Step 3: Collect services ──
	s.emitProgress(3, "Collecting services...", 14, "")
	serviceCollector := collector.NewServiceCollector()
	services, err := serviceCollector.Collect()
	if err != nil {
		services = []types.ServiceInfo{}
	}
	result.Summary.TotalServices = len(services)
	s.emitProgress(3, "Services collected", 21, fmt.Sprintf("%d services", len(services)))

	// ── Step 4: Scan registry ──
	s.emitProgress(4, "Scanning registry...", 21, "35 persistence keys")
	registryCollector := collector.NewRegistryCollector()
	registryCollector.Collect()
	s.emitProgress(4, "Registry scan complete", 28, "")

	// ── Step 5: Collect startup folder entries ──
	s.emitProgress(5, "Scanning startup folders...", 28, "")
	startupCollector := collector.NewStartupFolderCollector()
	startupEntries, err := startupCollector.Collect()
	if err != nil {
		startupEntries = []types.StartupEntry{}
	}
	s.emitProgress(5, "Startup folders scanned", 33, fmt.Sprintf("%d entries", len(startupEntries)))

	// ── Step 6: Collect PowerShell history ──
	s.emitProgress(6, "Reading PowerShell history...", 33, "")
	psHistoryCollector := collector.NewPowerShellHistoryCollector()
	psHistory, err := psHistoryCollector.Collect()
	if err != nil {
		psHistory = []types.PowerShellHistoryEntry{}
	}
	s.emitProgress(6, "PowerShell history collected", 38, fmt.Sprintf("%d commands", len(psHistory)))

	// ── Step 7: Collect DNS cache ──
	s.emitProgress(7, "Reading DNS cache...", 38, "")
	dnsCollector := collector.NewDNSCacheCollector()
	dnsEntries, err := dnsCollector.Collect()
	if err != nil {
		dnsEntries = []types.DNSCacheEntry{}
	}
	s.emitProgress(7, "DNS cache collected", 43, fmt.Sprintf("%d entries", len(dnsEntries)))

	// ── Step 8: Collect user accounts ──
	s.emitProgress(8, "Enumerating user accounts...", 43, "")
	userCollector := collector.NewUserAccountCollector()
	userAccounts, err := userCollector.Collect()
	if err != nil {
		userAccounts = []types.UserAccountInfo{}
	}
	s.emitProgress(8, "User accounts collected", 48, fmt.Sprintf("%d accounts", len(userAccounts)))

	// ── Step 9: Check antivirus status ──
	s.emitProgress(9, "Checking antivirus status...", 48, "")
	avCollector := collector.NewAntivirusCollector()
	avProducts, err := avCollector.Collect()
	if err != nil {
		avProducts = []types.AntivirusInfo{}
	}
	s.emitProgress(9, "Antivirus status checked", 53, fmt.Sprintf("%d products", len(avProducts)))

	// ── Step 10: Collect scheduled tasks ──
	s.emitProgress(10, "Collecting scheduled tasks...", 53, "")
	taskCollector := collector.NewScheduledTaskCollector()
	scheduledTasks, err := taskCollector.Collect()
	if err != nil {
		scheduledTasks = []types.ScheduledTaskInfo{}
	}
	s.emitProgress(10, "Scheduled tasks collected", 56, fmt.Sprintf("%d tasks", len(scheduledTasks)))

	// ── Step 11: Collect DLL modules ──
	s.emitProgress(11, "Collecting DLL modules...", 56, "")
	dllCollector := collector.NewDLLModuleCollector()
	dllModules, err := dllCollector.Collect(processes)
	if err != nil {
		dllModules = []types.DLLModuleInfo{}
	}
	s.emitProgress(11, "DLL modules collected", 59, fmt.Sprintf("%d modules", len(dllModules)))

	// ── Step 12: Parse Prefetch files ──
	s.emitProgress(12, "Parsing Prefetch files...", 59, "")
	prefetchCollector := collector.NewPrefetchCollector()
	prefetchEntries, err := prefetchCollector.Collect()
	if err != nil {
		prefetchEntries = []types.PrefetchInfo{}
	}
	s.emitProgress(12, "Prefetch files parsed", 62, fmt.Sprintf("%d files", len(prefetchEntries)))

	// ── Step 13: Parse Shimcache ──
	s.emitProgress(13, "Parsing Shimcache...", 62, "")
	shimcacheCollector := collector.NewShimcacheCollector()
	shimcacheEntries, err := shimcacheCollector.Collect()
	if err != nil {
		shimcacheEntries = []types.ShimcacheEntry{}
	}
	s.emitProgress(13, "Shimcache parsed", 64, fmt.Sprintf("%d entries", len(shimcacheEntries)))

	// ── Step 14: Parse Amcache ──
	s.emitProgress(14, "Parsing Amcache...", 64, "")
	amcacheCollector := collector.NewAmcacheCollector()
	amcacheEntries, err := amcacheCollector.Collect()
	if err != nil {
		amcacheEntries = []types.AmcacheEntry{}
	}
	s.emitProgress(14, "Amcache parsed", 66, fmt.Sprintf("%d entries", len(amcacheEntries)))

	// ── Step 15: Collect WMI persistence ──
	s.emitProgress(15, "Checking WMI persistence...", 66, "")
	wmiCollector := collector.NewWMIPersistenceCollector()
	wmiEntries, err := wmiCollector.Collect()
	if err != nil {
		wmiEntries = []types.WMIPersistenceInfo{}
	}
	s.emitProgress(15, "WMI persistence checked", 68, fmt.Sprintf("%d subscriptions", len(wmiEntries)))

	// ── Step 16: Collect browser history ──
	s.emitProgress(16, "Collecting browser history...", 68, "")
	browserCollector := collector.NewBrowserHistoryCollector()
	browserEntries, err := browserCollector.Collect()
	if err != nil {
		browserEntries = []types.BrowserHistoryEntry{}
	}
	s.emitProgress(16, "Browser history collected", 70, fmt.Sprintf("%d entries", len(browserEntries)))

	// ── Step 17: Collect USB history ──
	s.emitProgress(17, "Collecting USB history...", 70, "")
	usbCollector := collector.NewUSBHistoryCollector()
	usbDevices, err := usbCollector.Collect()
	if err != nil {
		usbDevices = []types.USBDeviceInfo{}
	}
	s.emitProgress(17, "USB history collected", 72, fmt.Sprintf("%d devices", len(usbDevices)))

	// ── Step 18: Run detection engines (24 detectors) ──
	s.emitProgress(18, "Running detection engines...", 72, "24 detection engines")

	// Original 11 detectors
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

	// Phase 1 detectors
	result.Detections = append(result.Detections, det.DetectSuspiciousStartup(startupEntries)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousPowerShell(psHistory)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousDNSCache(dnsEntries)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousAccounts(userAccounts)...)
	result.Detections = append(result.Detections, det.DetectAntivirusIssues(avProducts)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousScheduledTasks(scheduledTasks)...)

	// Phase 2 detectors
	result.Detections = append(result.Detections, det.DetectPrefetchAnomalies(prefetchEntries)...)
	result.Detections = append(result.Detections, det.DetectShimcacheAnomalies(shimcacheEntries)...)
	result.Detections = append(result.Detections, det.DetectAmcacheAnomalies(amcacheEntries)...)
	result.Detections = append(result.Detections, det.DetectDLLAnomalies(dllModules)...)
	result.Detections = append(result.Detections, det.DetectWMIPersistence(wmiEntries)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousBrowsing(browserEntries)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousUSB(usbDevices)...)

	detCount := len(result.Detections)
	s.emitProgress(18, "Detection engines complete", 78, fmt.Sprintf("%d detections", detCount))

	// ── Step 19: Live Sigma matching ──
	s.emitProgress(19, "Sigma rule matching...", 78, "")
	sigmaEngine := bundle.Sigma
	if sigmaEngine != nil {
		liveProcessResults := sigma.ScanLiveProcesses(sigmaEngine, processes)
		for _, r := range liveProcessResults {
			result.Detections = append(result.Detections, sigma.ConvertProcessSigmaMatch(r))
		}

		processMap := sigma.BuildProcessMap(processes)
		liveNetworkResults := sigma.ScanLiveNetwork(sigmaEngine, connections, processMap)
		for _, r := range liveNetworkResults {
			result.Detections = append(result.Detections, sigma.ConvertNetworkSigmaMatch(r))
		}

		s.emitProgress(19, "Sigma live matching complete", 84,
			fmt.Sprintf("%d rules, process %d + network %d",
				sigmaEngine.TotalRules(), len(liveProcessResults), len(liveNetworkResults)))
	}

	// ── Step 20: Event log Sigma scan ──
	s.emitProgress(20, "Analyzing event logs...", 84, "")
	if sigmaEngine != nil {
		progressCB := func(progress sigma.ScanProgress) {
			s.emitProgress(20, "Analyzing event logs...", 84,
				fmt.Sprintf("[%s] %d events, %d matches", progress.Channel, progress.Current, progress.Matches))
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
	s.emitProgress(20, "Event log analysis complete", 95, "")

	// ── Step 21: Aggregate results ──
	s.emitProgress(21, "Aggregating results...", 95, "")

	// Deduplicate FIRST, then count (fixes severity count mismatch bug)
	result.Detections = deduplicateDetections(result.Detections)

	// Enrich with user-friendly descriptions
	for i := range result.Detections {
		result.Detections[i].UserDescription = detector.GenerateUserDescription(&result.Detections[i])
		result.Detections[i].Recommendation = detector.GenerateRecommendation(&result.Detections[i])
	}

	// Count by severity (after dedup)
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
		case types.SeverityInfo:
			result.Summary.Detections.Informational++
		}
	}

	// Extract IOCs
	result.IOCs = det.ExtractIOCs(result)

	// Calculate duration
	result.ScanDurationMs = time.Since(startTime).Milliseconds()

	// Emit completion
	if s.progressCh != nil {
		s.progressCh <- Progress{
			Step:     totalSteps,
			Total:    totalSteps,
			StepName: "Scan complete",
			Percent:  100,
			Detail:   fmt.Sprintf("%d detections, %.1fs elapsed", len(result.Detections), time.Since(startTime).Seconds()),
			Done:     true,
		}
	}

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

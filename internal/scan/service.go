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

const totalSteps = 40

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

// Execute runs the full 40-step scan pipeline.
// Steps 1-10:  Phase 1 snapshot collectors
// Steps 11-17: Phase 2 forensic collectors
// Steps 18-36: Phase 3 collectors (driver, firewall, cert, share, arp, handle, bits, userassist, bam, rdp, recycle, jumplist, wer, mft, usn, srum, timeline, win11, etl)
// Step 37:     Detection engines (37+ detectors)
// Step 38:     Sigma matching (live)
// Step 39:     Event log Sigma scan
// Step 40:     Aggregation
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

	// ═══════════════════════════════════════════════════════
	// Phase 1 Collectors (Steps 1-10)
	// ═══════════════════════════════════════════════════════

	// ── Step 1: Collect processes ──
	s.emitProgress(1, "Collecting processes...", 0, "")
	processCollector := collector.NewProcessCollector()
	processes, err := processCollector.Collect()
	if err != nil {
		processes = []types.ProcessInfo{}
	}
	result.Summary.TotalProcesses = len(processes)
	s.emitProgress(1, "Processes collected", 3, fmt.Sprintf("%d processes", len(processes)))

	// ── Step 2: Collect network connections ──
	s.emitProgress(2, "Collecting network connections...", 3, "")
	networkCollector := collector.NewNetworkCollector()
	connections, err := networkCollector.Collect()
	if err != nil {
		connections = []types.NetworkConnection{}
	}
	result.Summary.TotalConnections = len(connections)
	s.emitProgress(2, "Network connections collected", 6, fmt.Sprintf("%d connections", len(connections)))

	// ── Step 3: Collect services ──
	s.emitProgress(3, "Collecting services...", 6, "")
	serviceCollector := collector.NewServiceCollector()
	services, err := serviceCollector.Collect()
	if err != nil {
		services = []types.ServiceInfo{}
	}
	result.Summary.TotalServices = len(services)
	s.emitProgress(3, "Services collected", 9, fmt.Sprintf("%d services", len(services)))

	// ── Step 4: Scan registry ──
	s.emitProgress(4, "Scanning registry...", 9, "35 persistence keys")
	registryCollector := collector.NewRegistryCollector()
	registryEntries, err := registryCollector.Collect()
	if err != nil {
		registryEntries = []types.RegistryEntry{}
	}
	_ = registryEntries // TODO: wire to registry-specific detector when implemented
	s.emitProgress(4, "Registry scan complete", 12, fmt.Sprintf("%d entries", len(registryEntries)))

	// ── Step 5: Collect startup folder entries ──
	s.emitProgress(5, "Scanning startup folders...", 12, "")
	startupCollector := collector.NewStartupFolderCollector()
	startupEntries, err := startupCollector.Collect()
	if err != nil {
		startupEntries = []types.StartupEntry{}
	}
	s.emitProgress(5, "Startup folders scanned", 14, fmt.Sprintf("%d entries", len(startupEntries)))

	// ── Step 6: Collect PowerShell history ──
	s.emitProgress(6, "Reading PowerShell history...", 14, "")
	psHistoryCollector := collector.NewPowerShellHistoryCollector()
	psHistory, err := psHistoryCollector.Collect()
	if err != nil {
		psHistory = []types.PowerShellHistoryEntry{}
	}
	s.emitProgress(6, "PowerShell history collected", 16, fmt.Sprintf("%d commands", len(psHistory)))

	// ── Step 7: Collect DNS cache ──
	s.emitProgress(7, "Reading DNS cache...", 16, "")
	dnsCollector := collector.NewDNSCacheCollector()
	dnsEntries, err := dnsCollector.Collect()
	if err != nil {
		dnsEntries = []types.DNSCacheEntry{}
	}
	s.emitProgress(7, "DNS cache collected", 18, fmt.Sprintf("%d entries", len(dnsEntries)))

	// ── Step 8: Collect user accounts ──
	s.emitProgress(8, "Enumerating user accounts...", 18, "")
	userCollector := collector.NewUserAccountCollector()
	userAccounts, err := userCollector.Collect()
	if err != nil {
		userAccounts = []types.UserAccountInfo{}
	}
	s.emitProgress(8, "User accounts collected", 20, fmt.Sprintf("%d accounts", len(userAccounts)))

	// ── Step 9: Check antivirus status ──
	s.emitProgress(9, "Checking antivirus status...", 20, "")
	avCollector := collector.NewAntivirusCollector()
	avProducts, err := avCollector.Collect()
	if err != nil {
		avProducts = []types.AntivirusInfo{}
	}
	s.emitProgress(9, "Antivirus status checked", 22, fmt.Sprintf("%d products", len(avProducts)))

	// ── Step 10: Collect scheduled tasks ──
	s.emitProgress(10, "Collecting scheduled tasks...", 22, "")
	taskCollector := collector.NewScheduledTaskCollector()
	scheduledTasks, err := taskCollector.Collect()
	if err != nil {
		scheduledTasks = []types.ScheduledTaskInfo{}
	}
	s.emitProgress(10, "Scheduled tasks collected", 24, fmt.Sprintf("%d tasks", len(scheduledTasks)))

	// ═══════════════════════════════════════════════════════
	// Phase 2 Collectors (Steps 11-17)
	// ═══════════════════════════════════════════════════════

	// ── Step 11: Collect DLL modules ──
	s.emitProgress(11, "Collecting DLL modules...", 24, "")
	dllCollector := collector.NewDLLModuleCollector()
	dllModules, err := dllCollector.Collect(processes)
	if err != nil {
		dllModules = []types.DLLModuleInfo{}
	}
	s.emitProgress(11, "DLL modules collected", 28, fmt.Sprintf("%d modules", len(dllModules)))

	// ── Step 12: Parse Prefetch files ──
	s.emitProgress(12, "Parsing Prefetch files...", 28, "")
	prefetchCollector := collector.NewPrefetchCollector()
	prefetchEntries, err := prefetchCollector.Collect()
	if err != nil {
		prefetchEntries = []types.PrefetchInfo{}
	}
	s.emitProgress(12, "Prefetch files parsed", 32, fmt.Sprintf("%d files", len(prefetchEntries)))

	// ── Step 13: Parse Shimcache ──
	s.emitProgress(13, "Parsing Shimcache...", 32, "")
	shimcacheCollector := collector.NewShimcacheCollector()
	shimcacheEntries, err := shimcacheCollector.Collect()
	if err != nil {
		shimcacheEntries = []types.ShimcacheEntry{}
	}
	s.emitProgress(13, "Shimcache parsed", 35, fmt.Sprintf("%d entries", len(shimcacheEntries)))

	// ── Step 14: Parse Amcache ──
	s.emitProgress(14, "Parsing Amcache...", 35, "")
	amcacheCollector := collector.NewAmcacheCollector()
	amcacheEntries, err := amcacheCollector.Collect()
	if err != nil {
		amcacheEntries = []types.AmcacheEntry{}
	}
	s.emitProgress(14, "Amcache parsed", 38, fmt.Sprintf("%d entries", len(amcacheEntries)))

	// ── Step 15: Collect WMI persistence ──
	s.emitProgress(15, "Checking WMI persistence...", 38, "")
	wmiCollector := collector.NewWMIPersistenceCollector()
	wmiEntries, err := wmiCollector.Collect()
	if err != nil {
		wmiEntries = []types.WMIPersistenceInfo{}
	}
	s.emitProgress(15, "WMI persistence checked", 41, fmt.Sprintf("%d subscriptions", len(wmiEntries)))

	// ── Step 16: Collect browser history ──
	s.emitProgress(16, "Collecting browser history...", 41, "")
	browserCollector := collector.NewBrowserHistoryCollector()
	browserEntries, err := browserCollector.Collect()
	if err != nil {
		browserEntries = []types.BrowserHistoryEntry{}
	}
	s.emitProgress(16, "Browser history collected", 44, fmt.Sprintf("%d entries", len(browserEntries)))

	// ── Step 17: Collect USB history ──
	s.emitProgress(17, "Collecting USB history...", 46, "")
	usbCollector := collector.NewUSBHistoryCollector()
	usbDevices, err := usbCollector.Collect()
	if err != nil {
		usbDevices = []types.USBDeviceInfo{}
	}
	s.emitProgress(17, "USB history collected", 48, fmt.Sprintf("%d devices", len(usbDevices)))

	// ═══════════════════════════════════════════════════════
	// Phase 3 Collectors (Steps 18-34)
	// ═══════════════════════════════════════════════════════

	// ── Step 18: Enumerate drivers ──
	s.emitProgress(18, "Enumerating drivers...", 48, "")
	driverCollector := collector.NewDriverCollector()
	drivers, err := driverCollector.Collect()
	if err != nil {
		drivers = []types.DriverInfo{}
	}
	s.emitProgress(18, "Drivers enumerated", 50, fmt.Sprintf("%d drivers", len(drivers)))

	// ── Step 19: Check firewall rules ──
	s.emitProgress(19, "Checking firewall rules...", 50, "")
	firewallCollector := collector.NewFirewallCollector()
	firewallRules, err := firewallCollector.Collect()
	if err != nil {
		firewallRules = []types.FirewallRuleInfo{}
	}
	s.emitProgress(19, "Firewall rules checked", 52, fmt.Sprintf("%d rules", len(firewallRules)))

	// ── Step 20: Scan certificates ──
	s.emitProgress(20, "Scanning certificates...", 52, "")
	certCollector := collector.NewCertificateCollector()
	certificates, err := certCollector.Collect()
	if err != nil {
		certificates = []types.CertificateInfo{}
	}
	s.emitProgress(20, "Certificates scanned", 54, fmt.Sprintf("%d certs", len(certificates)))

	// ── Step 21: Enumerate shared folders ──
	s.emitProgress(21, "Enumerating shared folders...", 54, "")
	shareCollector := collector.NewSharedFolderCollector()
	shares, err := shareCollector.Collect()
	if err != nil {
		shares = []types.SharedFolderInfo{}
	}
	s.emitProgress(21, "Shared folders enumerated", 56, fmt.Sprintf("%d shares", len(shares)))

	// ── Step 22: Read ARP table ──
	s.emitProgress(22, "Reading ARP table...", 56, "")
	arpCollector := collector.NewARPCollector()
	arpEntries, err := arpCollector.Collect()
	if err != nil {
		arpEntries = []types.ARPEntry{}
	}
	s.emitProgress(22, "ARP table read", 57, fmt.Sprintf("%d entries", len(arpEntries)))

	// ── Step 23: Check LSASS handles ──
	s.emitProgress(23, "Checking LSASS access...", 57, "")
	handleCollector := collector.NewOpenHandleCollector()
	handleEntries, err := handleCollector.Collect()
	if err != nil {
		handleEntries = []types.HandleInfo{}
	}
	s.emitProgress(23, "LSASS check complete", 58, fmt.Sprintf("%d suspicious", len(handleEntries)))

	// ── Step 24: Check BITS jobs ──
	s.emitProgress(24, "Checking BITS jobs...", 58, "")
	bitsCollector := collector.NewBITSCollector()
	bitsJobs, err := bitsCollector.Collect()
	if err != nil {
		bitsJobs = []types.BITSJobInfo{}
	}
	s.emitProgress(24, "BITS jobs checked", 60, fmt.Sprintf("%d jobs", len(bitsJobs)))

	// ── Step 25: Parse UserAssist ──
	s.emitProgress(25, "Parsing UserAssist...", 60, "")
	userassistCollector := collector.NewUserAssistCollector()
	userassistEntries, err := userassistCollector.Collect()
	if err != nil {
		userassistEntries = []types.UserAssistEntry{}
	}
	s.emitProgress(25, "UserAssist parsed", 62, fmt.Sprintf("%d entries", len(userassistEntries)))

	// ── Step 26: Parse BAM/DAM ──
	s.emitProgress(26, "Parsing BAM/DAM...", 62, "")
	bamCollector := collector.NewBAMCollector()
	bamEntries, err := bamCollector.Collect()
	if err != nil {
		bamEntries = []types.BAMEntry{}
	}
	s.emitProgress(26, "BAM/DAM parsed", 64, fmt.Sprintf("%d entries", len(bamEntries)))

	// ── Step 27: Check RDP history ──
	s.emitProgress(27, "Checking RDP history...", 64, "")
	rdpCollector := collector.NewRDPCacheCollector()
	rdpEntries, err := rdpCollector.Collect()
	if err != nil {
		rdpEntries = []types.RDPCacheEntry{}
	}
	s.emitProgress(27, "RDP history checked", 65, fmt.Sprintf("%d entries", len(rdpEntries)))

	// ── Step 28: Parse Recycle Bin ──
	s.emitProgress(28, "Parsing Recycle Bin...", 65, "")
	recycleCollector := collector.NewRecycleBinCollector()
	recycleEntries, err := recycleCollector.Collect()
	if err != nil {
		recycleEntries = []types.RecycleBinEntry{}
	}
	s.emitProgress(28, "Recycle Bin parsed", 67, fmt.Sprintf("%d deleted files", len(recycleEntries)))

	// ── Step 29: Parse Jumplist/LNK ──
	s.emitProgress(29, "Parsing Jumplist/LNK files...", 67, "")
	jumplistCollector := collector.NewJumplistCollector()
	jumplistEntries, err := jumplistCollector.Collect()
	if err != nil {
		jumplistEntries = []types.JumplistEntry{}
	}
	s.emitProgress(29, "Jumplist/LNK parsed", 69, fmt.Sprintf("%d entries", len(jumplistEntries)))

	// ── Step 30: Check WER reports ──
	s.emitProgress(30, "Checking crash reports (WER)...", 69, "")
	werCollector := collector.NewWERCollector()
	werEntries, err := werCollector.Collect()
	if err != nil {
		werEntries = []types.WEREntry{}
	}
	s.emitProgress(30, "Crash reports checked", 70, fmt.Sprintf("%d reports", len(werEntries)))

	// ── Step 31: Parse MFT (admin) ──
	s.emitProgress(31, "Parsing MFT...", 70, "")
	mftCollector := collector.NewMFTCollector()
	mftEntries, err := mftCollector.Collect()
	if err != nil {
		mftEntries = []types.MFTEntry{}
	}
	s.emitProgress(31, "MFT parsed", 73, fmt.Sprintf("%d records", len(mftEntries)))

	// ── Step 32: Read USN Journal (admin) ──
	s.emitProgress(32, "Reading USN Journal...", 73, "")
	usnCollector := collector.NewUSNJournalCollector()
	usnEntries, err := usnCollector.Collect()
	if err != nil {
		usnEntries = []types.USNJournalEntry{}
	}
	s.emitProgress(32, "USN Journal read", 75, fmt.Sprintf("%d entries", len(usnEntries)))

	// ── Step 33: Parse SRUM (admin) ──
	s.emitProgress(33, "Parsing SRUM...", 75, "")
	srumCollector := collector.NewSRUMCollector()
	srumEntries, err := srumCollector.Collect()
	if err != nil {
		srumEntries = []types.SRUMEntry{}
	}
	s.emitProgress(33, "SRUM parsed", 77, fmt.Sprintf("%d entries", len(srumEntries)))

	// ── Step 34: Collect Timeline ──
	s.emitProgress(34, "Collecting Timeline...", 77, "")
	timelineCollector := collector.NewTimelineCollector()
	timelineEntries, err := timelineCollector.Collect()
	if err != nil {
		timelineEntries = []types.TimelineEntry{}
	}
	s.emitProgress(34, "Timeline collected", 78, fmt.Sprintf("%d entries", len(timelineEntries)))

	// ── Step 35: Collect Win11 artifacts ──
	s.emitProgress(35, "Collecting Win11 artifacts...", 78, "")
	win11Collector := collector.NewWin11ArtifactsCollector()
	win11Entries, err := win11Collector.Collect()
	if err != nil {
		win11Entries = []types.Win11ArtifactEntry{}
	}
	s.emitProgress(35, "Win11 artifacts collected", 79, fmt.Sprintf("%d entries", len(win11Entries)))

	// ── Step 36: Collect ETL logs ──
	s.emitProgress(36, "Reading ETL logs...", 79, "")
	etlCollector := collector.NewETLLogCollector()
	etlEntries, err := etlCollector.Collect()
	if err != nil {
		etlEntries = []types.ETLLogEntry{}
	}
	s.emitProgress(36, "ETL logs read", 80, fmt.Sprintf("%d entries", len(etlEntries)))

	// Suppress unused variable warnings for data without dedicated detectors
	_ = timelineEntries
	_ = srumEntries
	_ = arpEntries
	_ = win11Entries
	_ = etlEntries

	// ═══════════════════════════════════════════════════════
	// Detection Engines (Step 37)
	// ═══════════════════════════════════════════════════════

	// ── Step 37: Run all detection engines ──
	s.emitProgress(37, "Running detection engines...", 80, "37+ detection engines")

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

	// Phase 3 detectors
	result.Detections = append(result.Detections, det.DetectUnsignedDrivers(drivers)...)
	result.Detections = append(result.Detections, det.DetectFirewallAnomalies(firewallRules)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousCertificates(certificates)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousShares(shares)...)
	result.Detections = append(result.Detections, det.DetectLSASSAccess(handleEntries)...)
	result.Detections = append(result.Detections, det.DetectSuspiciousBITS(bitsJobs)...)
	result.Detections = append(result.Detections, det.DetectUserAssistAnomalies(userassistEntries)...)
	result.Detections = append(result.Detections, det.DetectBAMAnomalies(bamEntries)...)
	result.Detections = append(result.Detections, det.DetectRDPAnomalies(rdpEntries)...)
	result.Detections = append(result.Detections, det.DetectRecycleBinAnomalies(recycleEntries)...)
	result.Detections = append(result.Detections, det.DetectJumplistAnomalies(jumplistEntries)...)
	result.Detections = append(result.Detections, det.DetectWERAnomalies(werEntries)...)
	result.Detections = append(result.Detections, det.DetectTimestomping(mftEntries)...)
	result.Detections = append(result.Detections, det.DetectEvidenceDestruction(recycleEntries, usnEntries)...)
	result.Detections = append(result.Detections, det.DetectBeaconing(connections)...)

	detCount := len(result.Detections)
	s.emitProgress(37, "Detection engines complete", 86, fmt.Sprintf("%d detections", detCount))

	// ── Step 38: Live Sigma matching ──
	s.emitProgress(38, "Sigma rule matching...", 86, "")
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

		s.emitProgress(38, "Sigma live matching complete", 90,
			fmt.Sprintf("%d rules, process %d + network %d",
				sigmaEngine.TotalRules(), len(liveProcessResults), len(liveNetworkResults)))
	}

	// ── Step 39: Event log Sigma scan ──
	s.emitProgress(39, "Analyzing event logs...", 90, "")
	if sigmaEngine != nil {
		progressCB := func(progress sigma.ScanProgress) {
			s.emitProgress(39, "Analyzing event logs...", 90,
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
	s.emitProgress(39, "Event log analysis complete", 96, "")

	// ── Step 40: Aggregate results ──
	s.emitProgress(40, "Aggregating results...", 96, "")

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

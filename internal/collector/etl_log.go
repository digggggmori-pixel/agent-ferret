package collector

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ETLLogCollector reads ETW trace log files (.etl)
type ETLLogCollector struct{}

// NewETLLogCollector creates a new ETL log collector
func NewETLLogCollector() *ETLLogCollector {
	return &ETLLogCollector{}
}

// Collect reads relevant ETL log files using wevtapi.dll EvtQuery
func (c *ETLLogCollector) Collect() ([]types.ETLLogEntry, error) {
	logger.Section("ETL Log Collection")
	startTime := time.Now()

	var entries []types.ETLLogEntry

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}

	// Read boot trace log
	bootETL := filepath.Join(winDir, `System32\WDI\LogFiles\BootCKCL.etl`)
	if _, err := os.Stat(bootETL); err == nil {
		bootEntries := c.parseETL(bootETL)
		entries = append(entries, bootEntries...)
	}

	// Read shutdown trace log
	shutdownETL := filepath.Join(winDir, `System32\WDI\LogFiles\ShutdownCKCL.etl`)
	if _, err := os.Stat(shutdownETL); err == nil {
		shutdownEntries := c.parseETL(shutdownETL)
		entries = append(entries, shutdownEntries...)
	}

	logger.Timing("ETLLogCollector.Collect", startTime)
	logger.Info("ETL logs: %d entries collected", len(entries))

	return entries, nil
}

// etlEventXML is a local XML struct for parsing ETL events (includes Level field)
type etlEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     uint32 `xml:"EventID"`
		Level       uint8  `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseETL reads events from an .etl file using wevtapi.dll EvtQuery with EvtQueryFilePath
func (c *ETLLogCollector) parseETL(etlPath string) []types.ETLLogEntry {
	var entries []types.ETLLogEntry

	// Use EvtQuery with EvtQueryFilePath flag to read .etl files directly
	handle, err := evtQuery(etlPath, "*", EvtQueryFilePath|EvtQueryForwardDirection)
	if err != nil {
		logger.Debug("Cannot open ETL file %s: %v", etlPath, err)
		return entries
	}
	defer evtClose(handle)

	const batchSize = 100
	const maxEvents = 1000
	eventHandles := make([]syscall.Handle, batchSize)
	total := 0

	for total < maxEvents {
		returned, err := evtNext(handle, eventHandles)
		if err != nil {
			break
		}

		for i := uint32(0); i < returned && total < maxEvents; i++ {
			eventXMLStr, err := renderEventXML(eventHandles[i])
			evtClose(eventHandles[i])
			if err != nil {
				continue
			}

			entry := c.parseETLEventXML(eventXMLStr)
			if entry != nil {
				entries = append(entries, *entry)
				total++
			}
		}

		if returned < uint32(batchSize) {
			break
		}
	}

	return entries
}

// parseETLEventXML parses a single event XML into an ETLLogEntry
func (c *ETLLogCollector) parseETLEventXML(xmlStr string) *types.ETLLogEntry {
	var event etlEventXML
	if err := xml.Unmarshal([]byte(xmlStr), &event); err != nil {
		return nil
	}

	ts, _ := time.Parse(time.RFC3339Nano, event.System.TimeCreated.SystemTime)

	// Build message from event data fields
	var msgParts []string
	for _, d := range event.EventData.Data {
		if d.Value != "" {
			msgParts = append(msgParts, d.Value)
		}
	}
	message := strings.Join(msgParts, " | ")
	if len(message) > 200 {
		message = message[:200]
	}

	return &types.ETLLogEntry{
		Provider:  event.System.Provider.Name,
		EventID:   event.System.EventID,
		Level:     event.System.Level,
		Timestamp: ts,
		Message:   message,
	}
}

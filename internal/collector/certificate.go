package collector

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// CertificateCollector collects certificates from Windows certificate stores
type CertificateCollector struct{}

// NewCertificateCollector creates a new certificate collector
func NewCertificateCollector() *CertificateCollector {
	return &CertificateCollector{}
}

type certPSEntry struct {
	Subject      string `json:"Subject"`
	Issuer       string `json:"Issuer"`
	Thumbprint   string `json:"Thumbprint"`
	NotBefore    string `json:"NotBefore"`
	NotAfter     string `json:"NotAfter"`
	SerialNumber string `json:"SerialNumber"`
	Store        string `json:"Store"`
}

// Collect retrieves certificates from Root and CA stores
func (c *CertificateCollector) Collect() ([]types.CertificateInfo, error) {
	logger.Section("Certificate Collection")
	startTime := time.Now()

	var entries []types.CertificateInfo

	// Scan Root and CA certificate stores for suspicious certificates
	psScript := `
$results = @()
$stores = @(
    @{Path='Cert:\LocalMachine\Root'; Name='LocalMachine-Root'},
    @{Path='Cert:\LocalMachine\CA'; Name='LocalMachine-CA'},
    @{Path='Cert:\CurrentUser\Root'; Name='CurrentUser-Root'}
)
foreach ($store in $stores) {
    $certs = Get-ChildItem -Path $store.Path -ErrorAction SilentlyContinue
    foreach ($cert in $certs) {
        $results += @{
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            NotBefore = $cert.NotBefore.ToString('o')
            NotAfter = $cert.NotAfter.ToString('o')
            SerialNumber = $cert.SerialNumber
            Store = $store.Name
        }
    }
}
$results | ConvertTo-Json -Compress -Depth 2
`

	output, err := runPowerShell(psScript)
	if err != nil || strings.TrimSpace(output) == "" || output == "null" {
		logger.Debug("Cannot collect certificates: %v", err)
		return entries, nil
	}

	var rawEntries []certPSEntry
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &rawEntries); err != nil {
			logger.Debug("Failed to parse certificate JSON: %v", err)
		}
	} else if strings.HasPrefix(output, "{") {
		var single certPSEntry
		if json.Unmarshal([]byte(output), &single) == nil {
			rawEntries = append(rawEntries, single)
		}
	}

	now := time.Now()
	for _, raw := range rawEntries {
		notBefore, _ := time.Parse(time.RFC3339, raw.NotBefore)
		notAfter, _ := time.Parse(time.RFC3339, raw.NotAfter)

		entry := types.CertificateInfo{
			Subject:      raw.Subject,
			Issuer:       raw.Issuer,
			Thumbprint:   raw.Thumbprint,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			SerialNumber: raw.SerialNumber,
			Store:        raw.Store,
			IsSelfSigned: raw.Subject == raw.Issuer,
			IsExpired:    !notAfter.IsZero() && now.After(notAfter),
		}

		entries = append(entries, entry)
	}

	logger.Timing("CertificateCollector.Collect", startTime)
	logger.Info("Certificates: %d entries collected", len(entries))

	return entries, nil
}

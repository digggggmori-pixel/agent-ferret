package collector

import (
	"os/exec"
	"regexp"
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

// Collect retrieves certificates from Root and CA stores using certutil.exe
func (c *CertificateCollector) Collect() ([]types.CertificateInfo, error) {
	logger.Section("Certificate Collection")
	startTime := time.Now()

	var entries []types.CertificateInfo

	// Scan certificate stores using certutil.exe (native Windows binary)
	stores := []struct {
		args []string
		name string
	}{
		{[]string{"-store", "Root"}, "LocalMachine-Root"},
		{[]string{"-store", "CA"}, "LocalMachine-CA"},
		{[]string{"-user", "-store", "Root"}, "CurrentUser-Root"},
	}

	for _, store := range stores {
		cmd := exec.Command("certutil.exe", store.args...)
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		storeEntries := c.parseCertutilOutput(string(output), store.name)
		entries = append(entries, storeEntries...)
	}

	logger.Timing("CertificateCollector.Collect", startTime)
	logger.Info("Certificates: %d entries collected", len(entries))

	return entries, nil
}

// parseCertutilOutput parses the text output from "certutil -store"
func (c *CertificateCollector) parseCertutilOutput(output, storeName string) []types.CertificateInfo {
	var entries []types.CertificateInfo

	serialRe := regexp.MustCompile(`(?i)Serial Number:\s*(.+)`)
	issuerRe := regexp.MustCompile(`(?i)Issuer:\s*(.+)`)
	subjectRe := regexp.MustCompile(`(?i)^Subject:\s*(.+)`)
	notBeforeRe := regexp.MustCompile(`(?i)NotBefore:\s*(.+)`)
	notAfterRe := regexp.MustCompile(`(?i)NotAfter:\s*(.+)`)
	thumbprintRe := regexp.MustCompile(`(?i)Cert Hash\(sha1\):\s*(.+)`)

	var current *types.CertificateInfo
	now := time.Now()

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "================ Certificate") {
			if current != nil {
				current.IsSelfSigned = current.Subject == current.Issuer
				current.IsExpired = !current.NotAfter.IsZero() && now.After(current.NotAfter)
				entries = append(entries, *current)
			}
			current = &types.CertificateInfo{Store: storeName}
			continue
		}

		if current == nil {
			continue
		}

		if m := serialRe.FindStringSubmatch(line); len(m) > 1 {
			current.SerialNumber = strings.TrimSpace(m[1])
		}
		if m := issuerRe.FindStringSubmatch(line); len(m) > 1 {
			current.Issuer = strings.TrimSpace(m[1])
		}
		if m := subjectRe.FindStringSubmatch(line); len(m) > 1 {
			current.Subject = strings.TrimSpace(m[1])
		}
		if m := notBeforeRe.FindStringSubmatch(line); len(m) > 1 {
			current.NotBefore = parseCertutilTime(strings.TrimSpace(m[1]))
		}
		if m := notAfterRe.FindStringSubmatch(line); len(m) > 1 {
			current.NotAfter = parseCertutilTime(strings.TrimSpace(m[1]))
		}
		if m := thumbprintRe.FindStringSubmatch(line); len(m) > 1 {
			current.Thumbprint = strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
		}
	}

	// Add last cert
	if current != nil {
		current.IsSelfSigned = current.Subject == current.Issuer
		current.IsExpired = !current.NotAfter.IsZero() && now.After(current.NotAfter)
		entries = append(entries, *current)
	}

	return entries
}

// parseCertutilTime parses locale-dependent date formats from certutil output
func parseCertutilTime(s string) time.Time {
	layouts := []string{
		"1/2/2006 3:04 PM",
		"1/2/2006 3:04:05 PM",
		"2006/01/02 15:04",
		"2006/01/02 15:04:05",
		"01/02/2006 15:04:05",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

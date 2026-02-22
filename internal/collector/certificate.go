package collector

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// CertificateCollector collects certificates from Windows certificate stores
type CertificateCollector struct{}

// NewCertificateCollector creates a new certificate collector
func NewCertificateCollector() *CertificateCollector {
	return &CertificateCollector{}
}

// Additional crypt32 procs (modCrypt32 and others are in driver.go, same package)
var (
	procCertOpenStore                     = modCrypt32.NewProc("CertOpenStore")
	procCertGetCertificateContextProperty = modCrypt32.NewProc("CertGetCertificateContextProperty")
)

const (
	certStorePROVSystemW        = 10
	certSystemStoreLocalMachine = 0x00020000
	certSystemStoreCurrentUser  = 0x00010000
	certSHA1HashPropID          = 3
	certNameIssuerFlag          = 1
)

// cryptBlob matches Windows CRYPT_DATA_BLOB / CRYPT_INTEGER_BLOB on amd64
type cryptBlob struct {
	cbData uint32
	pbData uintptr // *byte
}

// cryptAlgID matches Windows CRYPT_ALGORITHM_IDENTIFIER on amd64
type cryptAlgID struct {
	pszObjId uintptr // LPSTR
	params   cryptBlob
}

// certContextLayout matches the Windows CERT_CONTEXT struct layout on amd64
type certContextLayout struct {
	dwCertEncodingType uint32
	pbCertEncoded      uintptr
	cbCertEncoded      uint32
	pCertInfo          uintptr
	hCertStore         uintptr
}

// certInfoLayout matches the beginning of CERT_INFO on amd64
// Uses nested structs to ensure Go's struct alignment matches the Windows C layout.
// Fields we need: SerialNumber, NotBefore, NotAfter (Subject/Issuer via CertGetNameStringW)
type certInfoLayout struct {
	dwVersion          uint32
	serialNumber       cryptBlob
	signatureAlgorithm cryptAlgID
	issuer             cryptBlob
	notBefore          syscall.Filetime
	notAfter           syscall.Filetime
}

// Collect retrieves certificates from Root and CA stores using crypt32.dll native API
// This avoids certutil.exe locale issues (Korean output fields don't match English regex)
func (c *CertificateCollector) Collect() ([]types.CertificateInfo, error) {
	logger.Section("Certificate Collection")
	startTime := time.Now()

	var entries []types.CertificateInfo

	stores := []struct {
		name      string
		storeName string
		flags     uint32
	}{
		{"LocalMachine-Root", "Root", certSystemStoreLocalMachine},
		{"LocalMachine-CA", "CA", certSystemStoreLocalMachine},
		{"CurrentUser-Root", "Root", certSystemStoreCurrentUser},
	}

	for _, store := range stores {
		storeEntries := c.enumerateStore(store.storeName, store.flags, store.name)
		entries = append(entries, storeEntries...)
	}

	logger.Timing("CertificateCollector.Collect", startTime)
	logger.Info("Certificates: %d entries collected", len(entries))

	return entries, nil
}

// enumerateStore opens a certificate store and enumerates all certificates
func (c *CertificateCollector) enumerateStore(storeName string, flags uint32, label string) []types.CertificateInfo {
	var entries []types.CertificateInfo

	storeNamePtr, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return entries
	}

	hStore, _, callErr := procCertOpenStore.Call(
		certStorePROVSystemW,
		0, // dwEncodingType is not used with system-store providers
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(storeNamePtr)),
	)
	if hStore == 0 {
		logger.Debug("Cannot open certificate store %s: %v", label, callErr)
		return entries
	}
	defer procCertCloseStore.Call(hStore, 0)

	now := time.Now()
	var certCtx uintptr

	for {
		certCtx, _, _ = procCertEnumCertificatesInStore.Call(hStore, certCtx)
		if certCtx == 0 {
			break
		}

		entry := c.extractCertInfo(certCtx, label)
		if entry != nil {
			entry.IsSelfSigned = entry.Subject == entry.Issuer
			entry.IsExpired = !entry.NotAfter.IsZero() && now.After(entry.NotAfter)
			entries = append(entries, *entry)
		}
	}

	return entries
}

// extractCertInfo extracts certificate details from a CERT_CONTEXT pointer
func (c *CertificateCollector) extractCertInfo(certCtx uintptr, storeName string) *types.CertificateInfo {
	entry := &types.CertificateInfo{Store: storeName}

	// Subject name (display name)
	entry.Subject = getCertNameString(certCtx, certNameSimpleDisplayType, 0)

	// Issuer name
	entry.Issuer = getCertNameString(certCtx, certNameSimpleDisplayType, certNameIssuerFlag)

	// Read CERT_CONTEXT to get pCertInfo
	ctx := (*certContextLayout)(unsafe.Pointer(certCtx))
	if ctx.pCertInfo != 0 {
		info := (*certInfoLayout)(unsafe.Pointer(ctx.pCertInfo))

		// NotBefore / NotAfter
		entry.NotBefore = filetimeToGoTime(info.notBefore)
		entry.NotAfter = filetimeToGoTime(info.notAfter)

		// Serial number (bytes are little-endian, display reversed as big-endian hex)
		if info.serialNumber.cbData > 0 && info.serialNumber.cbData < 256 {
			serialBytes := make([]byte, info.serialNumber.cbData)
			for i := uint32(0); i < info.serialNumber.cbData; i++ {
				serialBytes[i] = *(*byte)(unsafe.Pointer(info.serialNumber.pbData + uintptr(i)))
			}
			// Reverse for standard display (big-endian)
			for i, j := 0, len(serialBytes)-1; i < j; i, j = i+1, j-1 {
				serialBytes[i], serialBytes[j] = serialBytes[j], serialBytes[i]
			}
			entry.SerialNumber = hex.EncodeToString(serialBytes)
		}
	}

	// SHA1 thumbprint via CertGetCertificateContextProperty
	entry.Thumbprint = getCertThumbprint(certCtx)

	return entry
}

// getCertNameString extracts a name string from a cert context
func getCertNameString(certCtx uintptr, nameType uint32, flags uint32) string {
	var buf [256]uint16
	procCertGetNameStringW.Call(
		certCtx,
		uintptr(nameType),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	return syscall.UTF16ToString(buf[:])
}

// getCertThumbprint extracts the SHA1 thumbprint of a certificate
func getCertThumbprint(certCtx uintptr) string {
	var hashSize uint32 = 20 // SHA1 = 20 bytes
	hashBuf := make([]byte, hashSize)

	ret, _, _ := procCertGetCertificateContextProperty.Call(
		certCtx,
		certSHA1HashPropID,
		uintptr(unsafe.Pointer(&hashBuf[0])),
		uintptr(unsafe.Pointer(&hashSize)),
	)
	if ret == 0 {
		return ""
	}

	return fmt.Sprintf("%X", hashBuf[:hashSize])
}

// filetimeToGoTime converts a Windows FILETIME to Go time.Time
func filetimeToGoTime(ft syscall.Filetime) time.Time {
	if ft.HighDateTime == 0 && ft.LowDateTime == 0 {
		return time.Time{}
	}
	nsec := ft.Nanoseconds()
	return time.Unix(0, nsec)
}

package collector

import (
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// DriverCollector enumerates loaded kernel drivers
type DriverCollector struct{}

// NewDriverCollector creates a new driver collector
func NewDriverCollector() *DriverCollector {
	return &DriverCollector{}
}

// Collect enumerates kernel drivers using native WMI COM query + WinVerifyTrust signature check
func (c *DriverCollector) Collect() ([]types.DriverInfo, error) {
	logger.Section("Driver Collection")
	startTime := time.Now()

	var entries []types.DriverInfo

	rows, err := WMIQueryFields(`root\cimv2`,
		"SELECT Name, DisplayName, PathName, State, StartMode, Description FROM Win32_SystemDriver",
		[]string{"Name", "DisplayName", "PathName", "State", "StartMode", "Description"})
	if err != nil {
		logger.Error("Failed to query drivers via WMI: %v", err)
		return entries, nil
	}

	for _, row := range rows {
		driverPath := resolveDriverPath(row["PathName"])
		signed, signer := verifyFileSignature(driverPath)

		entries = append(entries, types.DriverInfo{
			Name:        row["Name"],
			DisplayName: row["DisplayName"],
			Path:        row["PathName"],
			State:       row["State"],
			StartMode:   row["StartMode"],
			Description: row["Description"],
			IsSigned:    signed,
			Signer:      signer,
		})
	}

	logger.Timing("DriverCollector.Collect", startTime)
	logger.Info("Drivers: %d entries collected", len(entries))

	return entries, nil
}

// resolveDriverPath normalizes WMI driver paths to filesystem paths
// e.g., "\SystemRoot\system32\drivers\foo.sys" → "C:\Windows\system32\drivers\foo.sys"
//
//	"\??\C:\Windows\..." → "C:\Windows\..."
func resolveDriverPath(rawPath string) string {
	if rawPath == "" {
		return ""
	}

	path := rawPath

	// \SystemRoot\ → %WINDIR%\
	if strings.HasPrefix(strings.ToLower(path), `\systemroot\`) {
		winDir := os.Getenv("WINDIR")
		if winDir == "" {
			winDir = `C:\Windows`
		}
		path = winDir + path[11:] // len(`\SystemRoot`) == 11
	}

	// \??\ prefix (NT path)
	if strings.HasPrefix(path, `\??\`) {
		path = path[4:]
	}

	// system32\drivers\... (relative, no leading slash)
	if !strings.Contains(path, `:`) && !strings.HasPrefix(path, `\`) {
		winDir := os.Getenv("WINDIR")
		if winDir == "" {
			winDir = `C:\Windows`
		}
		path = winDir + `\` + path
	}

	return path
}

// ── WinVerifyTrust via wintrust.dll ──────────────────────────────────────────

var (
	modWintrust        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID: {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
var actionGenericVerifyV2 = syscall.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdCacheOnlyURLRetrieval = 0x1000
	wtdUseDefaultOSVerCheck  = 0x0400
)

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject *syscall.GUID
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       syscall.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// verifyFileSignature checks if a file has a valid Authenticode signature using WinVerifyTrust.
// Returns (isSigned bool, signerName string).
func verifyFileSignature(filePath string) (bool, string) {
	if filePath == "" {
		return false, ""
	}

	if _, err := os.Stat(filePath); err != nil {
		return false, ""
	}

	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return false, ""
	}

	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: pathPtr,
	}

	trustData := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               &fileInfo,
		dwStateAction:       wtdStateActionVerify,
		dwProvFlags:         wtdCacheOnlyURLRetrieval | wtdUseDefaultOSVerCheck,
	}

	actionGUID := actionGenericVerifyV2

	ret, _, _ := procWinVerifyTrust.Call(
		^uintptr(0), // INVALID_HANDLE_VALUE
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	// Close the state handle
	trustData.dwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(
		^uintptr(0),
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	isSigned := ret == 0 // S_OK = 0 means valid signature

	signer := ""
	if isSigned {
		signer = getSignerName(filePath)
	}

	return isSigned, signer
}

// ── Signer name extraction via crypt32.dll ───────────────────────────────────

var (
	modCrypt32                     = syscall.NewLazyDLL("crypt32.dll")
	procCryptQueryObject           = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam           = modCrypt32.NewProc("CryptMsgGetParam")
	procCertEnumCertificatesInStore = modCrypt32.NewProc("CertEnumCertificatesInStore")
	procCertGetNameStringW         = modCrypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext = modCrypt32.NewProc("CertFreeCertificateContext")
	procCertCloseStore             = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgClose              = modCrypt32.NewProc("CryptMsgClose")
)

const (
	certQueryObjectFile                 = 1
	certQueryContentFlagPKCS7SignedEmbed = 0x400
	certQueryFormatFlagBinary           = 2
	certNameSimpleDisplayType           = 4
)

// getSignerName extracts the signer subject name from a signed PE file
func getSignerName(filePath string) string {
	pathPtr, _ := syscall.UTF16PtrFromString(filePath)

	var hStore, hMsg syscall.Handle
	var dwEncoding, dwContentType, dwFormatType uint32

	ret, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		certQueryContentFlagPKCS7SignedEmbed,
		certQueryFormatFlagBinary,
		0,
		uintptr(unsafe.Pointer(&dwEncoding)),
		uintptr(unsafe.Pointer(&dwContentType)),
		uintptr(unsafe.Pointer(&dwFormatType)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)
	if ret == 0 {
		return ""
	}
	defer procCryptMsgClose.Call(uintptr(hMsg))
	defer procCertCloseStore.Call(uintptr(hStore), 0)

	// Get the first certificate from the embedded signature store (the signer cert)
	certCtx, _, _ := procCertEnumCertificatesInStore.Call(uintptr(hStore), 0)
	if certCtx == 0 {
		return ""
	}
	defer procCertFreeCertificateContext.Call(certCtx)

	// Extract the subject display name
	var buf [256]uint16
	procCertGetNameStringW.Call(
		certCtx,
		certNameSimpleDisplayType,
		0,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	return syscall.UTF16ToString(buf[:])
}

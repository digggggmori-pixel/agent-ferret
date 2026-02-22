package collector

import (
	"unicode/utf16"
	"unsafe"
)

// procMultiByteToWideChar and procGetOEMCP use modkernel32 declared in host.go
var (
	procMultiByteToWideChar = modkernel32.NewProc("MultiByteToWideChar")
	procGetOEMCP            = modkernel32.NewProc("GetOEMCP")
)

// decodeOEMOutput converts command output from the system's OEM codepage to a UTF-8 Go string.
// Windows CLI tools (netsh, fsutil, etc.) output text in the OEM codepage (e.g. CP949 on Korean
// Windows), not UTF-8. Go string literals are UTF-8, so comparing Korean field names against
// raw OEM bytes will fail. This function performs the necessary codepage → UTF-8 conversion.
func decodeOEMOutput(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Get OEM code page (e.g. 949 for Korean, 437 for US English)
	cp, _, _ := procGetOEMCP.Call()

	// If codepage is already UTF-8, no conversion needed
	if cp == 65001 {
		return string(data)
	}

	// Get required buffer size (number of wide chars)
	n, _, _ := procMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, 0,
	)
	if n == 0 {
		return string(data) // fallback to raw bytes
	}

	// Convert from OEM codepage to UTF-16
	buf := make([]uint16, n)
	procMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&buf[0])), n,
	)

	// Convert UTF-16 to Go string (UTF-8)
	return string(utf16.Decode(buf))
}

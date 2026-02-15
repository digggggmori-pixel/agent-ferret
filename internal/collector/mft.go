package collector

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// MFTCollector parses the Master File Table ($MFT) for file creation/modification history
type MFTCollector struct{}

// NewMFTCollector creates a new MFT collector
func NewMFTCollector() *MFTCollector {
	return &MFTCollector{}
}

const (
	mftRecordSize     = 1024
	mftSignature      = 0x454C4946 // "FILE"
	attrStdInfo       = 0x10       // $STANDARD_INFORMATION
	attrFileName      = 0x30       // $FILE_NAME
	attrEndMarker     = 0xFFFFFFFF
	maxMFTRecords     = 50000 // Limit to prevent excessive memory usage
)

// Collect copies and parses the $MFT file
func (c *MFTCollector) Collect() ([]types.MFTEntry, error) {
	logger.Section("MFT Collection")
	startTime := time.Now()

	var entries []types.MFTEntry

	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Copy $MFT to temp using esentutl (handles locked files)
	tempDir := os.TempDir()
	tempCopy := filepath.Join(tempDir, "ferret_mft_copy")
	defer os.Remove(tempCopy)

	mftPath := systemDrive + `\$MFT`

	// Try esentutl /y (Volume Shadow Copy)
	copyCmd := exec.Command("esentutl.exe", "/y", mftPath, "/vssrec", "/d", tempCopy)
	if err := copyCmd.Run(); err != nil {
		// Try direct raw volume read via syscall
		c.rawCopyMFT(systemDrive, tempCopy)
	}

	// Check if copy succeeded
	if _, err := os.Stat(tempCopy); err != nil {
		logger.Debug("Cannot copy $MFT (admin required): %v", err)
		return entries, nil
	}

	// Parse the MFT file
	entries = c.parseMFT(tempCopy)

	logger.Timing("MFTCollector.Collect", startTime)
	logger.Info("MFT: %d entries parsed", len(entries))

	return entries, nil
}

// rawCopyMFT reads the first 10MB from the raw volume using syscall
func (c *MFTCollector) rawCopyMFT(drive, destPath string) {
	volumePath := `\\.\` + drive
	pathPtr, _ := syscall.UTF16PtrFromString(volumePath)

	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(handle)

	// Read first 10MB (same as PS version)
	buf := make([]byte, 10*1024*1024)
	var bytesRead uint32
	err = syscall.ReadFile(handle, buf, &bytesRead, nil)
	if err != nil || bytesRead == 0 {
		return
	}

	os.WriteFile(destPath, buf[:bytesRead], 0600)
}

// parseMFT reads and parses MFT records
func (c *MFTCollector) parseMFT(path string) []types.MFTEntry {
	var entries []types.MFTEntry

	f, err := os.Open(path)
	if err != nil {
		return entries
	}
	defer f.Close()

	buf := make([]byte, mftRecordSize)
	recordNum := uint64(0)

	for recordNum < maxMFTRecords {
		n, err := f.Read(buf)
		if err != nil || n < mftRecordSize {
			break
		}

		entry := c.parseMFTRecord(buf, recordNum)
		if entry != nil {
			entries = append(entries, *entry)
		}

		recordNum++
	}

	return entries
}

// parseMFTRecord parses a single MFT record
func (c *MFTCollector) parseMFTRecord(data []byte, recordNumber uint64) *types.MFTEntry {
	if len(data) < 42 {
		return nil
	}

	// Check FILE signature
	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != mftSignature {
		return nil
	}

	// Flags at offset 22 (2 bytes)
	flags := binary.LittleEndian.Uint16(data[22:24])
	inUse := flags&0x01 != 0
	isDirectory := flags&0x02 != 0

	// Skip directories for now (focus on files)
	_ = isDirectory

	// First attribute offset at offset 20 (2 bytes)
	firstAttrOffset := int(binary.LittleEndian.Uint16(data[20:22]))
	if firstAttrOffset < 42 || firstAttrOffset >= len(data) {
		return nil
	}

	entry := &types.MFTEntry{
		RecordNumber: recordNumber,
		InUse:        inUse,
		IsDeleted:    !inUse,
	}

	// Walk attributes
	offset := firstAttrOffset
	for offset+8 < len(data) {
		attrType := binary.LittleEndian.Uint32(data[offset : offset+4])
		if attrType == attrEndMarker || attrType == 0 {
			break
		}

		attrLen := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if attrLen <= 0 || offset+attrLen > len(data) {
			break
		}

		switch attrType {
		case attrStdInfo:
			c.parseStdInfo(data[offset:offset+attrLen], entry)
		case attrFileName:
			c.parseFileName(data[offset:offset+attrLen], entry)
		}

		offset += attrLen
	}

	if entry.FileName == "" {
		return nil
	}

	return entry
}

// parseStdInfo parses $STANDARD_INFORMATION attribute
func (c *MFTCollector) parseStdInfo(data []byte, entry *types.MFTEntry) {
	// Non-resident check (byte at offset 8)
	if len(data) < 24 {
		return
	}
	isResident := data[8] == 0
	if !isResident {
		return
	}

	// Content offset at offset 20 (2 bytes)
	contentOffset := int(binary.LittleEndian.Uint16(data[20:22]))
	if contentOffset+32 > len(data) {
		return
	}

	content := data[contentOffset:]
	if len(content) < 32 {
		return
	}

	// $SI timestamps (all FILETIME, 8 bytes each)
	entry.SICreated = filetimeToTime(binary.LittleEndian.Uint64(content[0:8]))
	entry.SIModified = filetimeToTime(binary.LittleEndian.Uint64(content[8:16]))
}

// parseFileName parses $FILE_NAME attribute
func (c *MFTCollector) parseFileName(data []byte, entry *types.MFTEntry) {
	if len(data) < 24 {
		return
	}
	isResident := data[8] == 0
	if !isResident {
		return
	}

	contentOffset := int(binary.LittleEndian.Uint16(data[20:22]))
	if contentOffset+66 > len(data) {
		return
	}

	content := data[contentOffset:]
	if len(content) < 66 {
		return
	}

	// Parent directory reference (8 bytes, first 6 = record number, last 2 = sequence)
	// $FN timestamps
	entry.FNCreated = filetimeToTime(binary.LittleEndian.Uint64(content[8:16]))
	entry.FNModified = filetimeToTime(binary.LittleEndian.Uint64(content[16:24]))

	// File size at offset 40 (8 bytes)
	entry.FileSize = int64(binary.LittleEndian.Uint64(content[40:48]))

	// Name length at offset 64 (1 byte)
	nameLen := int(content[64])
	// Name namespace at offset 65 (1 byte): 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS
	nameNamespace := content[65]

	// Only use Win32 or Win32&DOS names (skip DOS 8.3 names)
	if nameNamespace == 2 && entry.FileName != "" {
		return // Skip DOS names if we already have a Win32 name
	}

	if 66+nameLen*2 > len(content) {
		return
	}

	// File name is UTF-16LE
	entry.FileName = decodeUTF16LE(content[66 : 66+nameLen*2])
}

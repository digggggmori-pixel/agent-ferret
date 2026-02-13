package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
	"golang.org/x/sys/windows"
)

// PrefetchCollector parses Windows Prefetch (.pf) files
type PrefetchCollector struct{}

// NewPrefetchCollector creates a new Prefetch collector
func NewPrefetchCollector() *PrefetchCollector {
	return &PrefetchCollector{}
}

var (
	ntdll                    = windows.NewLazyDLL("ntdll.dll")
	procRtlDecompressBufferEx = ntdll.NewProc("RtlDecompressBufferEx")
)

const (
	// Compression format constants
	compressionFormatXpressHuff = 0x0004

	// Prefetch signatures
	prefetchCompressedSig = 0x044D414D // "MAM\x04" (little-endian)
	prefetchVersion30     = 30         // Windows 10

	// Prefetch v30 header offsets (inside decompressed data)
	pfV30ExeNameOffset    = 16
	pfV30ExeNameSize      = 60 // 30 UTF-16 chars
	pfV30RunCountOffset   = 208
	pfV30LastRunOffset    = 128
	pfV30LastRunCount     = 8 // Up to 8 last run times
)

// Collect reads and parses all Prefetch files from the Windows Prefetch directory
func (c *PrefetchCollector) Collect() ([]types.PrefetchInfo, error) {
	logger.Section("Prefetch Collection")
	startTime := time.Now()

	var entries []types.PrefetchInfo

	winDir := os.Getenv("WINDIR")
	if winDir == "" {
		winDir = `C:\Windows`
	}
	prefetchDir := filepath.Join(winDir, "Prefetch")

	dirEntries, err := os.ReadDir(prefetchDir)
	if err != nil {
		logger.Error("Cannot read Prefetch directory: %v", err)
		return entries, nil
	}

	for _, de := range dirEntries {
		if de.IsDir() || !strings.HasSuffix(strings.ToLower(de.Name()), ".pf") {
			continue
		}

		fullPath := filepath.Join(prefetchDir, de.Name())
		info, err := c.parsePrefetchFile(fullPath)
		if err != nil {
			logger.Debug("Failed to parse %s: %v", de.Name(), err)
			continue
		}

		if info != nil {
			fi, _ := de.Info()
			if fi != nil {
				info.FileSize = fi.Size()
			}
			entries = append(entries, *info)
		}
	}

	logger.Timing("PrefetchCollector.Collect", startTime)
	logger.Info("Prefetch: %d files parsed", len(entries))

	return entries, nil
}

func (c *PrefetchCollector) parsePrefetchFile(path string) (*types.PrefetchInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) < 8 {
		return nil, nil
	}

	// Check for compressed format (MAM\x04)
	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig == prefetchCompressedSig {
		return c.parseCompressedPrefetch(path, data)
	}

	// Try uncompressed format
	return c.parseUncompressedPrefetch(path, data)
}

func (c *PrefetchCollector) parseCompressedPrefetch(path string, data []byte) (*types.PrefetchInfo, error) {
	if len(data) < 8 {
		return nil, nil
	}

	// Compressed header:
	//   0-3: Signature (MAM\x04)
	//   4-7: Uncompressed size
	uncompressedSize := binary.LittleEndian.Uint32(data[4:8])
	compressedData := data[8:]

	if uncompressedSize == 0 || uncompressedSize > 10*1024*1024 { // Max 10MB
		return nil, nil
	}

	// Decompress using Windows RtlDecompressBufferEx (LZXPRESS Huffman)
	decompressed, err := decompressXpressHuffman(compressedData, uncompressedSize)
	if err != nil {
		logger.Debug("Decompression failed for %s: %v", filepath.Base(path), err)
		return nil, nil
	}

	return c.parseUncompressedPrefetch(path, decompressed)
}

func (c *PrefetchCollector) parseUncompressedPrefetch(path string, data []byte) (*types.PrefetchInfo, error) {
	if len(data) < 84 {
		return nil, nil
	}

	// Check version
	version := binary.LittleEndian.Uint32(data[0:4])
	if version != prefetchVersion30 && version != 23 && version != 26 {
		// Only parse known versions (17=XP, 23=Vista/7, 26=Win8, 30=Win10+)
		// We focus on v30 but try others for basic info
	}

	// Executable name at offset 16 (60 bytes, UTF-16LE)
	exeName := ""
	if len(data) >= pfV30ExeNameOffset+pfV30ExeNameSize {
		exeName = decodeUTF16LE(data[pfV30ExeNameOffset : pfV30ExeNameOffset+pfV30ExeNameSize])
		// Trim null and any trailing garbage
		if idx := strings.IndexByte(exeName, 0); idx >= 0 {
			exeName = exeName[:idx]
		}
	}

	if exeName == "" {
		return nil, nil
	}

	info := &types.PrefetchInfo{
		ExecutableName: exeName,
		PrefetchPath:   path,
	}

	// Run count (offset 208 for v30, different for other versions)
	runCountOffset := pfV30RunCountOffset
	if version == 23 {
		runCountOffset = 152
	} else if version == 26 {
		runCountOffset = 208
	}

	if len(data) >= runCountOffset+4 {
		info.RunCount = binary.LittleEndian.Uint32(data[runCountOffset : runCountOffset+4])
	}

	// Last run times (8 FILETIME values for v30, 1 for older)
	lastRunOffset := pfV30LastRunOffset
	if version == 23 {
		lastRunOffset = 120
	} else if version == 26 {
		lastRunOffset = 128
	}

	numRunTimes := pfV30LastRunCount
	if version == 23 {
		numRunTimes = 1
	}

	for i := 0; i < numRunTimes; i++ {
		off := lastRunOffset + (i * 8)
		if off+8 > len(data) {
			break
		}
		ft := binary.LittleEndian.Uint64(data[off : off+8])
		t := filetimeToTime(ft)
		if !t.IsZero() {
			info.LastRunTimes = append(info.LastRunTimes, t)
		}
	}

	return info, nil
}

// decompressXpressHuffman uses Windows RtlDecompressBufferEx to decompress LZXPRESS Huffman data
func decompressXpressHuffman(compressed []byte, uncompressedSize uint32) ([]byte, error) {
	output := make([]byte, uncompressedSize)

	// RtlDecompressBufferEx needs a workspace buffer
	workspace := make([]byte, 256*1024) // 256KB workspace

	var finalSize uint32

	ret, _, _ := procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(uncompressedSize),
		uintptr(unsafe.Pointer(&compressed[0])),
		uintptr(len(compressed)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)

	// NTSTATUS: 0 = STATUS_SUCCESS
	if ret != 0 {
		return nil, windows.NTStatus(ret)
	}

	return output[:finalSize], nil
}

// Package logger provides debug logging functionality for Agent Lite
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Level represents log level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger is the main logger instance
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
	enabled  bool
	level    Level
}

var (
	instance *Logger
	once     sync.Once
)

// Init initializes the global logger
func Init(outputDir string, enabled bool) error {
	var initErr error
	once.Do(func() {
		instance = &Logger{
			enabled: enabled,
			level:   LevelDebug,
		}

		if !enabled {
			return
		}

		// Create log file with timestamp
		timestamp := time.Now().Format("20060102_150405")
		hostname, _ := os.Hostname()
		logFileName := fmt.Sprintf("agent-lite_debug_%s_%s.log", hostname, timestamp)

		if outputDir == "" {
			outputDir = "."
		}

		logPath := filepath.Join(outputDir, logFileName)
		file, err := os.Create(logPath)
		if err != nil {
			initErr = fmt.Errorf("failed to create log file: %w", err)
			return
		}

		instance.file = file
		instance.filePath = logPath

		// Write header
		instance.writeHeader()
	})

	return initErr
}

// GetLogPath returns the path to the log file
func GetLogPath() string {
	if instance == nil || instance.file == nil {
		return ""
	}
	return instance.filePath
}

// Close closes the log file
func Close() {
	if instance != nil && instance.file != nil {
		instance.writeFooter()
		instance.file.Close()
	}
}

func (l *Logger) writeHeader() {
	l.mu.Lock()
	defer l.mu.Unlock()

	hostname, _ := os.Hostname()
	header := fmt.Sprintf(`================================================================================
Agent Lite Debug Log
================================================================================
Start Time: %s
Hostname:   %s
OS:         %s/%s
Go Version: %s
================================================================================

`, time.Now().Format("2006-01-02 15:04:05.000 MST"), hostname, runtime.GOOS, runtime.GOARCH, runtime.Version())

	l.file.WriteString(header)
}

func (l *Logger) writeFooter() {
	l.mu.Lock()
	defer l.mu.Unlock()

	footer := fmt.Sprintf(`
================================================================================
End Time: %s
================================================================================
`, time.Now().Format("2006-01-02 15:04:05.000 MST"))

	l.file.WriteString(footer)
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if l == nil || !l.enabled || l.file == nil {
		return
	}

	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)

	// Get caller info
	_, file, line, ok := runtime.Caller(2)
	caller := ""
	if ok {
		caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	logLine := fmt.Sprintf("[%s] [%-5s] [%-20s] %s\n", timestamp, level.String(), caller, msg)
	l.file.WriteString(logLine)
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	if instance != nil {
		instance.log(LevelDebug, format, args...)
	}
}

// Info logs an info message
func Info(format string, args ...interface{}) {
	if instance != nil {
		instance.log(LevelInfo, format, args...)
	}
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	if instance != nil {
		instance.log(LevelWarn, format, args...)
	}
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	if instance != nil {
		instance.log(LevelError, format, args...)
	}
}

// Section logs a section header for better readability
func Section(name string) {
	if instance != nil {
		instance.log(LevelInfo, "")
		instance.log(LevelInfo, "========== %s ==========", name)
	}
}

// SubSection logs a subsection header
func SubSection(name string) {
	if instance != nil {
		instance.log(LevelInfo, "--- %s ---", name)
	}
}

// Data logs structured data (key-value pairs)
func Data(prefix string, data map[string]interface{}) {
	if instance == nil || !instance.enabled {
		return
	}
	for k, v := range data {
		Debug("%s.%s = %v", prefix, k, v)
	}
}

// Timing logs execution time for a function
func Timing(operation string, start time.Time) {
	if instance != nil {
		elapsed := time.Since(start)
		instance.log(LevelDebug, "[TIMING] %s completed in %v", operation, elapsed)
	}
}

// ProcessInfo logs process information
func ProcessInfo(pid uint32, name, path, cmdline string) {
	Debug("Process: PID=%d Name=%s Path=%s CmdLine=%s", pid, name, path, truncate(cmdline, 200))
}

// NetworkInfo logs network connection information
func NetworkInfo(protocol, localAddr string, localPort uint16, remoteAddr string, remotePort uint16, state string, pid uint32) {
	Debug("Network: %s %s:%d -> %s:%d [%s] PID=%d", protocol, localAddr, localPort, remoteAddr, remotePort, state, pid)
}

// ServiceInfo logs service information
func ServiceInfo(name, displayName, status, startType, binaryPath string) {
	Debug("Service: %s (%s) Status=%s StartType=%s Path=%s", name, displayName, status, startType, truncate(binaryPath, 200))
}

// DetectionInfo logs detection information
func DetectionInfo(detType, severity, description string) {
	Info("Detection: [%s] [%s] %s", severity, detType, description)
}

// SigmaMatch logs sigma rule match
func SigmaMatch(ruleID, ruleName, severity string, eventID uint32) {
	Info("Sigma Match: %s (%s) Severity=%s EventID=%d", ruleName, ruleID, severity, eventID)
}

// APICall logs Windows API calls
func APICall(api string, params ...interface{}) {
	paramStr := fmt.Sprintf("%v", params)
	Debug("API Call: %s %s", api, paramStr)
}

// APIResult logs Windows API call results
func APIResult(api string, result interface{}, err error) {
	if err != nil {
		Error("API Result: %s failed: %v", api, err)
	} else {
		Debug("API Result: %s success: %v", api, result)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

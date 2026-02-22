package collector

import (
	"encoding/csv"
	"os/exec"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-ferret/internal/logger"
	"github.com/digggggmori-pixel/agent-ferret/pkg/types"
)

// ScheduledTaskCollector collects Windows scheduled tasks
type ScheduledTaskCollector struct{}

// NewScheduledTaskCollector creates a new scheduled task collector
func NewScheduledTaskCollector() *ScheduledTaskCollector {
	return &ScheduledTaskCollector{}
}

// Collect retrieves all scheduled tasks via schtasks CSV output
func (c *ScheduledTaskCollector) Collect() ([]types.ScheduledTaskInfo, error) {
	logger.Section("Scheduled Task Collection")
	startTime := time.Now()

	var tasks []types.ScheduledTaskInfo

	// Use schtasks with CSV format for reliable parsing
	cmd := exec.Command("schtasks", "/Query", "/FO", "CSV", "/V", "/NH")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to query scheduled tasks: %v", err)
		return tasks, nil
	}

	reader := csv.NewReader(strings.NewReader(decodeOEMOutput(output)))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // Variable fields

	records, err := reader.ReadAll()
	if err != nil {
		logger.Error("Failed to parse schtasks CSV: %v", err)
		return tasks, nil
	}

	// schtasks /V /FO CSV columns (no header with /NH):
	// 0:HostName, 1:TaskName, 2:NextRunTime, 3:Status, 4:LogonMode,
	// 5:LastRunTime, 6:LastResult, 7:Author, 8:TaskToRun, 9:StartIn,
	// 10:Comment, 11:ScheduledTaskState, 12:IdleTime, 13:PowerManagement,
	// 14:RunAsUser, 15:DeleteTaskIfNotRescheduled, 16:StopTaskIfRunsXHours,
	// 17:Schedule, 18:ScheduleType, 19:StartTime, 20:StartDate,
	// 21:EndDate, 22:Days, 23:Months, 24:RepeatEvery, 25:RepeatUntilTime,
	// 26:RepeatUntilDuration, 27:RepeatStopIfStillRunning
	for _, record := range records {
		if len(record) < 15 {
			continue
		}

		taskName := strings.TrimSpace(record[1])
		// Skip Microsoft built-in tasks for noise reduction
		if strings.HasPrefix(taskName, `\Microsoft\`) {
			continue
		}

		task := types.ScheduledTaskInfo{
			Name:   taskName,
			Path:   taskName,
			State:  strings.TrimSpace(record[3]),
			Author: safeField(record, 7),
		}

		// Parse task to run (action)
		if len(record) > 8 {
			actionPath := strings.TrimSpace(record[8])
			task.ActionPath, task.ActionArgs = splitTaskAction(actionPath)
		}

		// Parse principal (Run As User)
		task.Principal = safeField(record, 14)

		// Parse comment/description
		task.Description = safeField(record, 10)

		// Parse scheduled task state (Enabled/Disabled)
		if len(record) > 11 {
			state := strings.TrimSpace(record[11])
			if strings.EqualFold(state, "Disabled") {
				task.State = "Disabled"
			}
		}

		// Parse times
		task.NextRunTime = parseTaskTime(safeField(record, 2))
		task.LastRunTime = parseTaskTime(safeField(record, 5))

		// Hidden detection: tasks in unusual paths
		task.IsHidden = strings.Contains(taskName, "{") && strings.Contains(taskName, "}")

		tasks = append(tasks, task)
	}

	logger.Timing("ScheduledTaskCollector.Collect", startTime)
	logger.Info("Scheduled tasks: %d non-Microsoft tasks", len(tasks))

	return tasks, nil
}

func splitTaskAction(action string) (path, args string) {
	action = strings.TrimSpace(action)
	if action == "" || strings.EqualFold(action, "N/A") {
		return "", ""
	}

	// Handle quoted paths
	if strings.HasPrefix(action, `"`) {
		endQuote := strings.Index(action[1:], `"`)
		if endQuote > 0 {
			path = action[1 : endQuote+1]
			args = strings.TrimSpace(action[endQuote+2:])
			return
		}
	}

	// Split on first space
	parts := strings.SplitN(action, " ", 2)
	path = parts[0]
	if len(parts) > 1 {
		args = parts[1]
	}
	return
}

func safeField(record []string, idx int) string {
	if idx < len(record) {
		return strings.TrimSpace(record[idx])
	}
	return ""
}

func parseTaskTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "N/A") || strings.EqualFold(s, "Never") {
		return time.Time{}
	}

	// Try common schtasks date formats
	formats := []string{
		"1/2/2006 3:04:05 PM",
		"2006/01/02 15:04:05",
		"01/02/2006 15:04:05",
		"2006-01-02 15:04:05",
		"1/2/2006 15:04:05",
	}

	for _, fmt := range formats {
		if t, err := time.Parse(fmt, s); err == nil {
			return t
		}
	}

	return time.Time{}
}

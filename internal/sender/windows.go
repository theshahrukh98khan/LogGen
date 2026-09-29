package sender

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// This file turns a WinEvent into the two shapes a SIEM commonly receives
// Windows logs in: Snare's tab-delimited MSWinEventLog line, and the
// eventchannel JSON that the Wazuh agent emits.

// encodeWinSnare renders the classic Snare record.
//
// The layout is fifteen tab-separated fields. Field 13 (DataString) is left
// empty, as Snare itself leaves it for most events, which is why two tabs
// appear in a row before the description.
func encodeWinSnare(e *core.WinEvent, now time.Time) string {
	fields := []string{
		"MSWinEventLog",                        // 1  header
		strconv.Itoa(e.Criticality),            // 2  criticality 0-4
		e.Channel,                              // 3  log name
		strconv.Itoa(e.RecordID),               // 4  Snare event counter
		now.Format("Mon Jan 02 15:04:05 2006"), // 5  submit time
		e.EventID,                              // 6  event ID
		e.Provider,                             // 7  source name
		snareUser(e.User),                      // 8  user
		snareSIDType(e.User),                   // 9  SID type
		e.AuditType,                            // 10 event log type
		e.Computer,                             // 11 computer
		e.TaskName,                             // 12 category
		"",                                     // 13 data string
		snareFlatten(e.Message),                // 14 expanded description
		strconv.Itoa(e.RecordID),               // 15 counter
	}
	return strings.Join(fields, "\t")
}

// snareFlatten collapses the description to one line. Tabs must go too: a stray
// tab inside the description would be read as a field separator and shift every
// field after it.
func snareFlatten(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	for strings.Contains(s, "   ") {
		s = strings.ReplaceAll(s, "   ", "  ")
	}
	return strings.TrimSpace(s)
}

func snareUser(u string) string {
	if strings.TrimSpace(u) == "" {
		return "N/A"
	}
	return u
}

// snareSIDType reports what kind of principal field 8 holds.
func snareSIDType(u string) string {
	switch {
	case strings.TrimSpace(u) == "", u == "N/A", u == "-":
		return "N/A"
	case strings.HasSuffix(u, "$"):
		return "Computer"
	default:
		return "User"
	}
}

// ---------------------------------------------------------------------------
// Eventchannel JSON
// ---------------------------------------------------------------------------

type winJSONEnvelope struct {
	Win winJSONBody `json:"win"`
}

type winJSONBody struct {
	System    map[string]string `json:"system"`
	EventData map[string]string `json:"eventdata,omitempty"`
}

// encodeWinJSON renders the shape a Wazuh agent forwards for Windows events,
// so a rule written against win.system.* and win.eventdata.* fields matches
// whether the record came from an agent or from here.
func encodeWinJSON(e *core.WinEvent, now time.Time) string {
	sys := map[string]string{
		"providerName":  e.Provider,
		"eventID":       e.EventID,
		"version":       "0",
		"level":         "0",
		"task":          e.Task,
		"opcode":        "0",
		"keywords":      e.Keywords,
		"systemTime":    now.UTC().Format("2006-01-02T15:04:05.0000000Z"),
		"eventRecordID": strconv.Itoa(e.RecordID),
		"processID":     strconv.Itoa(e.ProcessID),
		"threadID":      strconv.Itoa(e.ThreadID),
		"channel":       e.Channel,
		"computer":      e.Computer,
		"severityValue": severityValue(e.AuditType),
		"message":       e.Message,
	}
	if e.ProviderGUID != "" {
		sys["providerGuid"] = e.ProviderGUID
	}

	env := winJSONEnvelope{Win: winJSONBody{System: sys, EventData: e.EventData}}

	// json.Marshal escapes newlines and tabs inside the description, so the
	// result is already a single physical line.
	b, err := json.Marshal(env)
	if err != nil {
		return ""
	}
	return string(b)
}

func severityValue(auditType string) string {
	switch auditType {
	case core.AuditSuccess:
		return "AUDIT_SUCCESS"
	case core.AuditFailure:
		return "AUDIT_FAILURE"
	case core.AuditWarning:
		return "WARNING"
	case core.AuditError:
		return "ERROR"
	default:
		return "INFORMATION"
	}
}

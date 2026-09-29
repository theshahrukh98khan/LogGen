// Package core holds the shared types used across LogGen: the simulated
// estate (Env), the SIEM targets (Profile), and the catalog contract that each
// log source (Windows, Linux, Nginx, Apache) plugs into.
package core

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Simulated estate
// ---------------------------------------------------------------------------

// Env describes the fake environment the generated logs refer to. Keeping it in
// one place is what makes a Windows logon, a sudo call and an Nginx hit look
// like they came from the same organisation.
type Env struct {
	Domain    string `json:"domain"`    // corp.local
	NetBIOS   string `json:"netbios"`   // CORP
	WinHost   string `json:"winHost"`   // WIN-DC01
	LinuxHost string `json:"linuxHost"` // ubuntu-app01
	WebHost   string `json:"webHost"`   // web-prod01
	DBHost    string `json:"dbHost"`    // oracle-db01
	DBName    string `json:"dbName"`    // ORCL  (Oracle SID / service name)
	Subnet    string `json:"subnet"`    // 10.20.30  (first three octets)
}

// DefaultEnv is the estate a fresh install starts with.
func DefaultEnv() Env {
	return Env{
		Domain:    "corp.local",
		NetBIOS:   "CORP",
		WinHost:   "WIN-DC01",
		LinuxHost: "ubuntu-app01",
		WebHost:   "web-prod01",
		DBHost:    "oracle-db01",
		DBName:    "ORCL",
		Subnet:    "10.20.30",
	}
}

// Normalize fills any blank field with its default.
func (e Env) Normalize() Env {
	d := DefaultEnv()
	if strings.TrimSpace(e.Domain) == "" {
		e.Domain = d.Domain
	}
	if strings.TrimSpace(e.NetBIOS) == "" {
		e.NetBIOS = d.NetBIOS
	}
	if strings.TrimSpace(e.WinHost) == "" {
		e.WinHost = d.WinHost
	}
	if strings.TrimSpace(e.LinuxHost) == "" {
		e.LinuxHost = d.LinuxHost
	}
	if strings.TrimSpace(e.WebHost) == "" {
		e.WebHost = d.WebHost
	}
	if strings.TrimSpace(e.DBHost) == "" {
		e.DBHost = d.DBHost
	}
	if strings.TrimSpace(e.DBName) == "" {
		e.DBName = d.DBName
	}
	if strings.TrimSpace(e.Subnet) == "" {
		e.Subnet = d.Subnet
	}
	e.NetBIOS = strings.ToUpper(e.NetBIOS)
	e.DBName = strings.ToUpper(strings.TrimSpace(e.DBName))
	e.Subnet = strings.TrimSuffix(strings.TrimSpace(e.Subnet), ".")
	return e
}

// ---------------------------------------------------------------------------
// SIEM target profiles
// ---------------------------------------------------------------------------

// Transport protocols.
const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"
)

// Wire formats for the syslog header.
const (
	FormatRFC3164 = "rfc3164" // classic BSD syslog, what Wazuh's syslog listener expects
	FormatRFC5424 = "rfc5424" // structured syslog
	FormatRaw     = "raw"     // no header at all, just the log line
)

// TCP framing modes (RFC 6587).
const (
	FramingLF    = "lf"    // non-transparent framing, newline delimited
	FramingOctet = "octet" // octet counting: "<len> <msg>"
)

// Profile is one SIEM target: where to send, over what, in what shape.
type Profile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`   // udp | tcp
	Format     string `json:"format"`     // rfc3164 | rfc5424 | raw
	TCPFraming string `json:"tcpFraming"` // lf | octet
	WinFormat  string `json:"winFormat"`  // snare | json   (used by the Windows source)
	WebRaw     bool   `json:"webRaw"`     // send web access logs with no syslog header
	IsDefault  bool   `json:"isDefault"`
}

// Addr is the dial target.
func (p Profile) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// Normalize applies defaults and clamps anything invalid so a half-filled form
// from the UI still produces a usable profile.
func (p Profile) Normalize() Profile {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "Unnamed profile"
	}
	p.Host = strings.TrimSpace(p.Host)
	if p.Host == "" {
		p.Host = "127.0.0.1"
	}
	if p.Port <= 0 || p.Port > 65535 {
		p.Port = 514
	}
	switch strings.ToLower(p.Protocol) {
	case ProtoTCP:
		p.Protocol = ProtoTCP
	default:
		p.Protocol = ProtoUDP
	}
	switch strings.ToLower(p.Format) {
	case FormatRFC5424:
		p.Format = FormatRFC5424
	case FormatRaw:
		p.Format = FormatRaw
	default:
		p.Format = FormatRFC3164
	}
	switch strings.ToLower(p.TCPFraming) {
	case FramingOctet:
		p.TCPFraming = FramingOctet
	default:
		p.TCPFraming = FramingLF
	}
	switch strings.ToLower(p.WinFormat) {
	case "json":
		p.WinFormat = "json"
	default:
		p.WinFormat = "snare"
	}
	return p
}

// DefaultProfile is the target created on first run: a local Wazuh manager
// listening on the standard syslog port.
func DefaultProfile() Profile {
	return Profile{
		ID:         "wazuh-local",
		Name:       "Wazuh Manager (local)",
		Host:       "127.0.0.1",
		Port:       514,
		Protocol:   ProtoUDP,
		Format:     FormatRFC3164,
		TCPFraming: FramingLF,
		WinFormat:  "snare",
		WebRaw:     false,
		IsDefault:  true,
	}
}

// ---------------------------------------------------------------------------
// Syslog facilities and severities (RFC 5424 numeric values)
// ---------------------------------------------------------------------------

const (
	FacKern     = 0
	FacUser     = 1
	FacMail     = 2
	FacDaemon   = 3
	FacAuth     = 4
	FacSyslog   = 5
	FacCron     = 9
	FacAuthPriv = 10
	FacLocal0   = 16
	FacLocal1   = 17
	FacLocal2   = 18
	FacLocal3   = 19
	FacLocal4   = 20
	FacLocal5   = 21
	FacLocal6   = 22
	FacLocal7   = 23
)

const (
	SevEmerg   = 0
	SevAlert   = 1
	SevCrit    = 2
	SevErr     = 3
	SevWarning = 4
	SevNotice  = 5
	SevInfo    = 6
	SevDebug   = 7
)

// Priority is the syslog PRI value: facility*8 + severity.
func Priority(facility, severity int) int { return facility*8 + severity }

// ---------------------------------------------------------------------------
// Catalog contract
// ---------------------------------------------------------------------------

// Log source identifiers.
const (
	SourceWindows = "windows"
	SourceLinux   = "linux"
	SourceNginx   = "nginx"
	SourceApache  = "apache"
	SourceOracle  = "oracle"
)

// Severity labels used for colour coding in the UI.
const (
	SevLabelInfo     = "info"
	SevLabelLow      = "low"
	SevLabelMedium   = "medium"
	SevLabelHigh     = "high"
	SevLabelCritical = "critical"
)

// Param is one operator-editable field on a control (username, source IP, ...).
// Leaving it blank in the UI means "generate something realistic".
type Param struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
}

// Control is the metadata for one clickable simulation. It is pure data so it
// can be serialised straight to the UI.
type Control struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"`
	Group    string   `json:"group"`
	Name     string   `json:"name"`
	Desc     string   `json:"desc"`
	EventID  string   `json:"eventId,omitempty"` // Windows Event ID
	Channel  string   `json:"channel,omitempty"` // Windows channel / Linux facility
	Severity string   `json:"severity"`
	Mitre    []string `json:"mitre,omitempty"` // ATT&CK technique IDs
	Wazuh    []string `json:"wazuh,omitempty"` // rule IDs expected to fire
	Params   []Param  `json:"params,omitempty"`
}

// Windows audit outcomes, as they appear in the Snare EventLogType field.
const (
	AuditSuccess = "Success Audit"
	AuditFailure = "Failure Audit"
	AuditInfo    = "Information"
	AuditWarning = "Warning"
	AuditError   = "Error"
)

// WinEvent is one Windows event log record, held in a format-neutral shape so
// the same definition can be emitted as Snare or as eventchannel JSON.
type WinEvent struct {
	EventID      string
	Channel      string // Security, System, Microsoft-Windows-PowerShell/Operational, ...
	Provider     string
	ProviderGUID string
	Task         string // numeric task code
	TaskName     string // the category string shown in Event Viewer
	AuditType    string // one of the Audit* constants
	Keywords     string
	Computer     string
	User         string // the account Windows attributes the record to
	Message      string // the full multi-line description
	EventData    map[string]string
	Criticality  int // Snare criticality, 0-4
	RecordID     int
	ProcessID    int
	ThreadID     int
}

// Payload is what a control produces: a single log record, already rendered,
// but not yet wrapped in a syslog header.
type Payload struct {
	Kind     string // one of the Source* constants
	Tag      string // syslog tag / program name, e.g. "sshd"; empty for none
	PID      int    // syslog tag PID, 0 for none
	Host     string // syslog hostname
	Facility int
	Severity int
	Message  string    // the log line itself; ignored when Win is set
	Win      *WinEvent // set for Windows records, which the sender encodes
	Raw      bool      // true to skip the syslog header entirely
}

// Definition binds a Control's metadata to the function that renders it.
type Definition struct {
	Control
	Build func(c *Ctx) Payload
}

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------

// Activity is one send attempt, kept in a ring buffer for the UI.
type Activity struct {
	// Seq increases monotonically for the life of the process. The console uses
	// it to append only what is new, instead of rebuilding the whole feed on
	// every poll, which would discard any text the operator had selected.
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	ControlID string    `json:"controlId"`
	Control   string    `json:"control"`
	Source    string    `json:"source"`
	Profile   string    `json:"profile"`
	Target    string    `json:"target"`
	Wire      string    `json:"wire"`
	Bytes     int       `json:"bytes"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
}

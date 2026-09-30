package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Trend Micro Vision One controls.
//
// Vision One is a cloud XDR platform; its Syslog Connector forwards events in
// CEF. The header is seven pipe-separated fields:
//
//	CEF:0|Trend Micro|Vision One|<product version>|<signature id>|<name>|<severity>|<extensions>
//
// Everything after the seventh pipe is space-separated key=value extensions.
// Pipes inside a header field and equals signs inside an extension value must
// be escaped, which is what cefHeaderEscape and cefValueEscape handle: getting
// that wrong is the usual reason a CEF line fails to parse.
//
// These are Vision One records specifically, not Deep Security or Apex One,
// which are separate products with their own formats.
//
// Source: Trend Vision One event logging and Syslog Content Mapping - CEF.
//
//	https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-event-logging
//	https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-syslog-mapping-cef
//
// What the published documentation confirms, and what these records follow:
//
//   - The Syslog Connector forwards Workbench alerts, Observed Attack
//     Techniques, and account and system audit logs. Those are the categories
//     modelled here.
//   - src, spt, dst and dpt carry straight through with their CEF meanings.
//   - The CEF mapping is applied globally across endpoint events, so a given
//     event will not populate every field. Events originating from products
//     that do not report network data, Apex One among them, arrive with src,
//     spt, dst and dpt empty. oatNoNetwork below reproduces that rather than
//     always filling them in, because a rule written against a field that is
//     usually absent will not fire.
//   - One OAT event carrying several filter objects is split into one syslog
//     entry per object. Each entry repeats the parent id and carries its own
//     unique_id, which is how a SIEM is meant to regroup them.
//
// What is NOT confirmed: the exact custom-string slot assignments. The vendor
// pages that hold the cs1Label through cs6Label table do not render, so those
// below are inferred from the field names Vision One exposes and should be
// checked against a real forwarder before a decoder is written against them.

const (
	cefVersion    = "CEF:0"
	cefVendor     = "Trend Micro"
	cefProduct    = "Vision One"
	cefProductVer = "1.0"
)

// cefHeaderEscape escapes the characters CEF reserves in a header field.
func cefHeaderEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefValueEscape escapes the characters CEF reserves in an extension value.
func cefValueEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	// A newline inside a value has to be escaped rather than emitted.
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", "")
}

// cefRecord assembles a full CEF line.
func cefRecord(sigID, name string, severity int, ext []string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s",
		cefVersion, cefVendor, cefProduct, cefProductVer,
		cefHeaderEscape(sigID), cefHeaderEscape(name), severity,
		strings.Join(ext, " "))
}

// kv renders one CEF extension pair.
func cefKV(k, v string) string { return k + "=" + cefValueEscape(v) }

// cefTime is the format CEF's rt and similar fields use.
func cefTime(c *core.Ctx) string { return c.Now.Format("Jan 02 2006 15:04:05") }

func trendPayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind: core.SourceTrendVision,
		// No syslog tag: the CEF record is the message, and a tag would put
		// "CEF: " in front of "CEF:0|...".
		Host: "visionone",
		// The Vision One syslog connector is commonly pointed at local0.
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

func init() {
	registerTrendVisionOne()
}

func registerTrendVisionOne() {
	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-workbench-alert", Source: core.SourceTrendVision,
			Group: "Workbench", Name: "Workbench alert",
			Desc:    "A correlated detection raised in the Workbench, which is the alert an analyst actually triages.",
			EventID: "WB", Channel: "workbench", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1059.001"},
			Params: []core.Param{pUser, param("host", "Endpoint", "auto"), param("model", "Detection model", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			model := c.P("model", c.Pick(
				"Possible Credential Dumping via LSASS",
				"Suspicious PowerShell Download Cradle",
				"Cobalt Strike Beacon Behaviour",
			))
			wbID := fmt.Sprintf("WB-%d-%s", c.Int(1000, 9999), c.Now.Format("20060102"))

			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("dvchost", host),
				cefKV("suser", c.Env.NetBIOS+`\`+user),
				cefKV("src", c.InternalIP()),
				cefKV("dst", c.ExternalIP()),
				cefKV("externalId", wbID),
				cefKV("cat", "Workbench"),
				cefKV("cs1Label", "modelName"),
				cefKV("cs1", model),
				cefKV("cs2Label", "modelId"),
				cefKV("cs2", strings.Trim(c.GUID(), "{}")),
				cefKV("cs3Label", "severity"),
				cefKV("cs3", "critical"),
				cefKV("cs4Label", "mitreTactic"),
				cefKV("cs4", "Execution"),
				cefKV("cs5Label", "mitreTechnique"),
				cefKV("cs5", "T1059.001"),
				cefKV("cn1Label", "score"),
				cefKV("cn1", fmt.Sprint(c.Int(70, 100))),
				cefKV("msg", model+" detected on "+host),
			}
			return trendPayload(c, core.SevCrit, cefRecord(wbID, model, 9, ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-oat-technique", Source: core.SourceTrendVision,
			Group: "Observed Attack Techniques", Name: "Observed attack technique",
			Desc:    "An OAT event: a single observed behaviour mapped to an ATT&CK technique, below the threshold of a Workbench alert.",
			EventID: "OAT", Channel: "oat", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1003.001", "T1059.001", "T1047"},
			Params: []core.Param{pUser, param("host", "Endpoint", "auto"), param("technique", "ATT&CK technique", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())

			type oat struct{ id, name, tactic, filter string }
			pick := []oat{
				{"T1003.001", "LSASS Memory Access", "Credential Access",
					"Credential Dumping via Process Access to LSASS"},
				{"T1059.001", "PowerShell Encoded Command", "Execution",
					"Encoded PowerShell Command Execution"},
				{"T1047", "WMI Process Creation", "Execution",
					"Process Created via WMI"},
			}
			o := pick[c.Int(0, len(pick)-1)]
			if t := c.P("technique", ""); t != "" {
				o.id = t
			}

			// A parent id shared across the entries an event splits into, and
			// a unique_id per entry. A SIEM regroups on the first.
			parentID := strings.Trim(c.GUID(), "{}")

			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("dvchost", host),
				cefKV("suser", c.Env.NetBIOS+`\`+user),
				cefKV("src", c.InternalIP()),
				cefKV("externalId", parentID),
				cefKV("cs6Label", "uniqueId"),
				cefKV("cs6", strings.Trim(c.GUID(), "{}")),
				cefKV("cat", "ObservedAttackTechniques"),
				cefKV("act", "detected"),
				cefKV("cs1Label", "filterName"),
				cefKV("cs1", o.filter),
				cefKV("cs2Label", "mitreTechniqueId"),
				cefKV("cs2", o.id),
				cefKV("cs3Label", "mitreTactic"),
				cefKV("cs3", o.tactic),
				cefKV("cs4Label", "riskLevel"),
				cefKV("cs4", "high"),
				cefKV("deviceProcessName", "powershell.exe"),
				cefKV("dproc", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
				cefKV("msg", o.filter+" on "+host),
			}
			return trendPayload(c, core.SevWarning, cefRecord(o.id, o.name, 8, ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-malware-detection", Source: core.SourceTrendVision,
			Group: "Detections", Name: "Malware detected",
			Desc:    "An endpoint detection where a file was identified as malware and acted on.",
			EventID: "MALWARE", Channel: "detection", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1204.002"},
			Params: []core.Param{pUser, param("host", "Endpoint", "auto"), param("threat", "Threat name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			user := c.P("user", c.User())
			threat := c.P("threat", c.Pick(
				"TROJ_GEN.R002C0DIF23", "Ransom.Win32.CONTI.SMYXBGZ", "HackTool.Win64.MIMIKATZ.A"))
			file := c.Pick("invoice.exe", "update.dll", "setup_x64.msi")

			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("dvchost", host),
				cefKV("suser", c.Env.NetBIOS+`\`+user),
				cefKV("src", c.InternalIP()),
				cefKV("externalId", strings.Trim(c.GUID(), "{}")),
				cefKV("cat", "Detections"),
				cefKV("act", "Quarantine"),
				cefKV("fname", file),
				cefKV("filePath", `C:\Users\`+user+`\Downloads\`+file),
				cefKV("fileHash", c.HexLower(64)),
				cefKV("cs1Label", "malwareName"),
				cefKV("cs1", threat),
				cefKV("cs2Label", "detectionType"),
				cefKV("cs2", "Real-time Scan"),
				cefKV("cs3Label", "engine"),
				cefKV("cs3", "Predictive Machine Learning"),
				cefKV("msg", threat+" quarantined on "+host),
			}
			return trendPayload(c, core.SevCrit, cefRecord("MALWARE", threat, 10, ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-c2-callback", Source: core.SourceTrendVision,
			Group: "Detections", Name: "Command-and-control callback",
			Desc:    "An endpoint reached out to known command-and-control infrastructure and the connection was blocked.",
			EventID: "CNC", Channel: "detection", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1071.001"},
			Params: []core.Param{param("host", "Endpoint", "auto"), pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			dst := c.P("dstip", c.ExternalIP())

			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("dvchost", host),
				cefKV("src", c.InternalIP()),
				cefKV("dst", dst),
				cefKV("spt", fmt.Sprint(c.EphemeralPort())),
				cefKV("dpt", "443"),
				cefKV("proto", "TCP"),
				cefKV("externalId", strings.Trim(c.GUID(), "{}")),
				cefKV("cat", "Detections"),
				cefKV("act", "Block"),
				cefKV("request", "https://"+dst+"/"+c.Pick("gate.php", "api/v2/beacon", "submit.php")),
				cefKV("cs1Label", "ruleName"),
				cefKV("cs1", "C&C Callback Detected"),
				cefKV("cs2Label", "cncListSource"),
				cefKV("cs2", "Global Intelligence"),
				cefKV("cs3Label", "riskLevel"),
				cefKV("cs3", "high"),
				cefKV("msg", "Callback to known C&C server blocked"),
			}
			return trendPayload(c, core.SevCrit, cefRecord("CNC", "C&C Callback Detected", 9, ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-audit-log", Source: core.SourceTrendVision,
			Group: "Audit", Name: "Console audit event",
			Desc:    "An administrative action in the Vision One console. Changes to detection rules or exclusions matter here.",
			EventID: "AUDIT", Channel: "audit", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{pUser, param("action", "Action", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			action := c.P("action", c.Pick(
				"Added an exception to the detection model",
				"Disabled a detection model",
				"Modified an endpoint isolation policy",
			))
			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("suser", c.UPN(user)),
				cefKV("src", c.ExternalIP()),
				cefKV("externalId", strings.Trim(c.GUID(), "{}")),
				cefKV("cat", "AuditLogs"),
				cefKV("act", "update"),
				cefKV("cs1Label", "activity"),
				cefKV("cs1", action),
				cefKV("cs2Label", "result"),
				cefKV("cs2", "Success"),
				cefKV("msg", action),
			}
			return trendPayload(c, core.SevNotice, cefRecord("AUDIT", "Console audit event", 5, ext))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "trendmicro-endpoint-isolated", Source: core.SourceTrendVision,
			Group: "Response", Name: "Endpoint isolated",
			Desc:    "A response action: an endpoint was cut off from the network, automatically or by an analyst.",
			EventID: "RESPONSE", Channel: "response", Severity: core.SevLabelHigh,
			Params: []core.Param{pUser, param("host", "Endpoint", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("host", c.Workstation())
			ext := []string{
				cefKV("rt", cefTime(c)),
				cefKV("dvchost", host),
				cefKV("suser", c.UPN(c.P("user", c.AdminUser()))),
				cefKV("src", c.InternalIP()),
				cefKV("externalId", strings.Trim(c.GUID(), "{}")),
				cefKV("cat", "ResponseActions"),
				cefKV("act", "isolate"),
				cefKV("cs1Label", "actionStatus"),
				cefKV("cs1", "Succeeded"),
				cefKV("cs2Label", "triggeredBy"),
				cefKV("cs2", "Workbench alert"),
				cefKV("msg", "Endpoint "+host+" isolated from the network"),
			}
			return trendPayload(c, core.SevWarning,
				cefRecord("RESPONSE", "Endpoint isolated", 7, ext))
		},
	})
}

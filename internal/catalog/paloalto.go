package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Palo Alto Networks PAN-OS controls.
//
// PAN-OS syslog is positional CSV, not key=value, which makes it unforgiving:
// a field in the wrong slot does not fail, it silently lands in the next
// field's meaning. The orders below are taken from the PAN-OS 11.0 syslog field
// descriptions, and every FUTURE_USE placeholder is emitted so the positions
// after it stay correct.
//
//	https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions

// panTime is the timestamp format PAN-OS writes into its own fields, which is
// not the syslog header's format.
func panTime(c *core.Ctx) string { return c.Now.Format("2006/01/02 15:04:05") }

// panPayload frames a PAN-OS record. The device sends these at local0 by
// default, with the firewall as the syslog hostname.
func panPayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourcePaloAlto,
		Host:     c.Env.FWHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

// panTraffic builds a TRAFFIC record.
//
// Field order, positions 1-53, from the PAN-OS traffic log reference. The
// leading field is FUTURE_USE and carries "1" on a real device.
func panTraffic(c *core.Ctx, action, sessionEnd, app, rule string,
	src, dst string, sport, dport int, srcZone, dstZone string) string {

	sent, received := c.Int(64, 900000), c.Int(64, 3000000)
	pktSent, pktRecv := c.Int(1, 2000), c.Int(1, 2500)

	f := []string{
		"1",                                 //  1 FUTURE_USE
		panTime(c),                          //  2 Receive Time
		c.Env.FWSerial,                      //  3 Serial Number
		"TRAFFIC",                           //  4 Type
		sessionEnd,                          //  5 Threat/Content Type (subtype)
		"",                                  //  6 FUTURE_USE
		panTime(c),                          //  7 Generated Time
		src,                                 //  8 Source Address
		dst,                                 //  9 Destination Address
		"0.0.0.0",                           // 10 NAT Source IP
		"0.0.0.0",                           // 11 NAT Destination IP
		rule,                                // 12 Rule Name
		"",                                  // 13 Source User
		"",                                  // 14 Destination User
		app,                                 // 15 Application
		"vsys1",                             // 16 Virtual System
		srcZone,                             // 17 Source Zone
		dstZone,                             // 18 Destination Zone
		c.Env.IntIface,                      // 19 Inbound Interface
		c.Env.ExtIface,                      // 20 Outbound Interface
		"Log-Forwarding",                    // 21 Log Action
		"",                                  // 22 FUTURE_USE
		c.SessionID(),                       // 23 Session ID
		"1",                                 // 24 Repeat Count
		fmt.Sprint(sport),                   // 25 Source Port
		fmt.Sprint(dport),                   // 26 Destination Port
		"0",                                 // 27 NAT Source Port
		"0",                                 // 28 NAT Destination Port
		"0x400000",                          // 29 Flags
		"tcp",                               // 30 Protocol
		action,                              // 31 Action
		fmt.Sprint(sent + received),         // 32 Bytes
		fmt.Sprint(sent),                    // 33 Bytes Sent
		fmt.Sprint(received),                // 34 Bytes Received
		fmt.Sprint(pktSent + pktRecv),       // 35 Packets
		panTime(c),                          // 36 Start Time
		fmt.Sprint(c.Int(0, 300)),           // 37 Elapsed Time
		"any",                               // 38 Category
		"",                                  // 39 FUTURE_USE
		fmt.Sprint(c.Int(1000000, 9999999)), // 40 Sequence Number
		"0x0",                               // 41 Action Flags
		"10.0.0.0-10.255.255.255",           // 42 Source Country
		"US",                                // 43 Destination Country
		"",                                  // 44 FUTURE_USE
		fmt.Sprint(pktSent),                 // 45 Packets Sent
		fmt.Sprint(pktRecv),                 // 46 Packets Received
		sessionEndReason(action),            // 47 Session End Reason
		"0",                                 // 48 Device Group Hierarchy Level 1
		"0",                                 // 49 Device Group Hierarchy Level 2
		"0",                                 // 50 Device Group Hierarchy Level 3
		"0",                                 // 51 Device Group Hierarchy Level 4
		"vsys1",                             // 52 Virtual System Name
		c.Env.FWHost,                        // 53 Device Name
	}
	return strings.Join(f, ",")
}

func sessionEndReason(action string) string {
	switch action {
	case "allow":
		return "tcp-fin"
	case "deny", "drop":
		return "policy-deny"
	default:
		return "unknown"
	}
}

// panThreat builds a THREAT record. Field order, positions 1-60, from the
// PAN-OS threat log reference; the fields beyond 60 are optional in practice
// and are left off rather than guessed at.
func panThreat(c *core.Ctx, subtype, action, threatName, threatID, severity,
	src, dst string, sport, dport int, url string) string {

	f := []string{
		"1",                                 //  1 FUTURE_USE
		panTime(c),                          //  2 Receive Time
		c.Env.FWSerial,                      //  3 Serial Number
		"THREAT",                            //  4 Type
		subtype,                             //  5 Threat/Content Type
		"",                                  //  6 FUTURE_USE
		panTime(c),                          //  7 Generated Time
		src,                                 //  8 Source Address
		dst,                                 //  9 Destination Address
		"0.0.0.0",                           // 10 NAT Source IP
		"0.0.0.0",                           // 11 NAT Destination IP
		"Outbound-Web",                      // 12 Rule Name
		"",                                  // 13 Source User
		"",                                  // 14 Destination User
		"web-browsing",                      // 15 Application
		"vsys1",                             // 16 Virtual System
		"trust",                             // 17 Source Zone
		"untrust",                           // 18 Destination Zone
		c.Env.IntIface,                      // 19 Inbound Interface
		c.Env.ExtIface,                      // 20 Outbound Interface
		"Log-Forwarding",                    // 21 Log Action
		"",                                  // 22 FUTURE_USE
		c.SessionID(),                       // 23 Session ID
		"1",                                 // 24 Repeat Count
		fmt.Sprint(sport),                   // 25 Source Port
		fmt.Sprint(dport),                   // 26 Destination Port
		"0",                                 // 27 NAT Source Port
		"0",                                 // 28 NAT Destination Port
		"0x80403000",                        // 29 Flags
		"tcp",                               // 30 IP Protocol
		action,                              // 31 Action
		url,                                 // 32 URL/Filename
		threatID,                            // 33 Threat ID
		"any",                               // 34 Category
		severity,                            // 35 Severity
		"client-to-server",                  // 36 Direction
		fmt.Sprint(c.Int(1000000, 9999999)), // 37 Sequence Number
		"0x0",                               // 38 Action Flags
		"10.0.0.0-10.255.255.255",           // 39 Source Location
		"US",                                // 40 Destination Location
		"",                                  // 41 FUTURE_USE
		"0",                                 // 42 Content Type
		"0",                                 // 43 PCAP_ID
		"",                                  // 44 File Digest
		"",                                  // 45 Cloud
		"0",                                 // 46 URL Index
		"",                                  // 47 User Agent
		"",                                  // 48 File Type
		"",                                  // 49 X-Forwarded-For
		"",                                  // 50 Referer
		"",                                  // 51 Sender
		"",                                  // 52 Subject
		"",                                  // 53 Recipient
		"0",                                 // 54 Report ID
		"0",                                 // 55 Device Group Hierarchy Level 1
		"0",                                 // 56 Device Group Hierarchy Level 2
		"0",                                 // 57 Device Group Hierarchy Level 3
		"0",                                 // 58 Device Group Hierarchy Level 4
		"vsys1",                             // 59 Virtual System Name
		c.Env.FWHost,                        // 60 Device Name
	}
	_ = threatName
	return strings.Join(f, ",")
}

// pSrcIP and pUser are declared with the Windows controls; appliance records
// add a destination address.
var pDstIP = param("dstip", "Destination IP", "auto")

func init() {
	registerPaloAlto()
}

func registerPaloAlto() {
	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-traffic-allow", Source: core.SourcePaloAlto,
			Group: "Traffic", Name: "Session allowed",
			Desc:    "A session permitted by policy. The baseline every firewall rule has to tolerate.",
			EventID: "TRAFFIC", Channel: "traffic", Severity: core.SevLabelInfo,
			Params: []core.Param{pSrcIP, pDstIP, param("app", "Application", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return panPayload(c, core.SevInfo, panTraffic(c, "allow", "end",
				c.P("app", c.Pick("web-browsing", "ssl", "dns", "ms-rdp")),
				"Outbound-Web",
				c.P("srcip", c.InternalIP()), c.P("dstip", c.ExternalIP()),
				c.EphemeralPort(), c.Pick1(80, 443, 53, 3389),
				"trust", "untrust"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-traffic-deny", Source: core.SourcePaloAlto,
			Group: "Traffic", Name: "Session denied",
			Desc:    "A session dropped by policy. Burst this to simulate a scan being blocked at the edge.",
			EventID: "TRAFFIC", Channel: "traffic", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046"},
			Params: []core.Param{pSrcIP, pDstIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			dport := c.PInt("dport", c.WellKnownPort())
			return panPayload(c, core.SevNotice, panTraffic(c, "deny", "end",
				"not-applicable", "Default-Deny",
				c.P("srcip", c.ExternalIP()), c.P("dstip", c.InternalIP()),
				c.EphemeralPort(), dport, "untrust", "trust"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-threat-vulnerability", Source: core.SourcePaloAlto,
			Group: "Threat", Name: "Vulnerability exploit blocked",
			Desc:    "The threat engine matched an exploit signature and reset the session.",
			EventID: "THREAT", Channel: "threat", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1190"},
			Params: []core.Param{pSrcIP, pDstIP, param("threatid", "Threat ID", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return panPayload(c, core.SevWarning, panThreat(c, "vulnerability",
				"reset-both", "Apache Log4j Remote Code Execution Vulnerability",
				c.P("threatid", fmt.Sprint(c.Int(30000, 99999))), "critical",
				c.P("srcip", c.ExternalIP()), c.P("dstip", c.InternalIP()),
				c.EphemeralPort(), 443, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-threat-virus", Source: core.SourcePaloAlto,
			Group: "Threat", Name: "Malware blocked",
			Desc:    "Antivirus matched a file in transit and blocked it.",
			EventID: "THREAT", Channel: "threat", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1204"},
			Params: []core.Param{pSrcIP, param("file", "File name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			file := c.P("file", c.Pick("invoice.exe", "update.zip", "setup_x64.msi"))
			return panPayload(c, core.SevWarning, panThreat(c, "virus",
				"block", "Trojan/Win32.generic",
				fmt.Sprint(c.Int(200000, 299999)), "high",
				c.P("srcip", c.InternalIP()), c.ExternalIP(),
				c.EphemeralPort(), 80, "http://"+c.ExternalIP()+"/"+file))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-threat-url", Source: core.SourcePaloAlto,
			Group: "Threat", Name: "URL filtering block",
			Desc:    "A request to a blocked category. Command-and-control and phishing categories matter most here.",
			EventID: "THREAT", Channel: "url", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1071.001"},
			Params: []core.Param{pSrcIP, param("url", "URL", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			url := c.P("url", c.ExternalIP()+"/"+c.Pick("gate.php", "panel/login", "c2/beacon"))
			return panPayload(c, core.SevNotice, panThreat(c, "url",
				"block-url", "", "9999", "medium",
				c.P("srcip", c.InternalIP()), c.ExternalIP(),
				c.EphemeralPort(), 80, url))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-threat-wildfire", Source: core.SourcePaloAlto,
			Group: "Threat", Name: "WildFire verdict: malicious",
			Desc:    "A file submitted to WildFire came back malicious, after it had already passed the firewall.",
			EventID: "THREAT", Channel: "wildfire", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1204.002"},
			Params: []core.Param{pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return panPayload(c, core.SevErr, panThreat(c, "wildfire-virus",
				"allow", "WildFire malicious verdict",
				fmt.Sprint(c.Int(300000, 399999)), "critical",
				c.P("srcip", c.InternalIP()), c.ExternalIP(),
				c.EphemeralPort(), 443, "https://"+c.ExternalIP()+"/payload.bin"))
		},
	})

	// SYSTEM records are free text rather than the positional threat layout.
	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-system-admin-login", Source: core.SourcePaloAlto,
			Group: "System", Name: "Administrator login",
			Desc:    "An administrator authenticated to the firewall's management plane.",
			EventID: "SYSTEM", Channel: "system", Severity: core.SevLabelMedium,
			Mitre: []string{"T1078"},
			Params: []core.Param{pUser, pSrcIP,
				param("outcome", "Outcome", "succeeded or failed")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			failed := strings.HasPrefix(strings.ToLower(c.P("outcome", "succeeded")), "f")

			sev, eventID, desc := "informational", "auth-success",
				fmt.Sprintf("User %s logged in via Web from %s using https", user, ip)
			syslogSev := core.SevInfo
			if failed {
				sev, eventID = "medium", "auth-fail"
				desc = fmt.Sprintf("failed authentication for user '%s'. Reason: Invalid username/password. From: %s.", user, ip)
				syslogSev = core.SevWarning
			}

			f := []string{
				"1", panTime(c), c.Env.FWSerial, "SYSTEM", "general", "",
				panTime(c), "", "general", eventID, "0", "", sev, desc,
				fmt.Sprint(c.Int(1000000, 9999999)), "0x0",
				"0", "0", "0", "0", "vsys1", c.Env.FWHost,
			}
			return panPayload(c, syslogSev, strings.Join(f, ","))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "paloalto-config-change", Source: core.SourcePaloAlto,
			Group: "System", Name: "Configuration changed",
			Desc:    "A commit changed the running configuration. Rule changes at the edge are worth alerting on.",
			EventID: "CONFIG", Channel: "config", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			f := []string{
				"1", panTime(c), c.Env.FWSerial, "CONFIG", "0", "",
				panTime(c), ip, "set", user, "Web",
				"Succeeded", "rulebase security rules \"Outbound-Web\"",
				fmt.Sprint(c.Int(1000000, 9999999)), "0x0",
				"0", "0", "0", "0", "vsys1", c.Env.FWHost,
			}
			return panPayload(c, core.SevNotice, strings.Join(f, ","))
		},
	})
}

package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Cisco ASA and Firepower Threat Defense controls.
//
// ASA syslog is not key=value or CSV; each message ID has its own fixed
// sentence, and decoders match that wording literally. The structure is:
//
//	%ASA-<severity>-<message id>: <message text>
//
// where severity is the syslog level 0-7 baked into the message itself. FTD
// emits the same catalogue under an %FTD- prefix, plus its own connection and
// intrusion events in the 430000 range.
//
// The message texts below follow Cisco's published system log message
// reference. Where a field's exact spelling could not be confirmed it is kept
// simple rather than embellished, because a decoder keys on the literal words.

// asaMessage renders the %ASA-level-id: text prefix.
func asaMessage(prefix string, level int, id, text string) string {
	return fmt.Sprintf("%%%s-%d-%s: %s", prefix, level, id, text)
}

func ciscoPayload(c *core.Ctx, kind string, severity int, msg string) core.Payload {
	return core.Payload{
		Kind: kind,
		Host: c.Env.FWHost,
		// ASA defaults to local4 for syslog.
		Facility: core.FacLocal4,
		Severity: severity,
		Message:  msg,
	}
}

func init() {
	registerCiscoASA()
	registerCiscoFTD()
}

// ---------------------------------------------------------------------------
// Cisco ASA
// ---------------------------------------------------------------------------

func registerCiscoASA() {
	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-302013-built-tcp", Source: core.SourceCiscoASA,
			Group: "Connections", Name: "TCP connection built",
			Desc:    "Message 302013: an inbound or outbound TCP connection was established. The baseline connection record.",
			EventID: "302013", Channel: "connection", Severity: core.SevLabelInfo,
			Params: []core.Param{pSrcIP, pDstIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			dport := c.PInt("dport", c.WellKnownPort())
			text := fmt.Sprintf(
				"Built outbound TCP connection %s for %s:%s/%d (%s/%d) to %s:%s/%d (%s/%d)",
				c.SessionID(), c.Env.ExtIface, dst, dport, dst, dport,
				c.Env.IntIface, src, c.EphemeralPort(), src, c.EphemeralPort())
			return ciscoPayload(c, core.SourceCiscoASA, core.SevInfo,
				asaMessage("ASA", 6, "302013", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-302014-teardown-tcp", Source: core.SourceCiscoASA,
			Group: "Connections", Name: "TCP connection torn down",
			Desc:    "Message 302014: a TCP connection closed, with the reason and the bytes transferred.",
			EventID: "302014", Channel: "connection", Severity: core.SevLabelInfo,
			Params: []core.Param{pSrcIP, pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			reason := c.Pick("TCP FINs", "TCP Reset-I", "TCP Reset-O", "SYN Timeout")
			text := fmt.Sprintf(
				"Teardown TCP connection %s for %s:%s/%d to %s:%s/%d duration %s bytes %d %s",
				c.SessionID(), c.Env.ExtIface, dst, c.WellKnownPort(),
				c.Env.IntIface, src, c.EphemeralPort(),
				fmt.Sprintf("0:%02d:%02d", c.Int(0, 59), c.Int(0, 59)),
				c.Bytes(), reason)
			return ciscoPayload(c, core.SourceCiscoASA, core.SevInfo,
				asaMessage("ASA", 6, "302014", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-106023-deny", Source: core.SourceCiscoASA,
			Group: "Access Control", Name: "Denied by access-group",
			Desc:    "Message 106023: a packet denied by an access list. Burst this to simulate a port scan hitting the edge.",
			EventID: "106023", Channel: "acl", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046"},
			Params: []core.Param{pSrcIP, pDstIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.ExternalIP())
			dst := c.P("dstip", c.InternalIP())
			dport := c.PInt("dport", c.WellKnownPort())
			text := fmt.Sprintf(
				"Deny tcp src %s:%s/%d dst %s:%s/%d by access-group \"%s_access_in\" [0x0, 0x0]",
				c.Env.ExtIface, src, c.EphemeralPort(),
				c.Env.IntIface, dst, dport, c.Env.ExtIface)
			return ciscoPayload(c, core.SourceCiscoASA, core.SevWarning,
				asaMessage("ASA", 4, "106023", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-106100-acl-hit", Source: core.SourceCiscoASA,
			Group: "Access Control", Name: "Access list permitted or denied",
			Desc:    "Message 106100: a per-flow access list hit, carrying the rule name and hit count.",
			EventID: "106100", Channel: "acl", Severity: core.SevLabelLow,
			Params: []core.Param{pSrcIP, pDstIP, param("action", "permitted or denied", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			action := strings.ToLower(c.P("action", c.Pick("permitted", "denied")))
			if action != "denied" {
				action = "permitted"
			}
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			text := fmt.Sprintf(
				"access-list %s_access_in %s tcp %s/%s(%d) -> %s/%s(%d) hit-cnt %d first hit [0x%s, 0x0]",
				c.Env.ExtIface, action, c.Env.IntIface, src, c.EphemeralPort(),
				c.Env.ExtIface, dst, c.WellKnownPort(), c.Int(1, 500), c.HexLower(8))
			sev := core.SevInfo
			if action == "denied" {
				sev = core.SevWarning
			}
			return ciscoPayload(c, core.SourceCiscoASA, sev,
				asaMessage("ASA", 6, "106100", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-605005-login-ok", Source: core.SourceCiscoASA,
			Group: "Administration", Name: "Management login permitted",
			Desc:    "Message 605005: an administrator was granted access to the management console.",
			EventID: "605005", Channel: "auth", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			text := fmt.Sprintf(
				"Login permitted from %s/%d to %s:%s/ssh for user \"%s\"",
				ip, c.EphemeralPort(), c.Env.IntIface, c.InternalIP(), user)
			return ciscoPayload(c, core.SourceCiscoASA, core.SevNotice,
				asaMessage("ASA", 6, "605005", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-611102-auth-failed", Source: core.SourceCiscoASA,
			Group: "Administration", Name: "User authentication failed",
			Desc:    "Message 611102: authentication failed. Burst this to simulate a brute force against the appliance.",
			EventID: "611102", Channel: "auth", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			text := fmt.Sprintf("User authentication failed: IP = %s, Uname = %s",
				c.P("srcip", c.ExternalIP()), c.P("user", c.AdminUser()))
			return ciscoPayload(c, core.SourceCiscoASA, core.SevWarning,
				asaMessage("ASA", 4, "611102", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-113012-aaa-ok", Source: core.SourceCiscoASA,
			Group: "VPN", Name: "VPN user authenticated",
			Desc:    "Message 113012: a remote access user authenticated against the local database.",
			EventID: "113012", Channel: "vpn", Severity: core.SevLabelLow,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			text := fmt.Sprintf(
				"AAA user authentication Successful : local database : user = %s",
				c.P("user", c.User()))
			return ciscoPayload(c, core.SourceCiscoASA, core.SevInfo,
				asaMessage("ASA", 6, "113012", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-113019-vpn-disconnect", Source: core.SourceCiscoASA,
			Group: "VPN", Name: "VPN session disconnected",
			Desc:    "Message 113019: a remote access session ended, with its duration and byte counts.",
			EventID: "113019", Channel: "vpn", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			text := fmt.Sprintf(
				"Group = corp-vpn, Username = %s, IP = %s, Session disconnected. "+
					"Session Type: SSL, Duration: 0h:%02dm:%02ds, Bytes xmt: %d, Bytes rcv: %d, "+
					"Reason: User Requested",
				c.P("user", c.User()), c.P("srcip", c.ExternalIP()),
				c.Int(1, 59), c.Int(1, 59), c.Bytes(), c.Bytes())
			return ciscoPayload(c, core.SourceCiscoASA, core.SevInfo,
				asaMessage("ASA", 4, "113019", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-733100-threat-detection", Source: core.SourceCiscoASA,
			Group: "Threat Detection", Name: "Threat detection rate exceeded",
			Desc:    "Message 733100: a basic threat detection rate was exceeded, which is how a scan or flood surfaces on an ASA.",
			EventID: "733100", Channel: "threat", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1046", "T1499"},
			Params: []core.Param{param("object", "Object", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			obj := c.P("object", c.Pick("Scanning", "Firewall", "Bad pkts", "ACL drop"))
			text := fmt.Sprintf(
				"Object %s exceeded the rate limit: Current burst rate is %d per second, "+
					"max configured rate is %d; Current average rate is %d per second, "+
					"max configured rate is %d; Cumulative total count is %d",
				obj, c.Int(20, 400), c.Int(5, 20), c.Int(10, 200), c.Int(5, 10),
				c.Int(1000, 90000))
			return ciscoPayload(c, core.SourceCiscoASA, core.SevWarning,
				asaMessage("ASA", 4, "733100", text))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-asa-111008-config", Source: core.SourceCiscoASA,
			Group: "Administration", Name: "Configuration command executed",
			Desc:    "Message 111008: an administrator ran a configuration command. Rule edits at the edge are worth alerting on.",
			EventID: "111008", Channel: "config", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{pUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cmd := c.P("command", c.Pick(
				"access-list outside_access_in extended permit tcp any any eq 3389",
				"no access-list outside_access_in extended deny ip any any",
				"logging host inside 10.20.30.9",
			))
			text := fmt.Sprintf("User '%s' executed the '%s' command.",
				c.P("user", c.AdminUser()), cmd)
			return ciscoPayload(c, core.SourceCiscoASA, core.SevNotice,
				asaMessage("ASA", 5, "111008", text))
		},
	})
}

// ---------------------------------------------------------------------------
// Cisco Firepower Threat Defense
// ---------------------------------------------------------------------------

// FTD keeps the ASA message catalogue under its own prefix, and adds the
// 430000 range for the Snort-based connection and intrusion events. Those
// carry a long comma-separated key:value body rather than a sentence.

func ftdFields(pairs ...string) string { return strings.Join(pairs, ", ") }

func registerCiscoFTD() {
	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-ftd-430003-connection-allow", Source: core.SourceCiscoFTD,
			Group: "Connections", Name: "Connection allowed",
			Desc:    "Message 430003: a connection permitted by an access control rule, with the application and rule that matched.",
			EventID: "430003", Channel: "connection", Severity: core.SevLabelInfo,
			Params: []core.Param{pSrcIP, pDstIP, param("app", "Application", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			body := ftdFields(
				"AccessControlRuleAction: Allow",
				"SrcIP: "+src,
				"DstIP: "+dst,
				fmt.Sprintf("SrcPort: %d", c.EphemeralPort()),
				fmt.Sprintf("DstPort: %d", c.Pick1(80, 443, 53)),
				"Protocol: tcp",
				"IngressInterface: "+c.Env.IntIface,
				"EgressInterface: "+c.Env.ExtIface,
				"ACPolicy: Corp-Policy",
				"AccessControlRuleName: Allow-Outbound-Web",
				"Prefilter Policy: Default Prefilter Policy",
				"User: No Authentication Required",
				"Client: "+c.P("app", c.Pick("Chrome", "Firefox", "SSL client")),
				"ApplicationProtocol: HTTPS",
				"ConnectionDuration: "+fmt.Sprint(c.Int(0, 300)),
				fmt.Sprintf("InitiatorPackets: %d", c.Packets()),
				fmt.Sprintf("ResponderPackets: %d", c.Packets()),
				fmt.Sprintf("InitiatorBytes: %d", c.Bytes()),
				fmt.Sprintf("ResponderBytes: %d", c.Bytes()),
				"NAPPolicy: Balanced Security and Connectivity",
			)
			return ciscoPayload(c, core.SourceCiscoFTD, core.SevInfo,
				asaMessage("FTD", 6, "430003", body))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-ftd-430003-connection-block", Source: core.SourceCiscoFTD,
			Group: "Connections", Name: "Connection blocked",
			Desc:    "Message 430003 with a Block action: a connection denied by an access control rule.",
			EventID: "430003", Channel: "connection", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046"},
			Params: []core.Param{pSrcIP, pDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			body := ftdFields(
				"AccessControlRuleAction: Block",
				"SrcIP: "+c.P("srcip", c.ExternalIP()),
				"DstIP: "+c.P("dstip", c.InternalIP()),
				fmt.Sprintf("SrcPort: %d", c.EphemeralPort()),
				fmt.Sprintf("DstPort: %d", c.WellKnownPort()),
				"Protocol: tcp",
				"IngressInterface: "+c.Env.ExtIface,
				"EgressInterface: "+c.Env.IntIface,
				"ACPolicy: Corp-Policy",
				"AccessControlRuleName: Block-Inbound",
				"Prefilter Policy: Default Prefilter Policy",
				"User: No Authentication Required",
				fmt.Sprintf("InitiatorPackets: %d", c.Int(1, 4)),
				"ResponderPackets: 0",
				fmt.Sprintf("InitiatorBytes: %d", c.Int(40, 400)),
				"ResponderBytes: 0",
			)
			return ciscoPayload(c, core.SourceCiscoFTD, core.SevWarning,
				asaMessage("FTD", 6, "430003", body))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-ftd-430001-intrusion", Source: core.SourceCiscoFTD,
			Group: "Intrusion", Name: "Intrusion event",
			Desc:    "Message 430001: the Snort engine matched an intrusion rule, carrying the GID, SID and classification.",
			EventID: "430001", Channel: "intrusion", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1190"},
			Params: []core.Param{pSrcIP, pDstIP, param("signature", "Signature", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			sig := c.P("signature", c.Pick(
				"SERVER-WEBAPP Apache Log4j logging remote code execution attempt",
				"MALWARE-CNC Win.Trojan.CobaltStrike outbound connection",
				"OS-WINDOWS Microsoft Windows SMB remote code execution attempt",
			))
			body := ftdFields(
				"DeviceUUID: "+strings.Trim(c.GUID(), "{}"),
				"InstanceID: 1",
				"FirstPacketSecond: "+c.Now.Format("2006-01-02T15:04:05Z"),
				"ConnectionEventType: Start",
				"AccessControlRuleAction: Block",
				"SrcIP: "+c.P("srcip", c.ExternalIP()),
				"DstIP: "+c.P("dstip", c.InternalIP()),
				fmt.Sprintf("SrcPort: %d", c.EphemeralPort()),
				"DstPort: 443",
				"Protocol: tcp",
				"IngressInterface: "+c.Env.ExtIface,
				"EgressInterface: "+c.Env.IntIface,
				"ACPolicy: Corp-Policy",
				"AccessControlRuleName: Block-Inbound",
				"Priority: 1",
				fmt.Sprintf("GID: 1, SID: %d, Revision: 1", c.Int(10000, 60000)),
				"Message: "+sig,
				"Classification: Attempted Administrator Privilege Gain",
				"InlineResult: Blocked",
			)
			return ciscoPayload(c, core.SourceCiscoFTD, core.SevAlert,
				asaMessage("FTD", 1, "430001", body))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "cisco-ftd-430005-file-malware", Source: core.SourceCiscoFTD,
			Group: "Malware", Name: "Malware file detected",
			Desc:    "Message 430005: a file event where the disposition came back malware.",
			EventID: "430005", Channel: "file", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1204"},
			Params: []core.Param{pSrcIP, param("file", "File name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			file := c.P("file", c.Pick("invoice.exe", "update.msi", "payload.dll"))
			body := ftdFields(
				"DeviceUUID: "+strings.Trim(c.GUID(), "{}"),
				"FileName: "+file,
				"FileSha256: "+c.HexLower(64),
				"FileSize: "+fmt.Sprint(c.Int(10000, 5000000)),
				"FileType: MSEXE",
				"FileDirection: Download",
				"FileAction: Block",
				"FilePolicy: Corp-File-Policy",
				"SHA_Disposition: Malware",
				"SperoDisposition: Spero detection not performed on file",
				"ThreatName: W32.GenericKD",
				"SrcIP: "+c.P("srcip", c.InternalIP()),
				"DstIP: "+c.ExternalIP(),
				fmt.Sprintf("SrcPort: %d", c.EphemeralPort()),
				"DstPort: 80",
				"Protocol: tcp",
				"ApplicationProtocol: HTTP",
				"User: No Authentication Required",
			)
			return ciscoPayload(c, core.SourceCiscoFTD, core.SevCrit,
				asaMessage("FTD", 1, "430005", body))
		},
	})
}

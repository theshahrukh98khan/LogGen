package catalog

import (
	"fmt"
	"strings"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Additional Windows event log controls, following the field structure
// documented at ultimatewindowssecurity.com/securitylog/encyclopedia.
//
// These cover the events a detection engineer reaches for once the basics are
// in place: delegation and SID history abuse, AD object changes, credential
// theft, recon, RDP sessions and the audit-pipeline tampering that precedes the
// rest. Most do not map to a stock Wazuh rule — they land on the generic
// grouping rules until you write one, which is the point of having them here.

func init() {
	registerWindowsAccountsExtended()
	registerWindowsDelegation()
	registerWindowsRecon()
	registerWindowsRDP()
	registerWindowsPrivilegePolicy()
	registerWindowsObjectAccess()
	registerWindowsSystemIntegrity()
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

func registerWindowsAccountsExtended() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4723-password-change", Source: core.SourceWindows,
			Group: "Account Management", Name: "Password change attempt",
			Desc:     "A user changed their own password, knowing the old one. Distinct from 4724, where an admin resets somebody else's.",
			EventID:  "4723", Channel: "Security", Severity: core.SevLabelLow,
			Mitre:  []string{"T1098"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			e := secEvent(c, "4723", "13824", "User Account Management", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"An attempt was made to change an account's password.", "",
				subject(c, user, c.LogonID()), "",
				"Target Account:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "targetUserName": user,
				"targetDomainName": c.Env.NetBIOS, "targetSid": c.UserSID(user),
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4767-account-unlocked", Source: core.SourceWindows,
			Group: "Account Management", Name: "Account unlocked",
			Desc:     "A locked account was released. Following a lockout burst, this is what an attacker needs to resume.",
			EventID:  "4767", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1098"},
			Params: []core.Param{pActor, pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			e := secEvent(c, "4767", "13824", "User Account Management", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A user account was unlocked.", "",
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

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4781-account-renamed", Source: core.SourceWindows,
			Group: "Account Management", Name: "Account name changed",
			Desc:     "An account was renamed, which can be used to disguise a privileged account or evade name-based rules.",
			EventID:  "4781", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1098"},
			Params: []core.Param{pActor, param("old", "Old name", "auto"), param("new", "New name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			old := c.P("old", c.User())
			neu := c.P("new", "svc_"+old)
			e := secEvent(c, "4781", "13824", "User Account Management", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"The name of an account was changed:", "",
				subject(c, actor, c.LogonID()), "",
				"Target Account:",
				kv("Security ID", c.UserSID(old)),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Old Account Name", old),
				kv("New Account Name", neu),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetDomainName": c.Env.NetBIOS,
				"oldTargetUserName": old, "newTargetUserName": neu,
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	// Group removals are the mirror of the additions already in the catalog, and
	// matter for detecting an attacker covering their tracks.
	for _, g := range []struct{ id, name, group, task string }{
		{"4729", "Removed from global security group", "Domain Admins", "13826"},
		{"4733", "Removed from local security group", "Administrators", "13826"},
	} {
		g := g
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + g.id + "-group-remove", Source: core.SourceWindows,
				Group: "Account Management", Name: g.name,
				Desc:     "A member was removed from a privileged group — either normal offboarding or an attacker cleaning up.",
				EventID:  g.id, Channel: "Security", Severity: core.SevLabelMedium,
				Mitre:  []string{"T1098"},
				Params: []core.Param{pActor, pUser, param("group", "Group name", g.group)},
			},
			Build: func(c *core.Ctx) core.Payload {
				actor := c.P("actor", c.AdminUser())
				member := c.P("user", c.User())
				group := c.P("group", g.group)
				e := secEvent(c, g.id, g.task, "Security Group Management", core.AuditSuccess, 2)
				e.User = c.Env.NetBIOS + `\` + actor
				e.Message = lines(
					"A member was removed from a security-enabled group.", "",
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
					"subjectUserName": actor, "memberSid": c.UserSID(member),
					"memberName":     fmt.Sprintf("CN=%s,CN=Users,%s", member, dn(c.Env.Domain)),
					"targetUserName": group, "targetDomainName": c.Env.NetBIOS,
				}
				return winPayload(c, e, core.SevNotice)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4727-group-created", Source: core.SourceWindows,
			Group: "Account Management", Name: "Security group created",
			Desc:     "A new security-enabled global group was created in the domain.",
			EventID:  "4727", Channel: "Security", Severity: core.SevLabelLow,
			Mitre:  []string{"T1136"},
			Params: []core.Param{pActor, param("group", "Group name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			group := c.P("group", c.Pick("Helpdesk Operators", "Backup Operators 2", "IT Support", "SvcAccounts"))
			e := secEvent(c, "4727", "13826", "Security Group Management", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A security-enabled global group was created.", "",
				subject(c, actor, c.LogonID()), "",
				"New Group:",
				kv("Security ID", c.UserSID(group)),
				kv("Group Name", group),
				kv("Group Domain", c.Env.NetBIOS), "",
				"Additional Information:",
				kv("Privileges", "-"),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": group,
				"targetDomainName": c.Env.NetBIOS, "targetSid": c.UserSID(group),
			}
			return winPayload(c, e, core.SevInfo)
		},
	})
}

// ---------------------------------------------------------------------------
// Delegation, SID history and credential theft
// ---------------------------------------------------------------------------

func registerWindowsDelegation() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4741-computer-created", Source: core.SourceWindows,
			Group: "Delegation & Credentials", Name: "Computer account created",
			Desc:     "A machine account was added. Any authenticated user can create up to ten by default, which is the basis of several escalation paths.",
			EventID:  "4741", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1136.002"},
			Params: []core.Param{pActor, param("computer", "Computer name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.User())
			comp := strings.TrimSuffix(c.P("computer", c.Pick("EVILPC", "WKS-9001", "DESKTOP-A1B2C3")), "$")
			e := secEvent(c, "4741", "13825", "Computer Account Management", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A computer account was created.", "",
				subject(c, actor, c.LogonID()), "",
				"New Computer Account:",
				kv("Security ID", c.UserSID(comp)),
				kv("Account Name", comp+"$"),
				kv("Account Domain", c.Env.NetBIOS), "",
				"Attributes:",
				kv("SAM Account Name", comp+"$"),
				kv("Display Name", "-"),
				kv("User Principal Name", "-"),
				kv("Home Directory", "-"),
				kv("Script Path", "-"),
				kv("Password Last Set", c.Now.Format("1/2/2006 3:04:05 PM")),
				kv("Primary Group ID", "515"),
				kv("AllowedToDelegateTo", "-"),
				kv("User Account Control", "%%2087 %%2048"),
				kv("DNS Host Name", "-"),
				kv("Service Principal Names", "-"),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": comp + "$",
				"targetDomainName": c.Env.NetBIOS, "targetSid": c.UserSID(comp),
				"samAccountName": comp + "$", "primaryGroupId": "515",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4742-computer-changed-delegation", Source: core.SourceWindows,
			Group: "Delegation & Credentials", Name: "Computer account delegation changed",
			Desc:     "AllowedToDelegateTo was set on a machine account — constrained delegation abuse, a path to impersonating any user against the named service.",
			EventID:  "4742", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1134.001", "T1098"},
			Params: []core.Param{pActor, param("computer", "Computer name", "auto"), param("spn", "Delegated SPN", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.User())
			comp := strings.TrimSuffix(c.P("computer", c.Pick("EVILPC", "WKS-9001")), "$")
			spn := c.P("spn", "cifs/"+strings.ToUpper(c.Env.WinHost)+"."+strings.ToLower(c.Env.Domain))

			e := secEvent(c, "4742", "13825", "Computer Account Management", core.AuditSuccess, 4)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A computer account was changed.", "",
				subject(c, actor, c.LogonID()), "",
				"Computer Account That Was Changed:",
				kv("Security ID", c.UserSID(comp)),
				kv("Account Name", comp+"$"),
				kv("Account Domain", c.Env.NetBIOS), "",
				"Changed Attributes:",
				kv("SAM Account Name", "-"),
				kv("Display Name", "-"),
				kv("User Principal Name", "-"),
				kv("Password Last Set", "-"),
				kv("AllowedToDelegateTo", spn),
				kv("Old UAC Value", "0x80"),
				kv("New UAC Value", "0x1080"),
				kv("User Account Control", "%%2093"),
				kv("SID History", "-"),
				kv("Service Principal Names", "-"), "",
				"Additional Information:",
				kv("Privileges", "-"),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": comp + "$",
				"targetDomainName": c.Env.NetBIOS, "allowedToDelegateTo": spn,
				"oldUacValue": "0x80", "newUacValue": "0x1080",
			}
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4765-sid-history-added", Source: core.SourceWindows,
			Group: "Delegation & Credentials", Name: "SID History added to account",
			Desc:     "A SID was injected into an account's SID History, granting it another principal's access invisibly. Almost never legitimate outside a domain migration.",
			EventID:  "4765", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1134.005"},
			Params: []core.Param{pActor, pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			injected := c.DomainSID() + "-512" // Domain Admins

			e := secEvent(c, "4765", "13824", "User Account Management", core.AuditSuccess, 4)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"SID History was added to an account.", "",
				subject(c, actor, c.LogonID()), "",
				"Target Account:",
				kv("Security ID", c.UserSID(target)),
				kv("Account Name", target),
				kv("Account Domain", c.Env.NetBIOS), "",
				"Source Account:",
				kv("Security ID", injected),
				kv("Account Name", "Domain Admins"), "",
				"Additional Information:",
				kv("Privileges", "-"),
				kv("SID List", injected),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": target,
				"targetDomainName": c.Env.NetBIOS, "targetSid": c.UserSID(target),
				"sourceUserName": "Domain Admins", "sidList": injected,
			}
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4782-password-hash-accessed", Source: core.SourceWindows,
			Group: "Delegation & Credentials", Name: "Password hash accessed",
			Desc:     "An account's password hash was read from the directory — what a credential dumping or migration tool triggers.",
			EventID:  "4782", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1003.003"},
			Params: []core.Param{pActor, pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			e := secEvent(c, "4782", "13824", "User Account Management", core.AuditSuccess, 4)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"The password hash of an account was accessed.", "",
				subject(c, actor, c.LogonID()), "",
				"Target Account:",
				kv("Account Name", target),
				kv("Account Domain", c.Env.NetBIOS),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetUserName": target,
				"targetDomainName": c.Env.NetBIOS,
			}
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-5379-credential-manager-read", Source: core.SourceWindows,
			Group: "Delegation & Credentials", Name: "Credential Manager credentials read",
			Desc:     "Stored credentials were enumerated from the Windows vault — what credential harvesting tools do first on a workstation.",
			EventID:  "5379", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1555.004"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			e := secEvent(c, "5379", "13824", "User Account Management", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Credential Manager credentials were read.", "",
				subject(c, user, c.LogonID()), "",
				kv("Read Operation", "Enumerate Credentials"), "",
				"This event occurs when a user performs a read operation on stored credentials in Credential Manager.",
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"readOperation": "%%8100", "countOfCredentialsReturned": fmt.Sprint(c.Int(3, 24)),
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Reconnaissance
// ---------------------------------------------------------------------------

func registerWindowsRecon() {
	for _, r := range []struct{ id, name, desc, summary string }{
		{"4798", "Local group membership enumerated (user)",
			"A user's local group membership was queried. SharpHound and BloodHound generate these in bulk during collection.",
			"A user's local group membership was enumerated."},
		{"4799", "Local group membership enumerated (group)",
			"A security-enabled local group's membership was queried. A burst across many groups is domain reconnaissance.",
			"A security-enabled local group membership was enumerated."},
	} {
		r := r
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + r.id + "-enumeration", Source: core.SourceWindows,
				Group: "Discovery", Name: r.name, Desc: r.desc,
				EventID: r.id, Channel: "Security", Severity: core.SevLabelHigh,
				Mitre:  []string{"T1087.001", "T1069.001"},
				Params: []core.Param{pUser, param("process", "Calling process", "auto")},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", c.User())
				proc := c.P("process", c.Pick(
					`C:\Windows\System32\net.exe`,
					`C:\Users\`+user+`\Downloads\SharpHound.exe`,
					`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				))
				e := secEvent(c, r.id, "13824", "User Account Management", core.AuditSuccess, 3)
				e.User = c.Env.NetBIOS + `\` + user
				e.Message = lines(
					r.summary, "",
					subject(c, user, c.LogonID()), "",
					"Group:",
					kv("Security ID", c.UserSID("Administrators")),
					kv("Group Name", "Administrators"),
					kv("Group Domain", strings.ToUpper(c.Env.WinHost)), "",
					"Process Information:",
					kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
					kv("Process Name", proc),
				)
				e.EventData = map[string]string{
					"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
					"targetUserName": "Administrators", "callerProcessName": proc,
				}
				return winPayload(c, e, core.SevWarning)
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Remote Desktop
// ---------------------------------------------------------------------------

func registerWindowsRDP() {
	for _, s := range []struct {
		id, name, desc, summary, task, taskName string
		sev                                     string
	}{
		{"4778", "RDP session reconnected",
			"A user reconnected to an existing Remote Desktop session, which does not produce a fresh 4624.",
			"A session was reconnected to a Window Station.", "12551", "Other Logon/Logoff Events", core.SevLabelMedium},
		{"4779", "RDP session disconnected",
			"A user disconnected from a Remote Desktop session without logging off, leaving it running.",
			"A session was disconnected from a Window Station.", "12551", "Other Logon/Logoff Events", core.SevLabelLow},
	} {
		s := s
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + s.id + "-rdp-session", Source: core.SourceWindows,
				Group: "Remote Access", Name: s.name, Desc: s.desc,
				EventID: s.id, Channel: "Security", Severity: s.sev,
				Mitre:  []string{"T1021.001"},
				Params: []core.Param{pUser, pSrcIP},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", c.User())
				ip := c.P("srcip", c.InternalIP())
				ws := c.Workstation()
				session := fmt.Sprintf("RDP-Tcp#%d", c.Int(0, 12))
				logonID := c.LogonID()

				e := secEvent(c, s.id, s.task, s.taskName, core.AuditSuccess, 2)
				e.User = c.Env.NetBIOS + `\` + user
				e.Message = lines(
					s.summary, "",
					"Subject:",
					kv("Account Name", user),
					kv("Account Domain", c.Env.NetBIOS),
					kv("Logon ID", logonID), "",
					"Session:",
					kv("Session Name", session), "",
					"Additional Information:",
					kv("Client Name", ws),
					kv("Client Address", ip),
				)
				e.EventData = map[string]string{
					"accountName": user, "accountDomain": c.Env.NetBIOS,
					"clientName": ws, "clientAddress": ip,
					"sessionName": session, "logonId": logonID,
				}
				return winPayload(c, e, core.SevNotice)
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4825-rdp-denied", Source: core.SourceWindows,
			Group: "Remote Access", Name: "Remote Desktop access denied",
			Desc:     "A user was refused RDP access because they lack Remote Desktop Users rights. Repeated denials indicate probing.",
			EventID:  "4825", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1021.001"},
			Params: []core.Param{pUser, pSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			ip := c.P("srcip", c.ExternalIP())
			e := secEvent(c, "4825", "12551", "Other Logon/Logoff Events", core.AuditFailure, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A user was denied the access to Remote Desktop. By default, users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group.", "",
				kv("Account Name", user),
				kv("Domain", c.Env.NetBIOS),
				kv("Logon Type", "10"),
				kv("Client Address", ip),
			)
			e.EventData = map[string]string{
				"accountName": user, "accountDomain": c.Env.NetBIOS,
				"logonType": "10", "clientAddress": ip,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// Privileges and policy
// ---------------------------------------------------------------------------

func registerWindowsPrivilegePolicy() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-4673-privileged-service", Source: core.SourceWindows,
			Group: "Privilege Use", Name: "Privileged service called",
			Desc:     "A sensitive privilege such as SeDebugPrivilege was exercised — what process injection and credential dumping need.",
			EventID:  "4673", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1134"},
			Params: []core.Param{pUser, param("privilege", "Privilege", "SeDebugPrivilege"), param("process", "Process", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			priv := c.P("privilege", c.Pick("SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeBackupPrivilege"))
			proc := c.P("process", c.Pick(`C:\Windows\Temp\mimikatz.exe`, `C:\Windows\System32\rundll32.exe`, `C:\Windows\System32\lsass.exe`))

			e := secEvent(c, "4673", "13056", "Sensitive Privilege Use", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A privileged service was called.", "",
				subject(c, user, c.LogonID()), "",
				"Service:",
				kv("Server", "Security"),
				kv("Service Name", "-"), "",
				"Process:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", proc), "",
				"Service Request Information:",
				kv("Privileges", priv),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"processName": proc, "privilegeList": priv, "service": "Security",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4704-user-right-assigned", Source: core.SourceWindows,
			Group: "Privilege Use", Name: "User right assigned",
			Desc:     "A privilege was granted to an account through policy. Granting SeDebugPrivilege or SeTcbPrivilege is a persistence move.",
			EventID:  "4704", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1098"},
			Params: []core.Param{pActor, pUser, param("privilege", "Privilege", "SeDebugPrivilege")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			priv := c.P("privilege", c.Pick("SeDebugPrivilege", "SeTcbPrivilege", "SeServiceLogonRight", "SeBackupPrivilege"))

			e := secEvent(c, "4704", "13568", "Authorization Policy Change", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A user right was assigned.", "",
				subject(c, actor, c.LogonID()), "",
				"Account Modified:",
				kv("Account Name", c.UserSID(target)), "",
				"New Right:",
				kv("User Right", priv),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "subjectDomainName": c.Env.NetBIOS,
				"targetSid": c.UserSID(target), "privilegeList": priv,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4717-security-access-granted", Source: core.SourceWindows,
			Group: "Privilege Use", Name: "System security access granted",
			Desc:     "An account was granted a logon right such as network or service logon, which can quietly enable remote access.",
			EventID:  "4717", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1098"},
			Params: []core.Param{pActor, pUser, param("access", "Access right", "SeNetworkLogonRight")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.AdminUser())
			target := c.P("user", c.User())
			right := c.P("access", c.Pick("SeNetworkLogonRight", "SeRemoteInteractiveLogonRight", "SeServiceLogonRight"))

			e := secEvent(c, "4717", "13568", "Authentication Policy Change", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"System security access was granted to an account.", "",
				subject(c, actor, c.LogonID()), "",
				"Account Modified:",
				kv("Account Name", c.UserSID(target)), "",
				"Access Granted:",
				kv("Access Right", right),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "targetSid": c.UserSID(target),
				"accessGranted": right,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4964-special-groups-logon", Source: core.SourceWindows,
			Group: "Authentication", Name: "Special groups assigned to logon",
			Desc:     "A logon matched the Special Groups watch list, which flags sessions holding groups you asked Windows to alert on.",
			EventID:  "4964", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078.002"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			logonID := c.LogonID()
			e := secEvent(c, "4964", "12548", "Special Logon", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Special groups have been assigned to a new logon.", "",
				subject(c, user, logonID), "",
				"New Logon:",
				kv("Security ID", c.UserSID(user)),
				kv("Account Name", user),
				kv("Account Domain", c.Env.NetBIOS),
				kv("Logon ID", logonID), "",
				kv("Group Membership", c.DomainSID()+"-512"),
			)
			e.EventData = map[string]string{
				"targetUserName": user, "targetDomainName": c.Env.NetBIOS,
				"targetLogonId": logonID, "groupMembership": c.DomainSID() + "-512",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})
}

// ---------------------------------------------------------------------------
// Object and directory access
// ---------------------------------------------------------------------------

func registerWindowsObjectAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-5136-directory-object-modified", Source: core.SourceWindows,
			Group: "Directory Service", Name: "Directory object modified",
			Desc:     "An AD object attribute changed. Writing msDS-AllowedToActOnBehalfOfOtherIdentity is resource-based constrained delegation abuse; changing a GPO link is policy hijacking.",
			EventID:  "5136", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1484.001", "T1098"},
			Params: []core.Param{pActor, param("attribute", "LDAP attribute", "auto"), param("object", "Object DN", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", c.User())
			attr := c.P("attribute", c.Pick(
				"msDS-AllowedToActOnBehalfOfOtherIdentity",
				"msDS-KeyCredentialLink",
				"gPCMachineExtensionNames",
				"scriptPath",
			))
			obj := c.P("object", fmt.Sprintf("CN=%s,CN=Computers,%s",
				strings.ToUpper(c.Env.WinHost), dn(c.Env.Domain)))

			e := secEvent(c, "5136", "14081", "Directory Service Changes", core.AuditSuccess, 4)
			e.User = c.Env.NetBIOS + `\` + actor
			e.Message = lines(
				"A directory service object was modified.", "",
				subject(c, actor, c.LogonID()), "",
				"Directory Service:",
				kv("Name", strings.ToLower(c.Env.Domain)),
				kv("Type", "Active Directory Domain Services"), "",
				"Object:",
				kv("DN", obj),
				kv("GUID", c.GUID()),
				kv("Class", "computer"), "",
				"Attribute:",
				kv("LDAP Display Name", attr),
				kv("Syntax (OID)", "2.5.5.15"),
				kv("Value", "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...)"), "",
				"Operation:",
				kv("Type", "Value Added"),
				kv("Correlation ID", c.GUID()),
				kv("Application Correlation ID", "-"),
			)
			e.EventData = map[string]string{
				"subjectUserName": actor, "subjectDomainName": c.Env.NetBIOS,
				"objectDN": obj, "objectClass": "computer",
				"attributeLDAPDisplayName": attr, "operationType": "%%14674",
			}
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4663-object-access", Source: core.SourceWindows,
			Group: "Object Access", Name: "File access attempt",
			Desc:     "An audited file or folder was accessed. Bursts of write and delete access are how ransomware surfaces in the Security log.",
			EventID:  "4663", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1005", "T1486"},
			Params: []core.Param{pUser, param("file", "File path", "auto"), param("access", "Accesses", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			file := c.P("file", c.Pick(
				`C:\Finance\Payroll\2026-Q3.xlsx`,
				`C:\Windows\NTDS\ntds.dit`,
				`C:\Shares\HR\contracts.zip`,
			))
			access := c.P("access", c.Pick("WriteData (or AddFile)", "ReadData (or ListDirectory)", "DELETE"))

			e := secEvent(c, "4663", "12800", "File System", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"An attempt was made to access an object.", "",
				subject(c, user, c.LogonID()), "",
				"Object:",
				kv("Object Server", "Security"),
				kv("Object Type", "File"),
				kv("Object Name", file),
				kv("Handle ID", fmt.Sprintf("0x%s", c.Hex(4))), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", `C:\Windows\explorer.exe`), "",
				"Access Request Information:",
				kv("Accesses", access),
				kv("Access Mask", "0x2"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "objectName": file,
				"objectType": "File", "accessList": access, "accessMask": "0x2",
				"processName": `C:\Windows\explorer.exe`,
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4670-permissions-changed", Source: core.SourceWindows,
			Group: "Object Access", Name: "Object permissions changed",
			Desc:     "An object's DACL was rewritten. Adding rights to a GPO, share or AdminSDHolder is a persistence technique.",
			EventID:  "4670", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1222.001"},
			Params: []core.Param{pUser, param("object", "Object name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			obj := c.P("object", c.Pick(
				`C:\Shares\Finance`,
				fmt.Sprintf("CN=AdminSDHolder,CN=System,%s", dn(c.Env.Domain)),
				`C:\Windows\SYSVOL\sysvol\`+strings.ToLower(c.Env.Domain)+`\Policies`,
			))

			e := secEvent(c, "4670", "12804", "Other Object Access Events", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Permissions on an object were changed.", "",
				subject(c, user, c.LogonID()), "",
				"Object:",
				kv("Object Server", "Security"),
				kv("Object Type", "File"),
				kv("Object Name", obj),
				kv("Handle ID", fmt.Sprintf("0x%s", c.Hex(4))), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", `C:\Windows\System32\icacls.exe`), "",
				"Permissions Change:",
				kv("Original Security Descriptor", "D:(A;;0x1200a9;;;BU)(A;;FA;;;BA)"),
				kv("New Security Descriptor", "D:(A;;FA;;;WD)(A;;FA;;;BA)"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "objectName": obj, "objectType": "File",
				"processName":        `C:\Windows\System32\icacls.exe`,
				"oldSd":              "D:(A;;0x1200a9;;;BU)(A;;FA;;;BA)",
				"newSd":              "D:(A;;FA;;;WD)(A;;FA;;;BA)",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-5142-share-added", Source: core.SourceWindows,
			Group: "Lateral Movement", Name: "Network share created",
			Desc:     "A new SMB share was published, which can be used to stage tools or exfiltrate data.",
			EventID:  "5142", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1135", "T1074.001"},
			Params: []core.Param{pUser, param("share", "Share name", "auto"), param("path", "Local path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			share := c.P("share", c.Pick("temp$", "data", "backup$", "public"))
			path := c.P("path", `C:\Windows\Temp\`+strings.TrimSuffix(share, "$"))

			e := secEvent(c, "5142", "12808", "File Share", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A network share object was added.", "",
				subject(c, user, c.LogonID()), "",
				"Share Information:",
				kv("Share Name", `\\*\`+share),
				kv("Share Path", path),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"shareName": `\\*\` + share, "shareLocalPath": path,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})
}

// ---------------------------------------------------------------------------
// System and audit integrity
// ---------------------------------------------------------------------------

func registerWindowsSystemIntegrity() {
	Register(core.Definition{
		Control: core.Control{
			ID: "win-1100-eventlog-shutdown", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "Event logging service shut down",
			Desc:     "The event log service stopped. Outside a clean shutdown this means logging was deliberately disabled.",
			EventID:  "1100", Channel: "Security", Severity: core.SevLabelCritical,
			Mitre: []string{"T1562.002"},
		},
		Build: func(c *core.Ctx) core.Payload {
			e := &core.WinEvent{
				EventID: "1100", Channel: "Security",
				Provider: "Microsoft-Windows-Eventlog",
				ProviderGUID: "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
				Task: "103", TaskName: "Service shutdown",
				AuditType: core.AuditInfo, Keywords: "0x4020000000000000",
				Computer: c.WinFQDN(), User: "N/A",
				Criticality: 4, RecordID: c.Int(100000, 999999),
				ProcessID: c.Int(500, 900), ThreadID: c.Int(1000, 9000),
				EventData: map[string]string{},
			}
			e.Message = "The event logging service has shut down."
			return winPayload(c, e, core.SevCrit)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4616-time-changed", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "System time changed",
			Desc:     "The clock was moved. Shifting time corrupts event ordering across the whole estate and can invalidate a timeline.",
			EventID:  "4616", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1070.006"},
			Params: []core.Param{pUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			previous := c.Now.Add(-time.Duration(c.Int(2, 72)) * time.Hour)

			e := secEvent(c, "4616", "12288", "Security State Change", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"The system time was changed.", "",
				subject(c, user, c.LogonID()), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Name", `C:\Windows\System32\cmd.exe`), "",
				kv("Previous Time", previous.Format("2006-01-02T15:04:05.000000000Z")),
				kv("New Time", c.Now.Format("2006-01-02T15:04:05.000000000Z")),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
				"previousTime": previous.Format("2006-01-02T15:04:05.000000000Z"),
				"newTime":      c.Now.Format("2006-01-02T15:04:05.000000000Z"),
				"processName":  `C:\Windows\System32\cmd.exe`,
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4907-audit-settings-changed", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "Object audit settings changed",
			Desc:     "An object's SACL was altered, which stops access to it being audited at all — quieter than clearing the log.",
			EventID:  "4907", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.002"},
			Params: []core.Param{pUser, param("object", "Object name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			obj := c.P("object", c.Pick(`C:\Windows\NTDS`, `C:\Shares\Finance`, `C:\Windows\System32\config`))

			e := secEvent(c, "4907", "12804", "Other Object Access Events", core.AuditSuccess, 3)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"Auditing settings on object were changed.", "",
				subject(c, user, c.LogonID()), "",
				"Object:",
				kv("Object Server", "Security"),
				kv("Object Type", "File"),
				kv("Object Name", obj),
				kv("Handle ID", fmt.Sprintf("0x%s", c.Hex(4))), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", `C:\Windows\System32\auditpol.exe`), "",
				"Auditing Settings:",
				kv("Original Security Descriptor", "S:ARAI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)"),
				kv("New Security Descriptor", "S:ARAI"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "objectName": obj,
				"processName": `C:\Windows\System32\auditpol.exe`,
				"oldSd":       "S:ARAI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)", "newSd": "S:ARAI",
			}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-5038-code-integrity-failure", Source: core.SourceWindows,
			Group: "Defense Evasion", Name: "Invalid image hash (code integrity)",
			Desc:     "A binary failed its integrity check, meaning it was modified on disk or is unsigned where signing is required.",
			EventID:  "5038", Channel: "Security", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1553"},
			Params: []core.Param{param("file", "File path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			file := c.P("file", c.Pick(
				`\Device\HarddiskVolume2\Windows\System32\drivers\evil.sys`,
				`\Device\HarddiskVolume2\Windows\Temp\loader.dll`,
			))
			e := secEvent(c, "5038", "12290", "System Integrity", core.AuditFailure, 3)
			e.User = "N/A"
			e.Message = lines(
				"Code integrity determined that the image hash of a file is not valid. "+
					"The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.", "",
				kv("File Name", file),
			)
			e.EventData = map[string]string{"fileNameBuffer": file}
			return winPayload(c, e, core.SevWarning)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-6416-external-device", Source: core.SourceWindows,
			Group: "Initial Access", Name: "New external device recognised",
			Desc:     "A removable device was attached. On a restricted host this is both an entry point and an exfiltration path.",
			EventID:  "6416", Channel: "Security", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1200", "T1091"},
			Params: []core.Param{pUser, param("device", "Device description", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			device := c.P("device", c.Pick("USB Mass Storage Device", "SanDisk Cruzer Blade USB Device", "Generic USB Hub"))
			deviceID := fmt.Sprintf(`USB\VID_0781&PID_5567\%s`, c.Hex(12))

			e := secEvent(c, "6416", "12290", "Plug and Play Events", core.AuditSuccess, 2)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A new external device was recognized by the system.", "",
				subject(c, user, c.LogonID()), "",
				kv("Device ID", deviceID),
				kv("Device Name", device),
				kv("Class ID", c.GUID()),
				kv("Class Name", "USB"),
				kv("Vendor IDs", "USB\\VID_0781&PID_5567"),
				kv("Location Information", "Port_#0003.Hub_#0001"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "deviceDescription": device,
				"deviceId": deviceID, "className": "USB",
			}
			return winPayload(c, e, core.SevNotice)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "win-4689-process-exited", Source: core.SourceWindows,
			Group: "Execution", Name: "Process exited",
			Desc:     "A process terminated. Paired with 4688 it gives execution duration, which separates a shell from a one-shot command.",
			EventID:  "4689", Channel: "Security", Severity: core.SevLabelInfo,
			Params: []core.Param{pUser, param("process", "Process path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			proc := c.P("process", c.Pick(
				`C:\Windows\System32\cmd.exe`,
				`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				`C:\Windows\System32\net.exe`,
			))
			e := secEvent(c, "4689", "13313", "Process Termination", core.AuditSuccess, 1)
			e.User = c.Env.NetBIOS + `\` + user
			e.Message = lines(
				"A process has exited.", "",
				subject(c, user, c.LogonID()), "",
				"Process Information:",
				kv("Process ID", fmt.Sprintf("0x%s", c.Hex(4))),
				kv("Process Name", proc),
				kv("Exit Status", "0x0"),
			)
			e.EventData = map[string]string{
				"subjectUserName": user, "processName": proc, "status": "0x0",
			}
			return winPayload(c, e, core.SevInfo)
		},
	})

	for _, t := range []struct{ id, name, desc, summary string }{
		{"4699", "Scheduled task deleted",
			"A scheduled task was removed, which is how an attacker cleans up a persistence mechanism after use.",
			"A scheduled task was deleted."},
		{"4702", "Scheduled task updated",
			"An existing task definition was rewritten. Repointing a legitimate task is quieter than creating a new one.",
			"A scheduled task was updated."},
	} {
		t := t
		Register(core.Definition{
			Control: core.Control{
				ID: "win-" + t.id + "-scheduled-task", Source: core.SourceWindows,
				Group: "Persistence", Name: t.name, Desc: t.desc,
				EventID: t.id, Channel: "Security", Severity: core.SevLabelHigh,
				Mitre:  []string{"T1053.005"},
				Params: []core.Param{pUser, param("task", "Task name", "auto")},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", c.AdminUser())
				task := c.P("task", c.Pick(
					`\Microsoft\Windows\UpdateOrchestrator\SysCheck`,
					`\WinDefendUpdate`,
					`\Microsoft\Windows\Defrag\ScheduledDefrag`))

				e := secEvent(c, t.id, "12804", "Other Object Access Events", core.AuditSuccess, 3)
				e.User = c.Env.NetBIOS + `\` + user
				e.Message = lines(
					t.summary, "",
					subject(c, user, c.LogonID()), "",
					kv("Task Name", task),
				)
				e.EventData = map[string]string{
					"subjectUserName": user, "subjectDomainName": c.Env.NetBIOS,
					"taskName": task,
				}
				return winPayload(c, e, core.SevWarning)
			},
		})
	}
}

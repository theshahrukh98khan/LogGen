package catalog

import (
	"fmt"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// VMware vCenter Server and ESXi controls.
//
// Virtualisation is the estate under the estate: an operator who reaches
// vCenter owns every workload at once, and the ransomware crews that specialise
// in ESXi do exactly four things once they are in - turn on SSH, drop a binary
// through the datastore browser, delete the snapshots, and power everything
// off. Those four are all present below.
//
// ---------------------------------------------------------------------------
// The wire shape
// ---------------------------------------------------------------------------
//
// A vCenter Server Appliance pointed at a remote syslog target emits several
// distinct streams on the same socket, and they do NOT share a format. Four are
// modelled here.
//
//  1. The vCenter event stream. Enabled with vpxd.event.syslog.enabled, this is
//     every vCenter Event (the same objects the vSphere Client shows under
//     Monitor > Events) rendered as one syslog record each, under APP-NAME
//     "vpxd". The body is nine bracketed fields:
//
//     Event [<key>] [<n-of-m>] [<createdTime>] [<eventTypeId>] [<severity>]
//     [<userName>] [<entity>] [<chainId>] [<fullFormattedMessage>]
//
//     userName or entity is routinely empty - an authentication event has no
//     entity, a host event has no user - and the brackets are still emitted, so
//     a decoder must tolerate "[] []". That is reproduced rather than filled in.
//
//  2. The vpxd service log, /var/log/vmware/vpx/vpxd.log. The body carries its
//     own timestamp and process name, which the syslog header then duplicates:
//
//     <ISO8601> <level> vpxd[<pid>] [Originator@6876 sub=<subsystem>
//     opID=<opID>] <message>
//
//     6876 is VMware's IANA enterprise number. sub= names the subsystem,
//     opID= ties every line of one operation together.
//
//  3. The SSO audit stream, /var/log/audit/sso-events/audit_events.log, added
//     in vSphere 6.7 Update 2 and forwarded automatically once syslog is on.
//     The body is a timestamp followed by a single JSON object with the keys
//     user, client, timestamp, description, eventSeverity and type.
//
//  4. ESXi host logs reaching the same collector: hostd and vobd. hostd uses
//     the same Originator@6876 shape as vpxd; vobd carries the esx.audit.*
//     observation events, which is where SSH and shell enablement land.
//
// ---------------------------------------------------------------------------
// Verified
// ---------------------------------------------------------------------------
//
//   - The vpxd.log line shape, against NXLog's vCenter integration guide, which
//     quotes a captured line verbatim and describes it as
//     "timestamp [tag-1] [optional-tag-2] message":
//     https://docs.nxlog.co/integrate/vmware.html
//
//   - The vpxd.log and vCenter-event bodies, against the raw samples published
//     with Sekoia's VMware vCenter parser - UserLoginSessionEvent,
//     UserLogoutSessionEvent, BadUsernameSessionEvent, EventEx for SSO login
//     success and failure and for SSH session open and close,
//     VmAcquiredTicketEvent, TaskEvent, and the hostd "Create Snapshot:" line:
//     https://docs.sekoia.com/integration/categories/endpoint/vmware_vcenter/
//
//   - That the vCenter event stream is carried under APP-NAME vpxd with the
//     vpxd pid as PROCID and no structured data ("vpxd 31038 - - Event [...]"),
//     and that it is gated on vpxd.event.syslog.enabled.
//
//   - The SSO audit JSON key set and the LoginSuccess, LoginFailure, Logout,
//     PrincipalManagement and PasswordPolicy description strings, against
//     VMware's own Single Sign-On Audit Events page and against the captured
//     6.7 U2 logs William Lam published:
//     https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/vsphere-security/understanding-vsphere-hardening-and-compliance/audit-logging/single-sign-on-audit-events.html
//     https://github.com/lamw/vcenter-authn-authz-log-examples
//
//   - The vpxd-svcs AuthorizationService.AuditLog lines for role add, update
//     and delete and for access-control grant and removal, verbatim from the
//     same repository.
//
//   - TaskEvent carries the task description as its message, and snapshot
//     activity is found by grepping for "[vim.event.TaskEvent]" together with
//     "Create virtual machine snapshot" or "Remove snapshot", per Broadcom KB
//     378812:
//     https://knowledge.broadcom.com/external/article/378812/understanding-and-monitoring-vcenter-sna.html
//
//   - "Permission created for <principal> on <entity>, role is <role>,
//     propagation is <propagate>" as the PermissionAddedEvent message.
//
//   - VmPoweredOffEvent as "<vm> on <host> in <datacenter> is powered off", and
//     VmStoppingEvent as the same sentence ending "is stopping", from a
//     captured vCenter event feed.
//
//   - The vobd audit line, verbatim:
//     "[UserLevelCorrelator] 327555108910us: [esx.audit.ssh.enabled] SSH access
//     has been enabled." and the matching esx.audit.shell.enabled and
//     esx.audit.account.locked events.
//
//   - The hostd failure line "Event <n> : Cannot login <user>@<ip>" under
//     sub=Vimsvc.ha-eventmgr, from Broadcom KB 401591 and 319996.
//
//   - That ESXi formats outbound syslog as RFC 3164 with RFC 3339 timestamps,
//     or RFC 5424, and repeats its in-file timestamp and program name inside
//     the message body:
//     https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/esx-installation-and-setup/installing-and-setting-up-esxi-install/setting-up-esxi-install/configuring-system-logging-install/protocols-formats-and-framing-of-esxi-syslog-messages-install.html
//
// ---------------------------------------------------------------------------
// NOT verified - treat these as inferred and check them against a real
// appliance before writing a decoder that depends on them
// ---------------------------------------------------------------------------
//
//   - The fullFormattedMessage wording for VmRemovedEvent, VmPoweredOnEvent,
//     PermissionRemovedEvent, HostAddedEvent and HostRemovedEvent. The event
//     type IDs are real and
//     documented in the vSphere API reference; the English sentences below are
//     modelled on the confirmed siblings in the same families and may differ in
//     wording or punctuation.
//
//   - The exact task descriptions carried by TaskEvent other than "Create
//     virtual machine snapshot" and "Remove snapshot", which KB 378812 states
//     outright. "Create virtual machine", "Clone virtual machine", "Remove all
//     snapshots" and "Search datastore" are inferred.
//
//   - The DatastoreFileUploadEvent and DatastoreFileDownloadEvent message
//     text. The event type IDs are confirmed by VMware, in William Lam's
//     write-up of auditing datastore activity; the sentences are not.
//
//   - esx.audit.lockdownmode.disabled and its message. The esx.audit.*
//     namespace and line shape are confirmed; this particular event ID and its
//     wording are not.
//
//   - The syslog facility on each stream, and the APP-NAME used for the SSO
//     audit file and for vobd. Facilities below are daemon for the services and
//     authpriv for the authentication streams, which is what a collector
//     usually sees, but ESXi and the VCSA rsyslog configuration can both be
//     changed by the operator.

// ---------------------------------------------------------------------------
// Payload helpers
// ---------------------------------------------------------------------------

// vcHost is the vCenter Server's fully qualified name, which is what it puts in
// the syslog hostname field.
func vcHost(c *core.Ctx) string { return c.Env.VCHost + "." + c.Env.Domain }

// esxHost is the managed ESXi host's fully qualified name.
func esxHost(c *core.Ctx) string { return c.Env.ESXHost + "." + c.Env.Domain }

// vcPayload builds a record attributed to the vCenter Server Appliance.
func vcPayload(c *core.Ctx, tag string, pid, facility, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceVCenter,
		Tag:      tag,
		PID:      pid,
		Host:     vcHost(c),
		Facility: facility,
		Severity: severity,
		Message:  msg,
	}
}

// esxPayload builds a record attributed to an ESXi host.
func esxPayload(c *core.Ctx, tag string, pid, facility, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceVCenter,
		Tag:      tag,
		PID:      pid,
		Host:     esxHost(c),
		Facility: facility,
		Severity: severity,
		Message:  msg,
	}
}

// vcTime is the timestamp vCenter writes inside its own log bodies.
func vcTime(c *core.Ctx) string { return c.Now.UTC().Format("2006-01-02T15:04:05.000Z") }

// vcEventTime is the createdTime inside a vCenter event record, which carries
// microseconds rather than milliseconds.
func vcEventTime(c *core.Ctx) string { return c.Now.UTC().Format("2006-01-02T15:04:05.000000Z") }

// vcOpID is the operation identifier vpxd and hostd thread through every line
// of one operation.
func vcOpID(c *core.Ctx) string { return c.HexLower(8) }

// vcEvent renders one record of the vCenter event syslog stream.
//
// The event key appears twice in a real record, once as the key and once as the
// chainId, and they match for an event that is not part of a longer chain. It
// is generated once here for exactly that reason.
func vcEvent(c *core.Ctx, eventType, severity, user, entity, msg string) string {
	key := c.Int(1000000, 99999999)
	return fmt.Sprintf("Event [%d] [1-1] [%s] [%s] [%s] [%s] [%s] [%d] [%s]",
		key, vcEventTime(c), eventType, severity, user, entity, key, msg)
}

// vcVpxd renders one vpxd.log line body.
func vcVpxd(c *core.Ctx, pid int, level, sub, opID, msg string) string {
	return fmt.Sprintf("%s %s vpxd[%05d] [Originator@6876 sub=%s opID=%s] %s",
		vcTime(c), level, pid, sub, opID, msg)
}

// vcSSOAudit renders one audit_events.log line body: a timestamp followed by a
// single JSON object.
func vcSSOAudit(c *core.Ctx, user, client, description, eventType string) string {
	return fmt.Sprintf(
		`%s {"user":"%s","client":"%s","timestamp":"%s","description":"%s","eventSeverity":"INFO","type":"%s"}`,
		vcTime(c), user, client, c.Now.UTC().Format("01/02/2006 15:04:05 UTC"), description, eventType)
}

// vcAuthzAudit renders one vpxd-svcs AuthorizationService.AuditLog line.
func vcAuthzAudit(c *core.Ctx, actor, action string) string {
	return fmt.Sprintf("%s [tomcat-exec-%d  INFO  AuthorizationService.AuditLog  opId=%s] Action performed by principal(name=%s,isGroup=false):%s",
		vcTime(c), c.Int(20, 250), vcOpID(c), actor, action)
}

// esxHostd renders one hostd.log line body.
func esxHostd(c *core.Ctx, pid int, level, sub, opID, msg string) string {
	return fmt.Sprintf("%s %s hostd[%d] [Originator@6876 sub=%s opID=%s] %s",
		vcTime(c), level, pid, sub, opID, msg)
}

// esxVob renders one vobd.log observation line.
func esxVob(c *core.Ctx, eventID, msg string) string {
	return fmt.Sprintf("[UserLevelCorrelator] %dus: [%s] %s",
		c.Int(100000000000, 999999999999), eventID, msg)
}

// ---------------------------------------------------------------------------
// Shared parameters and generators
// ---------------------------------------------------------------------------

var (
	vcpUser     = param("user", "vSphere principal", "auto")
	vcpSrcIP    = param("srcip", "Client IP", "auto")
	vcpVM       = param("vm", "Virtual machine", "auto")
	vcpDC       = param("datacenter", "Datacenter", "auto")
	vcpESX      = param("esxhost", "ESXi host", "auto")
	vcpRole     = param("role", "Role", "auto")
	vcpDS       = param("datastore", "Datastore", "auto")
	vcpFile     = param("file", "Datastore file", "auto")
	vcpSnapshot = param("snapshot", "Snapshot name", "auto")
)

// vcSSOUser returns a principal in the SSO form, user@domain.
func vcSSOUser(c *core.Ctx) string {
	return c.Pick(
		"administrator@vsphere.local",
		c.User()+"@vsphere.local",
		c.User()+"@"+c.Env.Domain,
		c.ServiceUser()+"@vsphere.local",
	)
}

// vcDomainUser returns a principal in the NETBIOS\user form vCenter uses for an
// Active Directory identity source.
func vcDomainUser(c *core.Ctx) string {
	return c.Pick(
		"VSPHERE.LOCAL\\Administrator",
		c.Env.NetBIOS+"\\"+c.User(),
		c.Env.NetBIOS+"\\"+c.AdminUser(),
	)
}

// vcVMName returns a workload name of the kind an estate actually runs.
func vcVMName(c *core.Ctx) string {
	return c.Pick(
		"SQL-PROD01", "FILE-SRV02", "DC01", "APP-WEB03",
		"BACKUP-VEEAM01", "EXCH-MBX01", "VDI-POOL-014",
	)
}

func vcDatacenter(c *core.Ctx) string { return c.P("datacenter", "DC-PRIMARY") }
func vcDatastore(c *core.Ctx) string {
	return c.P("datastore", c.Pick("DS-SAN01", "DS-NVME02", "vsanDatastore"))
}

func init() {
	registerVCenterAuth()
	registerVCenterIdentity()
	registerVCenterAuthz()
	registerVCenterVM()
	registerVCenterSnapshots()
	registerVCenterDatastore()
	registerVCenterESXiAccess()
	registerVCenterInventory()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func registerVCenterAuth() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-login-success", Source: core.SourceVCenter,
			Group: "Authentication", Name: "vCenter login succeeded",
			Desc:    "A principal authenticated to vCenter and opened a session. The client string names the SDK or UI used, which is how a scripted login is told apart from somebody at a browser.",
			EventID: "vim.event.UserLoginSessionEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelInfo,
			Mitre:    []string{"T1078"},
			Params:   []core.Param{vcpUser, vcpSrcIP, param("client", "Client string", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", vcDomainUser(c))
			ip := c.P("srcip", c.InternalIP())
			client := c.P("client", c.Pick(
				"VMware vim-java 1.0",
				"pyvmomi Python/3.11.2 (VMkernel; 8.0.3; x86_64)",
				"VMware-client/8.0.3",
				"PowerCLI/13.2.0",
			))
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.UserLoginSessionEvent", "info", user, "",
					fmt.Sprintf("User %s@%s logged in as %s", user, ip, client)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-login-bad-username", Source: core.SourceVCenter,
			Group: "Authentication", Name: "vCenter login rejected (bad username)",
			Desc:    "vCenter refused a session because the principal could not be authenticated. Repeat it from one address to simulate a password spray against the management plane.",
			EventID: "vim.event.BadUsernameSessionEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1110.003", "T1078"},
			Params:   []core.Param{vcpUser, vcpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.Pick("administrator", "root", "vcadmin", "svc_backup", "admin"))
			ip := c.P("srcip", c.ExternalIP())
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevErr,
				vcEvent(c, "vim.event.BadUsernameSessionEvent", "error", user, vcHost(c),
					fmt.Sprintf("Cannot login %s@%s", user, ip)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-login-success", Source: core.SourceVCenter,
			Group: "Authentication", Name: "SSO login succeeded",
			Desc:    "Single Sign-On accepted the credential. Authentication happens in SSO rather than vCenter, so this is the record that proves the password was correct.",
			EventID: "vim.event.EventEx", Channel: "vpxd event stream",
			Severity: core.SevLabelInfo,
			Mitre:    []string{"T1078"},
			Params:   []core.Param{vcpUser, vcpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", vcSSOUser(c))
			ip := c.P("srcip", c.InternalIP())
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.EventEx", "info", user, "",
					fmt.Sprintf("Successful login %s from %s at %s in SSO",
						user, ip, c.Now.UTC().Format("01/02/2006 15:04:05 GMT"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-login-failed", Source: core.SourceVCenter,
			Group: "Authentication", Name: "SSO login failed",
			Desc:    "Single Sign-On rejected the credential. This is the event to count for brute force against vCenter, because a failure never reaches the vCenter session layer at all.",
			EventID: "vim.event.EventEx", Channel: "vpxd event stream",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1110.003"},
			Params:   []core.Param{vcpUser, vcpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", vcSSOUser(c))
			ip := c.P("srcip", c.ExternalIP())
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.EventEx", "info", user, "",
					fmt.Sprintf("Failed login %s from %s at %s in SSO",
						user, ip, c.Now.UTC().Format("01/02/2006 15:04:05 GMT"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-audit-login-failure", Source: core.SourceVCenter,
			Group: "Authentication", Name: "SSO audit: login failure (JSON)",
			Desc:    "The SSO audit stream's own JSON record of a rejected login, carrying the HTTP response code. It arrives on the same socket as the event stream but in a completely different shape.",
			EventID: "com.vmware.sso.LoginFailure", Channel: "audit_events.log",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1110.003"},
			Params:   []core.Param{vcpUser, vcpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", vcSSOUser(c))
			ip := c.P("srcip", c.ExternalIP())
			return vcPayload(c, "audit_events", c.Int(1000, 65000), core.FacAuthPriv, core.SevWarning,
				vcSSOAudit(c, user, ip,
					fmt.Sprintf("User %s@%s failed to log in with response code 401", user, ip),
					"com.vmware.sso.LoginFailure"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vpxd-invalid-login", Source: core.SourceVCenter,
			Group: "Authentication", Name: "vpxd: SessionManager.login fault",
			Desc:    "The vpxd service log's own view of a rejected login, as a failed long running operation against vim.SessionManager.login. Useful for exercising a decoder against the vpxd.log shape rather than the event stream.",
			EventID: "vim.fault.InvalidLogin", Channel: "vpxd.log",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1110.003"},
			Params:   []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			pid := c.Int(1000, 65000)
			opID := vcOpID(c)
			return vcPayload(c, "vpxd", pid, core.FacDaemon, core.SevErr,
				vcVpxd(c, pid, "info", "Default", opID,
					fmt.Sprintf("[VpxLRO] -- ERROR lro-%d -- SessionManager -- vim.SessionManager.login: vim.fault.InvalidLogin:",
						c.Int(100000000, 999999999))))
		},
	})
}

// ---------------------------------------------------------------------------
// Identity and SSO administration
// ---------------------------------------------------------------------------

func registerVCenterIdentity() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-user-created", Source: core.SourceVCenter,
			Group: "Identity", Name: "SSO user created",
			Desc:    "A new local Single Sign-On account was created. A fresh vsphere.local account is a common persistence step once an operator holds vCenter administrator.",
			EventID: "com.vmware.sso.PrincipalManagement", Channel: "audit_events.log",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1136.001", "T1098"},
			Params:   []core.Param{vcpUser, param("newuser", "New account", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "Administrator@VSPHERE.LOCAL")
			target := c.P("newuser", c.Pick("vmsupport", "svc_monitor2", "helpdesk2", "vsphere-svc"))
			return vcPayload(c, "audit_events", c.Int(1000, 65000), core.FacAuthPriv, core.SevNotice,
				vcSSOAudit(c, actor, "",
					fmt.Sprintf("Creating local person user '%s' with details ('Adding Local SSO User','%s@%s','','','%s@vsphere.local')",
						target, target, c.Env.Domain, target),
					"com.vmware.sso.PrincipalManagement"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-password-reset", Source: core.SourceVCenter,
			Group: "Identity", Name: "SSO user password reset",
			Desc:    "An administrator reset another principal's SSO password. Against administrator@vsphere.local this is an account takeover of the whole virtual estate.",
			EventID: "com.vmware.sso.PrincipalManagement", Channel: "audit_events.log",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1098"},
			Params:   []core.Param{vcpUser, param("target", "Target account", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "Administrator@VSPHERE.LOCAL")
			target := c.P("target", c.User())
			return vcPayload(c, "audit_events", c.Int(1000, 65000), core.FacAuthPriv, core.SevNotice,
				vcSSOAudit(c, actor, "",
					fmt.Sprintf("Resetting local person user '%s' password", target),
					"com.vmware.sso.PrincipalManagement"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-group-member-added", Source: core.SourceVCenter,
			Group: "Identity", Name: "SSO group membership changed",
			Desc:    "Principals were added to a local SSO group. Adding an account to Administrators here grants vCenter administrator without ever touching a role or permission object.",
			EventID: "com.vmware.sso.PrincipalManagement", Channel: "audit_events.log",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1098", "T1078"},
			Params:   []core.Param{vcpUser, param("group", "Group", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "Administrator@VSPHERE.LOCAL")
			group := c.P("group", c.Pick("Administrators", "SystemConfiguration.Administrators", "LicenseService.Administrators"))
			return vcPayload(c, "audit_events", c.Int(1000, 65000), core.FacAuthPriv, core.SevNotice,
				vcSSOAudit(c, actor, "",
					fmt.Sprintf("Adding users to local group '%s'", group),
					"com.vmware.sso.PrincipalManagement"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-sso-password-policy-updated", Source: core.SourceVCenter,
			Group: "Identity", Name: "SSO password policy updated",
			Desc:    "The local SSO password policy was changed. Weakening length, complexity or lockout is a quiet way to keep a foothold usable, and it is rarely looked at.",
			EventID: "com.vmware.sso.PasswordPolicy", Channel: "audit_events.log",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1556", "T1562"},
			Params:   []core.Param{vcpUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "Administrator@VSPHERE.LOCAL")
			return vcPayload(c, "audit_events", c.Int(1000, 65000), core.FacAuthPriv, core.SevNotice,
				vcSSOAudit(c, actor, "", "Updating local password policy", "com.vmware.sso.PasswordPolicy"))
		},
	})
}

// ---------------------------------------------------------------------------
// Permissions and roles
// ---------------------------------------------------------------------------

func registerVCenterAuthz() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-permission-added", Source: core.SourceVCenter,
			Group: "Permissions and roles", Name: "Permission granted on inventory object",
			Desc:    "A principal was granted a role on an inventory object. Granting Administrator at the root folder with propagation on hands over the entire estate in one call.",
			EventID: "vim.event.PermissionAddedEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1098", "T1078"},
			Params:   []core.Param{vcpUser, vcpRole, param("principal", "Principal granted", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "VSPHERE.LOCAL\\Administrator")
			principal := c.P("principal", c.Env.NetBIOS+"\\"+c.User())
			role := c.P("role", "Administrator")
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.PermissionAddedEvent", "info", actor, vcDatacenter(c),
					fmt.Sprintf("Permission created for %s on %s, role is %s, propagation is true",
						principal, vcDatacenter(c), role)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-permission-removed", Source: core.SourceVCenter,
			Group: "Permissions and roles", Name: "Permission removed from inventory object",
			Desc:    "A permission rule was deleted. Stripping the rights of the accounts that would notice is a normal step before a destructive action.",
			EventID: "vim.event.PermissionRemovedEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1098", "T1531"},
			Params:   []core.Param{vcpUser, param("principal", "Principal removed", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "VSPHERE.LOCAL\\Administrator")
			principal := c.P("principal", c.Env.NetBIOS+"\\"+c.User())
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.PermissionRemovedEvent", "info", actor, vcDatacenter(c),
					fmt.Sprintf("Permission rule removed for %s on %s", principal, vcDatacenter(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-role-added", Source: core.SourceVCenter,
			Group: "Permissions and roles", Name: "Role created",
			Desc:    "A new role was defined, with its privilege list spelled out in the record. A bespoke role carrying Host.Config privileges is worth a look however innocent its name.",
			EventID: "AuthorizationService.AuditLog", Channel: "vpxd-svcs.log",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1098"},
			Params:   []core.Param{vcpUser, vcpRole},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "VSPHERE.LOCAL\\Administrator")
			role := c.P("role", c.Pick("BackupOperator", "SupportReadOnly", "vmtools-maint"))
			return vcPayload(c, "vpxd-svcs", c.Int(1000, 65000), core.FacDaemon, core.SevNotice,
				vcAuthzAudit(c, actor,
					fmt.Sprintf("Add role Id=%d,Name=%s,Description=,Tenant=Privileges=[System.Anonymous, System.Read, System.View, Host.Config.AdvancedConfig, VirtualMachine.Interact.ConsoleInteract]",
						c.Int(100000000, 999999999), role)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-role-removed", Source: core.SourceVCenter,
			Group: "Permissions and roles", Name: "Role deleted",
			Desc:    "A role was deleted by id. Deleting a role removes every permission built on it, which is both a cleanup step after an intrusion and a denial of service in its own right.",
			EventID: "AuthorizationService.AuditLog", Channel: "vpxd-svcs.log",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1098", "T1531"},
			Params:   []core.Param{vcpUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", "VSPHERE.LOCAL\\Administrator")
			return vcPayload(c, "vpxd-svcs", c.Int(1000, 65000), core.FacDaemon, core.SevNotice,
				vcAuthzAudit(c, actor, fmt.Sprintf("Delete role %d", c.Int(100000000, 999999999))))
		},
	})
}

// ---------------------------------------------------------------------------
// Virtual machine lifecycle
// ---------------------------------------------------------------------------

func registerVCenterVM() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-created", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "Virtual machine created",
			Desc:    "A new virtual machine was registered in the inventory. An unmanaged VM built inside the estate is a way to run tooling on trusted network with no endpoint agent on it.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1578.002"},
			Params:   []core.Param{vcpUser, vcpVM, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), vcDatacenter(c),
					"Task: Create virtual machine"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-deleted", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "Virtual machine deleted from disk",
			Desc:    "A virtual machine was removed and its files deleted. Destroying a VM destroys the evidence inside it, and a backup proxy or jump host is a popular choice.",
			EventID: "vim.event.VmRemovedEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1578.003", "T1485"},
			Params:   []core.Param{vcpUser, vcpVM, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			vm := c.P("vm", vcVMName(c))
			host := c.P("esxhost", esxHost(c))
			dc := vcDatacenter(c)
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.VmRemovedEvent", "info",
					c.P("user", vcDomainUser(c)), host,
					fmt.Sprintf("Removed %s on %s from %s", vm, host, dc)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-powered-on", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "Virtual machine powered on",
			Desc:    "A virtual machine was started. On its own it is routine; against a VM that has been dormant, or one created minutes earlier, it is the moment attacker infrastructure came up inside the estate.",
			EventID: "vim.event.VmPoweredOnEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelInfo,
			Mitre:    []string{"T1578.002"},
			Params:   []core.Param{vcpUser, vcpVM, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			vm := c.P("vm", vcVMName(c))
			host := c.P("esxhost", esxHost(c))
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.VmPoweredOnEvent", "info",
					c.P("user", vcDomainUser(c)), host,
					fmt.Sprintf("%s on %s in %s is powered on", vm, host, vcDatacenter(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-powered-off", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "Virtual machine powered off",
			Desc:    "A virtual machine was powered off. Fire this repeatedly to simulate the mass power-off that precedes ESXi ransomware encryption, which needs the VMDKs released before it can write to them.",
			EventID: "vim.event.VmPoweredOffEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1529", "T1486"},
			Params:   []core.Param{vcpUser, vcpVM, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			vm := c.P("vm", vcVMName(c))
			host := c.P("esxhost", esxHost(c))
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.VmPoweredOffEvent", "info",
					c.P("user", vcDomainUser(c)), host,
					fmt.Sprintf("%s on %s in %s is powered off", vm, host, vcDatacenter(c))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-cloned", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "Virtual machine cloned",
			Desc:    "A virtual machine was cloned. Cloning a domain controller and mounting its disk elsewhere lifts NTDS.dit without ever logging into the running machine.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1003.003", "T1005"},
			Params:   []core.Param{vcpUser, vcpVM, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), c.P("vm", vcVMName(c)),
					"Task: Clone virtual machine"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-vm-console-ticket", Source: core.SourceVCenter,
			Group: "Virtual machines", Name: "VM console ticket acquired (MKS)",
			Desc:    "Somebody opened the remote console on a guest. Console access bypasses the network entirely, so it leaves nothing in the guest's own authentication log and no firewall record at all.",
			EventID: "vim.event.VmAcquiredTicketEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1021", "T1078"},
			Params:   []core.Param{vcpUser, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("user", vcDomainUser(c))
			host := c.P("esxhost", esxHost(c))
			dc := vcDatacenter(c)
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.VmAcquiredTicketEvent", "info", actor, dc,
					fmt.Sprintf("A ticket for %s of type MKS on %s in %s has been acquired", actor, host, dc)))
		},
	})
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

func registerVCenterSnapshots() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-snapshot-created", Source: core.SourceVCenter,
			Group: "Snapshots", Name: "Snapshot created",
			Desc:    "A snapshot was taken. Benign on a change window, and the standard first move before tampering with a guest so the change can be rolled back and the evidence with it.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1578.001"},
			Params:   []core.Param{vcpUser, vcpVM},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), c.P("vm", vcVMName(c)),
					"Task: Create virtual machine snapshot"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-snapshot-removed", Source: core.SourceVCenter,
			Group: "Snapshots", Name: "Snapshot deleted",
			Desc:    "A snapshot was deleted. Snapshot deletion ahead of an encryption run is what makes ESXi ransomware unrecoverable, and the same event hides a rollback that an investigator would have wanted.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1490", "T1485"},
			Params:   []core.Param{vcpUser, vcpVM},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), c.P("vm", vcVMName(c)),
					"Task: Remove snapshot"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-snapshot-consolidate-all", Source: core.SourceVCenter,
			Group: "Snapshots", Name: "All snapshots removed from a VM",
			Desc:    "Every snapshot on a machine was deleted in one call. Run across a cluster in a short window this is the clearest pre-encryption signal vCenter produces.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1490"},
			Params:   []core.Param{vcpUser, vcpVM},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), c.P("vm", vcVMName(c)),
					"Task: Remove all snapshots"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-hostd-create-snapshot", Source: core.SourceVCenter,
			Group: "Snapshots", Name: "hostd: snapshot taken on the ESXi host",
			Desc:    "The ESXi host's own record of a snapshot, naming the VMX path and the principal behind the vpxuser impersonation. It is the only place the on-disk path appears, which matters when the VM name has been changed.",
			EventID: "esx.hostd.snapshot", Channel: "hostd.log",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1578.001"},
			Params:   []core.Param{vcpUser, vcpVM, vcpSnapshot, vcpDS},
		},
		Build: func(c *core.Ctx) core.Payload {
			pid := c.Int(100000, 9999999)
			vm := c.P("vm", vcVMName(c))
			snap := c.P("snapshot", c.Pick("pre-patch", "before-upgrade", "VEEAM BACKUP TEMPORARY SNAPSHOT", "test"))
			user := c.P("user", "vpxuser:"+c.Env.NetBIOS+"\\"+c.User())
			return esxPayload(c, "Hostd", pid, core.FacDaemon, core.SevInfo,
				fmt.Sprintf("%s info hostd[%d] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/%s-%s/%s/%s.vmx opID=%s sid=%s user=%s] Create Snapshot: %s, memory=false, quiescent=false state=5",
					vcTime(c), pid, c.HexLower(8), c.HexLower(8), vm, vm,
					vcOpID(c), c.HexLower(6), user, snap))
		},
	})
}

// ---------------------------------------------------------------------------
// Datastore activity
// ---------------------------------------------------------------------------

func registerVCenterDatastore() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-datastore-browse", Source: core.SourceVCenter,
			Group: "Datastore", Name: "Datastore browsed",
			Desc:    "The datastore browser was used to list files. It is how an operator finds the VMDKs worth stealing and the folder to drop a payload into, and it needs only the Datastore.Browse privilege.",
			EventID: "vim.event.TaskEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1083"},
			Params:   []core.Param{vcpUser, vcpDS},
		},
		Build: func(c *core.Ctx) core.Payload {
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevInfo,
				vcEvent(c, "vim.event.TaskEvent", "info",
					c.P("user", vcDomainUser(c)), vcDatastore(c),
					"Task: Search datastore"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-datastore-file-upload", Source: core.SourceVCenter,
			Group: "Datastore", Name: "File uploaded to a datastore",
			Desc:    "A file was pushed into a datastore over HTTPS. This is the documented path for dropping a binary, an ISO or a replacement VMX onto an ESXi host without an agent or an SSH session.",
			EventID: "vim.event.DatastoreFileUploadEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1105", "T1608"},
			Params:   []core.Param{vcpUser, vcpDS, vcpFile},
		},
		Build: func(c *core.Ctx) core.Payload {
			ds := vcDatastore(c)
			file := c.P("file", c.Pick(
				"ISO/boot.iso", "tools/nc64.exe", "ISO/winpe.iso",
				"scratch/vmtools.sh", "ISO/payload.iso"))
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.DatastoreFileUploadEvent", "info",
					c.P("user", vcDomainUser(c)), ds,
					fmt.Sprintf("File or directory %s uploaded to datastore %s", file, ds)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-datastore-file-download", Source: core.SourceVCenter,
			Group: "Datastore", Name: "File downloaded from a datastore",
			Desc:    "A file was pulled out of a datastore. Downloading a VMDK removes a whole machine's disk from the estate in one request, and no guest sees it happen.",
			EventID: "vim.event.DatastoreFileDownloadEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1005", "T1048"},
			Params:   []core.Param{vcpUser, vcpDS, vcpFile},
		},
		Build: func(c *core.Ctx) core.Payload {
			ds := vcDatastore(c)
			vm := vcVMName(c)
			file := c.P("file", vm+"/"+vm+"-flat.vmdk")
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.DatastoreFileDownloadEvent", "info",
					c.P("user", vcDomainUser(c)), ds,
					fmt.Sprintf("File or directory %s downloaded from datastore %s", file, ds)))
		},
	})
}

// ---------------------------------------------------------------------------
// ESXi host access
// ---------------------------------------------------------------------------

func registerVCenterESXiAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-ssh-enabled", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi SSH enabled",
			Desc:    "The SSH service was started on an ESXi host. SSH is off by default and stays off in a healthy estate; turning it on is the single most reliable precursor to hands-on-keyboard activity on a hypervisor.",
			EventID: "esx.audit.ssh.enabled", Channel: "vobd.log",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1021.004", "T1562.001"},
			Params:   []core.Param{vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			return esxPayload(c, "vobd", c.Int(2000000, 2999999), core.FacDaemon, core.SevWarning,
				esxVob(c, "esx.audit.ssh.enabled", "SSH access has been enabled."))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-shell-enabled", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi Shell enabled",
			Desc:    "The local ESXi Shell was enabled. Together with DCUI access it gives a full command line on the hypervisor, outside every vCenter permission check.",
			EventID: "esx.audit.shell.enabled", Channel: "vobd.log",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1059", "T1562.001"},
			Params:   []core.Param{vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			return esxPayload(c, "vobd", c.Int(2000000, 2999999), core.FacDaemon, core.SevWarning,
				esxVob(c, "esx.audit.shell.enabled", "The ESXi Shell has been enabled."))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-lockdown-disabled", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi lockdown mode disabled",
			Desc:    "Lockdown mode was turned off, restoring direct access to the host outside vCenter. Disabling it is how an operator escapes vCenter's roles and auditing in a single step.",
			EventID: "esx.audit.lockdownmode.disabled", Channel: "vobd.log",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1562.001", "T1548"},
			Params:   []core.Param{vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			return esxPayload(c, "vobd", c.Int(2000000, 2999999), core.FacDaemon, core.SevWarning,
				esxVob(c, "esx.audit.lockdownmode.disabled", "The system has exited lockdown mode."))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-ssh-session-opened", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi SSH session opened",
			Desc:    "An interactive SSH session was established on an ESXi host. Everything an operator does from here is invisible to vCenter's event stream.",
			EventID: "vim.event.EventEx", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1021.004"},
			Params:   []core.Param{vcpUser, vcpSrcIP, vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", "root")
			ip := c.P("srcip", c.InternalIP())
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.EventEx", "info", "", c.P("esxhost", esxHost(c)),
					fmt.Sprintf("SSH session was opened for '%s@%s'.", user, ip)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-login-failed", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi host login rejected",
			Desc:    "The host's management agent refused a login. Against a host in lockdown this is noisy and benign; from an outside address with varying usernames it is a brute force on the hypervisor itself.",
			EventID: "esx.hostd.login.failed", Channel: "hostd.log",
			Severity: core.SevLabelMedium,
			Mitre:    []string{"T1110.001"},
			Params:   []core.Param{vcpUser, vcpSrcIP, vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			pid := c.Int(100000, 9999999)
			user := c.P("user", c.Pick("root", "vpxuser", "dcui", "admin"))
			ip := c.P("srcip", c.ExternalIP())
			return esxPayload(c, "Hostd", pid, core.FacDaemon, core.SevWarning,
				esxHostd(c, pid, "info", "Vimsvc.ha-eventmgr", vcOpID(c),
					fmt.Sprintf("Event %d : Cannot login %s@%s", c.Int(1000, 9999999), user, ip)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-esxi-account-locked", Source: core.SourceVCenter,
			Group: "ESXi host access", Name: "ESXi local account locked out",
			Desc:    "A local ESXi account was locked after repeated failures. This is the tail end of a password attack on the host, and it names the account and the attempt count outright.",
			EventID: "esx.audit.account.locked", Channel: "vobd.log",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1110.001"},
			Params:   []core.Param{vcpUser, vcpESX},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", "root")
			return esxPayload(c, "vobd", c.Int(2000000, 2999999), core.FacDaemon, core.SevWarning,
				esxVob(c, "esx.audit.account.locked",
					fmt.Sprintf("Remote access for ESXi local user account '%s' has been locked for %d seconds after %d failed login attempts.",
						user, 900, c.Int(5, 64))))
		},
	})
}

// ---------------------------------------------------------------------------
// Cluster and host inventory
// ---------------------------------------------------------------------------

func registerVCenterInventory() {
	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-host-added", Source: core.SourceVCenter,
			Group: "Cluster inventory", Name: "ESXi host added to the cluster",
			Desc:    "A host was joined to a datacenter or cluster. An unexpected host inside the cluster can run workloads, mount the shared datastores, and read every VMDK on them.",
			EventID: "vim.event.HostAddedEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelHigh,
			Mitre:    []string{"T1578"},
			Params:   []core.Param{vcpUser, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("esxhost", esxHost(c))
			dc := vcDatacenter(c)
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.HostAddedEvent", "info",
					c.P("user", vcDomainUser(c)), host,
					fmt.Sprintf("Added host %s to datacenter %s", host, dc)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "vcenter-host-removed", Source: core.SourceVCenter,
			Group: "Cluster inventory", Name: "ESXi host removed from the cluster",
			Desc:    "A host was removed from vCenter. Detaching a host stops its events reaching the collector while the host itself keeps running every VM on it.",
			EventID: "vim.event.HostRemovedEvent", Channel: "vpxd event stream",
			Severity: core.SevLabelCritical,
			Mitre:    []string{"T1562.008", "T1578"},
			Params:   []core.Param{vcpUser, vcpESX, vcpDC},
		},
		Build: func(c *core.Ctx) core.Payload {
			host := c.P("esxhost", esxHost(c))
			dc := vcDatacenter(c)
			return vcPayload(c, "vpxd", c.Int(1000, 65000), core.FacDaemon, core.SevWarning,
				vcEvent(c, "vim.event.HostRemovedEvent", "info",
					c.P("user", vcDomainUser(c)), host,
					fmt.Sprintf("Removed host %s from datacenter %s", host, dc)))
		},
	})

}

package catalog

import (
	"fmt"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// macOS controls, written as the lines that land in /var/log/system.log and
// therefore as what a syslog forwarder or the Wazuh macOS agent actually ships.
//
// The bias throughout is towards what a SOC is asked to detect on a Mac fleet:
// Gatekeeper and XProtect verdicts, TCC grants, SIP and firewall being turned
// off, LaunchAgent persistence, keychain access, and remote access being
// switched on. Ordinary application chatter is left out; it is the bulk of a
// real system.log and none of it is worth a detection rule.

// macPayload builds a record for the configured Mac.
func macPayload(c *core.Ctx, tag string, facility, severity int, msg string) core.Payload {
	pid := c.PID()
	if tag == "kernel" {
		pid = 0 // the kernel is always pid 0, and a decoder may key on it
	}
	return core.Payload{
		Kind:     core.SourceMacOS,
		Tag:      tag,
		PID:      pid,
		Host:     c.Env.MacHost,
		Facility: facility,
		Severity: severity,
		Message:  msg,
	}
}

var (
	mUser  = param("user", "Username", "auto")
	mSrcIP = param("srcip", "Source IP", "auto")
	mApp   = param("app", "Application path", "auto")
)

// macApps are paths that look like something an operator downloaded, which is
// where most of these verdicts come from in practice.
func macApp(c *core.Ctx) string {
	return c.P("app", c.PickFrom([]string{
		"/Users/" + c.User() + "/Downloads/Installer.app",
		"/Users/" + c.User() + "/Downloads/FlashPlayer.app",
		"/Volumes/Setup/Setup.app",
		"/Users/" + c.User() + "/Desktop/CryptoWallet.app",
		"/tmp/.hidden/updater",
	}))
}

func init() {
	registerMacAuth()
	registerMacPrivilege()
	registerMacMalware()
	registerMacEvasion()
	registerMacPersistence()
	registerMacCredentials()
	registerMacRemote()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func registerMacAuth() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-ssh-accepted-password", Source: core.SourceMacOS,
			Group: "Authentication", Name: "SSH login succeeded (password)",
			Desc:    "A user authenticated to the Mac over SSH with a password. Remote Login is off by default, so this only happens where somebody turned it on.",
			Channel: "authpriv", Severity: core.SevLabelInfo,
			Mitre: []string{"T1021.004", "T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{mUser, mSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "sshd", core.FacAuth, core.SevInfo,
				fmt.Sprintf("Accepted password for %s from %s port %d ssh2",
					c.P("user", c.User()), c.P("srcip", c.InternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-ssh-failed-password", Source: core.SourceMacOS,
			Group: "Authentication", Name: "SSH failed password",
			Desc:    "A password was rejected over SSH. Repeat it to simulate brute force against a Mac with Remote Login enabled.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110.001"}, Wazuh: []string{"5760"},
			Params: []core.Param{mUser, mSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "sshd", core.FacAuth, core.SevInfo,
				fmt.Sprintf("Failed password for %s from %s port %d ssh2",
					c.P("user", c.User()), c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-ssh-invalid-user", Source: core.SourceMacOS,
			Group: "Authentication", Name: "SSH invalid user",
			Desc:    "An SSH attempt named an account that does not exist, which is what username spraying looks like.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110.001", "T1589.001"}, Wazuh: []string{"5710"},
			Params: []core.Param{mUser, mSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "sshd", core.FacAuth, core.SevInfo,
				fmt.Sprintf("Invalid user %s from %s port %d",
					c.P("user", c.PickFrom([]string{"admin", "test", "oracle", "ubuntu", "git"})),
					c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-opendirectory-auth-failed", Source: core.SourceMacOS,
			Group: "Authentication", Name: "Local account authentication failed",
			Desc:    "opendirectoryd rejected a local password. This is what a wrong password at the login window or an unlock prompt looks like.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5551"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "opendirectoryd", core.FacAuth, core.SevErr,
				fmt.Sprintf("Failed to authenticate user <%s> (tDirStatus: -14090).",
					c.P("user", c.User())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-loginwindow-session", Source: core.SourceMacOS,
			Group: "Authentication", Name: "Console session started",
			Desc:    "A user logged in at the console. Useful as the benign half of a pair when testing an out-of-hours logon rule.",
			Channel: "authpriv", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078.003"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "loginwindow", core.FacAuth, core.SevInfo,
				fmt.Sprintf("USER_PROCESS: %d console, user %s", c.Int(100, 900), c.P("user", c.User())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-screenlock-failed", Source: core.SourceMacOS,
			Group: "Authentication", Name: "Screen unlock failed",
			Desc:    "A wrong password at the lock screen. A burst of these on an unattended Mac is worth an alert.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "SecurityAgent", core.FacAuth, core.SevErr,
				fmt.Sprintf("User authentication failed for %s at the login window",
					c.P("user", c.User())))
		},
	})
}

// ---------------------------------------------------------------------------
// Privilege escalation
// ---------------------------------------------------------------------------

func registerMacPrivilege() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-sudo-success", Source: core.SourceMacOS,
			Group: "Privilege Escalation", Name: "sudo command executed",
			Desc:    "A command ran as root through sudo. The command itself is the interesting part, not the fact of the escalation.",
			Channel: "authpriv", Severity: core.SevLabelInfo,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5402"},
			Params: []core.Param{mUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevNotice,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=%s",
					u, c.Int(0, 20), u,
					c.P("command", c.PickFrom([]string{
						"/usr/bin/whoami", "/usr/sbin/systemsetup -setremotelogin on",
						"/usr/bin/dscl . -list /Users", "/bin/cat /etc/sudoers",
					}))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-sudo-failed-password", Source: core.SourceMacOS,
			Group: "Privilege Escalation", Name: "sudo incorrect password",
			Desc:    "A sudo attempt with the wrong password. Repeated, this is somebody guessing at a local admin password.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1548.003", "T1110"}, Wazuh: []string{"5401"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			// Counted once: called twice the number and its plural disagree.
			n := c.Int(1, 3)
			return macPayload(c, "sudo", core.FacAuth, core.SevErr,
				fmt.Sprintf("  %s : %d incorrect password attempt%s ; TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/bin/bash",
					u, n, plural(n), c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-sudo-not-in-sudoers", Source: core.SourceMacOS,
			Group: "Privilege Escalation", Name: "sudo by a user not in sudoers",
			Desc:    "A standard user tried to escalate. On a managed fleet this should never happen and is worth alerting on directly.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5403"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevAlert,
				fmt.Sprintf("  %s : user NOT in sudoers ; TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/bin/bash",
					u, c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-authd-admin-right-granted", Source: core.SourceMacOS,
			Group: "Privilege Escalation", Name: "Admin authorization granted",
			Desc:    "authd granted system.privilege.admin, which is what an administrator prompt looks like when somebody clicks through it.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1548"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "authd", core.FacAuth, core.SevNotice,
				fmt.Sprintf("engine:%d Succeeded authorizing right 'system.privilege.admin' by client '/usr/libexec/security_authtrampoline' [%d] for authorization created by '/usr/bin/sudo' [%d] (100002,0)",
					c.Int(1000, 99999), c.Int(400, 9000), c.Int(400, 9000)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-admin-group-added", Source: core.SourceMacOS,
			Group: "Privilege Escalation", Name: "User added to admin group",
			Desc:    "An account was granted local administrator rights. On a managed Mac this should come from MDM, not from a shell.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1098", "T1078.003"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "opendirectoryd", core.FacAuth, core.SevNotice,
				fmt.Sprintf("Client: dscl, UID: 0, EUID: 0, GID: 0, EGID: 0 - added member '%s' to group 'admin'",
					c.P("user", c.User())))
		},
	})
}

// ---------------------------------------------------------------------------
// Malware protection
// ---------------------------------------------------------------------------

func registerMacMalware() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-gatekeeper-blocked", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "Gatekeeper blocked an app",
			Desc:    "Gatekeeper refused to run an application because it is not signed by an identified developer or not notarized.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1553.001", "T1204.002"},
			Params: []core.Param{mApp},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "syspolicyd", core.FacDaemon, core.SevErr,
				fmt.Sprintf("ASP: Security policy would not allow process: %d, %s",
					c.Int(400, 9000), macApp(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-xprotect-detection", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "XProtect detected malware",
			Desc:    "Apple's built-in signature scanner matched a known family. A detection here means the file already reached the disk.",
			Channel: "daemon", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1204.002"},
			Params: []core.Param{mApp, param("family", "Malware family", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "XProtectService", core.FacDaemon, core.SevCrit,
				fmt.Sprintf("XProtect detected malware %s in %s",
					c.P("family", c.PickFrom([]string{
						"OSX.Dummy.A", "OSX.Genieo.E", "OSX.Bundlore.C",
						"OSX.Adload.K", "OSX.Shlayer.E",
					})), macApp(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-mrt-remediation", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "Malware removed by MRT",
			Desc:    "The Malware Removal Tool cleaned a known family. Worth an alert even though it succeeded, because it proves the Mac was infected.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1204.002"},
			Params: []core.Param{param("family", "Malware family", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "MRT", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("Successfully remediated %s",
					c.P("family", c.PickFrom([]string{
						"OSX.Genieo.A", "OSX.Pirrit.C", "OSX.Shlayer.B", "OSX.Adload.F",
					}))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-amfid-signature-invalid", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "Code signature not valid",
			Desc:    "amfid refused a binary whose signature does not verify. Tampered or ad-hoc signed tooling shows up here.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1553.002", "T1036"},
			Params: []core.Param{mApp},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "amfid", core.FacDaemon, core.SevErr,
				fmt.Sprintf("%s signature not valid: -67030", macApp(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-notarization-failed", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "Notarization check failed",
			Desc:    "A downloaded app has no valid notarization ticket, so Apple has never scanned it. Common on both cracked software and early-stage malware.",
			Channel: "daemon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1553.001"},
			Params: []core.Param{mApp},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "syspolicyd", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("Notarization check failed for %s: no ticket found", macApp(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-sandbox-denied-keychain", Source: core.SourceMacOS,
			Group: "Malware Protection", Name: "Sandbox denied keychain read",
			Desc:    "The kernel blocked a sandboxed process from reading the login keychain. A script interpreter appearing here is a strong signal.",
			Channel: "kernel", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1555.001"},
			Params: []core.Param{mUser, param("process", "Process name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "kernel", core.FacKern, core.SevWarning,
				fmt.Sprintf("Sandbox: %s(%d) deny(1) file-read-data /Users/%s/Library/Keychains/login.keychain-db",
					c.P("process", c.PickFrom([]string{"osascript", "python3", "curl", "bash"})),
					c.Int(400, 9000), u))
		},
	})
}

// ---------------------------------------------------------------------------
// Defense evasion
// ---------------------------------------------------------------------------

func registerMacEvasion() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-sip-disabled", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "System Integrity Protection disabled",
			Desc:    "SIP was turned off. It requires a reboot into recovery, so this is deliberate and is close to a confirmed compromise on a managed Mac.",
			Channel: "authpriv", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevAlert,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/bin/csrutil disable",
					u, c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-gatekeeper-disabled", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "Gatekeeper disabled",
			Desc:    "spctl --master-disable turns off assessment entirely, so unsigned code runs without a prompt. Almost always precedes running something Apple would have blocked.",
			Channel: "authpriv", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001", "T1553.001"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevAlert,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/sbin/spctl --master-disable",
					u, c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-firewall-disabled", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "Application firewall disabled",
			Desc:    "The built-in firewall was switched off, which usually comes just before something starts listening.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre: []string{"T1562.004"},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "socketfilterfw", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("<SocketfilterfwTool(%d)> Set global state to disabled", c.Int(400, 9000)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-quarantine-removed", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "Quarantine attribute stripped",
			Desc:    "Removing com.apple.quarantine stops Gatekeeper ever assessing a downloaded file. There is no legitimate reason for a user to do this.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1553.001", "T1070.004"},
			Params: []core.Param{mUser, mApp},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevNotice,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/bin/xattr -d com.apple.quarantine %s",
					u, c.Int(0, 20), u, macApp(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-unified-log-erased", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "Unified log erased",
			Desc:    "log erase wipes the unified log. Anti-forensics, and one of the few macOS events that is essentially never benign.",
			Channel: "authpriv", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1070.002"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevAlert,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/bin/log erase --all",
					u, c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-tcc-reset", Source: core.SourceMacOS,
			Group: "Defense Evasion", Name: "Privacy permissions reset",
			Desc:    "tccutil reset clears the record of which apps were granted camera, microphone or full disk access, which hides what was approved earlier.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1070"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevNotice,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/bin/tccutil reset All",
					u, c.Int(0, 20), u))
		},
	})
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func registerMacPersistence() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-launchagent-loaded", Source: core.SourceMacOS,
			Group: "Persistence", Name: "LaunchAgent loaded",
			Desc:    "A per-user LaunchAgent was registered. This is the most common macOS persistence mechanism by a wide margin.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1543.001"},
			Params: []core.Param{mUser, param("label", "Job label", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Generated once: called twice it picks a different label each
			// time and the job name stops matching its own plist path.
			label := c.P("label", macJobLabel(c))
			return macPayload(c, "com.apple.xpc.launchd", core.FacDaemon, core.SevNotice,
				fmt.Sprintf("(%s) Service registered from /Users/%s/Library/LaunchAgents/%s.plist",
					label, c.P("user", c.User()), label))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-launchdaemon-installed", Source: core.SourceMacOS,
			Group: "Persistence", Name: "LaunchDaemon installed",
			Desc:    "A system-wide LaunchDaemon was written. It runs as root at boot with no user logged in, so it is the more serious half of the pair.",
			Channel: "daemon", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1543.004"},
			Params: []core.Param{param("label", "Job label", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			label := c.P("label", macJobLabel(c))
			return macPayload(c, "com.apple.xpc.launchd", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("(%s) Service registered from /Library/LaunchDaemons/%s.plist",
					label, label))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-login-item-added", Source: core.SourceMacOS,
			Group: "Persistence", Name: "Login item added",
			Desc:    "An application registered itself to start at login. Quieter than a LaunchAgent and easy to miss on a user-managed Mac.",
			Channel: "daemon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1547.015"},
			Params: []core.Param{mUser, mApp},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "backgroundtaskmanagementd", core.FacDaemon, core.SevNotice,
				fmt.Sprintf("Registered login item %s for user %s",
					macApp(c), c.P("user", c.User())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-profile-installed", Source: core.SourceMacOS,
			Group: "Persistence", Name: "Configuration profile installed",
			Desc:    "A profile can set proxies, trust a CA or install a certificate. Outside MDM this is a strong signal on a managed fleet.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1176", "T1553.004"},
			Params: []core.Param{param("profile", "Profile identifier", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "mdmclient", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("Installed configuration profile '%s' (not delivered by MDM)",
					c.P("profile", c.PickFrom([]string{
						"com.support.helper.profile", "com.vpn.client.config",
						"com.rootca.trust",
					}))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-pkg-installed", Source: core.SourceMacOS,
			Group: "Persistence", Name: "Package installed",
			Desc:    "A pkg ran its install scripts as root. Postinstall scripts are a routine way to drop persistence during what looks like a normal install.",
			Channel: "daemon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1543", "T1204.002"},
			Params: []core.Param{param("package", "Package name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "installd", core.FacDaemon, core.SevNotice,
				fmt.Sprintf("PackageKit: Installed \"%s\"",
					c.P("package", c.PickFrom([]string{
						"System Helper", "Media Player Update", "Flash Player",
					}))))
		},
	})
}

// ---------------------------------------------------------------------------
// Credential access
// ---------------------------------------------------------------------------

func registerMacCredentials() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-keychain-dump", Source: core.SourceMacOS,
			Group: "Credential Access", Name: "Keychain dump attempted",
			Desc:    "security dump-keychain reads stored secrets. There is no administrative reason to run it on a user's Mac.",
			Channel: "authpriv", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1555.001"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevAlert,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/bin/security dump-keychain -d /Users/%s/Library/Keychains/login.keychain-db",
					u, c.Int(0, 20), u, u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-keychain-unlocked", Source: core.SourceMacOS,
			Group: "Credential Access", Name: "Keychain unlocked by a process",
			Desc:    "A process unlocked the login keychain. Benign for browsers and mail clients, notable for anything else.",
			Channel: "authpriv", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1555.001"},
			Params: []core.Param{param("process", "Process name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "securityd", core.FacAuth, core.SevNotice,
				fmt.Sprintf("Keychain login.keychain-db unlocked by %s (%d)",
					c.P("process", c.PickFrom([]string{"osascript", "Terminal", "python3", "Safari"})),
					c.Int(400, 9000)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-tcc-full-disk-granted", Source: core.SourceMacOS,
			Group: "Credential Access", Name: "Full Disk Access granted",
			Desc:    "Full Disk Access lets a process read Mail, Messages and browser data without further prompting. Granting it to a terminal or a script host is a red flag.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1548", "T1005"},
			Params: []core.Param{param("client", "Client bundle ID", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "tccd", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("Granted kTCCServiceSystemPolicyAllFiles to %s",
					c.P("client", c.PickFrom([]string{
						"com.apple.Terminal", "com.googlecode.iterm2",
						"com.support.helper", "org.python.python",
					}))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-tcc-screen-recording", Source: core.SourceMacOS,
			Group: "Credential Access", Name: "Screen recording permission granted",
			Desc:    "Screen recording captures everything on display, including credentials being typed. Stalkerware and infostealers both ask for it.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1113"},
			Params: []core.Param{param("client", "Client bundle ID", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "tccd", core.FacDaemon, core.SevWarning,
				fmt.Sprintf("Granted kTCCServiceScreenCapture to %s",
					c.P("client", c.PickFrom([]string{
						"com.support.helper", "com.zoom.xos", "com.teamviewer.TeamViewer",
					}))))
		},
	})
}

// ---------------------------------------------------------------------------
// Remote access
// ---------------------------------------------------------------------------

func registerMacRemote() {
	Register(core.Definition{
		Control: core.Control{
			ID: "macos-remote-login-enabled", Source: core.SourceMacOS,
			Group: "Remote Access", Name: "Remote Login enabled",
			Desc:    "SSH was switched on. It is off by default on macOS, so somebody turned it on deliberately.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021.004", "T1543"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevNotice,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/usr/sbin/systemsetup -setremotelogin on",
					u, c.Int(0, 20), u))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-screensharing-success", Source: core.SourceMacOS,
			Group: "Remote Access", Name: "Screen Sharing session started",
			Desc:    "Somebody connected over VNC. The viewer address is the field worth alerting on when it is outside the estate.",
			Channel: "daemon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1021.005"},
			Params: []core.Param{mUser, mSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "screensharingd", core.FacDaemon, core.SevInfo,
				fmt.Sprintf("Authentication: SUCCEEDED :: User Name: %s :: Viewer Address: %s :: Type: DH",
					c.P("user", c.User()), c.P("srcip", c.InternalIP())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-screensharing-failed", Source: core.SourceMacOS,
			Group: "Remote Access", Name: "Screen Sharing authentication failed",
			Desc:    "A rejected VNC login. Repeat it to simulate brute force against an exposed Screen Sharing service.",
			Channel: "daemon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021.005", "T1110"},
			Params: []core.Param{mUser, mSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return macPayload(c, "screensharingd", core.FacDaemon, core.SevErr,
				fmt.Sprintf("Authentication: FAILED :: User Name: %s :: Viewer Address: %s :: Type: DH",
					c.P("user", c.User()), c.P("srcip", c.ExternalIP())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "macos-ard-enabled", Source: core.SourceMacOS,
			Group: "Remote Access", Name: "Apple Remote Desktop enabled",
			Desc:    "ARD was turned on with full privileges for all users, which grants remote control and remote command execution at once.",
			Channel: "authpriv", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021.005"},
			Params: []core.Param{mUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			u := c.P("user", c.User())
			return macPayload(c, "sudo", core.FacAuth, core.SevNotice,
				fmt.Sprintf("  %s : TTY=ttys%03d ; PWD=/Users/%s ; USER=root ; COMMAND=/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all",
					u, c.Int(0, 20), u))
		},
	})
}

// macJobLabel returns a launchd label that looks like something trying to pass
// for a system component.
func macJobLabel(c *core.Ctx) string {
	return c.PickFrom([]string{
		"com.apple.softwareupdate.helper",
		"com.adobe.flash.updater",
		"com.system.helper",
		"com.google.keystone.agent",
	})
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

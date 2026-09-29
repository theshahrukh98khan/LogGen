# LogGen

[![CI](https://github.com/theshahrukh98khan/LogGen/actions/workflows/ci.yml/badge.svg)](https://github.com/theshahrukh98khan/LogGen/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/theshahrukh98khan/LogGen)](https://github.com/theshahrukh98khan/LogGen/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/theshahrukh98khan/LogGen)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A log simulation lab for SIEM onboarding and detection-rule testing.

LogGen generates correctly structured log records for common sources and ships
them to a SIEM over syslog, so decoders, field extraction and detection rules can
be exercised without a real estate behind them. Click a control in the browser,
one record goes out.

Built and tested against [Wazuh](https://wazuh.com), but it speaks plain syslog,
so it works with any collector that does.

- Single static binary — runs on Linux, Windows and macOS, x86-64 and ARM64
- No runtime dependencies, no third-party Go modules, no build step for the UI
- 206 controls across Windows, Linux, web servers, Oracle, and five network security platforms
- Multiple SIEM target profiles: host, port, TCP/UDP, syslog format
- An Administration view for adding your own log sources and records
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
| **Oracle** | 35 | Standard and unified audit trails, listener log, alert log |
| **Palo Alto** | 8 | TRAFFIC, THREAT (vulnerability, virus, URL, WildFire), SYSTEM, CONFIG |
| **FortiGate** | 9 | Traffic, IPS, antivirus, web filter, admin login, VPN, config change |
| **Sophos** | 6 | Firewall rule, IPS, ATP, administration |
| **Cisco ASA** | 10 | Connections, access lists, VPN, threat detection, administration |
| **Cisco FTD** | 4 | Connection, intrusion and file events (430000 range) |
| **Trend Micro** | 6 | Vision One Workbench alerts, OAT, detections, audit, response |

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

### Network security platforms

These five are unforgiving in a way the text-based sources are not, so the
formats are pinned by tests rather than trusted:

| Platform | Shape | Why it breaks quietly |
|---|---|---|
| **Palo Alto** | positional CSV | A field in the wrong slot silently becomes the next field's meaning. TRAFFIC is 53 fields, THREAT is 60, and every `FUTURE_USE` placeholder is emitted so the positions after it stay correct. |
| **FortiGate** | `key=value` | Order is not load bearing, but `logid` is ten digits and decoders key on the header set. |
| **Sophos** | `key="value"` | `log_type`, `log_component` and `log_subtype` are what a decoder matches. |
| **Cisco ASA / FTD** | `%ASA-<level>-<id>: <text>` | Each message ID has its own fixed sentence that decoders match literally. |
| **Trend Micro** | CEF | Seven pipe-separated header fields; an unescaped pipe shifts every field after it. |

The PAN-OS field orders are taken from the
[PAN-OS 11.0 syslog field descriptions](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions),
and tests assert the exact field counts and the positions of Serial Number,
Type, Action and Device Name, plus that the reserved slots are still empty.

Trend Micro here is **Vision One**, the cloud XDR platform, not Deep Security or
Apex One — those are different products with different formats.

### Oracle Database

Oracle reaches a SIEM by three different paths, and they produce three unrelated
record shapes. All are provided:

| Path | Enabled by | Record |
|---|---|---|
| Standard audit trail | `AUDIT_SYSLOG_LEVEL` | `Oracle Audit[pid]: LENGTH: "414" SESSIONID:[7] "…"` — fields carry an explicit value length |
| Unified audit trail (12c+) | `UNIFIED_AUDIT_SYSTEMLOG` | `Oracle Unified Audit[pid]: LENGTH: '209' TYPE:"4" DBID:"…"` — different field names, no length markers, single-quoted `LENGTH` |
| Listener and alert logs | shipping the files | `*`-delimited TNS records, and ISO-8601 alert records |

Which audit path applies depends on the database's version and migration state.
`AUDIT_SYSLOG_LEVEL` has **no effect** once a database has been migrated to
unified auditing, so a decoder written for one will not read the other.

Coverage: logon success and failure (return codes 1017, 28000, 28001), logoff,
SELECT on audited tables, `BY SESSION` summaries with `SES$ACTIONS`, denied
access (942, 1031), user create/drop/alter, system privilege and role grants,
database links, DROP and TRUNCATE, `NOAUDIT` and `ALTER SYSTEM`, listener
connections and TNS errors (12514, 12502, 12525, 01189), service registration
and death, instance startup and shutdown, ORA-00600, ORA-01555, and fatal NI
connect errors.

> **Wazuh ships no Oracle decoders.** Unlike the other four sources, these
> records will not decode out of the box — the upstream ruleset has decoders for
> MySQL, PostgreSQL, MariaDB, MongoDB and SQL Server, but none for Oracle, and
> there is no reserved rule-ID range for it. Write custom decoders and rules in
> the user range (100000+). That is precisely what these controls are for.

A few details could not be confirmed against a captured record and are marked in
the source: what `LENGTH` counts, which Oracle release introduced the
`NAME:[len]` form, and the exact syslog spelling of `SQLTEXT` and `SES$TID`.
Check against one real record from your own instance before relying on those
fields.

## Install

LogGen is a single static binary with no runtime dependencies. It runs on
**Linux, Windows and macOS**, on both x86-64 and ARM64. Building needs Go 1.24
or newer; running needs nothing at all.

### Ubuntu / Linux

```sh
git clone https://github.com/theshahrukh98khan/LogGen
cd LogGen
go build -o loggen .
./loggen
```

If Go is not installed:

```sh
sudo apt update && sudo apt install -y golang-go git
```

Ubuntu's packaged Go can lag behind. If `go version` reports older than 1.24,
install a current toolchain from [go.dev/dl](https://go.dev/dl/) instead.

### Windows

```powershell
git clone https://github.com/theshahrukh98khan/LogGen
cd LogGen
go build -o loggen.exe .
.\loggen.exe
```

Install Go with `winget install GoLang.Go` or from
[go.dev/dl](https://go.dev/dl/). On first run Windows Defender Firewall will ask
whether to allow the console to accept connections — allow it on **private
networks only**, or decline and reach it at `http://127.0.0.1:8088`.

### Docker

A container image is published to GitHub Packages on every release:

```sh
docker run --rm -p 127.0.0.1:8088:8088 -v loggen-data:/data \
  ghcr.io/theshahrukh98khan/loggen:latest
```

Then open <http://127.0.0.1:8088>. The named volume keeps your profiles and
estate between runs. Tags are `latest` and the version for releases, and `edge`
for the current `main`.

The image is built from `scratch`-style distroless with a static binary: no
shell, no package manager, and it runs as a non-root user. Publishing the port
to `127.0.0.1` rather than `0.0.0.0` keeps the unauthenticated console off the
network.

To build it yourself:

```sh
docker build -t loggen .
```

### Cross-compiling

The build is pure Go, so one machine can produce binaries for every platform:

```sh
make release          # all platforms into dist/

# or individually
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o loggen .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o loggen.exe .
```

`make` targets: `build`, `run`, `vet`, `fmt`, `release`, `clean`. Windows
without `make` can run the underlying `go` commands directly.

### Running as a service on Ubuntu

A hardened systemd unit is in [`packaging/loggen.service`](packaging/loggen.service):

```sh
sudo useradd --system --home /var/lib/loggen --shell /usr/sbin/nologin loggen
sudo mkdir -p /opt/loggen /var/lib/loggen
sudo install -m 0755 loggen /opt/loggen/loggen
sudo chown loggen:loggen /var/lib/loggen
sudo cp packaging/loggen.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now loggen
```

The unit binds the console to localhost, since it is unauthenticated. To reach
it from your workstation, tunnel over SSH rather than exposing it:

```sh
ssh -L 8088:127.0.0.1:8088 user@the-host
```

### Notes for either platform

Sending to a SIEM on port 514 needs no special privileges — LogGen only connects
outbound. Running the **sink** on a port below 1024 does need privileges on
Linux (`sudo ./loggen -sink :514`); use a high port like `:5514` to avoid that.

### Running it

The console binds to all interfaces on port 8088, so it is reachable from other
machines on the same network out of the box. On startup it prints every address
it can be reached on, labelled by interface, so you know which one to type:

```
LogGen console reachable at:
    http://127.0.0.1:8088  (this machine)
    http://192.168.18.7:8088  (Wi-Fi)
    http://192.168.79.1:8088  (VMware Network Adapter VMnet1)
```

Interfaces that are down, and addresses in `169.254.0.0/16`, are left out: a
link-local address means the interface never got a lease, so nothing will reach
it there.

To use a different port, or to restrict it to this machine only:

```sh
./loggen -addr 0.0.0.0:9090        # all interfaces, port 9090
./loggen -addr 127.0.0.1:8088      # this machine only
./loggen -addr 192.168.18.7:8088   # one specific interface
```

**On Windows**, the first run raises a Windows Defender Firewall prompt. Allow
it, or nothing on the network will reach the console even though it is listening.
If you dismissed the prompt, add the rule from an elevated PowerShell:

```powershell
New-NetFirewallRule -DisplayName "LogGen console" -Direction Inbound `
  -Protocol TCP -LocalPort 8088 -Action Allow -Profile Private
```

Use `-Profile Private,Public` only if the network you are on is classified as
Public and you accept that. Check with `Get-NetConnectionProfile`.

> **The console has no authentication and will send syslog traffic to any host
> you point it at.** Anyone who can reach the port can drive it. Keep it on a
> network you control, and use `-addr 127.0.0.1:8088` when you do not need
> access from another machine.

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `0.0.0.0:8088` | Console listen address |
| `-data` | `data` | Directory holding `profiles.json` |
| `-open` | `true` | Open a browser on start |
| `-sink` | *(off)* | Run as a syslog receiver instead, e.g. `-sink :5514` |
| `-version` | | Print the version and exit |

LogGen shuts down cleanly on Ctrl+C or `SIGTERM`, letting in-flight requests
finish, so a burst that is interrupted does not leave you wondering whether the
last records went out.

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
| **Host / Port** | Where records go, as a **host name or an IP address** — `wazuh.corp.local` works as well as `10.20.30.5`. Wazuh's syslog listener is normally 514. |
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

## Administration

Everything configurable lives behind the **Administration** button: target
profiles, the simulated estate, and your own controls.

### Adding your own records

Built-in controls are compiled in, which is what lets them reproduce a format
exactly. The Administration view adds a second kind: a control you define
yourself, saved to disk, which appears in the simulation view alongside the rest.

Use it to add a record to a source that already exists, or type a **new source
name** to create one. A source nobody has written Go code for is simulated the
same way.

A control carries a **record template** with `{{placeholder}}` tokens:

```
Connection closed by authenticating user {{user}} {{external_ip}} port {{port}} [preauth]
```

Roughly thirty tokens are available, listed in the form and insertable by
clicking. They cover the estate (`{{domain}}`, `{{winhost}}`, `{{dbname}}`),
identities (`{{user}}`, `{{admin}}`, `{{sid}}`), the network (`{{internal_ip}}`,
`{{external_ip}}`, `{{port}}`, `{{mac}}`), system values (`{{pid}}`, `{{uuid}}`,
`{{logon_id}}`, `{{hex:8}}`), time (`{{timestamp}}`, `{{syslog_time}}`,
`{{epoch}}`) and randomness (`{{int:1-50}}`, `{{pick:a|b|c}}`).

You also set the syslog tag, facility, severity, and whether a PID follows the
tag, so a custom record is framed exactly like a real one.

### Parameters

Declaring a parameter gives the control an editable field in the simulation
view's detail drawer, just like a built-in one. Each parameter takes a
**default**, which may itself be a token:

| Parameter | Default | Result |
|---|---|---|
| `srcip` | `{{external_ip}}` | generated when left blank, used verbatim when typed |

A token naming a declared parameter is always resolved, so an unfilled field
never leaks `{{braces}}` into a record. A token that is neither a parameter nor a
known placeholder is left **as written**, so a typo shows up in the preview
instead of silently becoming an empty string.

Preview renders the real wire format before you save.

Custom controls persist in `data/profiles.json` and cannot shadow a built-in ID.

## Using it

The console has three places: **Send**, **Targets** and **Library**.

### The destination bar

Across the top sits the destination and its actual state, because sending to
nowhere is the first thing that goes wrong:

| State | Meaning |
|---|---|
| **Connected** | TCP handshake succeeded; something is listening. |
| **Ready** | UDP socket opened. **Delivery is not confirmed.** |
| **Unreachable** | Nothing is listening. Check host, port and firewall. |

The UDP wording is deliberate. A UDP send always looks successful even when the
collector is down, so the bar says the delivery is unverified rather than
showing a green light that means nothing. Confirm a record actually arrived at
the collector.

### Sending

- **Click a card** to send it. **Details** opens a drawer to set specific fields
  and preview the exact wire format first.
- **Recently sent** keeps the last few one click away, since the same records
  get fired repeatedly while a rule is being written.
- **Repeat** emits up to 500 records at a set interval, reusing one connection
  and regenerating fields per record, so a brute-force run looks like one.

### Keyboard

| Key | Action |
|---|---|
| `/` | Jump to search from anywhere |
| `Enter` | Send the first match |
| `↓` | Step from search into the grid |
| `← → ↑ ↓` | Move between cards |
| `Enter` / `Space` | Send the focused card |
| `Esc` | Close the drawer, or clear the search |

### Seeing what went out

The **Last record** panel shows the most recent line byte for byte, with its
priority decoded — `PRI 132` becomes `local0 · warning`. Below it, **Sent** is a
compact history; clicking any row puts that record back in the panel. That is
the fastest way to establish whether a decoding problem is in the log or in the
SIEM.

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
Makefile                 build, cross-compile and release targets
packaging/               systemd unit for running as a service on Linux
.github/workflows/       CI (vet, cross-compile, catalog check) and release builds
internal/core/           shared types: Env, Profile, Control, Payload, Ctx + generators
internal/store/          JSON persistence for profiles and estate
internal/sender/         syslog encoding (3164/5424/raw), Snare and eventchannel JSON,
                         UDP/TCP transport
internal/catalog/        control registry
  windows.go             core Windows event log controls
  windows_extended.go    delegation, discovery, directory and audit-integrity events
  linux.go               Linux syslog controls
  web.go                 Nginx + Apache, generated from one shared case table
  oracle.go              Oracle standard/unified audit, listener and alert logs
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

## Contributing

New controls are the most useful contribution — a log source that is missing, or
an event ID that matters for a detection you are writing.

The one rule that matters: **keep the record faithful to what the real source
emits.** A control that is nearly right is worse than none, because it teaches a
rule to match something that will never occur in production. Where a format
cannot be confirmed against a real captured record or vendor documentation, say
so in a comment rather than guessing — there are several such notes already in
`oracle.go`.

Before opening a pull request:

```sh
gofmt -l .           # must print nothing
go vet ./...
go test ./...        # or: make test
go test ./... -race  # needs a C toolchain
```

CI runs all of those on every push, cross-compiles for four platforms, runs the
browser suite, and starts the binary to confirm the catalogue still registers
cleanly.

### What the tests cover

**Go tests** render every control and check that none produces an empty record
or an unresolved format verb, that Snare records keep their fifteen fields, that
the Windows JSON envelope parses, and that a value appearing in a Windows
record's description also appears in its structured fields — a generator called
twice would silently break any rule correlating the two. The store is covered
for atomic writes, concurrent access, and recovery from a config that will not
parse.

**Browser tests** live in [`test/browser`](test/browser) and drive a real
browser against a running server: rendering, filtering, search, destination
state, sending, the keyboard path, creating and deleting a custom control,
accessibility and responsive layout. See that directory's README for how to run
them locally.

## Author

Built by **Shahrukh Khan**.

- Website — [heyshahrukh.me](https://www.heyshahrukh.me)
- LinkedIn — [Shahrukh98khan](https://www.linkedin.com/in/shahrukh98khan)

## License

[MIT](LICENSE) © Shahrukh Khan

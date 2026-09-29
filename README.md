# LogSource

A log simulation lab for **Wazuh log onboarding and detection-rule testing** at SOCByte.

It generates correctly structured records for common log sources and ships them to a SIEM over syslog, so decoders, field extraction and detection rules can be exercised without a real estate behind them. Click a control, one record goes out.

## Status

| Piece | State |
|---|---|
| SIEM profiles (host / port / TCP / UDP / format) | Done |
| Syslog sender (RFC 3164, RFC 5424, raw) | Done |
| Operator console + activity feed | Done |
| Local syslog sink for testing | Done |
| Windows log source | Not started |
| Linux log source | Not started |
| Nginx log source | Not started |
| Apache log source | Not started |

## Requirements

Go 1.24 or newer. No third-party dependencies — everything is standard library.

## Build and run

```powershell
cd D:\Shahrukh\LogSource
go build -o logsource.exe .
.\logsource.exe
```

The console opens at <http://127.0.0.1:8088>.

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `127.0.0.1:8088` | Console listen address |
| `-data` | `data` | Directory holding `profiles.json` |
| `-open` | `true` | Open a browser on start |
| `-sink` | *(off)* | Run as a syslog receiver instead, e.g. `-sink :5514` |

## Testing without Wazuh

The same binary can play collector. In one terminal:

```powershell
.\logsource.exe -sink :5514
```

In another, start the console, add a profile pointing at `127.0.0.1:5514`, and click a control. The sink prints exactly what arrived on the wire.

## SIEM profiles

A profile is one target. Several can be configured and switched between from the top bar.

| Field | Notes |
|---|---|
| **Host / Port** | Where records go. Wazuh's syslog listener is normally 514. |
| **Protocol** | `udp` or `tcp`. |
| **Syslog format** | `rfc3164` (classic BSD — what Wazuh expects), `rfc5424` (structured), or `raw` (no header). |
| **TCP framing** | `lf` (newline delimited, RFC 6587 non-transparent) or `octet` (length prefix). Ignored for UDP. |
| **Windows format** | `snare` (`MSWinEventLog` tab-delimited) or `json` (eventchannel). Used once the Windows source lands. |
| **Web raw** | Send web access logs with no syslog header, which Wazuh's `web-accesslog` decoder reads most cleanly. |

### Testing a target

The **Test** button opens a socket to the target. For TCP that is a real check — a failed handshake means nothing is listening. For **UDP it only proves a route and a local socket exist**; UDP is fire-and-forget, so a black hole still reports success. To actually confirm UDP delivery, send a heartbeat and look for it on the Wazuh side.

### Wazuh side

To accept syslog, the manager needs a remote block in `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.20.30.0/24</allowed-ips>
</remote>
```

Restart with `systemctl restart wazuh-manager`. Records then land in `/var/ossec/logs/archives/archives.log` when `<logall>yes</logall>` is set, and alerts in `alerts.json`.

## Simulated estate

The **Estate** dialog holds the domain, NetBIOS name, Windows/Linux/web hostnames and subnet prefix that every generated record draws from. Setting it once is what makes a Windows logon, a sudo call and an Nginx hit look like they came from the same organisation. Domain and user SIDs are derived from these names, so an account keeps the same SID across restarts.

## Sending

- **Click a card** — sends one record immediately with generated field values.
- **Details** — opens a drawer to set specific fields (username, source IP, …) before sending, and to preview the exact wire format without sending.
- **Burst / Delay** — emit up to 500 records at a set interval. Bursts reuse one connection and regenerate fields per record, so a brute-force run looks like a brute-force run.

Everything sent is recorded in the **Activity** feed with the exact bytes, which is the fastest way to check a decoder problem is in the log rather than in Wazuh.

## Layout

```
main.go                  entry point, flags, embedded web assets
internal/core/           shared types: Env, Profile, Control, Payload, Ctx + generators
internal/store/          JSON persistence for profiles and estate
internal/sender/         syslog encoding (3164/5424/raw) and UDP/TCP transport
internal/catalog/        control registry — log sources register here
internal/sink/           local syslog receiver for testing
internal/server/         HTTP API and console
web/                     operator console (no build step, no framework)
data/profiles.json       created on first run
```

## Adding a log source

Each source is one file in `internal/catalog/` that registers its controls from `init()`. Nothing else needs to change — the console, the API and the sender pick them up automatically.

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

`c.P(key, fallback)` is the one rule to follow: return the operator's value when they typed one, otherwise generate something realistic. That is what makes every control work both as a one-click button and as a precise, hand-tuned test case.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Estate, profiles and controls in one call |
| `GET` | `/api/controls` | Control catalog |
| `GET` | `/api/activity` | Send history, newest first |
| `PUT` | `/api/env` | Update the estate |
| `GET POST` | `/api/profiles` | List / create profiles |
| `PUT DELETE` | `/api/profiles/{id}` | Update / delete a profile |
| `POST` | `/api/profiles/{id}/default` | Set the default target |
| `POST` | `/api/profiles/{id}/test` | Probe connectivity |
| `POST` | `/api/preview` | Render a control without sending |
| `POST` | `/api/send` | Render and send |

`/api/send` takes `{controlId, profileId, params, count, delayMs}`. A single record is sent inline and returns the result; a burst returns `202` and reports through the activity feed.

## Scope

This tool writes synthetic log records for a SIEM you control. It is for validating parsers and detection logic in the SOCByte lab. It is not an attack tool and generates no real activity on any host.

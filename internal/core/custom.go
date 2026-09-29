package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CustomControl is a simulation defined by the operator rather than compiled in.
//
// Built-in controls render through Go code, which is what lets them reproduce a
// format exactly. A custom control instead carries a message template with
// {{placeholder}} tokens, so a new record can be added without rebuilding, and a
// source that nobody has written a Go file for can still be simulated.
type CustomControl struct {
	ID       string   `json:"id"`
	Source   string   `json:"source"`
	Group    string   `json:"group"`
	Name     string   `json:"name"`
	Desc     string   `json:"desc"`
	EventID  string   `json:"eventId,omitempty"`
	Channel  string   `json:"channel,omitempty"`
	Severity string   `json:"severity"`
	Mitre    []string `json:"mitre,omitempty"`
	Wazuh    []string `json:"wazuh,omitempty"`

	// Wire settings. Host is derived from the source when left blank.
	Tag        string `json:"tag"`
	IncludePID bool   `json:"includePid"`
	Host       string `json:"host,omitempty"`
	Facility   int    `json:"facility"`
	SyslogSev  int    `json:"syslogSeverity"`

	// Template is the record itself, with {{placeholder}} tokens.
	Template string  `json:"template"`
	Params   []Param `json:"params,omitempty"`
}

// Normalize fills defaults and clamps anything the form could get wrong.
func (cc CustomControl) Normalize() CustomControl {
	cc.Name = strings.TrimSpace(cc.Name)
	cc.Source = strings.ToLower(strings.TrimSpace(cc.Source))
	cc.Group = strings.TrimSpace(cc.Group)
	cc.Desc = strings.TrimSpace(cc.Desc)
	cc.Tag = strings.TrimSpace(cc.Tag)

	if cc.Source == "" {
		cc.Source = "custom"
	}
	if cc.Group == "" {
		cc.Group = "Custom"
	}
	if cc.Name == "" {
		cc.Name = "Unnamed control"
	}
	switch cc.Severity {
	case SevLabelInfo, SevLabelLow, SevLabelMedium, SevLabelHigh, SevLabelCritical:
	default:
		cc.Severity = SevLabelInfo
	}
	if cc.Facility < 0 || cc.Facility > 23 {
		cc.Facility = FacLocal0
	}
	if cc.SyslogSev < 0 || cc.SyslogSev > 7 {
		cc.SyslogSev = SevInfo
	}

	cc.Mitre = trimAll(cc.Mitre)
	cc.Wazuh = trimAll(cc.Wazuh)
	return cc
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Control returns the metadata the console renders as a card.
func (cc CustomControl) Control() Control {
	return Control{
		ID: cc.ID, Source: cc.Source, Group: cc.Group,
		Name: cc.Name, Desc: cc.Desc,
		EventID: cc.EventID, Channel: cc.Channel,
		Severity: cc.Severity, Mitre: cc.Mitre, Wazuh: cc.Wazuh,
		Params: cc.Params, Custom: true,
	}
}

// Build renders the template into a payload.
func (cc CustomControl) Build(c *Ctx) Payload {
	host := strings.TrimSpace(cc.Host)
	if host == "" {
		host = defaultHostFor(cc.Source, c.Env)
	}
	pid := 0
	if cc.IncludePID {
		pid = c.PID()
	}
	c.Declare(cc.Params)

	return Payload{
		Kind:     cc.Source,
		Tag:      cc.Tag,
		PID:      pid,
		Host:     Expand(host, c),
		Facility: cc.Facility,
		Severity: cc.SyslogSev,
		Message:  Expand(cc.Template, c),
	}
}

// defaultHostFor picks the estate host that matches a source.
func defaultHostFor(source string, env Env) string {
	switch source {
	case SourceWindows:
		return env.WinHost
	case SourceNginx, SourceApache:
		return env.WebHost
	case SourceOracle:
		return env.DBHost
	default:
		return env.LinuxHost
	}
}

// ---------------------------------------------------------------------------
// Template expansion
// ---------------------------------------------------------------------------

var tokenRE = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_:|.\- ]+?)\s*\}\}`)

// Placeholder documents one token for the console's reference panel.
type Placeholder struct {
	Token   string `json:"token"`
	Meaning string `json:"meaning"`
	Group   string `json:"group"`
}

// Placeholders is the set of tokens a template may use. The console renders
// this so the operator does not have to guess.
func Placeholders() []Placeholder {
	return []Placeholder{
		{"{{domain}}", "AD domain, e.g. corp.local", "Estate"},
		{"{{netbios}}", "NetBIOS name, e.g. CORP", "Estate"},
		{"{{winhost}}", "Windows hostname", "Estate"},
		{"{{linuxhost}}", "Linux hostname", "Estate"},
		{"{{webhost}}", "Web server hostname", "Estate"},
		{"{{dbhost}}", "Database hostname", "Estate"},
		{"{{dbname}}", "Oracle SID or service name", "Estate"},
		{"{{subnet}}", "Internal subnet prefix", "Estate"},

		{"{{user}}", "Random employee account", "Identity"},
		{"{{admin}}", "Random privileged account", "Identity"},
		{"{{service_user}}", "Random service account", "Identity"},
		{"{{upn}}", "user@domain for a random user", "Identity"},
		{"{{workstation}}", "Random workstation name", "Identity"},
		{"{{sid}}", "Stable SID for a random user", "Identity"},
		{"{{domain_sid}}", "The estate's domain SID", "Identity"},

		{"{{internal_ip}}", "Address inside the estate subnet", "Network"},
		{"{{external_ip}}", "Routable public address", "Network"},
		{"{{port}}", "Ephemeral client port", "Network"},
		{"{{mac}}", "Random MAC address", "Network"},
		{"{{user_agent}}", "Browser User-Agent string", "Network"},

		{"{{pid}}", "Process identifier", "System"},
		{"{{uuid}}", "Random GUID in braces", "System"},
		{"{{logon_id}}", "Windows logon ID, e.g. 0x3A91C4", "System"},
		{"{{hex:8}}", "N uppercase hex digits", "System"},

		{"{{timestamp}}", "RFC 3339 timestamp", "Time"},
		{"{{syslog_time}}", "Syslog timestamp, e.g. Sep 29 14:05:06", "Time"},
		{"{{epoch}}", "Unix seconds", "Time"},

		{"{{int:1-100}}", "Random integer in a range", "Random"},
		{"{{pick:a|b|c}}", "One of the listed values", "Random"},

		{"{{param_name}}", "Any parameter key you declare below", "Parameters"},
	}
}

// Expand replaces every {{token}} in s.
//
// A parameter the operator typed wins over a generator of the same name, which
// is what makes a custom control behave like a built-in one: leave a field blank
// and it is invented, fill it in and it is used verbatim.
func Expand(s string, c *Ctx) string {
	return tokenRE.ReplaceAllStringFunc(s, func(match string) string {
		inner := strings.TrimSpace(match[2 : len(match)-2])

		// An operator-supplied value always wins.
		if v := c.P(inner, ""); v != "" {
			return v
		}
		// A declared parameter the operator left blank falls back to its
		// default, which may itself be a token. Resolving it here is what stops
		// an unfilled parameter leaking {{braces}} into the record.
		if p, ok := c.Declared(inner); ok {
			if strings.TrimSpace(p.Default) != "" {
				return Expand(p.Default, c)
			}
			return ""
		}
		if v, ok := expandToken(inner, c); ok {
			return v
		}
		// Anything else is left untouched, so a mistyped token shows up in the
		// preview instead of silently becoming an empty string.
		return match
	})
}

func expandToken(tok string, c *Ctx) (string, bool) {
	// Parameterised forms first.
	if rest, ok := strings.CutPrefix(tok, "hex:"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil || n < 1 || n > 64 {
			n = 8
		}
		return c.Hex(n), true
	}
	if rest, ok := strings.CutPrefix(tok, "int:"); ok {
		lo, hi, found := strings.Cut(rest, "-")
		if !found {
			return "", false
		}
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return "", false
		}
		return strconv.Itoa(c.Int(a, b)), true
	}
	if rest, ok := strings.CutPrefix(tok, "pick:"); ok {
		opts := strings.Split(rest, "|")
		for i := range opts {
			opts[i] = strings.TrimSpace(opts[i])
		}
		return c.PickFrom(opts), true
	}

	switch tok {
	case "domain":
		return c.Env.Domain, true
	case "netbios":
		return c.Env.NetBIOS, true
	case "winhost":
		return c.Env.WinHost, true
	case "linuxhost":
		return c.Env.LinuxHost, true
	case "webhost":
		return c.Env.WebHost, true
	case "dbhost":
		return c.Env.DBHost, true
	case "dbname":
		return c.Env.DBName, true
	case "subnet":
		return c.Env.Subnet, true

	case "user":
		return c.User(), true
	case "admin":
		return c.AdminUser(), true
	case "service_user":
		return c.ServiceUser(), true
	case "upn":
		return c.UPN(c.User()), true
	case "workstation":
		return c.Workstation(), true
	case "sid":
		return c.UserSID(c.User()), true
	case "domain_sid":
		return c.DomainSID(), true

	case "internal_ip":
		return c.InternalIP(), true
	case "external_ip":
		return c.ExternalIP(), true
	case "port":
		return strconv.Itoa(c.EphemeralPort()), true
	case "mac":
		return c.MAC(), true
	case "user_agent":
		return c.UserAgent(), true

	case "pid":
		return strconv.Itoa(c.PID()), true
	case "uuid":
		return c.GUID(), true
	case "logon_id":
		return c.LogonID(), true

	case "timestamp":
		return c.Now.Format(time.RFC3339), true
	case "syslog_time":
		return c.Now.Format("Jan _2 15:04:05"), true
	case "epoch":
		return strconv.FormatInt(c.Now.Unix(), 10), true
	}
	return "", false
}

// CustomID turns a name into a stable, URL-safe control ID.
func CustomID(source, name string) string {
	var b strings.Builder
	b.WriteString("custom-")
	for _, r := range strings.ToLower(source + "-" + name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	if id == "custom" || id == "" {
		id = fmt.Sprintf("custom-%d", time.Now().UnixNano()%100000)
	}
	return id
}

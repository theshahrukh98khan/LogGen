package sender

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

func testTime() time.Time {
	return time.Date(2026, 9, 29, 14, 5, 6, 0, time.UTC)
}

func linuxPayload() core.Payload {
	return core.Payload{
		Kind: core.SourceLinux, Tag: "sshd", PID: 4242, Host: "ubuntu-app01",
		Facility: core.FacAuthPriv, Severity: core.SevInfo,
		Message: "Failed password for jdoe from 203.0.113.9 port 51234 ssh2",
	}
}

func profile(mutate func(*core.Profile)) core.Profile {
	p := core.DefaultProfile()
	if mutate != nil {
		mutate(&p)
	}
	return p.Normalize()
}

func TestPriority(t *testing.T) {
	// authpriv (10) * 8 + info (6) = 86
	if got := core.Priority(core.FacAuthPriv, core.SevInfo); got != 86 {
		t.Errorf("Priority(authpriv, info) = %d, want 86", got)
	}
	// local0 (16) * 8 + info (6) = 134, the value Oracle audit records carry.
	if got := core.Priority(core.FacLocal0, core.SevInfo); got != 134 {
		t.Errorf("Priority(local0, info) = %d, want 134", got)
	}
}

func TestEncodeRFC3164(t *testing.T) {
	got := Encode(linuxPayload(), profile(nil), testTime())
	want := "<86>Sep 29 14:05:06 ubuntu-app01 sshd[4242]: " +
		"Failed password for jdoe from 203.0.113.9 port 51234 ssh2"
	if got != want {
		t.Errorf("RFC3164 encoding\n got: %s\nwant: %s", got, want)
	}
}

// RFC 3164 pads a single-digit day with a space, which parsers rely on.
func TestEncodeRFC3164PadsSingleDigitDay(t *testing.T) {
	ts := time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC)
	got := Encode(linuxPayload(), profile(nil), ts)
	if !strings.Contains(got, "Sep  5 01:02:03") {
		t.Errorf("single-digit day not space-padded: %s", got)
	}
}

func TestEncodeRFC5424(t *testing.T) {
	p := profile(func(p *core.Profile) { p.Format = core.FormatRFC5424 })
	got := Encode(linuxPayload(), p, testTime())
	re := regexp.MustCompile(`^<86>1 2026-09-29T14:05:06\.000Z ubuntu-app01 sshd 4242 - - Failed password`)
	if !re.MatchString(got) {
		t.Errorf("RFC5424 encoding did not match: %s", got)
	}
}

func TestEncodeRaw(t *testing.T) {
	p := profile(func(p *core.Profile) { p.Format = core.FormatRaw })
	got := Encode(linuxPayload(), p, testTime())
	if strings.HasPrefix(got, "<") {
		t.Errorf("raw format should carry no syslog header: %s", got)
	}
	if got != linuxPayload().Message {
		t.Errorf("raw format altered the message: %s", got)
	}
}

// A tag-less payload must not leave a stray separator behind.
func TestEncodeWithoutTag(t *testing.T) {
	pl := linuxPayload()
	pl.Tag, pl.PID = "", 0
	got := Encode(pl, profile(nil), testTime())
	if strings.Contains(got, ": :") || strings.Contains(got, "[0]") {
		t.Errorf("tag-less record is malformed: %s", got)
	}
	if !strings.HasSuffix(got, pl.Message) {
		t.Errorf("message missing from tag-less record: %s", got)
	}
}

// Syslog is line oriented: an embedded newline would be read as a second,
// malformed record.
func TestEncodeFlattensNewlines(t *testing.T) {
	pl := linuxPayload()
	pl.Message = "first line\nsecond line\r\nthird\tline"
	got := Encode(pl, profile(nil), testTime())
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("encoded record still contains a line break: %q", got)
	}
	if strings.Contains(got, "\t") {
		t.Errorf("encoded record still contains a tab: %q", got)
	}
}

func TestWebRawAppliesOnlyToWebSources(t *testing.T) {
	p := profile(func(p *core.Profile) { p.WebRaw = true })

	web := core.Payload{
		Kind: core.SourceNginx, Tag: "nginx", Host: "web-prod01",
		Facility: core.FacLocal7, Severity: core.SevInfo,
		Message: `10.0.0.1 - - [29/Sep/2026:14:05:06 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"`,
	}
	if got := Encode(web, p, testTime()); strings.HasPrefix(got, "<") {
		t.Errorf("webRaw should strip the header for web sources: %s", got)
	}
	if got := Encode(linuxPayload(), p, testTime()); !strings.HasPrefix(got, "<") {
		t.Errorf("webRaw must not affect non-web sources: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Windows encoders
// ---------------------------------------------------------------------------

func winPayload() core.Payload {
	return core.Payload{
		Kind: core.SourceWindows, Host: "WIN-DC01",
		Facility: core.FacLocal0, Severity: core.SevWarning,
		Win: &core.WinEvent{
			EventID: "4625", Channel: "Security",
			Provider:     "Microsoft-Windows-Security-Auditing",
			ProviderGUID: "{54849625-5478-4994-a5ba-3e3b0328c30d}",
			Task:         "12544", TaskName: "Logon",
			AuditType: core.AuditFailure, Keywords: "0x8010000000000000",
			Computer: "WIN-DC01.corp.local", User: `CORP\jdoe`,
			Message:     "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\tS-1-0-0",
			Criticality: 2, RecordID: 12345, ProcessID: 700, ThreadID: 1400,
			EventData: map[string]string{"targetUserName": "jdoe", "status": "0xc000006d"},
		},
	}
}

func TestSnareHasFifteenFields(t *testing.T) {
	got := Encode(winPayload(), profile(nil), testTime())
	body := got[strings.Index(got, "MSWinEventLog"):]
	fields := strings.Split(body, "\t")

	if len(fields) != 15 {
		t.Fatalf("Snare record has %d fields, want 15:\n%s", len(fields), got)
	}
	if fields[0] != "MSWinEventLog" {
		t.Errorf("field 1 = %q, want MSWinEventLog", fields[0])
	}
	if fields[2] != "Security" {
		t.Errorf("field 3 (channel) = %q, want Security", fields[2])
	}
	if fields[5] != "4625" {
		t.Errorf("field 6 (event ID) = %q, want 4625", fields[5])
	}
	if fields[9] != core.AuditFailure {
		t.Errorf("field 10 (audit type) = %q, want %q", fields[9], core.AuditFailure)
	}
	// Snare leaves DataString empty, which is why two tabs appear in a row.
	if fields[12] != "" {
		t.Errorf("field 13 (DataString) = %q, want empty", fields[12])
	}
	if !strings.Contains(fields[13], "An account failed to log on.") {
		t.Errorf("field 14 (description) is wrong: %q", fields[13])
	}
	if strings.ContainsAny(fields[13], "\r\n") {
		t.Errorf("field 14 still contains a line break: %q", fields[13])
	}
}

func TestSnareSIDType(t *testing.T) {
	for user, want := range map[string]string{
		`CORP\jdoe`: "User", "WIN-DC01$": "Computer", "": "N/A", "N/A": "N/A",
	} {
		pl := winPayload()
		pl.Win.User = user
		got := Encode(pl, profile(nil), testTime())
		fields := strings.Split(got[strings.Index(got, "MSWinEventLog"):], "\t")
		if fields[8] != want {
			t.Errorf("SID type for user %q = %q, want %q", user, fields[8], want)
		}
	}
}

func TestWindowsJSONIsValidAndSingleLine(t *testing.T) {
	p := profile(func(p *core.Profile) { p.WinFormat = "json" })
	got := Encode(winPayload(), p, testTime())

	idx := strings.Index(got, `{"win"`)
	if idx < 0 {
		t.Fatalf("no win envelope in output: %s", got)
	}
	body := got[idx:]

	if strings.ContainsAny(body, "\n\r") {
		t.Error("JSON record spans more than one physical line")
	}

	var env struct {
		Win struct {
			System    map[string]string `json:"system"`
			EventData map[string]string `json:"eventdata"`
		} `json:"win"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("JSON record does not parse: %v\n%s", err, body)
	}
	if env.Win.System["eventID"] != "4625" {
		t.Errorf("eventID = %q, want 4625", env.Win.System["eventID"])
	}
	if env.Win.System["severityValue"] != "AUDIT_FAILURE" {
		t.Errorf("severityValue = %q, want AUDIT_FAILURE", env.Win.System["severityValue"])
	}
	// The description must survive intact, newlines and all, inside the string.
	if !strings.Contains(env.Win.System["message"], "An account failed to log on.") {
		t.Error("description lost in the JSON envelope")
	}
	if env.Win.EventData["targetUserName"] != "jdoe" {
		t.Errorf("eventdata lost: %v", env.Win.EventData)
	}
}

// ---------------------------------------------------------------------------
// Transport framing
// ---------------------------------------------------------------------------

func TestTCPFraming(t *testing.T) {
	const wire = "<86>hello"

	lf := &Conn{profile: profile(func(p *core.Profile) {
		p.Protocol = core.ProtoTCP
		p.TCPFraming = core.FramingLF
	})}
	if got := string(lf.frame(wire)); got != wire+"\n" {
		t.Errorf("newline framing = %q, want %q", got, wire+"\n")
	}

	oct := &Conn{profile: profile(func(p *core.Profile) {
		p.Protocol = core.ProtoTCP
		p.TCPFraming = core.FramingOctet
	})}
	if got := string(oct.frame(wire)); got != "9 "+wire {
		t.Errorf("octet framing = %q, want %q", got, "9 "+wire)
	}

	// UDP needs no delimiter: one datagram is one message.
	udp := &Conn{profile: profile(nil)}
	if got := string(udp.frame(wire)); got != wire {
		t.Errorf("UDP framing altered the payload: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Destination name resolution
// ---------------------------------------------------------------------------

// A destination may be named rather than numbered. An address needs no lookup,
// and saying so lets the console skip reporting what it "resolved to".
func TestResolveAcceptsAnAddress(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.20.30.5", "::1"} {
		got := Resolve(core.Profile{Host: host, Port: 514})
		if got.Failed {
			t.Errorf("Resolve(%q) failed: %s", host, got.Message)
		}
		if !got.IsIP {
			t.Errorf("Resolve(%q) should not need a lookup", host)
		}
		if len(got.Addrs) != 1 {
			t.Errorf("Resolve(%q) returned %d addresses, want 1", host, len(got.Addrs))
		}
	}
}

func TestResolveLooksUpAName(t *testing.T) {
	got := Resolve(core.Profile{Host: "localhost", Port: 514})
	if got.Failed {
		t.Fatalf("localhost did not resolve: %s", got.Message)
	}
	if got.IsIP {
		t.Error("a name should be reported as needing a lookup")
	}
	if len(got.Addrs) == 0 {
		t.Error("no addresses returned for localhost")
	}
}

// A name that does not resolve must be reported as a resolution failure, not
// left for the dialler to report as a connection problem: the two have
// different fixes and the advice differs.
func TestResolveReportsAnUnknownName(t *testing.T) {
	got := Resolve(core.Profile{Host: "siem.invalid.example", Port: 514})
	if !got.Failed {
		t.Fatal("an unresolvable name was reported as fine")
	}
	if got.Message == "" {
		t.Error("no reason given for the failure")
	}
	if got.IsIP {
		t.Error("a name was misreported as an address")
	}
}

// Whitespace around a pasted hostname must not defeat the lookup.
func TestResolveTrimsTheHost(t *testing.T) {
	got := Resolve(core.Profile{Host: "  localhost  ", Port: 514})
	if got.Failed {
		t.Errorf("a padded hostname failed to resolve: %s", got.Message)
	}
	if got.Host != "localhost" {
		t.Errorf("Host = %q, want it trimmed", got.Host)
	}
}

// Addr has to bracket an IPv6 literal, or a dial to it fails.
func TestNamedDestinationAddr(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"wazuh.corp.local", "wazuh.corp.local:514"},
		{"10.20.30.5", "10.20.30.5:514"},
		{"::1", "[::1]:514"},
	} {
		got := core.Profile{Host: tc.host, Port: 514}.Addr()
		if got != tc.want {
			t.Errorf("Addr(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

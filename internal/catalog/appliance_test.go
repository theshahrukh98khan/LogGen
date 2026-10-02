package catalog

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// bodyOf renders a control and returns just the record, without any syslog
// framing, which is what these format assertions care about.
func bodyOf(t *testing.T, id string) string {
	t.Helper()
	def, ok := Get(id)
	if !ok {
		t.Fatalf("control %q is not registered", id)
	}
	return def.Build(core.NewCtx(core.DefaultEnv(), nil)).Message
}

// ---------------------------------------------------------------------------
// Palo Alto
// ---------------------------------------------------------------------------

// PAN-OS is positional CSV: a field in the wrong slot does not fail, it
// silently becomes the next field's meaning. The counts come from the PAN-OS
// 11.0 syslog field descriptions.
func TestPanOSFieldCounts(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want int
	}{
		{"paloalto-traffic-allow", 53},
		{"paloalto-traffic-deny", 53},
		{"paloalto-threat-vulnerability", 60},
		{"paloalto-threat-virus", 60},
		{"paloalto-threat-url", 60},
		{"paloalto-threat-wildfire", 60},
	} {
		got := strings.Split(bodyOf(t, tc.id), ",")
		if len(got) != tc.want {
			t.Errorf("%s produced %d fields, want %d", tc.id, len(got), tc.want)
		}
	}
}

func TestPanOSFixedPositions(t *testing.T) {
	f := strings.Split(bodyOf(t, "paloalto-traffic-allow"), ",")
	if len(f) < 53 {
		t.Fatalf("record is too short: %d fields", len(f))
	}
	// Positions are 1-based in the vendor reference, 0-based here.
	for _, tc := range []struct {
		pos  int
		want string
		name string
	}{
		{3, core.DefaultEnv().FWSerial, "Serial Number"},
		{4, "TRAFFIC", "Type"},
		{31, "allow", "Action"},
		{53, core.DefaultEnv().FWHost, "Device Name"},
	} {
		if got := f[tc.pos-1]; got != tc.want {
			t.Errorf("field %d (%s) = %q, want %q", tc.pos, tc.name, got, tc.want)
		}
	}
	// The reserved slots must be present, or everything after them shifts.
	for _, pos := range []int{6, 22, 39, 44} {
		if f[pos-1] != "" {
			t.Errorf("field %d should be an empty FUTURE_USE slot, got %q", pos, f[pos-1])
		}
	}
	if f[0] != "1" {
		t.Errorf("field 1 = %q, want \"1\"", f[0])
	}
}

func TestPanOSThreatPositions(t *testing.T) {
	f := strings.Split(bodyOf(t, "paloalto-threat-vulnerability"), ",")
	if len(f) < 60 {
		t.Fatalf("record is too short: %d fields", len(f))
	}
	if f[3] != "THREAT" {
		t.Errorf("field 4 (Type) = %q, want THREAT", f[3])
	}
	if f[4] != "vulnerability" {
		t.Errorf("field 5 (Threat/Content Type) = %q, want vulnerability", f[4])
	}
	if f[34] != "critical" {
		t.Errorf("field 35 (Severity) = %q, want critical", f[34])
	}
}

// ---------------------------------------------------------------------------
// FortiGate
// ---------------------------------------------------------------------------

func TestFortiGateKeyValueShape(t *testing.T) {
	for _, id := range []string{
		"fortigate-traffic-accept", "fortigate-traffic-deny",
		"fortigate-ips-signature", "fortigate-av-blocked",
		"fortigate-webfilter-block", "fortigate-admin-login",
		"fortigate-vpn-tunnel-up", "fortigate-config-change",
	} {
		body := bodyOf(t, id)
		// The header fields a decoder keys on must all be present.
		for _, key := range []string{"date=", "time=", "devname=", "devid=",
			"logid=", "type=", "subtype=", "level=", "eventtime="} {
			if !strings.Contains(body, key) {
				t.Errorf("%s is missing %s", id, key)
			}
		}
		// Quoted values must be balanced, or the rest of the line is unparseable.
		if strings.Count(body, `"`)%2 != 0 {
			t.Errorf("%s has an unbalanced quote: %.120s", id, body)
		}
	}
}

func TestFortiGateLogIDIsTenDigits(t *testing.T) {
	re := regexp.MustCompile(`logid="(\d+)"`)
	for _, c := range Controls() {
		if c.Source != core.SourceFortiGate {
			continue
		}
		m := re.FindStringSubmatch(bodyOf(t, c.ID))
		if m == nil {
			t.Errorf("%s has no logid", c.ID)
			continue
		}
		if len(m[1]) != 10 {
			t.Errorf("%s logid %q is %d digits, want 10", c.ID, m[1], len(m[1]))
		}
	}
}

// ---------------------------------------------------------------------------
// Sophos
// ---------------------------------------------------------------------------

func TestSophosRecordShape(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceSophos {
			continue
		}
		body := bodyOf(t, c.ID)
		if !strings.HasPrefix(body, `device="SFW"`) {
			t.Errorf("%s does not open with the device block: %.60s", c.ID, body)
		}
		for _, key := range []string{"log_type=", "log_component=", "log_subtype=", "device_id="} {
			if !strings.Contains(body, key) {
				t.Errorf("%s is missing %s", c.ID, key)
			}
		}
		if strings.Count(body, `"`)%2 != 0 {
			t.Errorf("%s has an unbalanced quote", c.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Cisco
// ---------------------------------------------------------------------------

// Decoders match the %ASA-level-id: prefix literally, so its shape is fixed.
func TestCiscoMessagePrefix(t *testing.T) {
	re := regexp.MustCompile(`^%(ASA|FTD)-[0-7]-\d{6}: `)
	for _, c := range Controls() {
		if c.Source != core.SourceCiscoASA && c.Source != core.SourceCiscoFTD {
			continue
		}
		body := bodyOf(t, c.ID)
		if !re.MatchString(body) {
			t.Errorf("%s does not open with a valid message prefix: %.60s", c.ID, body)
		}
		// The prefix must name the platform the control belongs to.
		wantPrefix := "%ASA-"
		if c.Source == core.SourceCiscoFTD {
			wantPrefix = "%FTD-"
		}
		if !strings.HasPrefix(body, wantPrefix) {
			t.Errorf("%s uses the wrong platform prefix: %.20s", c.ID, body)
		}
		// The message ID in the text must match the one advertised on the card.
		if c.EventID != "" && !strings.Contains(body, "-"+c.EventID+": ") {
			t.Errorf("%s advertises event ID %s but the message says %.24s",
				c.ID, c.EventID, body)
		}
	}
}

// ---------------------------------------------------------------------------
// Trend Micro Vision One
// ---------------------------------------------------------------------------

// CEF is seven pipe-separated header fields followed by the extensions. A
// stray unescaped pipe shifts every header field after it.
func TestTrendMicroCEFHeader(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceTrendVision {
			continue
		}
		body := bodyOf(t, c.ID)

		if !strings.HasPrefix(body, "CEF:0|") {
			t.Errorf("%s does not open with CEF:0|: %.40s", c.ID, body)
			continue
		}
		// Split on unescaped pipes only.
		parts := splitUnescaped(body, '|')
		if len(parts) < 8 {
			t.Errorf("%s has %d header fields, want at least 8", c.ID, len(parts))
			continue
		}
		if parts[1] != "Trend Micro" {
			t.Errorf("%s vendor = %q, want Trend Micro", c.ID, parts[1])
		}
		if parts[2] != "Vision One" {
			t.Errorf("%s product = %q, want Vision One", c.ID, parts[2])
		}
		// CEF severity is a number 0-10, so it has to be compared as one.
		sev, err := strconv.Atoi(parts[6])
		if err != nil || sev < 0 || sev > 10 {
			t.Errorf("%s severity = %q, want an integer 0-10", c.ID, parts[6])
		}
		if strings.ContainsAny(body, "\n\r") {
			t.Errorf("%s spans more than one line", c.ID)
		}
	}
}

// splitUnescaped splits on sep, ignoring occurrences preceded by a backslash.
func splitUnescaped(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == sep {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	out = append(out, cur.String())
	return out
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// None of these formats survives an embedded newline, and several would be
// misparsed by a stray tab.
func TestApplianceRecordsAreSingleLine(t *testing.T) {
	appliance := map[string]bool{
		core.SourcePaloAlto: true, core.SourceFortiGate: true,
		core.SourceSophos: true, core.SourceCiscoASA: true,
		core.SourceCiscoFTD: true, core.SourceTrendVision: true,
	}
	for _, c := range Controls() {
		if !appliance[c.Source] {
			continue
		}
		if strings.ContainsAny(bodyOf(t, c.ID), "\n\r\t") {
			t.Errorf("%s contains a newline or tab", c.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// SAP Security Audit Log
// ---------------------------------------------------------------------------

// A SAL record is fixed width: every field is read by offset, so a value one
// character too long shifts everything after it and the record silently decodes
// as something else. The offsets are the ones documented in sap.go.
func TestSAPSALRecordLayout(t *testing.T) {
	ids := []string{}
	for _, c := range Controls() {
		if c.Source == core.SourceSAP {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no SAP controls are registered")
	}

	msgID := regexp.MustCompile(`^[A-Z][A-Z0-9]{2}$`)
	digits := regexp.MustCompile(`^\d+$`)

	for _, id := range ids {
		body := bodyOf(t, id)
		if len(body) != 200 {
			t.Errorf("%s produced a %d character record, want 200", id, len(body))
			continue
		}
		if body[0:1] != "3" {
			t.Errorf("%s: version character is %q, want \"3\"", id, body[0:1])
		}
		if got := body[1:4]; !msgID.MatchString(got) {
			t.Errorf("%s: message id %q is not three upper-case characters", id, got)
		}
		if got := body[4:12]; !digits.MatchString(got) {
			t.Errorf("%s: date field %q is not eight digits", id, got)
		}
		if got := body[12:18]; !digits.MatchString(got) {
			t.Errorf("%s: time field %q is not six digits", id, got)
		}
		if got := body[20:25]; !digits.MatchString(got) {
			t.Errorf("%s: OS pid field %q is not five digits", id, got)
		}
		if got := body[27:30]; !digits.MatchString(got) {
			t.Errorf("%s: work process number %q is not three digits", id, got)
		}
		if got := body[30:32]; got != salDialog && got != salBackground {
			t.Errorf("%s: work process and task type %q is neither %q nor %q",
				id, got, salDialog, salBackground)
		}
		if got := body[112:115]; !digits.MatchString(got) {
			t.Errorf("%s: client %q is not three digits", id, got)
		}
		// Fields are left justified and blank padded, never shifted right.
		for _, f := range []struct {
			name       string
			start, end int
		}{
			{"user", 40, 52},
			{"transaction", 52, 72},
			{"program", 72, 112},
			{"variables", 116, 180},
			{"terminal", 180, 200},
		} {
			v := body[f.start:f.end]
			if strings.TrimSpace(v) != "" && v[0] == ' ' {
				t.Errorf("%s: %s field is not left justified: %q", id, f.name, v)
			}
		}
	}
}

// Every variable in the 64-character area is terminated by "&", and the count
// field holds the number of populated slots.
func TestSAPSALVariableArea(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceSAP {
			continue
		}
		body := bodyOf(t, c.ID)
		if len(body) != 200 {
			t.Fatalf("%s produced a %d character record", c.ID, len(body))
		}
		vars := strings.TrimRight(body[116:180], " ")
		if vars == "" {
			if body[115:116] != "0" {
				t.Errorf("%s: no variables but count field is %q", c.ID, body[115:116])
			}
			continue
		}
		if !strings.HasSuffix(vars, "&") {
			t.Errorf("%s: variable area %q does not end in \"&\"", c.ID, vars)
		}
		populated := 0
		for _, v := range strings.Split(strings.TrimSuffix(vars, "&"), "&") {
			if v != "" {
				populated++
			}
		}
		if got, want := body[115:116], strconv.Itoa(populated); got != want {
			t.Errorf("%s: count field is %q but %d variables are populated", c.ID, got, populated)
		}
	}
}

// A control that generates a value twice instead of once produces two different
// values, which is the commonest bug in this catalog. Where a SAL record repeats
// a value in two places, the two have to agree.
func TestSAPRepeatedValuesAgree(t *testing.T) {
	for i := 0; i < 50; i++ {
		// AU3 carries the transaction code in both the record field and in
		// variable A; AUW does the same with the program name.
		au3 := bodyOf(t, "sap-au3-sensitive-transaction")
		if tcode, varA := strings.TrimSpace(au3[52:72]), strings.TrimSpace(strings.Split(au3[116:180], "&")[0]); tcode != varA {
			t.Fatalf("AU3 transaction field %q does not match variable A %q", tcode, varA)
		}
		auw := bodyOf(t, "sap-auw-sensitive-report")
		if prog, varA := strings.TrimSpace(auw[72:112]), strings.TrimSpace(strings.Split(auw[116:180], "&")[0]); prog != varA {
			t.Fatalf("AUW program field %q does not match variable A %q", prog, varA)
		}
		// AUM carries the client in the client field and in variable A, and the
		// user in the user field and in variable B.
		aum := bodyOf(t, "sap-aum-user-locked")
		v := strings.Split(aum[116:180], "&")
		if client := aum[112:115]; client != v[0] {
			t.Fatalf("AUM client field %q does not match variable A %q", client, v[0])
		}
		if user := strings.TrimSpace(aum[40:52]); user != v[1] {
			t.Fatalf("AUM user field %q does not match variable B %q", user, v[1])
		}
	}
}

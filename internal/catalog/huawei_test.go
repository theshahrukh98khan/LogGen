package catalog

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// The VRP header is the whole value of this source: a decoder keys on the
// %%01Module/Severity/Brief(Flag) structure, and a record that gets the shape
// wrong parses as nothing at all.
//
// Reference, from Huawei's "Log Message Format Description":
//
//	Aug 6 2011 20:34:46 HUAWEI %%01HWCM/5/EXIT(l)[1]: exit from configure mode
var hwHeader = regexp.MustCompile(
	`^<(\d{1,3})>[A-Z][a-z]{2} [ 0-9]\d \d{4} \d{2}:\d{2}:\d{2} (\S+) %%01([A-Z0-9_-]+)/(\d)/([A-Z0-9_]+)\(([ltds])\)(\[\d+\])?:`)

// huaweiControls renders every Huawei control once.
func huaweiControls(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range Controls() {
		if c.Source != core.SourceHuawei {
			continue
		}
		def, ok := Get(c.ID)
		if !ok {
			t.Fatalf("control %q is not registered", c.ID)
		}
		out[c.ID] = def.Build(core.NewCtx(core.DefaultEnv(), nil)).Message
	}
	if len(out) == 0 {
		t.Fatal("no Huawei controls are registered")
	}
	return out
}

func TestHuaweiHeaderShape(t *testing.T) {
	for id, line := range huaweiControls(t) {
		switch id {
		// The session log timestamps itself differently and the threat record
		// is trap text; both are checked separately below.
		case "huawei-session-teardown", "huawei-ips-threat":
			continue
		}
		m := hwHeader.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("%s does not match the VRP header: %s", id, line)
			continue
		}
		// The severity in the Brief and the severity in the PRI are the same
		// number on a real device; local7 is facility 23.
		sev, err := strconv.Atoi(m[4])
		if err != nil {
			t.Errorf("%s: severity %q is not a number", id, m[4])
			continue
		}
		if want := "<" + strconv.Itoa(23*8+sev) + ">"; !strings.HasPrefix(line, want) {
			t.Errorf("%s: PRI does not carry severity %d, want prefix %s: %s", id, sev, want, line)
		}
	}
}

// The firewall service logs are captured without a serial number; the
// information-centre logs are documented with one.
func TestHuaweiPolicyHasNoSerial(t *testing.T) {
	lines := huaweiControls(t)
	for _, id := range []string{"huawei-policy-permit", "huawei-policy-deny"} {
		m := hwHeader.FindStringSubmatch(lines[id])
		if m == nil {
			t.Fatalf("%s does not match the VRP header: %s", id, lines[id])
		}
		if m[7] != "" {
			t.Errorf("%s carries a serial number %s, captured records have none", id, m[7])
		}
	}
}

func TestHuaweiSessionAndTrapShape(t *testing.T) {
	lines := huaweiControls(t)

	// SECLOG session records use "2006-01-02 15:04:05".
	session := regexp.MustCompile(
		`^<190>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ %%01SECLOG/6/SESSION_TEARDOWN\(l\):IPVer=4,`)
	if !session.MatchString(lines["huawei-session-teardown"]) {
		t.Errorf("session record has the wrong shape: %s", lines["huawei-session-teardown"])
	}

	// A trap rendered as a log has no %%01 and no flag.
	trap := lines["huawei-ips-threat"]
	if strings.Contains(trap, "%%01") {
		t.Errorf("threat trap should not carry the %%%%01 prefix: %s", trap)
	}
	if !strings.Contains(trap, " IPSTRAP/4/THREATTRAP:OID 1.3.6.1.4.1.2011.6.122.43.1.2.8 ") {
		t.Errorf("threat trap lost its OID: %s", trap)
	}
}

// Every record ships Raw: the PRI, timestamp and hostname are already in it, so
// a second syslog header would corrupt the line.
func TestHuaweiPayloadsAreRaw(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceHuawei {
			continue
		}
		def, _ := Get(c.ID)
		if p := def.Build(core.NewCtx(core.DefaultEnv(), nil)); !p.Raw {
			t.Errorf("%s is not Raw, so the sender would prepend a second header", c.ID)
		}
	}
}

// The estate has to reach the records: a Huawei line names the device.
func TestHuaweiUsesEstateHosts(t *testing.T) {
	env := core.DefaultEnv()
	lines := huaweiControls(t)
	for id, line := range lines {
		if !strings.Contains(line, env.FWHost) && !strings.Contains(line, env.SwitchHost) {
			t.Errorf("%s names neither %s nor %s: %s", id, env.FWHost, env.SwitchHost, line)
		}
	}
}

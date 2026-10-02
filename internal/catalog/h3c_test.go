package catalog

import (
	"regexp"
	"strings"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// h3cControls returns every registered H3C control.
func h3cControls(t *testing.T) []core.Control {
	t.Helper()
	var out []core.Control
	for _, c := range Controls() {
		if c.Source == core.SourceH3C {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no H3C controls registered")
	}
	return out
}

// Every Comware record sent to a log host opens with the vendor ID and log
// version, then Module/Level/Mnemonic. A decoder anchors on that prefix, so if
// it is wrong nothing downstream matches.
var h3cDigest = regexp.MustCompile(`^%%10[A-Z0-9]+/[0-7]/[A-Z0-9_]+:`)

func TestH3CDigestPrefix(t *testing.T) {
	for _, ctl := range h3cControls(t) {
		body := bodyOf(t, ctl.ID)
		if !h3cDigest.MatchString(body) {
			t.Errorf("%s: does not open with %%%%10Module/Level/Mnemonic: %q", ctl.ID, body)
		}
	}
}

// The Level inside the digest is the syslog severity. Comware sets both from
// the same number, so a record whose PRI disagrees with its own digest would
// be impossible on a real device.
func TestH3CLevelMatchesSeverity(t *testing.T) {
	for _, ctl := range h3cControls(t) {
		def, _ := Get(ctl.ID)
		p := def.Build(core.NewCtx(core.DefaultEnv(), nil))
		parts := strings.SplitN(p.Message, "/", 3)
		if len(parts) < 3 {
			t.Fatalf("%s: malformed digest %q", ctl.ID, p.Message)
		}
		if got := parts[1]; got != string(rune('0'+p.Severity)) {
			t.Errorf("%s: digest level %s but syslog severity %d", ctl.ID, got, p.Severity)
		}
	}
}

// The fast-log-output modules write "Key(id)=value;" pairs with no space after
// the mnemonic's colon, and the conventional modules write a sentence with
// one. Mixing the two is the easiest way to break a parser.
func TestH3CFastLogSpacing(t *testing.T) {
	// Modules whose published examples run the first field straight onto the
	// colon, and the terminator each fast-log module ends on.
	tight := map[string]bool{
		"SESSION": true, "ATK": true, "IPS": true, "AUDIT": true, "OBJP": true,
		"PORTSEC": true, "DOT1X": true,
	}
	term := map[string]string{
		"SESSION": ";", "IPS": ";", "AUDIT": ";", "OBJP": ";", "ATK": ".",
	}

	for _, ctl := range h3cControls(t) {
		body := bodyOf(t, ctl.ID)
		module := strings.SplitN(strings.TrimPrefix(body, "%%10"), "/", 2)[0]
		after := body[strings.Index(body, ":")+1:]

		if tight[module] {
			if strings.HasPrefix(after, " ") {
				t.Errorf("%s: %s must not put a space after the colon: %q", ctl.ID, module, body)
			}
		} else if !strings.HasPrefix(after, " ") {
			t.Errorf("%s: %s must put one space after the colon: %q", ctl.ID, module, body)
		}

		if want, ok := term[module]; ok && !strings.HasSuffix(body, want) {
			t.Errorf("%s: %s record must end with %q: %q", ctl.ID, module, want, body)
		}
	}
}

// Comware writes MAC addresses as three hyphen-separated groups of four hex
// digits. A colon-separated address would be a different vendor's format.
func TestH3CMACFormat(t *testing.T) {
	mac := regexp.MustCompile(`[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}`)
	for _, id := range []string{"h3c-portsec-violation", "h3c-mac-move", "h3c-dot1x-login-failure", "h3c-arp-inspection"} {
		body := bodyOf(t, id)
		if !mac.MatchString(body) {
			t.Errorf("%s: no Comware-style MAC address in %q", id, body)
		}
	}
}

// A session record repeats its addresses and ports across the NAT keys. Two
// calls to a generator would quietly produce a record that contradicts itself,
// which is the bug this catalog has hit before.
func TestH3CSessionValuesAreConsistent(t *testing.T) {
	for i := 0; i < 50; i++ {
		body := bodyOf(t, "h3c-deny-session-ipv4-flow")
		f := map[string]string{}
		for _, pair := range strings.Split(strings.TrimSuffix(body, ";"), ";") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				f[kv[0]] = kv[1]
			}
		}
		if f["SrcIPAddr(1003)"] != f["NATSrcIPAddr(1005)"] {
			t.Fatalf("source address and NAT source address differ: %q vs %q",
				f["SrcIPAddr(1003)"], f["NATSrcIPAddr(1005)"])
		}
		if f["DstPort(1008)"] != f["NATDstPort(1010)"] {
			t.Fatalf("destination port and NAT destination port differ: %q vs %q",
				f["DstPort(1008)"], f["NATDstPort(1010)"])
		}
	}
}

// The MAC flapping record names two ports and they must not be the same one.
func TestH3CMacMovePortsDiffer(t *testing.T) {
	re := regexp.MustCompile(`moved from port (\S+) to port (\S+) for`)
	for i := 0; i < 50; i++ {
		body := bodyOf(t, "h3c-mac-move")
		m := re.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("unexpected wording: %q", body)
		}
		if m[1] == m[2] {
			t.Fatalf("MAC flapping record moved a MAC to the port it was already on: %q", body)
		}
	}
}

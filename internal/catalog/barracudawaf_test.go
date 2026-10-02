package catalog

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// The Barracuda WAF emits five positional formats that differ only after the
// third field. A record written in the wrong field order still parses, it just
// means something else, so these tests pin the order rather than the content.

// bwFields splits a Barracuda record into logical fields. Two things make a
// naive strings.Fields wrong: the timestamp "yyyy-mm-dd hh:mm:ss.sss +hhmm"
// occupies three whitespace-separated tokens but is one field (%t), and quoted
// values such as the User-Agent contain spaces.
func bwFields(rec string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range rec {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ' ' && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	if len(out) < 3 {
		return out
	}
	// Fold the three timestamp tokens back into the single %t field.
	return append([]string{strings.Join(out[:3], " ")}, out[3:]...)
}

// bwIDs returns every registered Barracuda WAF control for one log type.
func bwIDs(logType string) []string {
	var ids []string
	for _, c := range Controls() {
		if c.Source == core.SourceBarracudaWAF && c.Channel == logType {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// TestBarracudaWAFPreamble checks the three fields every log type shares: %t,
// %un and %lt. %lt is the discriminator a decoder branches on, so if it lands
// in the wrong slot nothing downstream works.
func TestBarracudaWAFPreamble(t *testing.T) {
	for _, lt := range []string{"WF", "TR", "AUDIT", "NF", "SYS"} {
		ids := bwIDs(lt)
		if len(ids) == 0 {
			t.Errorf("no %s controls are registered", lt)
		}
		for _, id := range ids {
			rec := bodyOf(t, id)
			f := bwFields(rec)
			if len(f) < 3 {
				t.Fatalf("%s: record is too short: %q", id, rec)
			}
			// %t: "yyyy-mm-dd hh:mm:ss.s TZD", as the vendor examples print it.
			if _, err := time.Parse("2006-01-02 15:04:05.000 -0700", f[0]); err != nil {
				t.Errorf("%s: field 1 is not a Barracuda timestamp: %q", id, f[0])
			}
			if f[1] != core.DefaultEnv().WAFHost {
				t.Errorf("%s: field 2 (%%un) is %q, want the unit name %q",
					id, f[1], core.DefaultEnv().WAFHost)
			}
			if f[2] != lt {
				t.Errorf("%s: field 3 (%%lt) is %q, want %q", id, f[2], lt)
			}
		}
	}
}

// TestBarracudaWAFAccessFieldOrder pins the access log against the vendor's own
// worked example:
//
//	%t %un %lt %ai %ap %ci %cp %id %cu %m %p %h %v %s %bs %br %ch %tt %si %sp
//	%st %sid %rtf %pmf %pf %wmf %u %q %r %c %ua %px %pp %au %cs1 %cs2 %cs3
func TestBarracudaWAFAccessFieldOrder(t *testing.T) {
	for _, id := range bwIDs("TR") {
		f := bwFields(bodyOf(t, id))
		if len(f) != 37 {
			t.Errorf("%s produced %d access log fields, want 37", id, len(f))
			continue
		}
		// %id and %cu are quoted even when empty; the vendor sample shows "-".
		for _, pos := range []int{7, 8} {
			if !strings.HasPrefix(f[pos], `"`) || !strings.HasSuffix(f[pos], `"`) {
				t.Errorf("%s: field %d is %q, want a quoted value", id, pos+1, f[pos])
			}
		}
		// Numeric slots. A string landing here means the order has slipped.
		for _, pos := range []int{4, 6, 13, 14, 15, 16, 17, 19, 20, 32} {
			if _, err := strconv.Atoi(f[pos]); err != nil {
				t.Errorf("%s: field %d is %q, want a number", id, pos+1, f[pos])
			}
		}
		switch f[12] {
		case "HTTP/1.0", "HTTP/1.1", "HTTP/2":
		default:
			t.Errorf("%s: field 13 (%%v) is %q, want an HTTP version", id, f[12])
		}
		if f[16] != "0" && f[16] != "1" {
			t.Errorf("%s: field 17 (%%ch) is %q, want 0 or 1", id, f[16])
		}
		if f[22] != "INTERNAL" && f[22] != "SERVER" {
			t.Errorf("%s: field 23 (%%rtf) is %q, want INTERNAL or SERVER", id, f[22])
		}
		if f[23] != "DEFAULT" && f[23] != "PROFILED" {
			t.Errorf("%s: field 24 (%%pmf) is %q, want DEFAULT or PROFILED", id, f[23])
		}
		switch f[24] {
		case "PASSIVE", "PROTECTED", "UNPROTECTED":
		default:
			t.Errorf("%s: field 25 (%%pf) is %q, want PASSIVE, PROTECTED or UNPROTECTED",
				id, f[24])
		}
		if f[25] != "VALID" && f[25] != "INVALID" {
			t.Errorf("%s: field 26 (%%wmf) is %q, want VALID or INVALID", id, f[25])
		}
		if !strings.HasPrefix(f[26], "/") {
			t.Errorf("%s: field 27 (%%u) is %q, want a request path", id, f[26])
		}
		if !strings.HasPrefix(f[30], `"`) {
			t.Errorf("%s: field 31 (%%ua) is %q, want a quoted User-Agent", id, f[30])
		}
	}
}

// TestBarracudaWAFWebFirewallFieldOrder pins the Web Firewall log:
//
//	%t %un %lt %sl %ad %ci %cp %ai %ap %ri %rt %at %fa %adl %m %u %p %sid %ua
//	%px %pp %au %r
//
// The total field count is not asserted because %rt ("URL POLICY") and %adl
// legitimately contain spaces, as does the audit log's %trt ("UNSUCCESSFUL
// LOGIN"). The fixed offsets up to %ap and the enumerated values are what a
// decoder actually depends on.
func TestBarracudaWAFWebFirewallFieldOrder(t *testing.T) {
	actions := map[string]int{}
	for _, id := range bwIDs("WF") {
		rec := bodyOf(t, id)
		f := bwFields(rec)
		if len(f) < 9 {
			t.Fatalf("%s: web firewall record is too short: %q", id, rec)
		}
		switch f[3] {
		case "EMER", "ALER", "CRIT", "ERRO", "WARN", "NOTI", "INFO", "DEBU":
		default:
			t.Errorf("%s: field 4 (%%sl) is %q, want a Barracuda severity token", id, f[3])
		}
		// %ad is the Attack Name in Export Logs: upper case with underscores.
		if f[4] != strings.ToUpper(f[4]) || strings.ContainsAny(f[4], " -") {
			t.Errorf("%s: field 5 (%%ad) is %q, want an export-log attack name", id, f[4])
		}
		for _, pos := range []int{6, 8} {
			if _, err := strconv.Atoi(f[pos]); err != nil {
				t.Errorf("%s: field %d is %q, want a port", id, pos+1, f[pos])
			}
		}
		// %adl is bracketed, which is the one thing the vendor sample confirms
		// about its contents.
		if open := strings.Index(rec, "["); open < 0 || !strings.Contains(rec[open:], "]") {
			t.Errorf("%s: no bracketed attack detail (%%adl) in the record", id)
		}
		// %at is the field a SOC rule keys on, and %fa follows it immediately.
		found := false
		for _, a := range []string{"DENY", "LOG", "WARNING"} {
			for _, fa := range []string{"NONE", "LOCKED"} {
				if strings.Contains(rec, " "+a+" "+fa+" [") {
					actions[a]++
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s: no documented %%at/%%fa pair before the attack detail: %s", id, rec)
		}
	}
	// A catalog where every attack is blocked is not useful. The records worth
	// alerting on hardest are the ones the WAF matched and served anyway.
	if actions["LOG"] < 3 {
		t.Errorf("only %d web firewall controls use action LOG; detected-but-not-blocked "+
			"is the more interesting case and should be well represented", actions["LOG"])
	}
	if actions["DENY"] == 0 {
		t.Error("no web firewall control uses action DENY")
	}
	if actions["WARNING"] == 0 {
		t.Error("no web firewall control uses action WARNING")
	}
}

// TestBarracudaWAFAuditFieldOrder pins the audit log:
//
//	%t %un %lt %an %ct %li %lp %trt %tri %cn %cht %ot %on %var %ov %nv %add
func TestBarracudaWAFAuditFieldOrder(t *testing.T) {
	for _, id := range bwIDs("AUDIT") {
		rec := bodyOf(t, id)
		f := bwFields(rec)
		if len(f) < 8 {
			t.Fatalf("%s: audit record is too short: %q", id, rec)
		}
		if f[4] != "GUI" && f[4] != "API" && f[4] != "CLI" {
			t.Errorf("%s: field 5 (%%ct) is %q, want a client type", id, f[4])
		}
		if _, err := strconv.Atoi(f[6]); err != nil {
			t.Errorf("%s: field 7 (%%lp) is %q, want a login port", id, f[6])
		}
		// %add is the last field and the vendor sample renders it bracketed.
		if !strings.HasSuffix(rec, "]") {
			t.Errorf("%s: record does not end with the bracketed %%add field", id)
		}
		// %cht must be one of the documented change types.
		change := ""
		for _, c := range []string{"NONE", "ADD", "DELETE", "SET"} {
			if strings.Contains(rec, " "+c+" ") {
				change = c
			}
		}
		if change == "" {
			t.Errorf("%s: no documented %%cht value in the record: %s", id, rec)
		}
		// The vendor states a transaction that changes nothing carries -1.
		if strings.Contains(rec, " LOGIN ") {
			if !strings.Contains(rec, " -1 ") {
				t.Errorf("%s: a login changes nothing persistent and should report "+
					"transaction ID -1: %s", id, rec)
			}
		}
	}
}

// TestBarracudaWAFSystemAndNetwork pins the two shorter formats:
//
//	SYS  %t %un %lt %md %ll %ei %ms
//	NF   %t %un %lt %sl %p %si %sp %di %dp %act %an %dsc
func TestBarracudaWAFSystemAndNetwork(t *testing.T) {
	for _, id := range bwIDs("SYS") {
		f := bwFields(bodyOf(t, id))
		if len(f) < 7 {
			t.Fatalf("%s: system record is too short", id)
		}
		if _, err := strconv.Atoi(f[5]); err != nil {
			t.Errorf("%s: field 6 (%%ei) is %q, want an event ID", id, f[5])
		}
	}
	for _, id := range bwIDs("NF") {
		f := bwFields(bodyOf(t, id))
		if len(f) < 12 {
			t.Fatalf("%s: network firewall record is too short", id)
		}
		if f[4] != "TCP" && f[4] != "UDP" && f[4] != "ICMP" {
			t.Errorf("%s: field 5 (%%p) is %q, want a protocol", id, f[4])
		}
		for _, pos := range []int{6, 8} {
			if _, err := strconv.Atoi(f[pos]); err != nil {
				t.Errorf("%s: field %d is %q, want a port", id, pos+1, f[pos])
			}
		}
		if f[9] != "ALLOW" && f[9] != "DENY" {
			t.Errorf("%s: field 10 (%%act) is %q, want ALLOW or DENY", id, f[9])
		}
	}
}

// TestBarracudaWAFNoEmptyPositionalFields guards the mistake positional formats
// punish hardest: an empty value collapses two separators into one and every
// field after it shifts left by one.
func TestBarracudaWAFNoEmptyPositionalFields(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceBarracudaWAF {
			continue
		}
		rec := bodyOf(t, c.ID)
		if strings.Contains(rec, "  ") {
			t.Errorf("%s: record contains a double space, which shifts every later "+
				"field: %s", c.ID, rec)
		}
		if strings.HasSuffix(rec, " ") {
			t.Errorf("%s: record ends with a trailing empty field", c.ID)
		}
	}
}

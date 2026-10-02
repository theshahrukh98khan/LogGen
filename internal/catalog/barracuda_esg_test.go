package catalog

import (
	"strconv"
	"strings"
	"testing"
)

// The Barracuda ESG mail syslog is positional: a field in the wrong slot does
// not fail to parse, it silently takes on the next field's meaning. These
// assertions pin the layout the vendor's Syslog Guide publishes:
//
//	<client> <msgid> <start> <end> <service> <info...>
//
// with the info section laid out per service.

func besFields(t *testing.T, id string) []string {
	t.Helper()
	return strings.Split(bodyOf(t, id), " ")
}

func besNumeric(t *testing.T, id string, f []string, pos int, name string) {
	t.Helper()
	if pos >= len(f) {
		t.Fatalf("%s: record is too short for %s at position %d", id, name, pos)
	}
	if _, err := strconv.Atoi(f[pos]); err != nil {
		t.Errorf("%s: %s at position %d is %q, want a number", id, name, pos, f[pos])
	}
}

func TestBarracudaESGScanLayout(t *testing.T) {
	for _, id := range []string{
		"barracuda-esg-virus-blocked",
		"barracuda-esg-score-blocked",
		"barracuda-esg-lookalike-delivered",
		"barracuda-esg-outbound-spam-blocked",
		"barracuda-esg-encrypted-message",
	} {
		body := bodyOf(t, id)
		f := strings.Split(body, " ")
		if len(f) < 14 {
			t.Fatalf("%s: SCAN record has %d fields, want at least 14", id, len(f))
		}
		if !strings.Contains(f[0], "[") || !strings.HasSuffix(f[0], "]") {
			t.Errorf("%s: client field is %q, want name[ip]", id, f[0])
		}
		besNumeric(t, id, f, 2, "start time")
		besNumeric(t, id, f, 3, "end time")
		if f[4] != "SCAN" {
			t.Errorf("%s: service is %q, want SCAN", id, f[4])
		}
		if f[5] != "-" {
			t.Errorf("%s: encrypted field is %q, want -", id, f[5])
		}
		// 6 sender, 7 recipient, 8 score, 9 action, 10 reason, 11 reason extra.
		for _, pos := range []int{9, 10} {
			besNumeric(t, id, f, pos, "action/reason code")
		}
		if !strings.Contains(f[8], ".") {
			t.Errorf("%s: score is %q, want a decimal score", id, f[8])
		}
		// The message id opens with the start timestamp; if they disagree the
		// two were generated separately, which is the bug this guards.
		if !strings.HasPrefix(f[1], f[2]+"-") {
			t.Errorf("%s: message id %q does not start with the start time %q", id, f[1], f[2])
		}
		sz := strings.Index(body, " SZ:")
		subj := strings.Index(body, " SUBJ:")
		if sz < 0 || subj < 0 || sz > subj {
			t.Errorf("%s: want SZ: immediately before SUBJ:, got %q", id, body)
		}
	}
}

func TestBarracudaESGRecvLayout(t *testing.T) {
	for _, id := range []string{
		"barracuda-esg-no-such-user",
		"barracuda-esg-rbl-match",
		"barracuda-esg-rate-control",
		"barracuda-esg-spf-failure",
	} {
		f := besFields(t, id)
		if len(f) < 10 {
			t.Fatalf("%s: RECV record has %d fields, want at least 10", id, len(f))
		}
		if f[4] != "RECV" {
			t.Errorf("%s: service is %q, want RECV", id, f[4])
		}
		// 5 sender, 6 recipient, 7 action, 8 reason, 9 reason extra. A RECV
		// line carries no encrypted flag and no score, unlike SCAN.
		besNumeric(t, id, f, 7, "action code")
		besNumeric(t, id, f, 8, "reason code")
		if !strings.HasPrefix(f[1], f[2]+"-") {
			t.Errorf("%s: message id %q does not start with the start time %q", id, f[1], f[2])
		}
	}
}

func TestBarracudaESGSendPlaceholders(t *testing.T) {
	for _, id := range []string{
		"barracuda-esg-send-delivered",
		"barracuda-esg-send-rejected",
		"barracuda-esg-send-tls-failed",
	} {
		f := besFields(t, id)
		if len(f) < 8 {
			t.Fatalf("%s: SEND record has %d fields, want at least 8", id, len(f))
		}
		// The appliance writes bogus values for the client and both times on a
		// SEND line, and a decoder has to be able to rely on that.
		if f[0] != "127.0.0.1" || f[2] != "0" || f[3] != "0" {
			t.Errorf("%s: want 127.0.0.1 and 0 0 placeholders, got %q %q %q", id, f[0], f[2], f[3])
		}
		if f[4] != "SEND" {
			t.Errorf("%s: service is %q, want SEND", id, f[4])
		}
		if f[5] != "-" {
			t.Errorf("%s: encrypted field is %q, want -", id, f[5])
		}
		besNumeric(t, id, f, 6, "action code")
	}
}

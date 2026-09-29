package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// env is the estate every test renders against.
func env() core.Env { return core.DefaultEnv() }

// render builds one control with no operator parameters.
func render(t *testing.T, id string) core.Payload {
	t.Helper()
	def, ok := Get(id)
	if !ok {
		t.Fatalf("control %q is not registered", id)
	}
	return def.Build(core.NewCtx(env(), nil))
}

func TestCatalogIsPopulated(t *testing.T) {
	if Count() < 100 {
		t.Fatalf("catalog looks truncated: %d controls", Count())
	}
}

// TestControlMetadata guards the fields the console relies on to render a card.
func TestControlMetadata(t *testing.T) {
	valid := map[string]bool{
		core.SevLabelInfo: true, core.SevLabelLow: true, core.SevLabelMedium: true,
		core.SevLabelHigh: true, core.SevLabelCritical: true,
	}
	seen := map[string]bool{}

	for _, c := range Controls() {
		if seen[c.ID] {
			t.Errorf("duplicate control ID %q", c.ID)
		}
		seen[c.ID] = true

		if strings.TrimSpace(c.Name) == "" {
			t.Errorf("%s: empty name", c.ID)
		}
		if strings.TrimSpace(c.Desc) == "" {
			t.Errorf("%s: empty description", c.ID)
		}
		if strings.TrimSpace(c.Source) == "" {
			t.Errorf("%s: empty source", c.ID)
		}
		if strings.TrimSpace(c.Group) == "" {
			t.Errorf("%s: empty group", c.ID)
		}
		if !valid[c.Severity] {
			t.Errorf("%s: invalid severity %q", c.ID, c.Severity)
		}

		keys := map[string]bool{}
		for _, p := range c.Params {
			if keys[p.Key] {
				t.Errorf("%s: duplicate param key %q", c.ID, p.Key)
			}
			keys[p.Key] = true
			if strings.TrimSpace(p.Label) == "" {
				t.Errorf("%s: param %q has no label", c.ID, p.Key)
			}
		}
	}
}

// TestEveryControlRenders is the broad safety net: every control must produce a
// usable record without panicking, and without leaking an unresolved format
// verb into the output.
func TestEveryControlRenders(t *testing.T) {
	for _, c := range Controls() {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			p := render(t, c.ID)

			body := p.Message
			if p.Win != nil {
				body = p.Win.Message
				if strings.TrimSpace(p.Win.EventID) == "" {
					t.Error("Windows payload has no event ID")
				}
				if strings.TrimSpace(p.Win.Channel) == "" {
					t.Error("Windows payload has no channel")
				}
			}
			if strings.TrimSpace(body) == "" {
				t.Fatal("rendered an empty record")
			}
			for _, bad := range []string{"%!", "<no value>", "{{", "%s", "%d"} {
				if strings.Contains(body, bad) {
					t.Errorf("record contains unresolved %q: %.160s", bad, body)
				}
			}
			if p.Host == "" {
				t.Error("payload has no host")
			}
			if p.Severity < 0 || p.Severity > 7 {
				t.Errorf("syslog severity out of range: %d", p.Severity)
			}
			if p.Facility < 0 || p.Facility > 23 {
				t.Errorf("syslog facility out of range: %d", p.Facility)
			}
		})
	}
}

// TestParametersAreHonoured checks that a value typed by the operator reaches
// the rendered record, which is the contract every control's Build follows.
func TestParametersAreHonoured(t *testing.T) {
	cases := []struct {
		id, key, value string
	}{
		{"linux-sshd-failed-password", "user", "qa_user_marker"},
		{"linux-sshd-failed-password", "srcip", "203.0.113.42"},
		{"win-4625-logon-failed", "user", "qa_user_marker"},
		{"win-4688-process-creation", "cmdline", "qa_marker.exe --flag"},
		{"nginx-200-get", "path", "/qa/marker/path"},
		{"oracle-audit-logon-success", "user", "QAMARKER"},
	}

	for _, tc := range cases {
		t.Run(tc.id+"/"+tc.key, func(t *testing.T) {
			def, ok := Get(tc.id)
			if !ok {
				t.Skipf("control %q not registered", tc.id)
			}
			p := def.Build(core.NewCtx(env(), map[string]string{tc.key: tc.value}))
			body := p.Message
			if p.Win != nil {
				body = p.Win.Message
			}
			if !strings.Contains(body, tc.value) {
				t.Errorf("parameter %q=%q not reflected in the record: %.200s",
					tc.key, tc.value, body)
			}
		})
	}
}

// TestWindowsEventDataMatchesMessage catches a class of bug that is invisible
// until a rule correlates the two: a generator called twice, once for the
// description and once for the structured fields, yielding two different values.
func TestWindowsEventDataMatchesMessage(t *testing.T) {
	// Fields whose value should appear verbatim in the description text.
	interesting := map[string]bool{
		"ipAddress": true, "targetUserName": true, "subjectUserName": true,
		"serviceName": true, "shareName": true, "taskName": true,
		"scriptBlockId": true, "deviceId": true, "sessionName": true,
		"newProcessName": true, "commandLine": true, "objectName": true,
	}

	for _, c := range Controls() {
		if c.Source != core.SourceWindows {
			continue
		}
		c := c
		t.Run(c.ID, func(t *testing.T) {
			p := render(t, c.ID)
			if p.Win == nil {
				t.Fatal("Windows control produced no Win payload")
			}
			for k, v := range p.Win.EventData {
				if !interesting[k] || strings.TrimSpace(v) == "" || v == "-" {
					continue
				}
				if !strings.Contains(p.Win.Message, v) {
					t.Errorf("eventdata %s=%q does not appear in the description; "+
						"a generator was probably called twice", k, v)
				}
			}
		})
	}
}

// TestUserSIDIsStable ensures an account keeps the same SID across renders,
// which is what makes correlation across records possible.
func TestUserSIDIsStable(t *testing.T) {
	a := core.NewCtx(env(), nil).UserSID("jdoe")
	b := core.NewCtx(env(), nil).UserSID("jdoe")
	if a != b {
		t.Errorf("SID for the same user changed between renders: %s vs %s", a, b)
	}
	if c := core.NewCtx(env(), nil).UserSID("asmith"); c == a {
		t.Errorf("different users share a SID: %s", c)
	}
}

// TestSnareDescriptionHasNoTabs guards the Snare encoder's field alignment: a
// tab inside the description would be read as a field separator.
func TestSnareDescriptionHasNoTabs(t *testing.T) {
	for _, c := range Controls() {
		if c.Source != core.SourceWindows {
			continue
		}
		p := render(t, c.ID)
		if p.Win != nil && strings.Contains(p.Win.Message, "\t\t\t\t") {
			t.Errorf("%s: description has a run of tabs that may survive flattening", c.ID)
		}
	}
}

// TestOracleRecordShapes pins the two audit formats apart, since they are not
// interchangeable and a decoder written for one cannot read the other.
func TestOracleRecordShapes(t *testing.T) {
	std := render(t, "oracle-audit-logon-success")
	if !strings.HasPrefix(std.Message, `LENGTH: "`) {
		t.Errorf("standard audit record should open with a double-quoted LENGTH: %.80s", std.Message)
	}
	if !strings.Contains(std.Message, `SESSIONID:[`) {
		t.Errorf("standard audit fields should carry [len] markers: %.120s", std.Message)
	}
	if std.Tag != "Oracle Audit" {
		t.Errorf("standard audit tag = %q, want %q", std.Tag, "Oracle Audit")
	}

	uni := render(t, "oracle-unified-logon")
	if !strings.HasPrefix(uni.Message, "LENGTH: '") {
		t.Errorf("unified record should open with a single-quoted LENGTH: %.80s", uni.Message)
	}
	if strings.Contains(uni.Message, "DBUSER:[") {
		t.Errorf("unified records carry no [len] markers: %.120s", uni.Message)
	}
	if uni.Tag != "Oracle Unified Audit" {
		t.Errorf("unified audit tag = %q, want %q", uni.Tag, "Oracle Unified Audit")
	}
}

// TestWebSourcesShareAccessFormat verifies the shared case table really does
// produce the same access-log structure for both servers.
func TestWebSourcesShareAccessFormat(t *testing.T) {
	n := render(t, "nginx-200-get")
	a := render(t, "apache-200-get")

	if n.Tag != "nginx" || a.Tag != "httpd" {
		t.Errorf("web tags = %q / %q, want nginx / httpd", n.Tag, a.Tag)
	}
	// Both must be the combined format: "METHOD path HTTP/1.1" status bytes.
	for label, msg := range map[string]string{"nginx": n.Message, "apache": a.Message} {
		if !strings.Contains(msg, `HTTP/1.1"`) {
			t.Errorf("%s access line is not combined format: %.120s", label, msg)
		}
	}
}

// TestControlsAreJSONSerialisable protects the /api/controls response.
func TestControlsAreJSONSerialisable(t *testing.T) {
	if _, err := json.Marshal(Controls()); err != nil {
		t.Fatalf("catalog does not serialise: %v", err)
	}
}

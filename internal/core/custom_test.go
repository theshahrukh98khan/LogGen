package core

import (
	"strings"
	"testing"
)

func ctx() *Ctx { return NewCtx(DefaultEnv(), nil) }

func TestExpandEstateTokens(t *testing.T) {
	c := ctx()
	got := Expand("{{domain}} {{netbios}} {{winhost}} {{dbname}}", c)
	want := "corp.local CORP WIN-DC01 ORCL"
	if got != want {
		t.Errorf("Expand() = %q, want %q", got, want)
	}
}

func TestExpandGeneratedTokens(t *testing.T) {
	c := ctx()
	for _, tok := range []string{
		"{{user}}", "{{admin}}", "{{workstation}}", "{{internal_ip}}",
		"{{external_ip}}", "{{port}}", "{{pid}}", "{{uuid}}", "{{logon_id}}",
		"{{mac}}", "{{sid}}", "{{timestamp}}", "{{epoch}}", "{{syslog_time}}",
	} {
		got := Expand(tok, c)
		if got == tok || strings.TrimSpace(got) == "" {
			t.Errorf("%s did not expand, got %q", tok, got)
		}
	}
}

func TestExpandParameterisedTokens(t *testing.T) {
	c := ctx()

	if got := Expand("{{hex:6}}", c); len(got) != 6 {
		t.Errorf("{{hex:6}} = %q, want 6 characters", got)
	}
	if got := Expand("{{int:5-5}}", c); got != "5" {
		t.Errorf("{{int:5-5}} = %q, want 5", got)
	}
	if got := Expand("{{pick:only}}", c); got != "only" {
		t.Errorf("{{pick:only}} = %q, want only", got)
	}
	// A pick must always return one of its options.
	for i := 0; i < 25; i++ {
		got := Expand("{{pick:a|b|c}}", c)
		if got != "a" && got != "b" && got != "c" {
			t.Fatalf("{{pick:a|b|c}} = %q, want one of a, b, c", got)
		}
	}
	if got := Expand("{{internal_ip}}", c); !strings.HasPrefix(got, "10.20.30.") {
		t.Errorf("{{internal_ip}} = %q, want the estate subnet", got)
	}
}

// An unknown token stays visible so a typo shows up in the preview instead of
// silently becoming an empty string.
func TestExpandLeavesUnknownTokensAlone(t *testing.T) {
	got := Expand("a {{not_a_real_token}} b", ctx())
	if !strings.Contains(got, "{{not_a_real_token}}") {
		t.Errorf("unknown token was swallowed: %q", got)
	}
}

func TestOperatorValueBeatsGenerator(t *testing.T) {
	c := NewCtx(DefaultEnv(), map[string]string{"user": "typed_user"})
	if got := Expand("{{user}}", c); got != "typed_user" {
		t.Errorf("Expand({{user}}) = %q, want the typed value", got)
	}
}

// A declared parameter left blank must resolve through its default rather than
// leaking {{braces}} into the record.
func TestDeclaredParameterFallsBackToDefault(t *testing.T) {
	cc := CustomControl{
		Source: "fortigate", Name: "test", Template: "srcip={{srcip}} dst={{dstip}}",
		Params: []Param{
			{Key: "srcip", Label: "Source IP", Default: "{{external_ip}}"},
			{Key: "dstip", Label: "Dest IP"}, // no default at all
		},
	}.Normalize()

	got := cc.Build(NewCtx(DefaultEnv(), nil)).Message
	if strings.Contains(got, "{{") {
		t.Errorf("a declared parameter leaked braces into the record: %q", got)
	}
	if !strings.Contains(got, "srcip=") {
		t.Errorf("record lost its structure: %q", got)
	}
	// The default is itself a token, so it must have been generated.
	if strings.Contains(got, "srcip= ") || strings.HasSuffix(got, "srcip=") {
		t.Errorf("default token did not generate a value: %q", got)
	}
}

func TestDeclaredParameterUsesTypedValue(t *testing.T) {
	cc := CustomControl{
		Source: "fortigate", Name: "test", Template: "srcip={{srcip}}",
		Params: []Param{{Key: "srcip", Default: "{{external_ip}}"}},
	}.Normalize()

	got := cc.Build(NewCtx(DefaultEnv(), map[string]string{"srcip": "198.51.100.9"})).Message
	if got != "srcip=198.51.100.9" {
		t.Errorf("typed parameter ignored: %q", got)
	}
}

func TestCustomControlNormalize(t *testing.T) {
	got := CustomControl{
		Name: "  ", Source: "  FortiGate ", Group: "",
		Severity: "bogus", Facility: 99, SyslogSev: 42,
		Mitre: []string{" T1110 ", "", "  "},
	}.Normalize()

	if got.Source != "fortigate" {
		t.Errorf("Source = %q, want fortigate (trimmed and lowercased)", got.Source)
	}
	if got.Severity != SevLabelInfo {
		t.Errorf("Severity = %q, want %q", got.Severity, SevLabelInfo)
	}
	if got.Facility != FacLocal0 {
		t.Errorf("Facility = %d, want %d", got.Facility, FacLocal0)
	}
	if got.SyslogSev != SevInfo {
		t.Errorf("SyslogSev = %d, want %d", got.SyslogSev, SevInfo)
	}
	if got.Group == "" || got.Name == "" {
		t.Errorf("blank group or name was not given a placeholder: %+v", got)
	}
	if len(got.Mitre) != 1 || got.Mitre[0] != "T1110" {
		t.Errorf("Mitre = %v, want [T1110] with blanks dropped", got.Mitre)
	}
}

// The host defaults to whichever estate machine matches the source, so a custom
// Windows record does not claim to come from the Linux box.
func TestCustomHostDefaultsBySource(t *testing.T) {
	env := DefaultEnv()
	for source, want := range map[string]string{
		SourceWindows: env.WinHost,
		SourceNginx:   env.WebHost,
		SourceApache:  env.WebHost,
		SourceOracle:  env.DBHost,
		SourceLinux:   env.LinuxHost,
		"fortigate":   env.LinuxHost,
	} {
		cc := CustomControl{Source: source, Name: "t", Template: "x"}.Normalize()
		if got := cc.Build(NewCtx(env, nil)).Host; got != want {
			t.Errorf("source %q host = %q, want %q", source, got, want)
		}
	}
}

func TestCustomHostAcceptsATemplate(t *testing.T) {
	cc := CustomControl{
		Source: "fortigate", Name: "t", Template: "x", Host: "{{webhost}}",
	}.Normalize()
	if got := cc.Build(NewCtx(DefaultEnv(), nil)).Host; got != DefaultEnv().WebHost {
		t.Errorf("Host = %q, want the expanded web host", got)
	}
}

func TestCustomBuildCarriesWireSettings(t *testing.T) {
	cc := CustomControl{
		Source: "linux", Name: "t", Template: "hello",
		Tag: "sshd", IncludePID: true,
		Facility: FacAuthPriv, SyslogSev: SevNotice,
	}.Normalize()

	p := cc.Build(NewCtx(DefaultEnv(), nil))
	if p.Tag != "sshd" {
		t.Errorf("Tag = %q, want sshd", p.Tag)
	}
	if p.PID == 0 {
		t.Error("IncludePID was set but no PID was generated")
	}
	if p.Facility != FacAuthPriv || p.Severity != SevNotice {
		t.Errorf("facility/severity = %d/%d, want %d/%d",
			p.Facility, p.Severity, FacAuthPriv, SevNotice)
	}
	if p.Kind != "linux" {
		t.Errorf("Kind = %q, want linux", p.Kind)
	}
}

func TestCustomIDIsStableAndSafe(t *testing.T) {
	a := CustomID("linux", "SSH key rejected")
	b := CustomID("linux", "SSH key rejected")
	if a != b {
		t.Errorf("CustomID is not stable: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "custom-") {
		t.Errorf("CustomID = %q, want a custom- prefix", a)
	}
	for _, r := range a {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !ok {
			t.Errorf("CustomID %q contains an unsafe character %q", a, r)
		}
	}
}

func TestPlaceholdersAreAllExpandable(t *testing.T) {
	c := ctx()
	for _, p := range Placeholders() {
		// The parameters group documents a shape, not a literal token.
		if p.Group == "Parameters" {
			continue
		}
		if got := Expand(p.Token, c); got == p.Token {
			t.Errorf("documented placeholder %s does not expand", p.Token)
		}
	}
}

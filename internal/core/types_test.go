package core

import "testing"

func TestProfileNormalizeClampsBadInput(t *testing.T) {
	got := Profile{
		Name: "   ", Host: "  ", Port: 99999,
		Protocol: "sctp", Format: "bogus",
		TCPFraming: "bogus", WinFormat: "bogus",
	}.Normalize()

	if got.Port != 514 {
		t.Errorf("Port = %d, want 514", got.Port)
	}
	if got.Protocol != ProtoUDP {
		t.Errorf("Protocol = %q, want %q", got.Protocol, ProtoUDP)
	}
	if got.Format != FormatRFC3164 {
		t.Errorf("Format = %q, want %q", got.Format, FormatRFC3164)
	}
	if got.TCPFraming != FramingLF {
		t.Errorf("TCPFraming = %q, want %q", got.TCPFraming, FramingLF)
	}
	if got.WinFormat != "snare" {
		t.Errorf("WinFormat = %q, want snare", got.WinFormat)
	}
	if got.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", got.Host)
	}
	if got.Name == "" {
		t.Error("blank name should get a placeholder")
	}
}

func TestProfileNormalizeKeepsValidInput(t *testing.T) {
	in := Profile{
		Name: "Prod", Host: "10.20.30.5", Port: 1514,
		Protocol: ProtoTCP, Format: FormatRFC5424,
		TCPFraming: FramingOctet, WinFormat: "json", WebRaw: true,
	}
	got := in.Normalize()

	if got.Protocol != ProtoTCP || got.Format != FormatRFC5424 ||
		got.TCPFraming != FramingOctet || got.WinFormat != "json" {
		t.Errorf("valid settings were altered: %+v", got)
	}
	if got.Port != 1514 || got.Host != "10.20.30.5" || !got.WebRaw {
		t.Errorf("valid settings were altered: %+v", got)
	}
}

func TestProfileAddr(t *testing.T) {
	p := Profile{Host: "10.0.0.1", Port: 514}
	if got := p.Addr(); got != "10.0.0.1:514" {
		t.Errorf("Addr() = %q, want 10.0.0.1:514", got)
	}
	// IPv6 literals must be bracketed or a dial will fail.
	p6 := Profile{Host: "::1", Port: 514}
	if got := p6.Addr(); got != "[::1]:514" {
		t.Errorf("IPv6 Addr() = %q, want [::1]:514", got)
	}
}

func TestEnvNormalizeFillsBlanks(t *testing.T) {
	d := DefaultEnv()
	got := Env{}.Normalize()

	if got.Domain != d.Domain || got.WinHost != d.WinHost ||
		got.LinuxHost != d.LinuxHost || got.WebHost != d.WebHost ||
		got.DBHost != d.DBHost || got.DBName != d.DBName || got.Subnet != d.Subnet {
		t.Errorf("blank estate not filled with defaults: %+v", got)
	}
}

func TestEnvNormalizeCanonicalises(t *testing.T) {
	got := Env{NetBIOS: "lower", DBName: "orcl", Subnet: "10.1.1."}.Normalize()

	if got.NetBIOS != "LOWER" {
		t.Errorf("NetBIOS = %q, want LOWER", got.NetBIOS)
	}
	if got.DBName != "ORCL" {
		t.Errorf("DBName = %q, want ORCL", got.DBName)
	}
	if got.Subnet != "10.1.1" {
		t.Errorf("Subnet = %q, want 10.1.1 (trailing dot stripped)", got.Subnet)
	}
}

func TestPriority(t *testing.T) {
	for _, tc := range []struct {
		facility, severity, want int
	}{
		{FacKern, SevEmerg, 0},
		{FacAuthPriv, SevInfo, 86},
		{FacLocal0, SevInfo, 134},
		{FacLocal7, SevWarning, 188},
	} {
		if got := Priority(tc.facility, tc.severity); got != tc.want {
			t.Errorf("Priority(%d, %d) = %d, want %d",
				tc.facility, tc.severity, got, tc.want)
		}
	}
}

func TestCtxParameterFallback(t *testing.T) {
	c := NewCtx(DefaultEnv(), map[string]string{"set": "value", "blank": "   "})

	if got := c.P("set", "fallback"); got != "value" {
		t.Errorf("P(set) = %q, want value", got)
	}
	if got := c.P("blank", "fallback"); got != "fallback" {
		t.Errorf("a whitespace-only parameter should fall back, got %q", got)
	}
	if got := c.P("missing", "fallback"); got != "fallback" {
		t.Errorf("P(missing) = %q, want fallback", got)
	}
}

func TestDomainSIDIsStable(t *testing.T) {
	a := NewCtx(DefaultEnv(), nil).DomainSID()
	b := NewCtx(DefaultEnv(), nil).DomainSID()
	if a != b {
		t.Errorf("domain SID changed between contexts: %s vs %s", a, b)
	}

	other := NewCtx(Env{Domain: "other.local"}.Normalize(), nil).DomainSID()
	if other == a {
		t.Errorf("different domains produced the same SID: %s", a)
	}
}

func TestInternalIPUsesConfiguredSubnet(t *testing.T) {
	c := NewCtx(Env{Subnet: "192.168.77"}.Normalize(), nil)
	for i := 0; i < 20; i++ {
		if ip := c.InternalIP(); len(ip) < 11 || ip[:11] != "192.168.77." {
			t.Fatalf("InternalIP() = %q, want the 192.168.77 subnet", ip)
		}
	}
}

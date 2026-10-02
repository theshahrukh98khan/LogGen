package catalog

import (
	"strings"
	"testing"
)

// The pf filter log is positional and its field count changes with IP version
// and protocol, so a record with the right values in the wrong slots parses
// cleanly and means something else entirely. These counts come from the Netgate
// BNF quoted in pfsense.go.
func TestPfSenseFilterFieldCounts(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want int
		why  string
	}{
		{"pfsense-block-wan-tcp-syn", 29, "IPv4 TCP"},
		{"pfsense-block-rdp-probe", 29, "IPv4 TCP"},
		{"pfsense-block-smb-lateral", 29, "IPv4 TCP"},
		{"pfsense-block-outbound-c2", 29, "IPv4 TCP"},
		{"pfsense-pass-inbound-admin", 29, "IPv4 TCP"},
		{"pfsense-pass-outbound-large-transfer", 29, "IPv4 TCP"},
		{"pfsense-block-udp-amplification", 23, "IPv4 UDP"},
		{"pfsense-pass-outbound-dns-external", 23, "IPv4 UDP"},
		{"pfsense-block-icmp-sweep", 23, "IPv4 ICMP echo"},
		{"pfsense-block-icmp-unreachport", 24, "IPv4 ICMP unreachport"},
		{"pfsense-block-ipv6-tcp", 26, "IPv6 TCP"},
		{"pfsense-block-ipv6-udp-rogue-dhcp", 20, "IPv6 UDP"},
	} {
		got := strings.Split(bodyOf(t, tc.id), ",")
		if len(got) != tc.want {
			t.Errorf("%s (%s) produced %d fields, want %d", tc.id, tc.why, len(got), tc.want)
		}
	}
}

// IPv4 writes protocol ID then protocol text; IPv6 writes protocol text then
// protocol ID, and upper cases the text. Reversing them is the mistake this
// format invites, so it is asserted directly.
func TestPfSenseProtocolFieldOrder(t *testing.T) {
	v4 := strings.Split(bodyOf(t, "pfsense-block-wan-tcp-syn"), ",")
	if v4[8] != "4" {
		t.Errorf("IPv4 record has IP version %q at field 9, want \"4\"", v4[8])
	}
	if v4[15] != "6" || v4[16] != "tcp" {
		t.Errorf("IPv4 fields 16,17 = %q,%q, want \"6\",\"tcp\"", v4[15], v4[16])
	}

	v6 := strings.Split(bodyOf(t, "pfsense-block-ipv6-tcp"), ",")
	if v6[8] != "6" {
		t.Errorf("IPv6 record has IP version %q at field 9, want \"6\"", v6[8])
	}
	if v6[12] != "TCP" || v6[13] != "6" {
		t.Errorf("IPv6 fields 13,14 = %q,%q, want \"TCP\",\"6\"", v6[12], v6[13])
	}
}

// Every filterlog record carries the same first nine fields, whatever follows.
func TestPfSenseCommonHeader(t *testing.T) {
	for _, id := range []string{
		"pfsense-block-wan-tcp-syn",
		"pfsense-block-udp-amplification",
		"pfsense-block-icmp-sweep",
		"pfsense-block-ipv6-udp-rogue-dhcp",
	} {
		f := strings.Split(bodyOf(t, id), ",")
		if f[5] != "match" {
			t.Errorf("%s: reason at field 6 is %q, want \"match\"", id, f[5])
		}
		if f[6] != "block" && f[6] != "pass" {
			t.Errorf("%s: action at field 7 is %q, want block or pass", id, f[6])
		}
		if f[7] != "in" && f[7] != "out" {
			t.Errorf("%s: direction at field 8 is %q, want in or out", id, f[7])
		}
	}
}

// pfBlockerNG writes its own CSV files, whose layouts are read out of
// pfblockerng.inc. Both are positional too.
func TestPfBlockerNGFieldCounts(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want int
	}{
		{"pfsense-pfblockerng-dnsbl-block", 10},
		{"pfsense-pfblockerng-ip-block-inbound", 21},
		{"pfsense-pfblockerng-ip-block-outbound", 21},
	} {
		got := strings.Split(bodyOf(t, tc.id), ",")
		if len(got) != tc.want {
			t.Errorf("%s produced %d fields, want %d", tc.id, len(got), tc.want)
		}
	}
}

// The DNSBL record repeats the domain as the evaluated TLD, and the ip_block
// record repeats the remote address as the address that matched the feed.
// Generating either twice would produce two different values.
func TestPfSenseRepeatedValuesMatch(t *testing.T) {
	f := strings.Split(bodyOf(t, "pfsense-pfblockerng-dnsbl-block"), ",")
	if f[2] != f[7] {
		t.Errorf("DNSBL domain %q and evaluated TLD %q differ", f[2], f[7])
	}

	in := strings.Split(bodyOf(t, "pfsense-pfblockerng-ip-block-inbound"), ",")
	if in[8] != in[15] {
		t.Errorf("inbound source %q and evaluated IP %q differ", in[8], in[15])
	}

	out := strings.Split(bodyOf(t, "pfsense-pfblockerng-ip-block-outbound"), ",")
	if out[9] != out[15] {
		t.Errorf("outbound destination %q and evaluated IP %q differ", out[9], out[15])
	}

	// The OpenVPN peer line prints the client address and port twice.
	ovpn := bodyOf(t, "pfsense-openvpn-peer-connected")
	i := strings.Index(ovpn, " ")
	first := ovpn[:i]
	if j := strings.Index(ovpn, "[AF_INET]"); j < 0 || ovpn[j+len("[AF_INET]"):] != first {
		t.Errorf("OpenVPN peer line repeats a different endpoint: %s", ovpn)
	}

	// The IKE_SA line prints each endpoint as address and as identity.
	ike := bodyOf(t, "pfsense-ipsec-ike-sa-established")
	for _, part := range strings.Split(strings.SplitN(ike, "established between ", 2)[1], "...") {
		addr, id, ok := strings.Cut(strings.TrimSuffix(part, "]"), "[")
		if !ok || addr != id {
			t.Errorf("IKE_SA endpoint %q does not repeat its own address", part)
		}
	}
}

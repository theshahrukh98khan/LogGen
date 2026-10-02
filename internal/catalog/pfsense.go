package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// pfSense controls.
//
// pfSense is FreeBSD, so it emits several unrelated shapes down one syslog
// stream and they must not be confused with each other:
//
//   - filterlog, the pf packet filter log, which is positional CSV with a
//     field count that changes with IP version and protocol;
//   - php-fpm, the web UI, which logs plain English sentences;
//   - openvpn, charon (strongSwan) and dhcpd, which are the stock daemons
//     logging in their own upstream formats, not in anything pfSense-specific;
//   - pfBlockerNG, a package, which writes its own CSV files.
//
// CONFIRMED
//
// Filter log field order and the per-variant field counts come from the Netgate
// raw filter log reference, including its BNF:
//
//	https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html
//
//	<log-data> ::= <rule-number>,<sub-rule-number>,<anchor>,<tracker>,
//	               <real-interface>,<reason>,<action>,<direction>,<ip-version>
//	<ipv4-specific-data> ::= <tos>,<ecn>,<ttl>,<id>,<offset>,<flags>,
//	                         <protocol-id>,<protocol-text>
//	<ipv6-specific-data> ::= <class>,<flow-label>,<hop-limit>,
//	                         <protocol-text>,<protocol-id>
//	<ip-data>  ::= <length>,<source-address>,<destination-address>
//	<tcp-data> ::= <source-port>,<destination-port>,<data-length>,<tcp-flags>,
//	               <sequence-number>,<ack-number>,<tcp-window>,<urg>,<tcp-options>
//	<udp-data> ::= <source-port>,<destination-port>,<data-length>
//
// Note that IPv4 writes the protocol ID before the protocol text and IPv6
// writes them the other way round. That reversal is the single easiest thing to
// get wrong here, and it is why the two builders below are separate functions
// rather than one with a flag.
//
// Field counts, which the tests in pfsense_test.go assert:
//
//	IPv4 TCP              29      9 common + 8 v4 + 3 addr + 9 tcp
//	IPv4 UDP              23      9 + 8 + 3 + 3
//	IPv4 ICMP echo        23      9 + 8 + 3 + 3 (type, id, sequence)
//	IPv4 ICMP unreachport 24      9 + 8 + 3 + 4 (type, dst, proto, port)
//	IPv6 TCP              26      9 common + 5 v6 + 3 addr + 9 tcp
//	IPv6 UDP              20      9 + 5 + 3 + 3
//
// The field order was cross-checked a second way, against pfBlockerNG's own
// filter.log parser, which indexes the same CSV by position ($d[3] tracker,
// $d[4] interface, $d[6] action, $d[8] IP version, $d[18]/$d[19] IPv4 source
// and destination, $d[15]/$d[16] for IPv6):
//
//	https://github.com/pfsense/FreeBSD-ports/blob/devel/net/pfSense-pkg-pfBlockerNG-devel/files/usr/local/pkg/pfblockerng/pfblockerng.inc
//
// Verbatim filterlog lines, including the local0.info priority and the
// filterlog[pid] tag, are taken from Elastic's pfSense integration test corpus,
// which is captured traffic rather than hand-written:
//
//	https://github.com/elastic/integrations/blob/main/packages/pfsense/data_stream/log/_dev/test/pipeline/test-pfsense-bsd.log
//
// The web UI sentences are quoted from pfSense's own source, so they are exact
// including the quoting around the username:
//
//	src/etc/inc/auth.inc
//	  log_auth("Successful login for user '%1$s' from: %2$s")
//	  log_auth("webConfigurator authentication error for user '%1$s' from: %2$s")
//	  log_error("Session timed out for user '%1$s' from: %2$s")
//	  log_error("User logged out for user '%1$s' from: %2$s")
//	src/etc/inc/config.lib.inc
//	  log_error(gettext("Configuration Change") . ": {$revision['description']}")
//
// OpenVPN, charon and dhcpd lines are quoted from the same Elastic corpus and
// from the Netgate IPsec troubleshooting page, which prints real charon output:
//
//	https://docs.netgate.com/pfsense/en/latest/troubleshooting/ipsec-logs.html
//
// pfBlockerNG's two CSV layouts are read directly out of the package source
// (pfblockerng.inc), where the lines are assembled:
//
//	dnsbl.log   "{$type},{$datereq},{$details},{$dup_entry}" with
//	            $details = "{$domain},{$src_ip},{$req_agent},{$pfb_mode},
//	                        {$pfb_group},{$pfb_final},{$pfb_feed}"   = 10 fields
//	ip_block.log "{$ts},{$d[3]},{$d[4]},{$int},{$d[6]},{$d[8]},
//	              {protoid},{PROTO[-flags]},{src},{dst},{sport},{dport}"
//	             then ",{$details},{$dup_entry}" where
//	             $details = "{$dir},{$geoip},{$pfb_alias},{$ip_evaluated},
//	                         {$feed},{$resolved_host},{$client_host},{$asn}"
//	                                                             = 21 fields
//
// INFERRED, and called out so nobody writes a rule against it believing it was
// verified:
//
//   - The syslog framing around pfBlockerNG records. pfBlockerNG writes to
//     files under /var/log/pfblockerng/ and does not ship them itself; whatever
//     tag appears depends on how the operator forwards them. The CSV bodies
//     below are from source, the "pfblockerng" tag around them is a convention,
//     not a vendor fact.
//   - The specific interface names (igb0/igb1) and tracker ID values. Both are
//     site-specific; only their position and rough shape are documented.
//   - The TCP options string and the IP ID, sequence and window numbers. These
//     are real packet values on a device, so they are generated here.
//   - The charon thread number and subsystem tag prefix (e.g. "09[IKE]") is
//     documented in Netgate's examples but the thread number is arbitrary.
//   - The sudo and sshd lines are stock FreeBSD daemon output, not pfSense
//     output, and are included only because pfSense ships them on the same
//     stream.

// ---------------------------------------------------------------------------
// Payload framing
// ---------------------------------------------------------------------------

// pfPayload frames one pfSense record. The firewall's own hostname is the
// syslog hostname; note that with the default BSD format pfSense omits the
// hostname when forwarding, but the transport here always writes one.
func pfPayload(c *core.Ctx, tag string, pid, facility, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourcePfSense,
		Tag:      tag,
		PID:      pid,
		Host:     c.Env.FWHost,
		Facility: facility,
		Severity: severity,
		Message:  msg,
	}
}

// pfFilterPayload frames a filterlog record. Observed priority is <134>, which
// is local0.info.
func pfFilterPayload(c *core.Ctx, msg string) core.Payload {
	return pfPayload(c, "filterlog", c.PID(), core.FacLocal0, core.SevInfo, msg)
}

var (
	pfUser    = param("user", "Username", "auto")
	pfSrcIP   = param("srcip", "Source IP", "auto")
	pfDstIP   = param("dstip", "Destination IP", "auto")
	pfDstPort = param("dstport", "Destination port", "auto")
	pfIface   = param("iface", "Real interface", "igb0")
	pfDomain  = param("domain", "Domain", "auto")
	pfWANIPP  = param("wanip", "Firewall WAN address", "198.51.100.10")
)

// pfWANIface and pfLANIface are the real FreeBSD interface names. pfSense logs
// the real name, not the friendly description, in the filter log.
func pfWANIface(c *core.Ctx) string { return c.P("iface", "igb0") }
func pfLANIface(c *core.Ctx) string { return c.P("iface", "igb1") }

// pfWANIP is the firewall's own WAN address, which is the destination of every
// inbound block. The estate does not carry a public address for the firewall,
// so it is a documentation-range default the operator can override.
func pfWANIP(c *core.Ctx) string { return c.P("wanip", "198.51.100.10") }

// pfTracker is the per-rule tracking ID. User-added rules on a current pfSense
// are allocated from 1000000101 upwards; auto-generated rules use other ranges.
func pfTracker(c *core.Ctx) string { return fmt.Sprint(c.Int(1000000101, 1599999999)) }

// pfAuthSource is the suffix get_user_remote_authsource() appends to the web UI
// login lines, which is how a SOC tells a local login from a RADIUS one.
func pfAuthSource(c *core.Ctx) string {
	return c.PickFrom([]string{"Local Database", "RADIUS/PFsense Radius", "LDAP/CORP-DC", "Local Database Fallback"})
}

func init() {
	registerPfFilterBlock()
	registerPfFilterPass()
	registerPfWebAuth()
	registerPfConfig()
	registerPfOpenVPN()
	registerPfIPsec()
	registerPfDHCP()
	registerPfBlockerNG()
	registerPfSystem()
}

// ---------------------------------------------------------------------------
// filterlog builders
// ---------------------------------------------------------------------------

// pfCommon returns the nine fields every filterlog record starts with.
func pfCommon(c *core.Ctx, iface, action, dir, ipver string) []string {
	return []string{
		fmt.Sprint(c.Int(1, 250)), //  1 rule number
		"",                        //  2 sub rule number
		"",                        //  3 anchor
		pfTracker(c),              //  4 tracker
		iface,                     //  5 real interface
		"match",                   //  6 reason
		action,                    //  7 action
		dir,                       //  8 direction
		ipver,                     //  9 IP version
	}
}

// pfV4 returns the eight IPv4 header fields. Protocol ID comes before protocol
// text on IPv4.
func pfV4(c *core.Ctx, protoID, protoText string) []string {
	return []string{
		c.PickFrom([]string{"0x0", "0x10", "0x20", "0x28", "0xb8", "0xc0"}), // 10 TOS
		"",                                 // 11 ECN
		fmt.Sprint(c.Int(48, 128)),         // 12 TTL
		fmt.Sprint(c.Int(0, 65535)),        // 13 ID
		"0",                                // 14 offset
		c.PickFrom([]string{"DF", "none"}), // 15 IP flags
		protoID,                            // 16 protocol ID
		protoText,                          // 17 protocol text (lower case on IPv4)
	}
}

// pfV6 returns the five IPv6 header fields. Protocol text comes before protocol
// ID on IPv6, the reverse of IPv4, and the text is upper case.
func pfV6(c *core.Ctx, protoID, protoText string) []string {
	return []string{
		"0x00",                     // 10 class
		"0x" + c.HexLower(5),       // 11 flow label
		fmt.Sprint(c.Int(1, 64)),   // 12 hop limit
		strings.ToUpper(protoText), // 13 protocol text
		protoID,                    // 14 protocol ID
	}
}

// pfTCPv4 builds a complete IPv4 TCP filterlog record: 29 fields.
func pfTCPv4(c *core.Ctx, iface, action, dir, src, dst string, sport, dport int, flags string) string {
	f := pfCommon(c, iface, action, dir, "4")
	f = append(f, pfV4(c, "6", "tcp")...)
	f = append(f,
		fmt.Sprint(c.Int(52, 76)),        // 18 length (a SYN carries no data, so it is small)
		src,                              // 19 source address
		dst,                              // 20 destination address
		fmt.Sprint(sport),                // 21 source port
		fmt.Sprint(dport),                // 22 destination port
		"0",                              // 23 data length
		flags,                            // 24 TCP flags
		fmt.Sprint(c.Int(1, 4294967000)), // 25 sequence number
		"",                               // 26 ACK number
		fmt.Sprint(c.Int(1024, 65535)),   // 27 window
		"",                               // 28 URG
		"mss;sackOK;TS;nop;wscale",       // 29 options
	)
	return strings.Join(f, ",")
}

// pfUDPv4 builds a complete IPv4 UDP filterlog record: 23 fields.
func pfUDPv4(c *core.Ctx, iface, action, dir, src, dst string, sport, dport int) string {
	length := c.Int(32, 1400)
	f := pfCommon(c, iface, action, dir, "4")
	f = append(f, pfV4(c, "17", "udp")...)
	f = append(f,
		fmt.Sprint(length),    // 18 length
		src,                   // 19 source address
		dst,                   // 20 destination address
		fmt.Sprint(sport),     // 21 source port
		fmt.Sprint(dport),     // 22 destination port
		fmt.Sprint(length-20), // 23 data length
	)
	return strings.Join(f, ",")
}

// pfICMPEchoV4 builds an IPv4 ICMP echo record: 23 fields.
func pfICMPEchoV4(c *core.Ctx, iface, action, dir, src, dst, echoType string) string {
	f := pfCommon(c, iface, action, dir, "4")
	f = append(f, pfV4(c, "1", "icmp")...)
	f = append(f,
		"84",                        // 18 length
		src,                         // 19 source address
		dst,                         // 20 destination address
		echoType,                    // 21 ICMP type: request | reply
		fmt.Sprint(c.Int(1, 65535)), // 22 ICMP ID
		fmt.Sprint(c.Int(1, 500)),   // 23 ICMP sequence
	)
	return strings.Join(f, ",")
}

// pfICMPUnreachPortV4 builds an IPv4 ICMP unreachport record: 24 fields.
func pfICMPUnreachPortV4(c *core.Ctx, iface, action, dir, src, dst, origDst string, port int) string {
	f := pfCommon(c, iface, action, dir, "4")
	f = append(f, pfV4(c, "1", "icmp")...)
	f = append(f,
		"56",             // 18 length
		src,              // 19 source address
		dst,              // 20 destination address
		"unreachport",    // 21 ICMP type
		origDst,          // 22 ICMP destination IP
		"UDP",            // 23 unreachable protocol
		fmt.Sprint(port), // 24 unreachable port
	)
	return strings.Join(f, ",")
}

// pfTCPv6 builds a complete IPv6 TCP filterlog record: 26 fields.
func pfTCPv6(c *core.Ctx, iface, action, dir, src, dst string, sport, dport int, flags string) string {
	f := pfCommon(c, iface, action, dir, "6")
	f = append(f, pfV6(c, "6", "tcp")...)
	f = append(f,
		fmt.Sprint(c.Int(40, 60)),        // 15 length (a SYN carries no data, so it is small)
		src,                              // 16 source address
		dst,                              // 17 destination address
		fmt.Sprint(sport),                // 18 source port
		fmt.Sprint(dport),                // 19 destination port
		"0",                              // 20 data length
		flags,                            // 21 TCP flags
		fmt.Sprint(c.Int(1, 4294967000)), // 22 sequence number
		"",                               // 23 ACK number
		fmt.Sprint(c.Int(1024, 65535)),   // 24 window
		"",                               // 25 URG
		"mss;sackOK;TS;nop;wscale",       // 26 options
	)
	return strings.Join(f, ",")
}

// pfUDPv6 builds a complete IPv6 UDP filterlog record: 20 fields.
func pfUDPv6(c *core.Ctx, iface, action, dir, src, dst string, sport, dport int) string {
	// On IPv6 the captured samples show length == data length, because the
	// IPv6 length field is the payload length and excludes the 40-byte header.
	// On IPv4 the same two fields differ by 20. Do not unify these.
	length := c.Int(32, 300)
	f := pfCommon(c, iface, action, dir, "6")
	f = append(f, pfV6(c, "17", "udp")...)
	f = append(f,
		fmt.Sprint(length), // 15 length
		src,                // 16 source address
		dst,                // 17 destination address
		fmt.Sprint(sport),  // 18 source port
		fmt.Sprint(dport),  // 19 destination port
		fmt.Sprint(length), // 20 data length
	)
	return strings.Join(f, ",")
}

// ---------------------------------------------------------------------------
// Firewall: blocks
// ---------------------------------------------------------------------------

func registerPfFilterBlock() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-wan-tcp-syn", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound TCP SYN blocked on WAN",
			Desc:    "The default deny rule dropped an unsolicited SYN arriving on the WAN. One is noise; a few hundred from one address in a minute is a port scan, which is what the rule should count.",
			Channel: "filterlog", Severity: core.SevLabelLow,
			Mitre: []string{"T1595.001"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstPort, pfIface, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfWANIface(c), "block", "in",
				c.P("srcip", c.ExternalIP()), pfWANIP(c),
				c.EphemeralPort(), c.PInt("dstport", c.Pick1(22, 23, 3389, 445, 8080, 5900)), "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-rdp-probe", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound RDP probe blocked",
			Desc:    "A SYN to 3389 from the internet, blocked. Exposed RDP is the single most common initial access route, so attempts against it deserve their own rule rather than being lost in the generic block count.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1595.001", "T1021.001"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfIface, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfWANIface(c), "block", "in",
				c.P("srcip", c.ExternalIP()), pfWANIP(c),
				c.EphemeralPort(), 3389, "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-smb-lateral", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Internal SMB blocked between segments",
			Desc:    "An internal host tried to reach 445 on another segment and the inter-VLAN rule denied it. East-west SMB that the policy does not permit is lateral movement until proven otherwise.",
			Channel: "filterlog", Severity: core.SevLabelHigh,
			Mitre: []string{"T1021.002", "T1210"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfLANIface(c)+".12", "block", "in",
				c.P("srcip", c.InternalIP()), c.P("dstip", c.InternalIP()),
				c.EphemeralPort(), 445, "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-outbound-c2", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Outbound connection to a blocked port",
			Desc:    "A workstation tried to open an outbound session on a port egress policy does not allow. Egress blocks are the cheapest signal that something on the inside is calling home.",
			Channel: "filterlog", Severity: core.SevLabelHigh,
			Mitre: []string{"T1071.001", "T1571"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstIP, pfDstPort},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfLANIface(c), "block", "in",
				c.P("srcip", c.InternalIP()), c.P("dstip", c.ExternalIP()),
				c.EphemeralPort(), c.PInt("dstport", c.Pick1(4444, 1337, 8443, 9001, 6667)), "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-udp-amplification", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound UDP to an amplification port blocked",
			Desc:    "UDP arriving on WAN aimed at an amplification service (DNS, NTP, SSDP, memcached). Either reconnaissance or the firewall absorbing a reflected flood.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1498.002"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstPort, pfIface, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfUDPv4(c, pfWANIface(c), "block", "in",
				c.P("srcip", c.ExternalIP()), pfWANIP(c),
				c.EphemeralPort(), c.PInt("dstport", c.Pick1(53, 123, 1900, 11211, 161))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-icmp-sweep", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound ICMP echo request blocked",
			Desc:    "A ping blocked at the edge. On its own it is nothing; sequential ICMP IDs across a range of destination addresses is a host sweep, and the ICMP variant of the record is where the sequence number lives.",
			Channel: "filterlog", Severity: core.SevLabelLow,
			Mitre: []string{"T1018", "T1595.001"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfIface, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfICMPEchoV4(c, pfWANIface(c), "block", "in",
				c.P("srcip", c.ExternalIP()), pfWANIP(c), "request"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-icmp-unreachport", Source: core.SourcePfSense,
			Group: "Firewall", Name: "ICMP port unreachable blocked",
			Desc:    "An ICMP port unreachable, which is the reply pattern a UDP scan produces. This is the 24-field ICMP variant that carries the original destination and port, so a parser that assumes the echo layout will mis-map it.",
			Channel: "filterlog", Severity: core.SevLabelLow,
			Mitre: []string{"T1046"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfIface, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			src := c.P("srcip", c.InternalIP())
			return pfFilterPayload(c, pfICMPUnreachPortV4(c, pfWANIface(c), "block", "in",
				src, pfWANIP(c), src, c.Int(1024, 65535)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-ipv6-tcp", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound IPv6 TCP blocked",
			Desc:    "The IPv6 form of an inbound block. IPv6 records carry five header fields instead of eight and reverse the protocol text and protocol ID, so this is the record that proves whether a parser handles both.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1595.001"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfDstPort, pfIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv6(c, pfWANIface(c), "block", "in",
				fmt.Sprintf("2001:db8:%x::%x", c.Int(1, 65535), c.Int(1, 65535)),
				fmt.Sprintf("2001:db8:1::%x", c.Int(1, 255)),
				c.EphemeralPort(), c.PInt("dstport", c.Pick1(22, 445, 3389, 23)), "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-block-ipv6-udp-rogue-dhcp", Source: core.SourcePfSense,
			Group: "Firewall", Name: "IPv6 DHCPv6 traffic blocked",
			Desc:    "DHCPv6 to the all-servers multicast group, blocked. A rogue RA or DHCPv6 responder on a segment is a man-in-the-middle setup, and it is the 20-field IPv6 UDP variant.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1557"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfIface},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfUDPv6(c, pfLANIface(c)+".27", "block", "in",
				fmt.Sprintf("fe80::208:9bff:fef3:%x", c.Int(4096, 65535)),
				"ff02::1:2", 546, 547))
		},
	})
}

// ---------------------------------------------------------------------------
// Firewall: passes worth seeing
// ---------------------------------------------------------------------------

func registerPfFilterPass() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pass-inbound-admin", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Inbound management port permitted",
			Desc:    "A rule explicitly allowed an inbound session to a management port. A pass is more interesting than a block here: it means somebody opened the edge, and the rule should fire on the pass, not the deny.",
			Channel: "filterlog", Severity: core.SevLabelHigh,
			Mitre: []string{"T1021.001", "T1133"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstIP, pfDstPort},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfWANIface(c), "pass", "in",
				c.P("srcip", c.ExternalIP()), c.P("dstip", c.InternalIP()),
				c.EphemeralPort(), c.PInt("dstport", c.Pick1(3389, 22, 5985, 443)), "S"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pass-outbound-dns-external", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Outbound DNS to an external resolver permitted",
			Desc:    "A host sent DNS straight out to a resolver that is not the internal one. Clients bypassing the corporate resolver defeat DNS logging and DNSBL, and sustained volume on that path is how DNS tunnelling looks on a firewall.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1071.004", "T1048.003"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfUDPv4(c, pfLANIface(c), "pass", "out",
				c.P("srcip", c.InternalIP()),
				c.P("dstip", c.PickFrom([]string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"})),
				c.EphemeralPort(), 53))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pass-outbound-large-transfer", Source: core.SourcePfSense,
			Group: "Firewall", Name: "Outbound session to a file sharing service permitted",
			Desc:    "An allowed outbound HTTPS session to a consumer file sharing host. The firewall cannot see the content, so the detection is on destination and sustained volume, which is the exfiltration shape available at this layer.",
			Channel: "filterlog", Severity: core.SevLabelMedium,
			Mitre: []string{"T1567.002"}, Wazuh: []string{"4100"},
			Params: []core.Param{pfSrcIP, pfDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfFilterPayload(c, pfTCPv4(c, pfLANIface(c), "pass", "out",
				c.P("srcip", c.InternalIP()), c.P("dstip", c.ExternalIP()),
				c.EphemeralPort(), 443, "S"))
		},
	})
}

// ---------------------------------------------------------------------------
// Web UI authentication (php-fpm)
// ---------------------------------------------------------------------------

// pfWebPage is the script path php-fpm prefixes each line with.
func pfWebPage(c *core.Ctx) string {
	return c.PickFrom([]string{"/index.php", "/diag_logs_filter.php", "/firewall_rules.php"})
}

func registerPfWebAuth() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-webgui-login-success", Source: core.SourcePfSense,
			Group: "Administration", Name: "Web UI login succeeded",
			Desc:    "An administrator authenticated to the webConfigurator. Every one of these is worth correlating against source address and hour, because a successful admin login from an unexpected place is the event that precedes a rule change.",
			Channel: "php-fpm", Severity: core.SevLabelMedium,
			Mitre: []string{"T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "php-fpm", c.PID(), core.FacLocal0, core.SevInfo,
				fmt.Sprintf("%s: Successful login for user '%s' from: %s (%s)",
					"/index.php", c.P("user", c.AdminUser()),
					c.P("srcip", c.InternalIP()), pfAuthSource(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-webgui-login-failed", Source: core.SourcePfSense,
			Group: "Administration", Name: "Web UI authentication error",
			Desc:    "A failed webConfigurator login. pfSense does not lock out by default, so a run of these from one address is an unthrottled brute force against the firewall itself.",
			Channel: "php-fpm", Severity: core.SevLabelHigh,
			Mitre: []string{"T1110.001", "T1078"}, Wazuh: []string{"5716"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "php-fpm", c.PID(), core.FacLocal0, core.SevInfo,
				fmt.Sprintf("/index.php: webConfigurator authentication error for user '%s' from: %s",
					c.P("user", c.PickFrom([]string{"admin", "root", "pfsense", "test", "administrator"})),
					c.P("srcip", c.ExternalIP())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-webgui-logout", Source: core.SourcePfSense,
			Group: "Administration", Name: "Web UI logout",
			Desc:    "An administrator logged out. On its own it is housekeeping; paired with the login it bounds the window in which any configuration change was made.",
			Channel: "php-fpm", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "php-fpm", c.PID(), core.FacDaemon, core.SevErr,
				fmt.Sprintf("%s: User logged out for user '%s' from: %s (%s)",
					pfWebPage(c), c.P("user", c.AdminUser()),
					c.P("srcip", c.InternalIP()), pfAuthSource(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-webgui-session-timeout", Source: core.SourcePfSense,
			Group: "Administration", Name: "Web UI session timed out",
			Desc:    "An idle admin session expired. Useful as the negative case: a session that never times out, because something is keeping it alive, is worth a look.",
			Channel: "php-fpm", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "php-fpm", c.PID(), core.FacDaemon, core.SevErr,
				fmt.Sprintf("%s: Session timed out for user '%s' from: %s (%s)",
					pfWebPage(c), c.P("user", c.AdminUser()),
					c.P("srcip", c.InternalIP()), pfAuthSource(c)))
		},
	})
}

// ---------------------------------------------------------------------------
// Configuration changes
// ---------------------------------------------------------------------------

// pfConfigChange renders a write_config() revision line. The username portion
// is "<user>@<ip> (<authsource>)", built once so the pair stays consistent.
func pfConfigChange(c *core.Ctx, page, desc string) core.Payload {
	who := fmt.Sprintf("%s@%s (%s)", c.P("user", c.AdminUser()),
		c.P("srcip", c.InternalIP()), pfAuthSource(c))
	return pfPayload(c, "php-fpm", c.PID(), core.FacDaemon, core.SevErr,
		fmt.Sprintf("%s: Configuration Change: %s: %s", page, who, desc))
}

func registerPfConfig() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-firewall-rule-added", Source: core.SourcePfSense,
			Group: "Configuration", Name: "Firewall rule added",
			Desc:    "A new rule was written to the ruleset. A permit rule appearing on the WAN interface outside a change window is the classic way an attacker keeps a door open.",
			Channel: "php-fpm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004", "T1098"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/firewall_rules_edit.php", "Firewall: Rules - saved/edited a firewall rule.")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-firewall-rule-disabled", Source: core.SourcePfSense,
			Group: "Configuration", Name: "Firewall rule disabled",
			Desc:    "An existing rule was turned off. Disabling a block rule is defence evasion carried out through the supported interface, which is why it never looks like an attack in isolation.",
			Channel: "php-fpm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/firewall_rules.php", "Firewall: Rules - disabled a firewall rule.")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-nat-port-forward", Source: core.SourcePfSense,
			Group: "Configuration", Name: "NAT port forward created",
			Desc:    "A port forward was created, publishing an internal host to the internet. Pair this with the matching inbound pass in the filter log to see what was actually exposed.",
			Channel: "php-fpm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1572", "T1133"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/firewall_nat_edit.php", "Firewall: NAT: Port Forward - saved/edited a NAT port forward rule.")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-user-added", Source: core.SourcePfSense,
			Group: "Configuration", Name: "Local user account created",
			Desc:    "A new local account was added to the firewall. An extra account in the admins group is persistence that survives a password reset on the original.",
			Channel: "php-fpm", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1136.001", "T1098"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/system_usermanager.php", "UserManager settings saved")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-remote-management-enabled", Source: core.SourcePfSense,
			Group: "Configuration", Name: "SSH management enabled",
			Desc:    "Secure Shell was enabled on the firewall. pfSense ships with it off, so somebody turning it on is a deliberate act and the first thing to confirm against a change record.",
			Channel: "php-fpm", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021.004", "T1562.004"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/system_advanced_admin.php", "Advanced: Admin Access")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-config-restored", Source: core.SourcePfSense,
			Group: "Configuration", Name: "Configuration restored from backup",
			Desc:    "A whole config.xml was uploaded and applied. This replaces the entire ruleset, user list and VPN config in one step and is the largest-blast-radius action available in the UI.",
			Channel: "php-fpm", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.004", "T1098"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfConfigChange(c, "/diag_backup.php", "Restored configuration.")
		},
	})
}

// ---------------------------------------------------------------------------
// OpenVPN
// ---------------------------------------------------------------------------

func pfOpenVPN(c *core.Ctx, severity int, facility int, msg string) core.Payload {
	return pfPayload(c, "openvpn", c.PID(), facility, severity, msg)
}

func registerPfOpenVPN() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-openvpn-auth-success", Source: core.SourcePfSense,
			Group: "VPN", Name: "OpenVPN user authenticated",
			Desc:    "A remote access VPN user passed authentication. Worth a rule on geography and hour rather than on the event itself: the same account authenticating from two countries inside an hour is the detection.",
			Channel: "openvpn", Severity: core.SevLabelMedium,
			Mitre: []string{"T1133", "T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{pfUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfOpenVPN(c, core.SevNotice, core.FacAuth,
				fmt.Sprintf("user '%s' authenticated", c.P("user", c.User())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-openvpn-auth-failed", Source: core.SourcePfSense,
			Group: "VPN", Name: "OpenVPN user could not authenticate",
			Desc:    "A VPN authentication failure. Repeats against one account are a password spray against the perimeter; repeats across many accounts from one address are credential stuffing.",
			Channel: "openvpn", Severity: core.SevLabelHigh,
			Mitre: []string{"T1110.003", "T1133"}, Wazuh: []string{"5716"},
			Params: []core.Param{pfUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfOpenVPN(c, core.SevWarning, core.FacAuth,
				fmt.Sprintf("user '%s' could not authenticate.", c.P("user", c.User())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-openvpn-peer-connected", Source: core.SourcePfSense,
			Group: "VPN", Name: "OpenVPN peer connection initiated",
			Desc:    "The tunnel came up and the daemon records the common name alongside the real source address. This is the line that ties a certificate to an internet address, which is what any VPN hunt needs.",
			Channel: "openvpn", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The address appears twice in this line and must match.
			ip := c.P("srcip", c.ExternalIP())
			port := c.EphemeralPort()
			return pfOpenVPN(c, core.SevNotice, core.FacDaemon,
				fmt.Sprintf("%s:%d [%s] Peer Connection Initiated with [AF_INET]%s:%d",
					ip, port, c.P("user", c.User()), ip, port))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-openvpn-pool-assignment", Source: core.SourcePfSense,
			Group: "VPN", Name: "OpenVPN tunnel address assigned",
			Desc:    "The server handed the client its tunnel address. Keep it: without this mapping nothing that the VPN user does afterwards can be attributed back to a person.",
			Channel: "openvpn", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfOpenVPN(c, core.SevNotice, core.FacDaemon,
				fmt.Sprintf("%s/%s:%d MULTI_sva: pool returned IPv4=%s.%d, IPv6=(Not enabled)",
					c.P("user", c.User()), c.P("srcip", c.ExternalIP()), c.EphemeralPort(),
					c.Env.Subnet, c.Int(200, 250)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-openvpn-tls-error", Source: core.SourcePfSense,
			Group: "VPN", Name: "OpenVPN TLS error, no HMAC",
			Desc:    "A packet arrived on the OpenVPN port without a valid tls-auth HMAC. That is either an internet scanner fingerprinting the port or somebody probing with the wrong key, and a burst of them is reconnaissance against the VPN.",
			Channel: "openvpn", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1595.002"},
			Params: []core.Param{pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfOpenVPN(c, core.SevErr, core.FacDaemon,
				fmt.Sprintf("TLS Error: cannot locate HMAC in incoming packet from [AF_INET]%s:%d",
					c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})
}

// ---------------------------------------------------------------------------
// IPsec (strongSwan charon)
// ---------------------------------------------------------------------------

// pfCharon frames a charon line. The body always starts with a two-digit
// thread number and a subsystem tag such as [IKE] or [CFG].
func pfCharon(c *core.Ctx, subsystem, msg string) core.Payload {
	return pfPayload(c, "charon", c.PID(), core.FacDaemon, core.SevInfo,
		fmt.Sprintf("%02d[%s] %s", c.Int(1, 16), subsystem, msg))
}

func registerPfIPsec() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-ike-sa-established", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec IKE_SA established",
			Desc:    "Phase 1 completed and a tunnel is up. A site-to-site tunnel establishing from an address that is not the documented peer is the whole point of watching this line.",
			Channel: "charon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1133"},
			Params: []core.Param{pfSrcIP, pfDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// Each endpoint appears twice in the line, as address and as ID.
			local := c.P("srcip", c.ExternalIP())
			remote := c.P("dstip", c.ExternalIP())
			return pfCharon(c, "IKE", fmt.Sprintf("IKE_SA con%d[%d] established between %s[%s]...%s[%s]",
				c.Int(1, 4), c.Int(1, 40), local, local, remote, remote))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-child-sa-established", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec CHILD_SA established",
			Desc:    "Phase 2 completed and the traffic selectors are logged. The selectors say which networks the tunnel actually carries, which is the detail that tells you whether a tunnel was widened.",
			Channel: "charon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1133"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfCharon(c, "IKE", fmt.Sprintf(
				"CHILD_SA con%d{%d} established with SPIs %s_i %s_o and TS %s.0/24|/0 === 10.42.42.0/24|/0",
				c.Int(1, 4), c.Int(1, 8), c.HexLower(8), c.HexLower(8), c.Env.Subnet))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-auth-failed", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec authentication failed",
			Desc:    "The peer rejected or was rejected on authentication. Against a mobile IPsec server this is a credential attack; against a site-to-site peer it is usually a rotated PSK, so the two need separating by connection name.",
			Channel: "charon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.003", "T1133"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfCharon(c, "IKE", "received AUTHENTICATION_FAILED error notify")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-no-peer-config", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec no peer config found",
			Desc:    "An IKE negotiation arrived from an address with no matching tunnel definition. That is an unknown party attempting to bring up IPsec against the firewall, which earns an alert on its own.",
			Channel: "charon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1133", "T1595.002"},
			Params: []core.Param{pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfCharon(c, "IKE", "no peer config found")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-no-proposal", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec no proposal chosen",
			Desc:    "Cipher negotiation failed. Worth watching after a hardening change, and worth questioning when a peer suddenly starts proposing weaker algorithms than it used to.",
			Channel: "charon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1600"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfCharon(c, "IKE", "no proposal found")
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-ipsec-aggressive-mode", Source: core.SourcePfSense,
			Group: "VPN", Name: "IPsec aggressive mode PSK refused",
			Desc:    "A peer tried aggressive mode with a pre-shared key, which leaks a crackable hash before authentication. strongSwan refuses it; something still asking for it is either badly configured or fishing for the hash.",
			Channel: "charon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557", "T1110.002"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfCharon(c, "IKE", "Aggressive Mode PSK disabled for security reasons")
		},
	})
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

func pfDHCP(c *core.Ctx, msg string) core.Payload {
	return pfPayload(c, "dhcpd", c.PID(), core.FacLocal7, core.SevInfo, msg)
}

func registerPfDHCP() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-dhcp-ack", Source: core.SourcePfSense,
			Group: "DHCP", Name: "DHCP lease granted",
			Desc:    "A lease was issued. This is the record that binds an IP to a MAC and a client-supplied hostname, which is what turns every other IP-only firewall record into something attributable.",
			Channel: "dhcpd", Severity: core.SevLabelInfo,
			Params: []core.Param{pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfDHCP(c, fmt.Sprintf("DHCPACK on %s to %s (%s) via %s",
				c.P("srcip", c.InternalIP()), c.MAC(), c.Workstation(), pfLANIface(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-dhcp-no-free-leases", Source: core.SourcePfSense,
			Group: "DHCP", Name: "DHCP pool exhausted",
			Desc:    "The pool ran out of addresses. Occasionally capacity; often a starvation attack, where a host requests leases under forged MACs so a rogue server can answer instead.",
			Channel: "dhcpd", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1557", "T1498"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			iface := pfLANIface(c)
			return pfDHCP(c, fmt.Sprintf("DHCPDISCOVER from %s via %s: network %s.0/24: no free leases",
				c.MAC(), iface, c.Env.Subnet))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-dhcp-duplicate-lease", Source: core.SourcePfSense,
			Group: "DHCP", Name: "DHCP address already in use",
			Desc:    "The server declined an address because something already answers on it. A statically configured host squatting inside the pool is usually benign; a host that appeared overnight is not.",
			Channel: "dhcpd", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1557"},
			Params: []core.Param{pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfDHCP(c, fmt.Sprintf("DHCPDECLINE of %s from %s (%s) via %s: abandoning IP address",
				c.P("srcip", c.InternalIP()), c.MAC(), c.Workstation(), pfLANIface(c)))
		},
	})
}

// ---------------------------------------------------------------------------
// pfBlockerNG
// ---------------------------------------------------------------------------

// pfBlockerPayload frames a pfBlockerNG CSV record. See the package comment:
// the CSV body is taken from pfblockerng.inc but the syslog tag around it is a
// forwarding convention, not something the package itself emits.
func pfBlockerPayload(c *core.Ctx, msg string) core.Payload {
	return pfPayload(c, "pfblockerng", 0, core.FacLocal0, core.SevInfo, msg)
}

// pfBlockerDate is the "M j H:i:s" stamp pfBlockerNG writes inside its own CSV,
// which is separate from the syslog header's timestamp.
func pfBlockerDate(c *core.Ctx) string { return c.Now.Format("Jan _2 15:04:05") }

func registerPfBlockerNG() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pfblockerng-dnsbl-block", Source: core.SourcePfSense,
			Group: "pfBlockerNG", Name: "DNSBL blocked a domain lookup",
			Desc:    "A client resolved a domain on a blocklist and DNSBL answered with the sinkhole. The source IP and the feed name together say which host asked and why it was considered bad.",
			Channel: "pfblockerng", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1071.004", "T1568"},
			Params: []core.Param{pfSrcIP, pfDomain},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The domain appears twice: as the queried name and as the
			// evaluated TLD. Generate it once.
			domain := c.P("domain", c.PickFrom([]string{
				"cdn-analytics-track.cc", "login-verify-account.top",
				"update-service-win32.xyz", "pool.minexmr-proxy.com",
			}))
			group, feed := pfBlockerFeed(c)
			f := []string{
				c.PickFrom([]string{"DNSBL-Full", "DNSBL-HTTPS", "DNSBL-JS", "DNSBL-1x1"}), //  1 type
				pfBlockerDate(c),             //  2 date timestamp
				domain,                       //  3 blocked domain
				c.P("srcip", c.InternalIP()), //  4 source IP
				// The agent string is comma-stripped: pfBlockerNG filters its own
				// CSV fields, and a stray comma here would shift every field after it.
				"-|GET / HTTP/1.1|" + strings.ReplaceAll(c.UserAgent(), ",", ""), //  5 referer|request|agent
				"DNSBL", //  6 block mode
				group,   //  7 group name
				domain,  //  8 evaluated domain/TLD
				feed,    //  9 feed name
				"+",     // 10 duplicate marker
			}
			return pfBlockerPayload(c, strings.Join(f, ","))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pfblockerng-ip-block-inbound", Source: core.SourcePfSense,
			Group: "pfBlockerNG", Name: "IP blocklist blocked an inbound connection",
			Desc:    "An inbound session was dropped because the remote address is on a reputation feed. The record carries country, ASN and feed name, which the plain filter log does not, so this is the one to alert on for known-bad sources.",
			Channel: "pfblockerng", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1595.001"},
			Params: []core.Param{pfSrcIP, pfDstPort, pfWANIPP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// The remote address is both the packet source and the address that
			// matched the feed, so it must be the same value in both slots.
			src := c.P("srcip", c.ExternalIP())
			return pfBlockerPayload(c, pfBlockerIP(c, "block", "in",
				pfWANIface(c), "WAN", src, pfWANIP(c), c.EphemeralPort(),
				c.PInt("dstport", c.Pick1(22, 443, 3389, 445)), src, c.Workstation()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-pfblockerng-ip-block-outbound", Source: core.SourcePfSense,
			Group: "pfBlockerNG", Name: "IP blocklist blocked an outbound connection",
			Desc:    "An internal host tried to reach an address on a threat feed and was stopped. Outbound hits are the ones that matter: something inside the estate already decided to contact a known-bad host.",
			Channel: "pfblockerng", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1071.001", "T1571"},
			Params: []core.Param{pfSrcIP, pfDstIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dst := c.P("dstip", c.ExternalIP())
			client := c.P("srcip", c.InternalIP())
			return pfBlockerPayload(c, pfBlockerIP(c, "block", "out",
				pfLANIface(c), "LAN", client, dst, c.EphemeralPort(), 443,
				dst, c.Workstation()))
		},
	})
}

// pfBlockerFeed returns a matching group and feed pair. They are reported in
// adjacent fields, so a mismatched pair is immediately obvious to anyone who
// knows the product.
func pfBlockerFeed(c *core.Ctx) (group, feed string) {
	switch c.Int(0, 3) {
	case 0:
		return "DNSBL_Malicious", "Abuse_URLhaus"
	case 1:
		return "DNSBL_Phishing", "OpenPhish"
	case 2:
		return "DNSBL_UT1", "UT1_malware"
	default:
		return "DNSBL_Ads", "EasyList"
	}
}

// pfBlockerIP builds an ip_block.log record: 21 fields.
//
//	date, tracker, real interface, friendly interface, action, IP version,
//	protocol ID, protocol text, source IP, destination IP, source port,
//	destination port, direction, country, alias, evaluated IP, feed,
//	resolved hostname, client hostname, ASN, duplicate marker
func pfBlockerIP(c *core.Ctx, action, dir, iface, friendly, src, dst string, sport, dport int, evaluated, clientHost string) string {
	f := []string{
		pfBlockerDate(c),  //  1 date timestamp
		pfTracker(c),      //  2 tracker ID
		iface,             //  3 real interface
		friendly,          //  4 friendly interface
		action,            //  5 action
		"4",               //  6 IP version
		"6",               //  7 protocol ID
		"TCP-S",           //  8 protocol text plus TCP flags
		src,               //  9 source IP
		dst,               // 10 destination IP
		fmt.Sprint(sport), // 11 source port
		fmt.Sprint(dport), // 12 destination port
		dir,               // 13 direction
		c.PickFrom([]string{"RU", "CN", "IR", "KP", "BR", "NL"}),           // 14 country
		c.PickFrom([]string{"pfB_Top_v4", "pfB_PRI1_v4", "pfB_Europe_v4"}), // 15 alias name
		evaluated, // 16 evaluated IP
		c.PickFrom([]string{"ET_Block", "Spamhaus_DROP", "Abuse_Feodo", "CINS_army"}), // 17 feed name
		"Unknown",                               // 18 resolved hostname
		clientHost,                              // 19 client hostname
		fmt.Sprintf("AS%d", c.Int(1000, 65000)), // 20 ASN
		"+",                                     // 21 duplicate marker
	}
	return strings.Join(f, ",")
}

// ---------------------------------------------------------------------------
// FreeBSD system daemons
// ---------------------------------------------------------------------------
//
// These are stock FreeBSD lines, not pfSense lines. They are included because
// pfSense ships them on the same syslog stream and a SOC watching the appliance
// will see them mixed in with everything above.

func registerPfSystem() {
	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-sshd-accepted-password", Source: core.SourcePfSense,
			Group: "System", Name: "SSH login to the firewall succeeded",
			Desc:    "Somebody reached the firewall shell over SSH. SSH is off by default on pfSense, so a successful login means it was enabled and someone used it, which is worth confirming every time.",
			Channel: "auth", Severity: core.SevLabelHigh,
			Mitre: []string{"T1021.004", "T1078"}, Wazuh: []string{"5715"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "sshd", c.PID(), core.FacAuth, core.SevInfo,
				fmt.Sprintf("Accepted password for %s from %s port %d ssh2",
					c.P("user", c.AdminUser()), c.P("srcip", c.InternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-sshd-failed-password", Source: core.SourcePfSense,
			Group: "System", Name: "SSH login to the firewall failed",
			Desc:    "A failed SSH password against the appliance. Repeats from one address are a brute force against the device that terminates the perimeter.",
			Channel: "auth", Severity: core.SevLabelHigh,
			Mitre: []string{"T1110.001"}, Wazuh: []string{"5716"},
			Params: []core.Param{pfUser, pfSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "sshd", c.PID(), core.FacAuth, core.SevInfo,
				fmt.Sprintf("Failed password for %s from %s port %d ssh2",
					c.P("user", c.PickFrom([]string{"root", "admin", "pfsense", "test"})),
					c.P("srcip", c.ExternalIP()), c.EphemeralPort()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "pfsense-reboot", Source: core.SourcePfSense,
			Group: "System", Name: "Firewall rebooted",
			Desc:    "The appliance restarted. An unscheduled reboot either hides a crash or clears volatile state, and either way it breaks the continuity of every other log on this device.",
			Channel: "syslogd", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1529"},
			Params: []core.Param{},
		},
		Build: func(c *core.Ctx) core.Payload {
			return pfPayload(c, "syslogd", 0, core.FacSyslog, core.SevInfo,
				"kernel boot file is /boot/kernel/kernel")
		},
	})
}

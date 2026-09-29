// Package sender turns a rendered Payload into bytes on the wire and ships
// them to a SIEM profile over UDP or TCP.
package sender

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// DialTimeout bounds how long we wait for a TCP connect.
const DialTimeout = 5 * time.Second

// WriteTimeout bounds how long a single write may block.
const WriteTimeout = 5 * time.Second

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// Encode wraps the payload's message in the syslog header the profile asks for
// and returns the exact string that will go on the wire.
//
// The message body is flattened to a single line first: syslog is a
// line-oriented protocol and an embedded newline would otherwise be read by the
// collector as the start of a second, malformed record.
func Encode(p core.Payload, pr core.Profile, now time.Time) string {
	var msg string
	switch {
	case p.Win != nil && pr.WinFormat == "json":
		msg = encodeWinJSON(p.Win, now)
	case p.Win != nil:
		msg = encodeWinSnare(p.Win, now)
	default:
		msg = flatten(p.Message)
	}

	// Web access logs are decoded most reliably by Wazuh's web-accesslog decoder
	// when they arrive as the bare log line, so a profile can opt into that for
	// the web sources alone without changing how everything else is framed.
	if p.Raw || pr.Format == core.FormatRaw || (pr.WebRaw && isWebSource(p.Kind)) {
		return msg
	}

	host := firstNonEmpty(p.Host, "localhost")
	pri := core.Priority(p.Facility, p.Severity)

	switch pr.Format {
	case core.FormatRFC5424:
		return encode5424(pri, now, host, p, msg)
	default:
		return encode3164(pri, now, host, p, msg)
	}
}

// encode3164 builds "<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG".
//
// RFC 3164 pads a single-digit day with a space ("Sep  9"), which Go's "_2"
// reference layout reproduces exactly.
func encode3164(pri int, now time.Time, host string, p core.Payload, msg string) string {
	ts := now.Format("Jan _2 15:04:05")

	var b strings.Builder
	fmt.Fprintf(&b, "<%d>%s %s ", pri, ts, host)
	if p.Tag != "" {
		b.WriteString(p.Tag)
		if p.PID > 0 {
			fmt.Fprintf(&b, "[%d]", p.PID)
		}
		b.WriteString(": ")
	}
	b.WriteString(msg)
	return b.String()
}

// encode5424 builds "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG".
func encode5424(pri int, now time.Time, host string, p core.Payload, msg string) string {
	ts := now.Format("2006-01-02T15:04:05.000Z07:00")
	app := nilIfEmpty(p.Tag)
	procID := "-"
	if p.PID > 0 {
		procID = fmt.Sprintf("%d", p.PID)
	}
	return fmt.Sprintf("<%d>1 %s %s %s %s - - %s", pri, ts, host, app, procID, msg)
}

// flatten collapses a multi-line record into one physical line, preserving the
// visual structure that Windows event descriptions rely on.
func flatten(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "  ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

// isWebSource reports whether a payload came from a web server.
func isWebSource(kind string) bool {
	return kind == core.SourceNginx || kind == core.SourceApache
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func nilIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// Conn is an open link to one SIEM target. Reusing a single Conn for a burst
// keeps TCP from paying a handshake per record.
type Conn struct {
	conn    net.Conn
	profile core.Profile
}

// Open dials the profile's target.
func Open(pr core.Profile) (*Conn, error) {
	pr = pr.Normalize()
	c, err := net.DialTimeout(pr.Protocol, pr.Addr(), DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s/%s: %w", pr.Protocol, pr.Addr(), err)
	}
	return &Conn{conn: c, profile: pr}, nil
}

// Write ships one already-encoded record.
func (c *Conn) Write(wire string) (int, error) {
	if err := c.conn.SetWriteDeadline(time.Now().Add(WriteTimeout)); err != nil {
		return 0, err
	}
	return c.conn.Write(c.frame(wire))
}

// frame applies the transport's message delimiting.
//
// UDP needs none: one datagram is one message. TCP is a byte stream, so the
// receiver needs a boundary — either a trailing newline (RFC 6587
// non-transparent framing) or a leading byte count (octet counting).
func (c *Conn) frame(wire string) []byte {
	if c.profile.Protocol != core.ProtoTCP {
		return []byte(wire)
	}
	if c.profile.TCPFraming == core.FramingOctet {
		return []byte(fmt.Sprintf("%d %s", len(wire), wire))
	}
	return []byte(wire + "\n")
}

// Close releases the connection.
func (c *Conn) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// SendOne opens a connection, writes a single record and closes it. Convenient
// for one-shot sends; use Open for bursts.
func SendOne(pr core.Profile, wire string) (int, error) {
	c, err := Open(pr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.Write(wire)
}

// Probe checks a target is reachable.
//
// For TCP this is a real test: a failed handshake means nothing is listening.
// For UDP it only proves a route and a local socket exist — UDP is fire and
// forget, so a silent black hole still looks like success. The UI says as much.
func Probe(pr core.Profile) error {
	c, err := Open(pr)
	if err != nil {
		return err
	}
	return c.Close()
}

// Failure classifies why a connection could not be made.
//
// A refusal and a timeout look the same in the UI but need opposite fixes. A
// refusal means the packet arrived and the host had nothing bound to that
// port, so the collector is not configured or not running. A timeout means
// nothing came back at all, so something in between is dropping it. Telling
// somebody to open a firewall when their SIEM simply is not listening on that
// port sends them to the wrong machine entirely.
type Failure string

const (
	// FailRefused is a host that answered with a reset.
	FailRefused Failure = "refused"
	// FailTimeout is a connection attempt that got no answer at all.
	FailTimeout Failure = "timeout"
	// FailOther is anything else, including local socket errors.
	FailOther Failure = "other"
)

// Classify inspects a dial error. It is only meaningful for TCP: a UDP socket
// opens whether or not anything is at the other end.
func Classify(err error) Failure {
	if err == nil {
		return FailOther
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return FailTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return FailTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return FailRefused
	}
	// Windows reports a refusal as WSAECONNREFUSED. Go maps it through
	// Errno.Is, but a wrapped or stringified error can still slip past, so the
	// text is checked as a fallback rather than relied on.
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return FailRefused
	}
	return FailOther
}

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

// Resolution describes what a destination's host turned out to be.
//
// A destination may be named rather than numbered, and the two fail in
// different ways. A name that does not resolve is a DNS problem, where advice
// about firewalls and listening ports is useless and misleading. Resolving
// separately from dialling lets the console say which of the two went wrong,
// and show which address a name actually points at — worth knowing when DNS is
// stale or a name carries several records.
type Resolution struct {
	Host    string   `json:"host"`              // what the operator typed
	IsIP    bool     `json:"isIp"`              // true when no lookup was needed
	Addrs   []string `json:"addrs,omitempty"`   // what the name resolved to
	Failed  bool     `json:"failed"`            // the name could not be resolved
	Message string   `json:"message,omitempty"` // why, when Failed
}

// Resolve looks up a destination's host without connecting to it.
func Resolve(pr core.Profile) Resolution {
	host := strings.TrimSpace(pr.Host)
	r := Resolution{Host: host}

	if ip := net.ParseIP(host); ip != nil {
		r.IsIP = true
		r.Addrs = []string{ip.String()}
		return r
	}

	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		r.Failed = true
		r.Message = err.Error()
		return r
	}
	for _, a := range ips {
		r.Addrs = append(r.Addrs, a.IP.String())
	}
	if len(r.Addrs) == 0 {
		r.Failed = true
		r.Message = "the name resolved to no addresses"
	}
	return r
}

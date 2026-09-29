// Package sender turns a rendered Payload into bytes on the wire and ships
// them to a SIEM profile over UDP or TCP.
package sender

import (
	"fmt"
	"net"
	"strings"
	"time"

	"socbyte.ai/logsource/internal/core"
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
	msg := flatten(p.Message)

	// Some sources (web access logs against Wazuh's web-accesslog decoder) are
	// decoded most reliably with no header at all.
	if p.Raw || pr.Format == core.FormatRaw {
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

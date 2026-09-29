package auth

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SendReset mails a password reset link.
//
// STARTTLS is required rather than preferred. A reset link is a bearer
// credential for the console, and a lab tool quietly downgrading to plaintext
// because a server did not advertise the extension is not a trade worth
// making silently. Port 465 is treated as implicit TLS, which is what almost
// everything using that port means.
func SendReset(s SMTP, to, link string) error {
	if !s.Configured() {
		return fmt.Errorf("no mail server is configured")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("no recovery address is set")
	}

	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	msg := buildMessage(s.From, to, link)

	c, err := dial(s, addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if s.User != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil {
				return fmt.Errorf("the mail server rejected the credentials: %w", err)
			}
		}
	}
	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("sender rejected: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("recipient rejected: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func dial(s SMTP, addr string) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}

	if s.Port == 465 {
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: s.Host})
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", addr, err)
		}
		return smtp.NewClient(conn, s.Host)
	}

	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return nil, err
	}
	ok, _ := c.Extension("STARTTLS")
	if !ok {
		c.Close()
		return nil, fmt.Errorf("%s does not offer STARTTLS, and a reset link will not be sent in the clear", addr)
	}
	if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
		c.Close()
		return nil, fmt.Errorf("start TLS with %s: %w", addr, err)
	}
	return c, nil
}

func buildMessage(from, to, link string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: Reset your LogGen password\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&b, "Somebody asked to reset the password on your LogGen console.\r\n\r\n")
	fmt.Fprintf(&b, "%s\r\n\r\n", link)
	fmt.Fprintf(&b, "The link is good for 30 minutes and stops working once the\r\n")
	fmt.Fprintf(&b, "password changes. If this was not you, nothing has happened yet\r\n")
	fmt.Fprintf(&b, "and you can ignore this message.\r\n")
	return []byte(b.String())
}

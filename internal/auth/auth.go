// Package auth holds the console's credentials, sessions and sign-in throttle.
//
// LogGen shipped with no authentication at all, on the understanding that it
// stays on a lab network. That is a fair assumption right up until somebody
// binds it to 0.0.0.0 so a colleague can reach it, at which point anyone who
// can route to the host can send records to the SIEM and read every
// destination that has been configured. This package is what stands in the
// way.
//
// Everything here is standard library. PBKDF2 is not the strongest choice
// available in 2026, but it is the strongest one Go ships, and adding a
// dependency to a tool whose whole distribution story is a single static
// binary is a worse trade than the margin bcrypt or argon2 would buy.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Iterations is the PBKDF2 work factor. It is stored alongside each hash, so
// raising it here does not invalidate existing passwords: they keep verifying
// at the count they were written with and are rewritten on the next change.
const Iterations = 210_000

const (
	saltLen = 16
	keyLen  = 32
)

// DefaultUser and DefaultPassword are what a fresh install starts with. They
// are deliberately guessable, because the alternative is printing a generated
// password that gets lost in a scrollback. The console says plainly that they
// are unchanged until they are.
const (
	DefaultUser     = "admin"
	DefaultPassword = "admin"
)

// Errors a caller is expected to distinguish.
var (
	ErrBadCredentials = errors.New("that username and password do not match")
	ErrBadToken       = errors.New("this link is not valid")
	ErrExpiredToken   = errors.New("this link has expired")
)

// SMTP is what the reset mail is sent through. Without it, a forgotten
// password is recovered from the command line instead.
type SMTP struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from,omitempty"`
}

// Configured reports whether a reset mail could be sent.
func (s SMTP) Configured() bool {
	return strings.TrimSpace(s.Host) != "" && s.Port > 0 && strings.TrimSpace(s.From) != ""
}

// Config is the stored credential. It is written to its own file with owner
// only permissions rather than into profiles.json, which is the file somebody
// would paste into an issue to show their destinations.
type Config struct {
	User  string `json:"user"`
	Salt  []byte `json:"salt"`
	Hash  []byte `json:"hash"`
	Iter  int    `json:"iter"`
	Email string `json:"recoveryEmail,omitempty"`
	SMTP  SMTP   `json:"smtp,omitzero"`

	// Secret signs session and reset tokens.
	Secret []byte `json:"secret"`

	// Gen rises on every credential change. It is carried in each token, so
	// changing a password signs out every session and voids any reset link
	// that was already in flight.
	Gen int `json:"gen"`

	// Pristine records that the password is still the shipped default, so the
	// console can say so rather than letting it pass unnoticed.
	Pristine bool `json:"pristine"`
}

// New builds the default credential for a fresh install.
func New() (Config, error) {
	c := Config{User: DefaultUser, Iter: Iterations, Gen: 1, Pristine: true}
	c.Secret = make([]byte, 32)
	if _, err := rand.Read(c.Secret); err != nil {
		return c, fmt.Errorf("generate session secret: %w", err)
	}
	if err := c.SetPassword(DefaultPassword); err != nil {
		return c, err
	}
	// SetPassword clears Pristine, because every other caller is a real
	// change. This one is not.
	c.Pristine = true
	return c, nil
}

// SetPassword replaces the stored hash with a fresh salt at the current work
// factor.
func (c *Config) SetPassword(pw string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, Iterations, keyLen)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	c.Salt, c.Hash, c.Iter = salt, key, Iterations
	c.Pristine = false
	c.Gen++
	return nil
}

// Verify checks a password in constant time.
func (c Config) Verify(pw string) bool {
	iter := c.Iter
	if iter <= 0 {
		iter = Iterations
	}
	key, err := pbkdf2.Key(sha256.New, pw, c.Salt, iter, len(c.Hash))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, c.Hash) == 1
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

// claims is what a token carries. Tokens are signed rather than stored, so a
// restart does not sign everybody out. Revocation is by Gen, which is enough
// for a tool with one account.
type claims struct {
	User    string `json:"u"`
	Expires int64  `json:"e"`
	Gen     int    `json:"g"`
	Purpose string `json:"p"`
}

const (
	purposeSession = "s"
	purposeReset   = "r"
)

func (c Config) sign(payload []byte) string {
	m := hmac.New(sha256.New, c.Secret)
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (c Config) token(purpose string, ttl time.Duration) (string, error) {
	b, err := json.Marshal(claims{
		User: c.User, Expires: time.Now().Add(ttl).Unix(), Gen: c.Gen, Purpose: purpose,
	})
	if err != nil {
		return "", err
	}
	return c.sign(b), nil
}

func (c Config) parse(tok, purpose string) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return ErrBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrBadToken
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrBadToken
	}

	m := hmac.New(sha256.New, c.Secret)
	m.Write(payload)
	if !hmac.Equal(mac, m.Sum(nil)) {
		return ErrBadToken
	}

	var cl claims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return ErrBadToken
	}
	// Purpose is checked so a session cookie cannot be presented as a password
	// reset, which would turn a stolen cookie into a full account takeover.
	if cl.Purpose != purpose || cl.User != c.User || cl.Gen != c.Gen {
		return ErrBadToken
	}
	if time.Now().Unix() > cl.Expires {
		return ErrExpiredToken
	}
	return nil
}

// SessionToken mints a signed session for the configured user.
func (c Config) SessionToken(ttl time.Duration) (string, error) {
	return c.token(purposeSession, ttl)
}

// ValidSession reports whether a cookie value is a live session.
func (c Config) ValidSession(tok string) bool { return c.parse(tok, purposeSession) == nil }

// ResetToken mints a single use password reset token. It stops working as
// soon as the password changes, because that raises Gen.
func (c Config) ResetToken(ttl time.Duration) (string, error) {
	return c.token(purposeReset, ttl)
}

// CheckReset validates a reset token, distinguishing expired from forged so
// the console can tell somebody to request a new link rather than implying
// they did something wrong.
func (c Config) CheckReset(tok string) error { return c.parse(tok, purposeReset) }

package core

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// Ctx is handed to every control's Build function. It carries the simulated
// estate, the operator's parameter overrides, and a set of generators that
// produce realistic filler for anything left blank.
type Ctx struct {
	Env    Env
	Now    time.Time
	params map[string]string
	rnd    *rand.Rand

	// declared are the parameters the control advertises. A token naming one of
	// these is always resolved, even when the operator left the field blank, so
	// an unfilled parameter never leaks {{braces}} into a record. A token that
	// is not a declared parameter and not a generator is left alone, so a typo
	// stays visible in the preview.
	declared map[string]Param
}

// NewCtx builds a render context. params may be nil.
func NewCtx(env Env, params map[string]string) *Ctx {
	if params == nil {
		params = map[string]string{}
	}
	return &Ctx{
		Env:    env.Normalize(),
		Now:    time.Now(),
		params: params,
		rnd:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Declare registers the parameters a control advertises.
func (c *Ctx) Declare(params []Param) {
	if len(params) == 0 {
		return
	}
	c.declared = make(map[string]Param, len(params))
	for _, p := range params {
		c.declared[p.Key] = p
	}
}

// Declared reports the parameter registered under key, if any.
func (c *Ctx) Declared(key string) (Param, bool) {
	p, ok := c.declared[key]
	return p, ok
}

// Rand exposes the underlying generator for callers that need it directly.
func (c *Ctx) Rand() *rand.Rand { return c.rnd }

// P returns the operator-supplied value for key, or fallback when it is unset
// or blank. This is the single entry point every control uses so that "leave it
// empty and I'll invent one" works consistently everywhere.
func (c *Ctx) P(key, fallback string) string {
	if v, ok := c.params[key]; ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return fallback
}

// PInt is P for integer parameters.
func (c *Ctx) PInt(key string, fallback int) int {
	if v, ok := c.params[key]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Word lists
// ---------------------------------------------------------------------------

var (
	humanUsers = []string{
		"jdoe", "asmith", "mkhan", "rpatel", "tmiller", "kwhite", "lchen",
		"dnguyen", "sgarcia", "bokafor", "hyamamoto", "avolkov",
	}
	serviceUsers = []string{
		"svc_backup", "svc_sql", "svc_iis", "svc_scan", "svc_monitor", "svc_deploy",
	}
	adminUsers = []string{"administrator", "adm_jdoe", "adm_root", "helpdesk"}

	workstations = []string{
		"WKS-0142", "WKS-0317", "WKS-0455", "LAP-0291", "LAP-0788", "WKS-1024",
	}

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	}
)

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

// Pick returns one of the supplied options at random.
func (c *Ctx) Pick(options ...string) string { return c.PickFrom(options) }

// PickFrom returns a random element of the slice, or "" when it is empty.
func (c *Ctx) PickFrom(options []string) string {
	if len(options) == 0 {
		return ""
	}
	return options[c.rnd.Intn(len(options))]
}

// Int returns a random integer in [min, max].
func (c *Ctx) Int(min, max int) int {
	if max <= min {
		return min
	}
	return min + c.rnd.Intn(max-min+1)
}

// Chance reports true with the given percentage probability.
func (c *Ctx) Chance(pct int) bool { return c.rnd.Intn(100) < pct }

// Hex returns n uppercase hex digits.
func (c *Ctx) Hex(n int) string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[c.rnd.Intn(16)]
	}
	return string(b)
}

// HexLower returns n lowercase hex digits.
func (c *Ctx) HexLower(n int) string { return strings.ToLower(c.Hex(n)) }

// LogonID returns a Windows-style logon identifier, e.g. 0x3A91C4.
func (c *Ctx) LogonID() string { return "0x" + c.Hex(c.Int(5, 6)) }

// GUID returns a random braced GUID.
func (c *Ctx) GUID() string {
	return fmt.Sprintf("{%s-%s-%s-%s-%s}",
		c.HexLower(8), c.HexLower(4), c.HexLower(4), c.HexLower(4), c.HexLower(12))
}

// User returns a regular employee account name.
func (c *Ctx) User() string { return c.PickFrom(humanUsers) }

// ServiceUser returns a service account name.
func (c *Ctx) ServiceUser() string { return c.PickFrom(serviceUsers) }

// AdminUser returns a privileged account name.
func (c *Ctx) AdminUser() string { return c.PickFrom(adminUsers) }

// Workstation returns a client machine name.
func (c *Ctx) Workstation() string { return c.PickFrom(workstations) }

// UserAgent returns a browser user agent string.
func (c *Ctx) UserAgent() string { return c.PickFrom(userAgents) }

// InternalIP returns an address inside the simulated estate's subnet.
func (c *Ctx) InternalIP() string {
	return fmt.Sprintf("%s.%d", c.Env.Subnet, c.Int(10, 250))
}

// ExternalIP returns a routable-looking public address.
func (c *Ctx) ExternalIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", c.Pick1(45, 91, 103, 185, 193, 209),
		c.Int(0, 255), c.Int(0, 255), c.Int(1, 254))
}

// Pick1 returns one of the supplied integers at random.
func (c *Ctx) Pick1(options ...int) int {
	if len(options) == 0 {
		return 0
	}
	return options[c.rnd.Intn(len(options))]
}

// EphemeralPort returns a client-side source port.
func (c *Ctx) EphemeralPort() int { return c.Int(49152, 65535) }

// PID returns a plausible process id.
func (c *Ctx) PID() int { return c.Int(600, 32000) }

// DomainSID derives a stable domain SID from the configured domain name, so the
// same estate always reports the same SID across restarts.
func (c *Ctx) DomainSID() string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(c.Env.Domain)))
	v := h.Sum64()
	return fmt.Sprintf("S-1-5-21-%d-%d-%d",
		uint32(v)|1, uint32(v>>16)|1, uint32(v>>32)|1)
}

// UserSID returns a domain SID with a per-user relative identifier. The RID is
// derived from the account name so the same user keeps the same SID.
func (c *Ctx) UserSID(user string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(user)))
	rid := 1000 + int(h.Sum32()%9000)
	return fmt.Sprintf("%s-%d", c.DomainSID(), rid)
}

// WinFQDN is the Windows host as a fully qualified name.
func (c *Ctx) WinFQDN() string {
	return strings.ToUpper(c.Env.WinHost) + "." + strings.ToLower(c.Env.Domain)
}

// MAC renders a random MAC address.
func (c *Ctx) MAC() string {
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = strings.ToLower(c.Hex(2))
	}
	return strings.Join(parts, ":")
}

// UPN builds user@domain.
func (c *Ctx) UPN(user string) string {
	return user + "@" + strings.ToLower(c.Env.Domain)
}

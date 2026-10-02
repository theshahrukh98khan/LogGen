package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// SAP NetWeaver AS ABAP Security Audit Log (SAL) controls.
//
// ---------------------------------------------------------------------------
// How this reaches a SIEM
// ---------------------------------------------------------------------------
//
// SAP does not emit syslog the way a firewall does. The Security Audit Log is
// configured in SM19 (RSAU_CONFIG on SAP_BASIS 7.52 and later), read in SM20
// (RSAU_READ_LOG), and written by the application server to a flat file on the
// instance host, at DIR_AUDIT with the name pattern FN_AUDIT. Everything that
// ships SAL to a SIEM starts from that file or from the RSAU read API
// (RSAU_API_GET_LOG_DATA, or the RSAU_LOG_API service on SAP_BASIS 7.56+).
//
// Three paths exist in practice:
//
//  1. A log shipper on the application server tails the audit file and forwards
//     the records as they are written: rsyslog imfile, a Splunk universal
//     forwarder, or a Wazuh agent localfile stanza. The record crosses the wire
//     unchanged, byte for byte as SAP wrote it.
//  2. SAP Enterprise Threat Detection consumes SAL and forwards its own
//     correlated alerts, in LEEF, to a SIEM. Those are ETD pattern alerts, not
//     audit records: the header is "LEEF:1.0|SAP|ETD|1.0 SP5|<pattern name>
//     (http://sap.com/secmon/basis)|" and the payload is pattern metadata
//     (PatternId, AlertId, Measurement) rather than a message ID and its
//     variables. See the IBM QRadar and Juniper JSA DSM sample pages cited
//     below for verbatim examples.
//  3. A commercial SAP connector reads the same data over RFC and re-emits it
//     in its own shape. None of those vendors publishes a byte-level sample.
//
// These controls implement path 1: the raw SAL record, because it is the only
// one whose exact bytes are published, it is what a Wazuh agent or an rsyslog
// imfile stanza on the SAP host actually ships, and it is the only one that
// carries the message ID (AU1, AU2, AUO, ...) a detection rule keys on. Path 2
// is deliberately not modelled here; ETD alerts belong to a different product
// with a different field set.
//
// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------
//
// A SAL audit file is one unbroken run of fixed-width 200-character records,
// with no separator and no newline. Field widths, confirmed against the Splunk
// parsing configuration published by WALLSEC and against the verbatim record
// quoted on the same page:
//
//	AUW20200616081842001684400004B4        DDIC                            RSDBA_DBH_SETUP_UPDATE_CHECK            0001RSDBA_DBH_SETUP_UPDATE_CHECK&
//
// The published LINE_BREAKER consumes the leading record-version character, so
// the quoted sample starts at the message ID. Laid out:
//
//	 1  version      1   "2" or "3" (the LINE_BREAKER accepts both)
//	 2  message id   3   AU1, AU2, AUO, ...
//	 3  date         8   YYYYMMDD, application server local time
//	 4  time         6   HHMMSS
//	 5  (unnamed)    2   "00" in the sample
//	 6  OS pid       5   process id of the work process
//	 7  (unnamed)    2   "00" in the sample
//	 8  WP number    3   zero padded, "004" in the sample
//	 9  WP type      1   "B" in the sample
//	10  task type    1   "4" in the sample
//	11  (unnamed)    8   blank in the sample
//	12  user        12   SAP user id, left justified, blank padded
//	13  transaction 20
//	14  program     40
//	15  client       3   MANDT, "000" in the sample
//	16  (unnamed)    1   "1" in the sample
//	17  variables   64   message variables, "&" after each
//	18  terminal    20   terminal name, or the client IP with rsau/ip_only=1
//
// 1+3+8+6+2+5+2+3+1+1+8+12+20+40+3+1+64+20 = 200, which matches the "200
// characters each" statement on the same page. The field offsets are confirmed
// a second way: the published variable extraction regexes anchor at ^.{130},
// which is the 115 characters that precede the variable field plus the 15 pipe
// characters the split transform inserts ahead of it.
//
// Message variables are the &A, &B, &C ... placeholders in the message text,
// stored positionally and separated by "&". A message that uses &A and &C but
// not &B therefore leaves the middle slot empty, which is what these records
// do.
//
// ---------------------------------------------------------------------------
// Confirmed
// ---------------------------------------------------------------------------
//
//   - The 200-character fixed-width layout and every field width above, from
//     the WALLSEC Splunk props.conf and transforms.conf and the verbatim record
//     published with them:
//     https://www.wallsec.de/blog/siem-your-sap-security-audit-log-with-splunk
//   - Every message ID used below, with its audit class, event class and
//     message text including the &A/&B/&C placeholders, from the sm20.csv
//     lookup published alongside that article, which is the content of SAP's
//     own report RSAU_INFO_SYAG (SAP Note 1970644):
//     https://github.com/WALLSEC/SAPtoSPLUNK/blob/master/sm20.csv
//     AU1, AU2, AU3, AU5, AU6, AUB, AUE, AUK, AUM, AUO, AUP and AUW were
//     corroborated independently against SAP community and SAP KBA material.
//     CUM ("Jump to ABAP Debugger") is spelled "CU_M" in that CSV, which is a
//     transcription slip: SAL message IDs are three characters, and SAP KBA
//     3226223 on monitoring debug activity uses CUM.
//   - Logon type and method are single letters. SAP KBA 2878506 quotes "Logon
//     successful (type=E, method=A )" and an SAP community thread quotes
//     "Logon failed (reason=1, type=H, method=P)". The letters used below are
//     taken from those two examples.
//   - Privileged account names (SAP*, DDIC, ALEREMOTE, BWREMOTE, SAPSYS,
//     WF-BATCH), sensitive tables (USR02, USH02, USRPWDHISTORY, PA0008),
//     sensitive profiles (SAP_ALL, SAP_NEW), sensitive function modules and
//     sensitive ABAP programs are the Microsoft Sentinel for SAP watchlists:
//     https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/SAP/Analytics/Watchlists
//
// ETD LEEF samples, quoted above only to explain why that path is not the one
// implemented here:
// https://www.ibm.com/docs/SS42VS_DSM/com.ibm.dsm.doc/c_dsm_guide_SAP_Enterprise_sample_event_messages.html
// https://www.juniper.net/documentation/us/en/software/jsa7.5.0/jsa-dsm/topics/concept/jsa-configuring-dsm-sample-event-message2.html
//
// ---------------------------------------------------------------------------
// Not confirmed
// ---------------------------------------------------------------------------
//
//   - The leading version character. The published LINE_BREAKER accepts "2" or
//     "3"; the sample record was broken on it, so its value there is unknown.
//     These records use "3".
//   - Fields 5, 7 and 11 have no published names. They are emitted with the
//     values the sample carries ("00", "00", and eight blanks).
//   - Field 10. "B4" in the sample is a background work process, and SAP's task
//     type numbering (1 dialog, 2 update, 3 spool, 4 background, 5 enqueue)
//     fits, so dialog records here carry "D1" and background records "B4".
//     That pairing is consistent with the one sample, not with documentation.
//   - Field 16. The sample holds "1" for a record with one variable, so these
//     records emit the count of populated variables. That is a guess from a
//     single observation; it may be a constant flag.
//   - Reason codes. reason=1 on a failed dialog logon and reason=2 on a failed
//     RFC logon are both quoted in SAP community threads, but SAP publishes no
//     full code table, so the codes on AU4 and AUX are indicative only.
//   - Function group names paired with function modules on AUK and AUL, and the
//     literal "Profile" in the AUU variables. The message texts are confirmed;
//     these particular values are not.
//   - Whether a forwarder preserves the trailing blanks of a short terminal
//     field. These records are built to the full 200 characters, but rsyslog
//     and most agents strip trailing whitespace before sending, and so does
//     LogGen's own sender. The preview shows the record at full width; the line
//     on the wire ends at the last non-blank character. A decoder should read
//     fields by offset from the left and never depend on the total length.
//
// Wazuh ships no SAP decoder, so these records will not decode out of the box.
// They are here to be written against: every field sits at a fixed offset,
// which makes them straightforward to pull apart in a decoder.

// salVersion is the leading record-format character. See the note above.
const salVersion = "3"

// Work process type and task type travel together; see field 10 above.
const (
	salDialog     = "D1"
	salBackground = "B4"
)

// salRec is one audit record before it is laid out on the wire.
type salRec struct {
	MsgID    string   // three-character message id, e.g. AU2
	WP       string   // salDialog or salBackground
	User     string   // SAP user id, at most 12 characters
	TCode    string   // transaction code, at most 20
	Program  string   // ABAP program, at most 40
	Client   string   // MANDT, three digits
	Vars     []string // message variables, in &A &B &C order
	Terminal string   // terminal name, or client IP with rsau/ip_only=1
}

// salPad left justifies a value in a fixed-width field, truncating anything too
// long. Every field in a SAL record is blank padded this way.
func salPad(s string, width int) string {
	if len(s) > width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// salVars renders the 64-character variable area: each variable is followed by
// "&", and an unused middle slot stays empty.
func salVars(vars []string) string {
	if len(vars) == 0 {
		return salPad("", 64)
	}
	return salPad(strings.Join(vars, "&")+"&", 64)
}

// salCount reports how many variable slots are populated, which is what field
// 16 appears to hold.
func salCount(vars []string) string {
	n := 0
	for _, v := range vars {
		if v != "" {
			n++
		}
	}
	return strconv.Itoa(n)
}

// salLine assembles the 200-character record.
func salLine(c *core.Ctx, r salRec) string {
	wp := r.WP
	if wp == "" {
		wp = salDialog
	}
	client := r.Client
	if client == "" {
		client = sapClient(c)
	}
	// A five digit pid keeps the field exactly full, which sidesteps the
	// question of whether SAP blank pads or zero pads a shorter one.
	pid := c.Int(10000, 99999)

	var b strings.Builder
	b.WriteString(salVersion)                        // 1  version
	b.WriteString(salPad(r.MsgID, 3))                // 2  message id
	b.WriteString(c.Now.Format("20060102"))          // 3  date
	b.WriteString(c.Now.Format("150405"))            // 4  time
	b.WriteString("00")                              // 5  unnamed
	b.WriteString(strconv.Itoa(pid))                 // 6  OS pid
	b.WriteString("00")                              // 7  unnamed
	b.WriteString(fmt.Sprintf("%03d", c.Int(0, 19))) // 8  work process number
	b.WriteString(wp)                                // 9  WP type and 10 task type
	b.WriteString(strings.Repeat(" ", 8))            // 11 unnamed
	b.WriteString(salPad(r.User, 12))                // 12 user
	b.WriteString(salPad(r.TCode, 20))               // 13 transaction
	b.WriteString(salPad(r.Program, 40))             // 14 program
	b.WriteString(salPad(client, 3))                 // 15 client
	b.WriteString(salCount(r.Vars))                  // 16 unnamed
	b.WriteString(salVars(r.Vars))                   // 17 variables
	b.WriteString(salPad(r.Terminal, 20))            // 18 terminal
	return b.String()
}

// sapPayload wraps a record for the configured SAP application server. There is
// no syslog tag: the record is parsed from offset zero, so a "tag: " prefix
// would shift every field.
func sapPayload(c *core.Ctx, severity int, msg string) core.Payload {
	return core.Payload{
		Kind:     core.SourceSAP,
		Host:     c.Env.SAPHost,
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

var (
	sapUserP    = param("user", "SAP user id", "auto")
	sapTargetP  = param("target", "Target SAP user id", "auto")
	sapClientP  = param("client", "Client (MANDT)", "100")
	sapTermP    = param("terminal", "Terminal or client IP", "auto")
	sapTCodeP   = param("tcode", "Transaction code", "auto")
	sapProgramP = param("program", "ABAP program", "auto")
	sapTableP   = param("table", "Table name", "auto")
	sapFuncP    = param("func", "Function module", "auto")
	sapProfileP = param("profile", "Profile or role", "auto")
	sapDestP    = param("dest", "RFC destination", "auto")
	sapFileP    = param("file", "Download file name", "auto")
	sapSizeP    = param("bytes", "Download size in bytes", "auto")
	sapReasonP  = param("reason", "Reason code", "auto")
	sapTypeP    = param("logontype", "Logon type letter", "auto")
	sapMethodP  = param("logonmethod", "Logon method letter", "auto")
)

// sapClient is the client (MANDT) the record was written in. Production
// business clients are three digits; 000 and 066 are SAP's own.
func sapClient(c *core.Ctx) string { return c.P("client", "100") }

// sapUser returns an ordinary named SAP user id. SAP user ids are upper case
// and at most 12 characters, so the shared estate names are folded to match.
func sapUser(c *core.Ctx) string {
	u := strings.ToUpper(c.User())
	if len(u) > 12 {
		u = u[:12]
	}
	return u
}

// sapStandardUser returns one of the SAP standard and technical accounts, the
// ones a SOC watches for interactive use. The list is the Microsoft Sentinel
// for SAP "Privileged Users" watchlist.
func sapStandardUser(c *core.Ctx) string {
	return c.Pick("SAP*", "DDIC", "ALEREMOTE", "BWREMOTE", "SAPSYS", "WF-BATCH")
}

// sapTerminal is the terminal field. With rsau/ip_only=1 set, which is the
// usual recommendation so that events can be tied to a source address, SAP
// writes the client IP there instead of the SAPGUI terminal name.
func sapTerminal(c *core.Ctx) string { return c.P("terminal", c.InternalIP()) }

// sapSensitiveTCode returns a transaction a SOC cares about seeing started.
func sapSensitiveTCode(c *core.Ctx) string {
	return c.P("tcode", c.Pick(
		"SE16",        // data browser, reads any table
		"SE16N",       // general table display, change capable
		"SE38",        // ABAP editor, runs any report
		"SA38",        // report execution
		"SM30",        // table maintenance
		"SM31",        // table maintenance
		"SU01",        // user maintenance
		"PFCG",        // role maintenance
		"SM49",        // execute an external OS command
		"SM59",        // RFC destinations
		"RSAU_CONFIG", // audit log configuration
		"RZ11",        // profile parameter maintenance
		"SE11",        // ABAP dictionary
		"STMS",        // transport management
	))
}

// sapSensitiveProgram returns an ABAP program worth alerting on. The list is
// the Microsoft Sentinel for SAP "Sensitive ABAP Programs" watchlist.
func sapSensitiveProgram(c *core.Ctx) string {
	return c.P("program", c.Pick(
		"RSBDCOS0",                // executes an OS command
		"RSPFLDOC",                // profile parameter maintenance
		"RSCDOK99",                // deletes change documents
		"RSTBPDEL",                // deletes table change logs
		"/1BCDWB/DBUSR02",         // data browser generated for USR02
		"/1BCDWB/DBUSRPWDHISTORY", // data browser for the password history
	))
}

// sapSensitiveTable returns a table whose contents are worth protecting. The
// list is the Microsoft Sentinel for SAP "Sensitive Tables" watchlist.
func sapSensitiveTable(c *core.Ctx) string {
	return c.P("table", c.Pick(
		"USR02",         // logon data, including password hashes
		"USH02",         // change history for logon data
		"USRPWDHISTORY", // password history
		"PA0008",        // basic pay
	))
}

// sapFuncPair returns a function module and the function group SAP groups it
// under. The module names are the Sentinel "Sensitive Function Modules"
// watchlist; the group names are indicative, see the header.
func sapFuncPair(c *core.Ctx) (string, string) {
	pairs := [][2]string{
		{"RFC_READ_TABLE", "SDTX"},
		{"RFC_GET_TABLE_ENTRIES", "SDTX"},
		{"RFC_ABAP_INSTALL_AND_RUN", "SUTL"},
		{"SXPG_COMMAND_EXECUTE", "SXPG"},
		{"BAPI_USER_CREATE1", "SU_USER"},
		{"BAPI_USER_PROFILES_ASSIGN", "SU_USER"},
		{"RSAU_CLEAR_AUDIT_LOG", "SECURITY_AUDIT"},
	}
	p := pairs[c.Int(0, len(pairs)-1)]
	return c.P("func", p[0]), p[1]
}

func init() {
	registerSAPLogon()
	registerSAPUserMaster()
	registerSAPDebug()
	registerSAPTransaction()
	registerSAPRFC()
	registerSAPDataAccess()
	registerSAPAuditConfig()
}

// ---------------------------------------------------------------------------
// Logon
//
// Audit classes "Dialog Logon" and "RFC Logon".
// ---------------------------------------------------------------------------

func registerSAPLogon() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au1-logon-success", Source: core.SourceSAP,
			Group: "Logon", Name: "AU1 Dialog logon successful",
			Desc:    "A named user logged on to the ABAP system. On its own it is routine; it is the baseline every logon anomaly rule is built from.",
			EventID: "AU1", Channel: "Dialog Logon", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP, sapTypeP, sapMethodP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Logon successful (type=&A, method=&C)" - &B is unused and stays
			// empty, which is why the variable area reads "A&&P&".
			return sapPayload(c, core.SevInfo, salLine(c, salRec{
				MsgID:    "AU1",
				User:     c.P("user", sapUser(c)),
				Program:  "SAPMSYST",
				Vars:     []string{c.P("logontype", "A"), "", c.P("logonmethod", "P")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au1-logon-standard-user", Source: core.SourceSAP,
			Group: "Logon", Name: "AU1 Logon with an SAP standard user",
			Desc:    "SAP*, DDIC or another standard or technical account logged on interactively. These accounts should never log on from a user terminal, and SAP* in particular carries hard-coded superuser rights.",
			EventID: "AU1", Channel: "Dialog Logon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1078.001", "T1078.003"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU1",
				User:     c.P("user", sapStandardUser(c)),
				Program:  "SAPMSYST",
				Vars:     []string{"A", "", "P"},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au2-logon-failed", Source: core.SourceSAP,
			Group: "Logon", Name: "AU2 Dialog logon failed",
			Desc:    "A dialog logon was rejected. Repeat it against one user id to simulate password guessing, which is the event an AU2 brute-force rule counts.",
			EventID: "AU2", Channel: "Dialog Logon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP, sapReasonP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Logon failed (reason=&B, type=&A, method=&C)".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU2",
				User:     c.P("user", sapUser(c)),
				Program:  "SAPMSYST",
				Vars:     []string{c.P("logontype", "A"), c.P("reason", "1"), c.P("logonmethod", "P")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au2-logon-failed-standard-user", Source: core.SourceSAP,
			Group: "Logon", Name: "AU2 Failed logon against SAP* or DDIC",
			Desc:    "A failed logon naming a standard account. Guessing SAP* or DDIC is the first thing an attacker who can reach the SAPGUI port tries, because their default passwords are published.",
			EventID: "AU2", Channel: "Dialog Logon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001", "T1078.001"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU2",
				User:     c.P("user", sapStandardUser(c)),
				Program:  "SAPMSYST",
				Vars:     []string{"A", "1", "P"},
				Terminal: c.P("terminal", c.ExternalIP()),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auo-logon-failed", Source: core.SourceSAP,
			Group: "Logon", Name: "AUO Logon failed (reason and type only)",
			Desc:    "The shorter failed-logon message, written where no logon method is recorded. Worth selecting in the audit filter alongside AU2, since a filter that only catches AU2 misses these.",
			EventID: "AUO", Channel: "Dialog Logon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110.001"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP, sapReasonP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Logon Failed (Reason = &B, Type = &A)".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUO",
				User:     c.P("user", sapUser(c)),
				Program:  "SAPMSYST",
				Vars:     []string{c.P("logontype", "A"), c.P("reason", "1")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aum-user-locked", Source: core.SourceSAP,
			Group: "Logon", Name: "AUM User locked after repeated password failures",
			Desc:    "The system locked a user id after too many wrong passwords. This is the end state of a brute-force run, and SAP itself classes it critical with a monitor alert.",
			EventID: "AUM", Channel: "Dialog Logon", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1110.001", "T1531"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "User &B Locked in Client &A After Erroneous Password Checks".
			// The client and the user each appear twice in the record, so both
			// are resolved once into a variable first.
			client := sapClient(c)
			user := c.P("user", sapUser(c))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUM",
				User:     user,
				Client:   client,
				Program:  "SAPMSYST",
				Vars:     []string{client, user},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-bu1-password-check-failed", Source: core.SourceSAP,
			Group: "Logon", Name: "BU1 Password check failed",
			Desc:    "A password verification failed outside a normal dialog logon, for example at a re-authentication prompt. Counted with AU2 it gives the full picture of credential guessing.",
			EventID: "BU1", Channel: "Other events", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Password check failed for user &B in client &A".
			client := sapClient(c)
			user := c.P("user", sapUser(c))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "BU1",
				User:     user,
				Client:   client,
				Vars:     []string{client, user},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au5-rfc-logon-success", Source: core.SourceSAP,
			Group: "Logon", Name: "AU5 RFC or CPIC logon successful",
			Desc:    "A remote system or interface account authenticated over RFC. High volume on a connected estate, which is why SAP recommends leaving it out of the catch-all filter, but it is the event that shows a stolen RFC credential being used.",
			EventID: "AU5", Channel: "RFC Logon", Severity: core.SevLabelLow,
			Mitre:  []string{"T1078.003", "T1021"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "RFC/CPIC logon successful (type=&A, method=&C)".
			return sapPayload(c, core.SevInfo, salLine(c, salRec{
				MsgID:    "AU5",
				User:     c.P("user", c.Pick("ALEREMOTE", "BWREMOTE", "RFCUSER", "SOLMANUSER")),
				Vars:     []string{"E", "", "A"},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au6-rfc-logon-failed", Source: core.SourceSAP,
			Group: "Logon", Name: "AU6 RFC or CPIC logon failed",
			Desc:    "A remote logon over RFC was rejected. A burst of these from one host is credential spraying against the RFC gateway, which is reachable from the network without a SAPGUI.",
			EventID: "AU6", Channel: "RFC Logon", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1110", "T1021"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP, sapReasonP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "RFC/CPIC logon failed, reason=&B, type=&A, method=&C".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU6",
				User:     c.P("user", c.Pick("ALEREMOTE", "BWREMOTE", "RFCUSER", "SAP*")),
				Vars:     []string{"E", c.P("reason", "2"), "P"},
				Terminal: c.P("terminal", c.ExternalIP()),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// User master and authorisations
//
// Audit class "User Master Record Change".
// ---------------------------------------------------------------------------

func registerSAPUserMaster() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au7-user-created", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "AU7 User created",
			Desc:    "A new user master record was created. Outside a change window, or created by an account that is not on the user administration team, this is persistence.",
			EventID: "AU7", Channel: "User Master Record Change", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1136.001"},
			Params: []core.Param{sapUserP, sapTargetP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "User &A Created".
			target := c.P("target", c.Pick("ZSUPPORT", "ZADMIN2", "FIREFIGHT", "ZTEMP01"))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU7",
				User:     c.P("user", sapUser(c)),
				TCode:    "SU01",
				Program:  "SAPLSUU5",
				Vars:     []string{target},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au8-user-deleted", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "AU8 User deleted",
			Desc:    "A user master record was deleted. Deleting the account that was used for an intrusion removes the easiest thread an investigator has to pull.",
			EventID: "AU8", Channel: "User Master Record Change", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1070", "T1531"},
			Params: []core.Param{sapUserP, sapTargetP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "User &A Deleted".
			target := c.P("target", c.Pick("ZSUPPORT", "FIREFIGHT", "ZTEMP01"))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU8",
				User:     c.P("user", sapUser(c)),
				TCode:    "SU01",
				Program:  "SAPLSUU5",
				Vars:     []string{target},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au9-user-locked-by-admin", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "AU9 User locked by an administrator",
			Desc:    "An administrator locked a user id. Mass locking is a denial-of-service pattern, and locking the one account that would have noticed is a classic cover-up.",
			EventID: "AU9", Channel: "User Master Record Change", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1531"},
			Params: []core.Param{sapUserP, sapTargetP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "User &A Locked".
			target := c.P("target", sapUser(c))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU9",
				User:     c.P("user", "ZADMIN"),
				TCode:    "SU01",
				Program:  "SAPLSUU5",
				Vars:     []string{target},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aub-authorizations-changed", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "AUB Authorizations for a user changed",
			Desc:    "A role or profile assignment changed on a user master record. This is the message that fires when SAP_ALL is granted, and privilege escalation inside SAP almost always passes through it.",
			EventID: "AUB", Channel: "User Master Record Change", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1098", "T1078.003"},
			Params: []core.Param{sapUserP, sapTargetP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Authorizations for User &A Changed".
			target := c.P("target", sapUser(c))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUB",
				User:     c.P("user", "ZADMIN"),
				TCode:    c.P("tcode", c.Pick("SU01", "PFCG")),
				Program:  "SAPLSUU5",
				Vars:     []string{target},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auu-profile-activated", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "AUU Profile activated",
			Desc:    "An authorization profile was activated. SAP_ALL, or a copy of it, being activated is the single most valuable alert in an SAP estate: it grants every authorization object in the system.",
			EventID: "AUU", Channel: "User Master Record Change", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1098", "T1068"},
			Params: []core.Param{sapUserP, sapProfileP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "&A &B Activated". The first variable names the object type; see
			// the note on unconfirmed values in the header.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUU",
				User:     c.P("user", "ZADMIN"),
				TCode:    "PFCG",
				Program:  "SAPLPROFGEN",
				Vars:     []string{"Profile", c.P("profile", c.Pick("SAP_ALL", "SAP_NEW", "Z_ALL_COPY"))},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-bu2-password-changed", Source: core.SourceSAP,
			Group: "User and authorisations", Name: "BU2 Password changed for a user",
			Desc:    "A password was changed. Changed on somebody else's account, or on a technical account that nobody logs on to, this is account takeover.",
			EventID: "BU2", Channel: "User Master Record Change", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1098"},
			Params: []core.Param{sapUserP, sapTargetP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Password changed for user &B in client &A".
			client := sapClient(c)
			target := c.P("target", sapStandardUser(c))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "BU2",
				User:     c.P("user", "ZADMIN"),
				Client:   client,
				TCode:    "SU01",
				Program:  "SAPLSUU5",
				Vars:     []string{client, target},
				Terminal: sapTerminal(c),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// Debug and replace
//
// Audit class "Other events". Debugging with change in production bypasses
// every authorization check the application performs, so SAP rates most of
// these critical or very critical.
// ---------------------------------------------------------------------------

func registerSAPDebug() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cum-debugger-jump", Source: core.SourceSAP,
			Group: "Debug and replace", Name: "CUM Jump in the ABAP debugger",
			Desc:    "A developer jumped to another line in the debugger, skipping the code in between. Skipping an authority-check turns a controlled transaction into an uncontrolled one.",
			EventID: "CUM", Channel: "Other events", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001", "T1622"},
			Params: []core.Param{sapUserP, sapProgramP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Jump to ABAP Debugger: &A". The program appears twice, so it is
			// resolved once.
			prog := sapSensitiveProgram(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUM",
				User:     c.P("user", sapUser(c)),
				TCode:    "SE38",
				Program:  prog,
				Vars:     []string{prog},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cul-field-content-changed", Source: core.SourceSAP,
			Group: "Debug and replace", Name: "CUL Field content changed in the debugger",
			Desc:    "Debug and replace: a variable was overwritten at runtime. Setting SY-SUBRC to zero after a failed authority-check defeats the check entirely and leaves no trace in the business document.",
			EventID: "CUL", Channel: "Other events", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.001", "T1622"},
			Params: []core.Param{sapUserP, sapProgramP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Field content changed: &A". The internal layout of that string
			// is not published; this carries the field name.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUL",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SE38", "SE16", "FB03")),
				Program:  sapSensitiveProgram(c),
				Vars:     []string{c.Pick("SY-SUBRC", "GV_AUTH_OK", "LV_AMOUNT")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cuo-debugger-commit", Source: core.SourceSAP,
			Group: "Debug and replace", Name: "CUO Database commit or rollback from the debugger",
			Desc:    "A database commit was forced from inside the debugger, writing a change the application never sanctioned. SAP rates this very critical, and so should any SOC with a production ERP.",
			EventID: "CUO", Channel: "Other events", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1565.001"},
			Params: []core.Param{sapUserP, sapProgramP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Explicit database commit or rollback from debugger &A".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUO",
				User:     c.P("user", sapUser(c)),
				TCode:    "SE38",
				Program:  sapSensitiveProgram(c),
				Vars:     []string{c.Pick("COMMIT", "ROLLBACK")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cup-debug-session-started", Source: core.SourceSAP,
			Group: "Debug and replace", Name: "CUP Non-exclusive debugging session started",
			Desc:    "A debugging session was opened. On a production system, where nobody should be debugging, this is the first event in the chain that CUL and CUO complete.",
			EventID: "CUP", Channel: "Other events", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1622"},
			Params: []core.Param{sapUserP, sapProgramP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Non-exclusive debugging session started" takes no variables.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUP",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SE38", "SE80", "SE24")),
				Program:  sapSensitiveProgram(c),
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cuk-c-debugging", Source: core.SourceSAP,
			Group: "Debug and replace", Name: "CUK C debugging activated",
			Desc:    "Kernel-level debugging was switched on. It reaches below the ABAP stack, where no application authorization check applies at all.",
			EventID: "CUK", Channel: "Other events", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1622", "T1562.001"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "C debugging activated" takes no variables.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUK",
				User:     c.P("user", sapUser(c)),
				TCode:    "SE38",
				Terminal: sapTerminal(c),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// Transaction and report start
//
// Audit classes "Transaction Start" and "Report Start".
// ---------------------------------------------------------------------------

func registerSAPTransaction() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au3-sensitive-transaction", Source: core.SourceSAP,
			Group: "Transaction and report start", Name: "AU3 Sensitive transaction started",
			Desc:    "A transaction from the watch list was started: SE16 and SE16N read any table, SE38 and SA38 run any report, SM30 maintains table contents, SU01 maintains users, SM49 runs an operating system command.",
			EventID: "AU3", Channel: "Transaction Start", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1059", "T1005"},
			Params: []core.Param{sapUserP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Transaction &A Started". The code appears in both the record
			// field and variable A, so it is resolved once.
			tcode := sapSensitiveTCode(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU3",
				User:     c.P("user", sapUser(c)),
				TCode:    tcode,
				Vars:     []string{tcode},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-au4-transaction-start-failed", Source: core.SourceSAP,
			Group: "Transaction and report start", Name: "AU4 Transaction start failed",
			Desc:    "A transaction start was refused, normally for want of authorization. A run of these across many transaction codes from one user is somebody mapping what their stolen account can reach.",
			EventID: "AU4", Channel: "Transaction Start", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1087", "T1078"},
			Params: []core.Param{sapUserP, sapTCodeP, sapTermP, sapClientP, sapReasonP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Start of transaction &A failed (Reason=&B)".
			tcode := sapSensitiveTCode(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AU4",
				User:     c.P("user", sapUser(c)),
				TCode:    tcode,
				Vars:     []string{tcode, c.P("reason", "2")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auw-sensitive-report", Source: core.SourceSAP,
			Group: "Transaction and report start", Name: "AUW Sensitive report started",
			Desc:    "An ABAP report from the watch list was run. RSBDCOS0 executes an operating system command as the <sid>adm account, which is a direct route from an SAP logon to a shell on the host.",
			EventID: "AUW", Channel: "Report Start", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1059", "T1569"},
			Params: []core.Param{sapUserP, sapProgramP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Report &A Started". Program name in both places, resolved once.
			prog := sapSensitiveProgram(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUW",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SE38", "SA38")),
				Program:  prog,
				Vars:     []string{prog},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aux-report-start-failed", Source: core.SourceSAP,
			Group: "Transaction and report start", Name: "AUX Report start failed",
			Desc:    "A report could not be started. Like AU4, a spread of these from one user is reconnaissance against the authorizations the account holds.",
			EventID: "AUX", Channel: "Report Start", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1087"},
			Params: []core.Param{sapUserP, sapProgramP, sapTermP, sapClientP, sapReasonP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Start Report &A Failed (Reason = &B)".
			prog := sapSensitiveProgram(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUX",
				User:     c.P("user", sapUser(c)),
				TCode:    "SA38",
				Program:  prog,
				Vars:     []string{prog, c.P("reason", "2")},
				Terminal: sapTerminal(c),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// RFC and remote execution
//
// Audit class "RFC Function Call". An RFC-enabled function module is a remote
// API into the system, and the standard ones include reading any table and
// running any operating system command.
// ---------------------------------------------------------------------------

func registerSAPRFC() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auk-rfc-call", Source: core.SourceSAP,
			Group: "RFC and remote execution", Name: "AUK Successful RFC call",
			Desc:    "A function module was called remotely. RFC_READ_TABLE returns the contents of any table to the caller and SXPG_COMMAND_EXECUTE runs an operating system command, so the module name is what makes this interesting.",
			EventID: "AUK", Channel: "RFC Function Call", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1021", "T1559"},
			Params: []core.Param{sapUserP, sapFuncP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Successful RFC Call &C (Function Group = &A)": &B is unused.
			fm, group := sapFuncPair(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUK",
				User:     c.P("user", c.Pick("ALEREMOTE", "RFCUSER", "BWREMOTE")),
				Vars:     []string{group, "", fm},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aul-rfc-call-failed", Source: core.SourceSAP,
			Group: "RFC and remote execution", Name: "AUL Failed RFC call",
			Desc:    "A remote function call was refused, usually by the S_RFC authorization check. Repeated failures across different modules is an attacker enumerating what the RFC account can reach.",
			EventID: "AUL", Channel: "RFC Function Call", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1021", "T1087"},
			Params: []core.Param{sapUserP, sapFuncP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Failed RFC Call &C (Function Group = &A)".
			fm, group := sapFuncPair(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUL",
				User:     c.P("user", c.Pick("ALEREMOTE", "RFCUSER", "SAP*")),
				Vars:     []string{group, "", fm},
				Terminal: c.P("terminal", c.ExternalIP()),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-cuz-generic-table-access-rfc", Source: core.SourceSAP,
			Group: "RFC and remote execution", Name: "CUZ Generic table access by RFC",
			Desc:    "A table was read or written over RFC rather than through a transaction. This is how an attacker holding RFC credentials pulls USR02 password hashes without ever opening a SAPGUI.",
			EventID: "CUZ", Channel: "RFC Function Call", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1005", "T1003"},
			Params: []core.Param{sapUserP, sapTableP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Generic table access by RFC to &A with activity &B". Activity is
			// an SAP ACTVT value: 03 display, 02 change.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "CUZ",
				User:     c.P("user", c.Pick("ALEREMOTE", "RFCUSER", "BWREMOTE")),
				Vars:     []string{sapSensitiveTable(c), c.Pick("03", "02")},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-duj-rfc-callback-rejected", Source: core.SourceSAP,
			Group: "RFC and remote execution", Name: "DUJ RFC callback rejected",
			Desc:    "A called system tried to call back into this one and was blocked by the callback whitelist. RFC callback abuse lets a compromised satellite system execute function modules in a trusted system under the caller's rights.",
			EventID: "DUJ", Channel: "RFC Function Call", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1021", "T1559"},
			Params: []core.Param{sapUserP, sapDestP, sapFuncP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "RFC callback rejected (destination &A, called &B, callback &C)".
			fm, _ := sapFuncPair(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID: "DUJ",
				User:  c.P("user", c.Pick("ALEREMOTE", "RFCUSER")),
				Vars: []string{
					c.P("dest", c.Pick("SAPDEV_RFC", "SAPQAS_RFC", "SOLMAN_RFC")),
					fm,
					"RFC_ABAP_INSTALL_AND_RUN",
				},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-fu1-dynamic-destination", Source: core.SourceSAP,
			Group: "RFC and remote execution", Name: "FU1 RFC call with a dynamic destination",
			Desc:    "A function module was called with a destination assembled at runtime rather than one configured in SM59. Dynamic destinations are how injected ABAP reaches a system that no configuration record points at.",
			EventID: "FU1", Channel: "RFC Function Call", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1021", "T1105"},
			Params: []core.Param{sapUserP, sapProgramP, sapFuncP, sapDestP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "RFC function &B with dynamic destination &C was called in
			// program &A".
			prog := sapSensitiveProgram(c)
			fm, _ := sapFuncPair(c)
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "FU1",
				User:     c.P("user", sapUser(c)),
				Program:  prog,
				Vars:     []string{prog, fm, c.P("dest", c.Pick("SAPDEV_RFC", "ZEXTERNAL", "NONE"))},
				Terminal: sapTerminal(c),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// Data access and download
//
// The exfiltration path out of an SAP system is rarely a network connection;
// it is a table read followed by a local download into a spreadsheet.
// ---------------------------------------------------------------------------

func registerSAPDataAccess() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auy-download-to-file", Source: core.SourceSAP,
			Group: "Data access and download", Name: "AUY Data downloaded to a local file",
			Desc:    "Table or report output was written to a file on the user's workstation. The byte count is in the record, so a rule can alert on a download far larger than that user's normal extract.",
			EventID: "AUY", Channel: "Other events", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1005", "T1074.001", "T1041"},
			Params: []core.Param{sapUserP, sapFileP, sapSizeP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Download &A Bytes to File &C": &B is unused.
			size := c.P("bytes", strconv.Itoa(c.Int(500000, 90000000)))
			file := c.P("file", c.Pick(
				`C:\Users\Public\USR02.XLS`,
				`C:\Temp\payroll_export.csv`,
				`C:\Users\Public\bank_details.txt`,
				`D:\extract\vendor_master.XLS`,
			))
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUY",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SE16", "SE16N", "SA38")),
				Vars:     []string{size, "", file},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-du9-generic-table-access", Source: core.SourceSAP,
			Group: "Data access and download", Name: "DU9 Generic table access from a transaction",
			Desc:    "A table was opened through a generic tool such as SE16 or SM30 rather than through the business transaction that owns it. Paired with AUY it is the read-then-extract pattern a data theft leaves behind.",
			EventID: "DU9", Channel: "Transaction Start", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1005", "T1003"},
			Params: []core.Param{sapUserP, sapTableP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Generic table access call to &A with activity &B (auth. check:
			// &C )". The third variable records the outcome of the
			// authorization check; see the note in the header.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "DU9",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SE16", "SE16N", "SM30", "SM31")),
				Vars:     []string{sapSensitiveTable(c), c.Pick("03", "02"), "X"},
				Terminal: sapTerminal(c),
			}))
		},
	})
}

// ---------------------------------------------------------------------------
// Audit configuration and system
//
// Audit class "System / housekeeping". SAP rates every one of these very
// critical, because they are the events that stop the other events happening.
// ---------------------------------------------------------------------------

func registerSAPAuditConfig() {
	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aue-audit-config-changed", Source: core.SourceSAP,
			Group: "Audit configuration and system", Name: "AUE Audit configuration changed",
			Desc:    "The Security Audit Log filter configuration was changed in SM19 or RSAU_CONFIG. Narrowing the filter is how an attacker makes the next hour of their work invisible, and this is the only record of it.",
			EventID: "AUE", Channel: "System / housekeeping", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.008", "T1562.001"},
			Params: []core.Param{sapUserP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Audit Configuration Changed" takes no variables.
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUE",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SM19", "RSAU_CONFIG")),
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-auj-audit-status-changed", Source: core.SourceSAP,
			Group: "Audit configuration and system", Name: "AUJ Audit active status set",
			Desc:    "Auditing was switched on or off. An audit log that stops producing records is itself the alert, and this message is the last thing it writes.",
			EventID: "AUJ", Channel: "System / housekeeping", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562.008"},
			Params: []core.Param{sapUserP, sapTCodeP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Audit: Active Status Set to &1".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "AUJ",
				User:     c.P("user", sapUser(c)),
				TCode:    c.P("tcode", c.Pick("SM19", "RSAU_CONFIG")),
				Vars:     []string{"Inactive"},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-eu5-audit-data-deleted", Source: core.SourceSAP,
			Group: "Audit configuration and system", Name: "EU5 Audit log data deleted",
			Desc:    "Audit records were deleted. On a system where the SIEM already holds a copy this is recoverable; where it does not, the evidence is gone.",
			EventID: "EU5", Channel: "System / housekeeping", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1070", "T1485"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Audit log data of &A was deleted (&B data records)".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "EU5",
				User:     c.P("user", sapUser(c)),
				TCode:    "RSAU_ADMIN",
				Vars:     []string{c.Now.Format("20060102"), strconv.Itoa(c.Int(1000, 400000))},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-eu1-system-changeability", Source: core.SourceSAP,
			Group: "Audit configuration and system", Name: "EU1 System changeability changed",
			Desc:    "A production system was opened for changes. Once it is modifiable, ABAP code and repository objects can be edited in place, with no transport and no second pair of eyes.",
			EventID: "EU1", Channel: "System / housekeeping", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562.001", "T1505"},
			Params: []core.Param{sapUserP, sapTermP, sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "System changeability changed (&A to &B)".
			return sapPayload(c, core.SevWarning, salLine(c, salRec{
				MsgID:    "EU1",
				User:     c.P("user", sapUser(c)),
				TCode:    "SE06",
				Vars:     []string{"not modifiable", "modifiable"},
				Terminal: sapTerminal(c),
			}))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "sap-aug-app-server-started", Source: core.SourceSAP,
			Group: "Audit configuration and system", Name: "AUG Application server started",
			Desc:    "An application server instance started. It matters because a restart is how a static audit configuration change takes effect, and because an unplanned restart can be the tail end of a crash somebody caused.",
			EventID: "AUG", Channel: "System / housekeeping", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1562.008"},
			Params: []core.Param{sapClientP},
		},
		Build: func(c *core.Ctx) core.Payload {
			// "Application Server Started" takes no variables, and runs in a
			// background work process under the SAP system account.
			return sapPayload(c, core.SevInfo, salLine(c, salRec{
				MsgID:  "AUG",
				WP:     salBackground,
				User:   "SAPSYS",
				Client: "000",
			}))
		},
	})
}

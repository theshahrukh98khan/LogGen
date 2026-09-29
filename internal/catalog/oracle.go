package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// Oracle Database controls, covering the three ways an Oracle estate reaches a
// SIEM: the audit trail written straight to syslog, the listener log, and the
// alert log.
//
// Two record shapes exist for the audit trail and they are not interchangeable:
//
//   - Standard (traditional) auditing, enabled with AUDIT_SYSLOG_LEVEL, emits
//     "Oracle Audit[pid]:" records whose fields carry an explicit value length,
//     as NAME:[len] "value".
//   - Unified auditing (12c+), enabled with UNIFIED_AUDIT_SYSTEMLOG, emits
//     "Oracle Unified Audit[pid]:" records with different field names, no length
//     markers, and single quotes around LENGTH. AUDIT_SYSLOG_LEVEL has no effect
//     once a database is migrated to unified auditing.
//
// Both are provided because which one a site runs depends on its Oracle version
// and migration state, and a decoder written for one will not read the other.
//
// Note on Wazuh: the upstream ruleset ships no Oracle decoders, so these records
// will not decode out of the box. They are here to be written against — see the
// README.

// ---------------------------------------------------------------------------
// Audit action codes
// ---------------------------------------------------------------------------

// Numeric ACTION values from SYS.AUDIT_ACTIONS. The set is version-specific;
// run "SELECT action, name FROM sys.audit_actions ORDER BY action" against the
// target database for its canonical list.
const (
	actCreateTable   = "1"
	actInsert        = "2"
	actSelect        = "3"
	actUpdate        = "6"
	actDelete        = "7"
	actDropTable     = "12"
	actGrantObject   = "17"
	actCreateDBLink  = "32"
	actAlterUser     = "43"
	actAlterSystem   = "49"
	actCreateUser    = "51"
	actDropUser      = "53"
	actNoauditObject = "31"
	actTruncateTable = "85"
	actLogon         = "100"
	actLogoff        = "101"
	actLogoffCleanup = "102"
	actSessionRec    = "103"
	actSystemNoaudit = "105"
	actSystemGrant   = "108"
	actGrantRole     = "114"
)

// Oracle return codes are the ORA- error number with the prefix and any leading
// zeros stripped. Zero means the action succeeded.
const (
	rcSuccess       = "0"
	rcBadCredential = "1017"  // ORA-01017 invalid username/password
	rcNoTable       = "942"   // ORA-00942 table or view does not exist
	rcNoPrivilege   = "1031"  // ORA-01031 insufficient privileges
	rcAccountLocked = "28000" // ORA-28000 the account is locked
	rcPasswordExp   = "28001" // ORA-28001 the password has expired
)

// ---------------------------------------------------------------------------
// Record builders
// ---------------------------------------------------------------------------

// auditField renders one standard-audit field as NAME:[len] "value", where the
// length is the byte length of the value. There is no space between the colon
// and the bracket.
func auditField(name, value string) string {
	return name + ":[" + strconv.Itoa(len(value)) + "] \"" + value + "\""
}

// standardAudit assembles an "Oracle Audit" record from its fields.
//
// LENGTH is the one field that carries no length marker and is separated from
// its value by a space. Oracle does not document what LENGTH counts; here it is
// the byte length of the field list that follows it, which matches the
// magnitude seen in real records. Do not rely on it being byte-exact against a
// live database.
func standardAudit(fields ...string) string {
	body := strings.Join(fields, " ")
	return fmt.Sprintf("LENGTH: %q %s", strconv.Itoa(len(body)), body)
}

// unifiedField renders one unified-audit field as NAME:"value". Unified records
// carry no length markers, and empty values are emitted rather than omitted.
func unifiedField(name, value string) string {
	return name + ":\"" + value + "\""
}

// unifiedAudit assembles an "Oracle Unified Audit" record. LENGTH is single
// quoted here, unlike the standard audit record.
func unifiedAudit(fields ...string) string {
	body := strings.Join(fields, " ")
	return fmt.Sprintf("LENGTH: '%d' %s", len(body), body)
}

// oraclePayload wraps a record for the configured database host.
func oraclePayload(c *core.Ctx, tag string, pid, severity int, msg string) core.Payload {
	return core.Payload{
		Kind: core.SourceOracle,
		Tag:  tag,
		PID:  pid,
		Host: c.Env.DBHost,
		// AUDIT_SYSLOG_LEVEL is conventionally set to local0.info, which is
		// what the priority on real Oracle audit records decodes to.
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  msg,
	}
}

// ---------------------------------------------------------------------------
// Estate helpers
// ---------------------------------------------------------------------------

var (
	oraDBUsers    = []string{"APP_USER", "REPORTS", "BATCH_JOB", "DEVOPS", "ANALYTICS"}
	oraPrivUsers  = []string{"SYS", "SYSTEM", "DBA_ADMIN", "SYSDBA"}
	oraSchemas    = []string{"HR", "FINANCE", "SALES", "PAYROLL"}
	oraTables     = []string{"EMPLOYEES", "SALARIES", "CUSTOMERS", "CARD_DATA", "ACCOUNTS"}
	oraPrograms   = []string{"sqlplus@app01 (TNS V1-V3)", "JDBC Thin Client", "SQL Developer", "toad.exe"}
	oraTerminals  = []string{"pts/0", "pts/1", "unknown", "APPSRV01"}
)

func oraUser(c *core.Ctx) string     { return c.PickFrom(oraDBUsers) }
func oraPrivUser(c *core.Ctx) string { return c.PickFrom(oraPrivUsers) }
func oraSchema(c *core.Ctx) string   { return c.PickFrom(oraSchemas) }
func oraTable(c *core.Ctx) string    { return c.PickFrom(oraTables) }

// oraSessionID returns an Oracle audit session identifier.
func oraSessionID(c *core.Ctx) string { return fmt.Sprint(c.Int(1000000, 9999999)) }

// oraDBID returns a stable-looking database identifier.
func oraDBID(c *core.Ctx) string { return fmt.Sprint(c.Int(1000000000, 2000000000)) }

// oraClientAddress renders the ADDRESS block Oracle embeds in COMMENT$TEXT.
func oraClientAddress(ip string, port int) string {
	return fmt.Sprintf("(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d))", ip, port)
}

var (
	oUser   = param("user", "Database user", "auto")
	oSrcIP  = param("srcip", "Client IP", "auto")
	oSchema = param("schema", "Schema", "auto")
	oTable  = param("table", "Table", "auto")
)

func init() {
	registerOracleStandardAudit()
	registerOracleUnifiedAudit()
	registerOracleListener()
	registerOracleAlert()
}

// ---------------------------------------------------------------------------
// Standard audit trail
// ---------------------------------------------------------------------------

// logonRecord builds a standard-audit logon or logoff record.
func logonRecord(c *core.Ctx, user, action, returnCode, srcIP string) string {
	host := strings.ToUpper(c.Env.NetBIOS) + `\` + strings.ToUpper(c.Workstation())
	comment := fmt.Sprintf(
		"Authenticated by: DATABASE;AUTHENTICATED IDENTITY: %s; Client address: %s",
		user, oraClientAddress(srcIP, c.EphemeralPort()))

	return standardAudit(
		auditField("SESSIONID", oraSessionID(c)),
		auditField("ENTRYID", "1"),
		auditField("STATEMENT", "1"),
		auditField("USERID", user),
		auditField("USERHOST", host),
		auditField("TERMINAL", c.PickFrom(oraTerminals)),
		auditField("ACTION", action),
		auditField("RETURNCODE", returnCode),
		auditField("COMMENT$TEXT", comment),
		auditField("OS$USERID", "oracle"),
		auditField("DBID", oraDBID(c)),
		auditField("PRIV$USED", "5"),
		auditField("CURRENT_USER", user),
	)
}

// objectRecord builds a standard-audit record for an action against an object.
func objectRecord(c *core.Ctx, user, action, returnCode, schema, object, sqlText string) string {
	fields := []string{
		auditField("SESSIONID", oraSessionID(c)),
		auditField("ENTRYID", fmt.Sprint(c.Int(2, 40))),
		auditField("STATEMENT", fmt.Sprint(c.Int(2, 30))),
		auditField("USERID", user),
		auditField("USERHOST", c.Env.DBHost),
		auditField("TERMINAL", c.PickFrom(oraTerminals)),
		auditField("ACTION", action),
		auditField("RETURNCODE", returnCode),
		auditField("OBJ$CREATOR", schema),
		auditField("OBJ$NAME", object),
		auditField("OS$USERID", "oracle"),
		auditField("DBID", oraDBID(c)),
	}
	if sqlText != "" {
		// SQLTEXT is only populated when the audit trail is set to DB_EXTENDED
		// or XML_EXTENDED. Its exact syslog spelling is taken from the AUD$
		// column name; it was not confirmed against a captured record.
		fields = append(fields, auditField("SQLTEXT", sqlText))
	}
	return standardAudit(fields...)
}

func registerOracleStandardAudit() {
	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-logon-success", Source: core.SourceOracle,
			Group: "Audit Trail", Name: "Database logon succeeded",
			Desc:     "A session was established. ACTION 100 with RETURNCODE 0 is the baseline every Oracle rule has to tolerate.",
			EventID:  actLogon, Channel: "audit", Severity: core.SevLabelInfo,
			Mitre:  []string{"T1078"},
			Params: []core.Param{oUser, oSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			ip := c.P("srcip", c.InternalIP())
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevInfo,
				logonRecord(c, user, actLogon, rcSuccess, ip))
		},
	})

	for _, f := range []struct {
		key, name, desc, rc, sev string
		mitre                    []string
	}{
		{"badpassword", "Logon failed (bad credentials)",
			"ACTION 100 with RETURNCODE 1017. Burst this control to simulate brute force against a database account.",
			rcBadCredential, core.SevLabelMedium, []string{"T1110"}},
		{"locked", "Logon failed (account locked)",
			"RETURNCODE 28000. The account hit FAILED_LOGIN_ATTEMPTS, which is usually the tail of a brute force.",
			rcAccountLocked, core.SevLabelHigh, []string{"T1110"}},
		{"expired", "Logon failed (password expired)",
			"RETURNCODE 28001. Often benign, but a cluster of these can mean credentials are being replayed after a rotation.",
			rcPasswordExp, core.SevLabelLow, nil},
	} {
		f := f
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-audit-logon-" + f.key, Source: core.SourceOracle,
				Group: "Audit Trail", Name: f.name, Desc: f.desc,
				EventID: actLogon, Channel: "audit", Severity: f.sev,
				Mitre:  f.mitre,
				Params: []core.Param{oUser, oSrcIP},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", oraUser(c))
				ip := c.P("srcip", c.ExternalIP())
				return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
					logonRecord(c, user, actLogon, f.rc, ip))
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-logoff", Source: core.SourceOracle,
			Group: "Audit Trail", Name: "Database logoff",
			Desc:     "ACTION 101. Paired with a logon it gives session duration.",
			EventID:  actLogoff, Channel: "audit", Severity: core.SevLabelInfo,
			Params: []core.Param{oUser},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevInfo,
				logonRecord(c, user, actLogoff, rcSuccess, c.InternalIP()))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-select-sensitive", Source: core.SourceOracle,
			Group: "Data Access", Name: "SELECT on a sensitive table",
			Desc:     "ACTION 3 against an audited table. Volume here is what separates a report from a bulk extraction.",
			EventID:  actSelect, Channel: "audit", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1005"},
			Params: []core.Param{oUser, oSchema, oTable},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			schema := c.P("schema", oraSchema(c))
			table := c.P("table", oraTable(c))
			sql := fmt.Sprintf("select * from %s.%s", schema, table)
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevNotice,
				objectRecord(c, user, actSelect, rcSuccess, schema, table, sql))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-session-summary", Source: core.SourceOracle,
			Group: "Data Access", Name: "Session summary (BY SESSION auditing)",
			Desc:     "ACTION 103. Under AUDIT ... BY SESSION, Oracle emits one summary whose SES$ACTIONS string encodes which statement types succeeded or failed.",
			EventID:  actSessionRec, Channel: "audit", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1005"},
			Params: []core.Param{oUser, oSchema, oTable},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			schema := c.P("schema", oraSchema(c))
			table := c.P("table", oraTable(c))

			// SES$ACTIONS has one character per statement type, in the order
			// ALTER, AUDIT, COMMENT, DELETE, GRANT, INDEX, INSERT, LOCK,
			// RENAME, SELECT, UPDATE, FLASHBACK; S succeeded, F failed, B both,
			// - not attempted. Positions 13-16 are reserved.
			actions := []byte("----------------")
			actions[9] = 'S' // SELECT succeeded
			if c.Chance(35) {
				actions[10] = 'S' // UPDATE succeeded
			}
			if c.Chance(20) {
				actions[3] = 'F' // DELETE failed
			}

			rec := standardAudit(
				auditField("SESSIONID", oraSessionID(c)),
				auditField("ENTRYID", "1"),
				auditField("STATEMENT", fmt.Sprint(c.Int(4, 30))),
				auditField("USERID", user),
				auditField("USERHOST", c.Env.DBHost),
				auditField("TERMINAL", c.PickFrom(oraTerminals)),
				auditField("ACTION", actSessionRec),
				auditField("RETURNCODE", rcSuccess),
				auditField("OBJ$CREATOR", schema),
				auditField("OBJ$NAME", table),
				auditField("SES$ACTIONS", string(actions)),
				auditField("SES$TID", fmt.Sprint(c.Int(10000, 99999))),
				auditField("OS$USERID", "oracle"),
			)
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevNotice, rec)
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-select-denied", Source: core.SourceOracle,
			Group: "Data Access", Name: "SELECT denied (table does not exist)",
			Desc:     "RETURNCODE 942. A burst of these from one session is schema enumeration, and is what blind SQL injection looks like from the database side.",
			EventID:  actSelect, Channel: "audit", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1190", "T1087"},
			Params: []core.Param{oUser, oTable},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			table := c.P("table", c.Pick("DBA_USERS", "ALL_TAB_PRIVS", "SYS.USER$", "V$SESSION", "CREDENTIALS"))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
				objectRecord(c, user, actSelect, rcNoTable, "SYS", table,
					fmt.Sprintf("select * from %s", table)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-insufficient-privileges", Source: core.SourceOracle,
			Group: "Data Access", Name: "Action denied (insufficient privileges)",
			Desc:     "RETURNCODE 1031. An account reaching for something it cannot have, repeatedly, is privilege probing.",
			EventID:  actSelect, Channel: "audit", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1068"},
			Params: []core.Param{oUser, oSchema, oTable},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			schema := c.P("schema", oraSchema(c))
			table := c.P("table", oraTable(c))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
				objectRecord(c, user, actSelect, rcNoPrivilege, schema, table,
					fmt.Sprintf("select * from %s.%s", schema, table)))
		},
	})

	// Account and privilege management.
	for _, a := range []struct {
		key, name, desc, action, sev string
		mitre                        []string
		sql                          func(c *core.Ctx, target string) string
	}{
		{"create-user", "Database user created",
			"ACTION 51. A new database account, which on a production instance should be rare and accounted for.",
			actCreateUser, core.SevLabelHigh, []string{"T1136"},
			func(c *core.Ctx, t string) string {
				return fmt.Sprintf("create user %s identified by *", t)
			}},
		{"drop-user", "Database user dropped",
			"ACTION 53. Removing an account can be cleanup after access.",
			actDropUser, core.SevLabelMedium, []string{"T1531"},
			func(c *core.Ctx, t string) string { return fmt.Sprintf("drop user %s cascade", t) }},
		{"alter-user", "Database user altered",
			"ACTION 43. Covers password changes and account unlocks.",
			actAlterUser, core.SevLabelMedium, []string{"T1098"},
			func(c *core.Ctx, t string) string {
				return fmt.Sprintf("alter user %s identified by *", t)
			}},
	} {
		a := a
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-audit-" + a.key, Source: core.SourceOracle,
				Group: "Account Management", Name: a.name, Desc: a.desc,
				EventID: a.action, Channel: "audit", Severity: a.sev,
				Mitre: a.mitre,
				Params: []core.Param{
					param("actor", "Acting account", "auto"),
					param("target", "Target account", "auto"),
				},
			},
			Build: func(c *core.Ctx) core.Payload {
				actor := c.P("actor", oraPrivUser(c))
				target := c.P("target", c.Pick("BATCH_SVC", "TEMP_ADMIN", "SUPPORT", "MIGRATION"))
				return oraclePayload(c, "Oracle Audit", c.PID(), core.SevNotice,
					objectRecord(c, actor, a.action, rcSuccess, "SYS", target, a.sql(c, target)))
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-system-grant", Source: core.SourceOracle,
			Group: "Account Management", Name: "System privilege granted",
			Desc:     "ACTION 108. Granting DBA or SELECT ANY TABLE hands over the instance; there is rarely a routine reason for it.",
			EventID:  actSystemGrant, Channel: "audit", Severity: core.SevLabelCritical,
			Mitre: []string{"T1098"},
			Params: []core.Param{
				param("actor", "Acting account", "auto"),
				param("target", "Grantee", "auto"),
				param("privilege", "Privilege", "DBA"),
			},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", oraPrivUser(c))
			target := c.P("target", oraUser(c))
			priv := c.P("privilege", c.Pick("DBA", "SELECT ANY TABLE", "ALTER SYSTEM", "CREATE ANY PROCEDURE", "SYSDBA"))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevErr,
				objectRecord(c, actor, actSystemGrant, rcSuccess, "SYS", target,
					fmt.Sprintf("grant %s to %s", priv, target)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-grant-role", Source: core.SourceOracle,
			Group: "Account Management", Name: "Role granted",
			Desc:     "ACTION 114. Role membership is the usual route to privilege, and is quieter than a direct system grant.",
			EventID:  actGrantRole, Channel: "audit", Severity: core.SevLabelHigh,
			Mitre: []string{"T1098"},
			Params: []core.Param{
				param("actor", "Acting account", "auto"),
				param("target", "Grantee", "auto"),
				param("role", "Role", "auto"),
			},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", oraPrivUser(c))
			target := c.P("target", oraUser(c))
			role := c.P("role", c.Pick("DBA", "EXP_FULL_DATABASE", "IMP_FULL_DATABASE", "AUDIT_ADMIN"))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
				objectRecord(c, actor, actGrantRole, rcSuccess, "SYS", role,
					fmt.Sprintf("grant %s to %s", role, target)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-create-dblink", Source: core.SourceOracle,
			Group: "Exfiltration", Name: "Database link created",
			Desc:     "ACTION 32. A database link is a standing outbound channel to another instance, and an easy way to move data off the box.",
			EventID:  actCreateDBLink, Channel: "audit", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1041"},
			Params: []core.Param{oUser, param("target", "Remote host", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			remote := c.P("target", c.ExternalIP())
			link := "EXPORT_LINK"
			sql := fmt.Sprintf(
				"create database link %s connect to remote_user identified by * using '(DESCRIPTION=(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=REMOTE)))'",
				link, remote)
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevErr,
				objectRecord(c, user, actCreateDBLink, rcSuccess, "SYS", link, sql))
		},
	})

	for _, d := range []struct {
		key, name, desc, action, sev string
		mitre                        []string
		sql                          string
	}{
		{"drop-table", "Table dropped",
			"ACTION 12. Destruction of a production table, whether malicious or a mistake.",
			actDropTable, core.SevLabelHigh, []string{"T1485"}, "drop table %s.%s"},
		{"truncate-table", "Table truncated",
			"ACTION 85. Truncation empties a table without generating undo, which makes recovery harder than a DELETE.",
			actTruncateTable, core.SevLabelHigh, []string{"T1485"}, "truncate table %s.%s"},
	} {
		d := d
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-audit-" + d.key, Source: core.SourceOracle,
				Group: "Data Destruction", Name: d.name, Desc: d.desc,
				EventID: d.action, Channel: "audit", Severity: d.sev,
				Mitre:  d.mitre,
				Params: []core.Param{oUser, oSchema, oTable},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", oraUser(c))
				schema := c.P("schema", oraSchema(c))
				table := c.P("table", oraTable(c))
				return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
					objectRecord(c, user, d.action, rcSuccess, schema, table,
						fmt.Sprintf(d.sql, schema, table)))
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-noaudit", Source: core.SourceOracle,
			Group: "Defense Evasion", Name: "Auditing disabled",
			Desc:     "ACTION 105. Turning auditing off is the database equivalent of clearing the event log, and the record of it is the last one you get.",
			EventID:  actSystemNoaudit, Channel: "audit", Severity: core.SevLabelCritical,
			Mitre:  []string{"T1562"},
			Params: []core.Param{param("actor", "Acting account", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", oraPrivUser(c))
			what := c.Pick("ALL", "SELECT TABLE", "CREATE SESSION", "GRANT ANY PRIVILEGE")
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevCrit,
				objectRecord(c, actor, actSystemNoaudit, rcSuccess, "SYS", "AUDIT_POLICY",
					fmt.Sprintf("noaudit %s", what)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-audit-alter-system", Source: core.SourceOracle,
			Group: "Defense Evasion", Name: "ALTER SYSTEM executed",
			Desc:     "ACTION 49. Instance-level parameter changes can disable auditing, relocate trace files or open network access.",
			EventID:  actAlterSystem, Channel: "audit", Severity: core.SevLabelHigh,
			Mitre:  []string{"T1562"},
			Params: []core.Param{param("actor", "Acting account", "auto"), param("parameter", "Parameter", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			actor := c.P("actor", oraPrivUser(c))
			p := c.P("parameter", c.Pick(
				"audit_trail=none scope=spfile",
				"audit_sys_operations=false scope=spfile",
				"remote_os_authent=true scope=spfile",
				"utl_file_dir='*' scope=spfile"))
			return oraclePayload(c, "Oracle Audit", c.PID(), core.SevWarning,
				objectRecord(c, actor, actAlterSystem, rcSuccess, "SYS", "SPFILE",
					fmt.Sprintf("alter system set %s", p)))
		},
	})
}

// ---------------------------------------------------------------------------
// Unified audit trail (12c+)
// ---------------------------------------------------------------------------

// unifiedRecord builds an "Oracle Unified Audit" record. Field order follows
// captured records: LENGTH, TYPE, DBID, SESID, CLIENTID, ENTRYID, STMTID,
// DBUSER, CURUSER, ACTION, RETCODE, SCHEMA, OBJNAME, PDB_GUID.
func unifiedRecord(c *core.Ctx, user, action, retCode, schema, object string) string {
	return unifiedAudit(
		unifiedField("TYPE", "4"),
		unifiedField("DBID", oraDBID(c)),
		unifiedField("SESID", fmt.Sprint(c.Int(100000000, 4000000000))),
		unifiedField("CLIENTID", ""),
		unifiedField("ENTRYID", "1"),
		unifiedField("STMTID", "1"),
		unifiedField("DBUSER", user),
		unifiedField("CURUSER", user),
		unifiedField("ACTION", action),
		unifiedField("RETCODE", retCode),
		unifiedField("SCHEMA", schema),
		unifiedField("OBJNAME", object),
		unifiedField("PDB_GUID", strings.ToUpper(strings.ReplaceAll(strings.Trim(c.GUID(), "{}"), "-", ""))),
	)
}

func registerOracleUnifiedAudit() {
	for _, u := range []struct {
		key, name, desc, action, rc, sev string
		mitre                            []string
	}{
		{"logon", "Unified audit: logon",
			"ACTION 100 in the unified format. Use this when the database has been migrated to unified auditing, where AUDIT_SYSLOG_LEVEL no longer applies.",
			actLogon, rcSuccess, core.SevLabelInfo, []string{"T1078"}},
		{"logon-failed", "Unified audit: logon failed",
			"RETCODE 1017 in the unified format. Burst it to simulate brute force.",
			actLogon, rcBadCredential, core.SevLabelMedium, []string{"T1110"}},
		{"logoff-cleanup", "Unified audit: logoff by cleanup",
			"ACTION 102, emitted when PMON cleans up a session that did not disconnect properly.",
			actLogoffCleanup, rcSuccess, core.SevLabelInfo, nil},
	} {
		u := u
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-unified-" + u.key, Source: core.SourceOracle,
				Group: "Unified Audit", Name: u.name, Desc: u.desc,
				EventID: u.action, Channel: "unified", Severity: u.sev,
				Mitre:  u.mitre,
				Params: []core.Param{oUser},
			},
			Build: func(c *core.Ctx) core.Payload {
				user := c.P("user", oraUser(c))
				sev := core.SevInfo
				if u.rc != rcSuccess {
					sev = core.SevWarning
				}
				return oraclePayload(c, "Oracle Unified Audit", c.PID(), sev,
					unifiedRecord(c, user, u.action, u.rc, "", ""))
			},
		})
	}

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-unified-object-access", Source: core.SourceOracle,
			Group: "Unified Audit", Name: "Unified audit: object access",
			Desc:     "A unified record naming the schema and object, which is where SCHEMA and OBJNAME are populated rather than empty.",
			EventID:  actSelect, Channel: "unified", Severity: core.SevLabelMedium,
			Mitre:  []string{"T1005"},
			Params: []core.Param{oUser, oSchema, oTable},
		},
		Build: func(c *core.Ctx) core.Payload {
			user := c.P("user", oraUser(c))
			schema := c.P("schema", oraSchema(c))
			table := c.P("table", oraTable(c))
			return oraclePayload(c, "Oracle Unified Audit", c.PID(), core.SevNotice,
				unifiedRecord(c, user, actSelect, rcSuccess, schema, table))
		},
	})
}

// ---------------------------------------------------------------------------
// Listener log
// ---------------------------------------------------------------------------

// listenerTime renders the uppercase DD-MON-YYYY stamp the listener log uses.
func listenerTime(c *core.Ctx) string {
	return strings.ToUpper(c.Now.Format("02-Jan-2006 15:04:05"))
}

// connectRecord builds a listener connection line. The documented layout is
// Timestamp * Connect Data * Protocol Info * Event * Service * Return Code,
// with any TNS error text on the following line.
func connectRecord(c *core.Ctx, program, user, service, srcIP string, port int, returnCode string) string {
	return fmt.Sprintf(
		"%s * (CONNECT_DATA=(CID=(PROGRAM=%s)(HOST=%s)(USER=%s))(SERVICE_NAME=%s)) * "+
			"(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)) * establish * %s * %s",
		listenerTime(c), program, c.Env.DBHost, user, service, srcIP, port, service, returnCode)
}

func registerOracleListener() {
	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-listener-connect", Source: core.SourceOracle,
			Group: "Listener", Name: "Listener connection established",
			Desc:     "A successful TNS connection, return code 0. The CONNECT_DATA block names the client program, which is the most useful field here.",
			Channel:  "listener", Severity: core.SevLabelInfo,
			Params: []core.Param{oUser, oSrcIP, param("program", "Client program", "auto")},
		},
		Build: func(c *core.Ctx) core.Payload {
			return oraclePayload(c, "oracle_listener", 0, core.SevInfo,
				connectRecord(c,
					c.P("program", c.PickFrom(oraPrograms)),
					c.P("user", strings.ToLower(oraUser(c))),
					c.Env.DBName,
					c.P("srcip", c.InternalIP()),
					c.EphemeralPort(), "0"))
		},
	})

	for _, l := range []struct {
		key, name, desc, code, text, sev string
		mitre                            []string
		// anonymous marks the cases where the client never supplied usable
		// connect data, which the listener records as "<unknown connect data>"
		// rather than an empty CONNECT_DATA block.
		anonymous bool
	}{
		{"unknown-service", "Listener: unknown service requested",
			"Return code 12514. A client asked for a service the listener does not serve — a misconfiguration, or somebody guessing service names.",
			"12514", "TNS-12514: TNS:listener does not currently know of service requested in connect descriptor",
			core.SevLabelMedium, []string{"T1046"}, false},
		{"no-connect-data", "Listener: no CONNECT_DATA received",
			"Return code 12502. The client opened a TNS session and sent nothing usable, which is what a port scanner produces.",
			"12502", "TNS-12502: TNS:listener received no CONNECT_DATA from client",
			core.SevLabelMedium, []string{"T1046"}, true},
		{"request-timeout", "Listener: client request timed out",
			"Return code 12525. The client connected and then stalled, holding a listener slot.",
			"12525", "TNS-12525: TNS:listener has not received client's request in time allowed",
			core.SevLabelMedium, nil, true},
		{"auth-failed", "Listener: user authentication failed",
			"Return code 1189. A failed attempt to authenticate to the listener itself, which normally only administrators do.",
			"1189", "TNS-01189: The listener could not authenticate the user",
			core.SevLabelHigh, []string{"T1110"}, false},
	} {
		l := l
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-listener-" + l.key, Source: core.SourceOracle,
				Group: "Listener", Name: l.name, Desc: l.desc,
				EventID: l.code, Channel: "listener", Severity: l.sev,
				Mitre:  l.mitre,
				Params: []core.Param{oSrcIP},
			},
			Build: func(c *core.Ctx) core.Payload {
				ip := c.P("srcip", c.ExternalIP())

				var rec string
				if l.anonymous {
					rec = fmt.Sprintf(
						"%s * <unknown connect data> * (ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)) * establish * <unknown sid> * %s",
						listenerTime(c), ip, c.EphemeralPort(), l.code)
				} else {
					rec = connectRecord(c,
						c.PickFrom(oraPrograms),
						strings.ToLower(oraUser(c)),
						c.Env.DBName, ip, c.EphemeralPort(), l.code)
				}

				// The listener writes the TNS error text on the line after the
				// connection record.
				return oraclePayload(c, "oracle_listener", 0, core.SevWarning,
					rec+"\n"+l.text)
			},
		})
	}

	for _, s := range []struct {
		key, name, desc, event, code, sev string
	}{
		{"service-register", "Listener: service registered",
			"An instance registered itself with the listener. Routine, and the baseline for noticing when one stops.",
			"service_register", "0", core.SevLabelInfo},
		{"service-died", "Listener: service died",
			"Return code 12537. The instance stopped answering the listener, which is either a crash or a shutdown nobody announced.",
			"service_died", "12537", core.SevLabelHigh},
	} {
		s := s
		Register(core.Definition{
			Control: core.Control{
				ID: "oracle-listener-" + s.key, Source: core.SourceOracle,
				Group: "Listener", Name: s.name, Desc: s.desc,
				Channel: "listener", Severity: s.sev,
			},
			Build: func(c *core.Ctx) core.Payload {
				sev := core.SevInfo
				if s.code != "0" {
					sev = core.SevErr
				}
				return oraclePayload(c, "oracle_listener", 0, sev,
					fmt.Sprintf("%s * %s * %s * %s",
						listenerTime(c), s.event, strings.ToLower(c.Env.DBName), s.code))
			},
		})
	}
}

// ---------------------------------------------------------------------------
// Alert log
// ---------------------------------------------------------------------------

// alertTime renders the ISO-8601 stamp with microseconds that 12.2+ alert logs
// use to open every record.
func alertTime(c *core.Ctx) string {
	return c.Now.Format("2006-01-02T15:04:05.000000-07:00")
}

// alertRecord joins the timestamp line and the message body the way the alert
// log writes them.
//
// A shipper that forwards the file line by line would send these as separate
// syslog messages; one that joins on the timestamp, as Oracle alert-log
// multiline patterns normally do, sends the whole record. This emits the whole
// record, which the sender then flattens onto one line.
func alertRecord(c *core.Ctx, body ...string) string {
	return alertTime(c) + "\n" + strings.Join(body, "\n")
}

func registerOracleAlert() {
	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-alert-startup", Source: core.SourceOracle,
			Group: "Alert Log", Name: "Instance startup",
			Desc:     "The instance started. Unscheduled restarts are worth alerting on, since a restart reloads parameters an attacker may have changed.",
			Channel:  "alert", Severity: core.SevLabelMedium,
		},
		Build: func(c *core.Ctx) core.Payload {
			return oraclePayload(c, "oracle_alert", 0, core.SevNotice,
				alertRecord(c,
					fmt.Sprintf("Starting ORACLE instance (normal) (OS id: %d)", c.PID()),
					"Completed: ALTER DATABASE OPEN"))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-alert-shutdown", Source: core.SourceOracle,
			Group: "Alert Log", Name: "Instance shutdown",
			Desc:     "The instance stopped. An unexplained shutdown takes the audit trail down with it.",
			Channel:  "alert", Severity: core.SevLabelHigh,
			Mitre:    []string{"T1489"},
		},
		Build: func(c *core.Ctx) core.Payload {
			return oraclePayload(c, "oracle_alert", 0, core.SevWarning,
				alertRecord(c, fmt.Sprintf("Instance shutdown complete (OS id: %d)", c.PID())))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-alert-ora600", Source: core.SourceOracle,
			Group: "Alert Log", Name: "ORA-00600 internal error",
			Desc:     "An internal error with a trace file and incident number. Repeated ORA-00600 is instability, and occasionally the visible edge of an exploit attempt.",
			EventID:  "ORA-00600", Channel: "alert", Severity: core.SevLabelHigh,
		},
		Build: func(c *core.Ctx) core.Payload {
			incident := c.Int(10000, 99999)
			pid := c.PID()
			trace := fmt.Sprintf("/opt/oracle/diag/rdbms/%s/%s/trace/%s_j000_%d.trc",
				strings.ToLower(c.Env.DBName), c.Env.DBName, c.Env.DBName, pid)
			return oraclePayload(c, "oracle_alert", 0, core.SevErr,
				alertRecord(c,
					fmt.Sprintf("Errors in file %s  (incident=%d):", trace, incident),
					"ORA-00600: internal error code, arguments: [kdsgrp1], [], [], [], [], [], [], [], [], [], [], []",
					fmt.Sprintf("Incident details in: /opt/oracle/diag/rdbms/%s/%s/incident/incdir_%d/%s_j000_%d_i%d.trc",
						strings.ToLower(c.Env.DBName), c.Env.DBName, incident, c.Env.DBName, pid, incident)))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-alert-ora1555", Source: core.SourceOracle,
			Group: "Alert Log", Name: "ORA-01555 snapshot too old",
			Desc:     "A long-running query outlived its undo. Usually a tuning problem, but a sudden cluster can mean somebody is running very large unplanned reads.",
			EventID:  "ORA-01555", Channel: "alert", Severity: core.SevLabelMedium,
		},
		Build: func(c *core.Ctx) core.Payload {
			return oraclePayload(c, "oracle_alert", 0, core.SevWarning,
				alertRecord(c,
					fmt.Sprintf("ORA-01555: snapshot too old: rollback segment number %d with name \"_SYSSMU%d_%d$\" too small",
						c.Int(1, 30), c.Int(1, 30), c.Int(100000000, 999999999))))
		},
	})

	Register(core.Definition{
		Control: core.Control{
			ID: "oracle-alert-ni-connect-error", Source: core.SourceOracle,
			Group: "Alert Log", Name: "Fatal NI connect error",
			Desc:     "A network-layer connection failure recorded against the instance, with the client address that caused it.",
			EventID:  "TNS-12537", Channel: "alert", Severity: core.SevLabelMedium,
			Mitre: []string{"T1046"},
			Params: []core.Param{oSrcIP},
		},
		Build: func(c *core.Ctx) core.Payload {
			ip := c.P("srcip", c.ExternalIP())
			return oraclePayload(c, "oracle_alert", 0, core.SevWarning,
				alertRecord(c,
					"Fatal NI connect error 12537, connecting to:",
					fmt.Sprintf(" %s", oraClientAddress(ip, c.EphemeralPort())),
					"  Tns error struct:",
					"    ns main err code: 12537",
					"TNS-12537: TNS:connection closed",
					"    ns secondary err code: 12560",
					"    nt main err code: 507",
					"TNS-00507: Connection closed",
					fmt.Sprintf("opiodr aborting process unknown ospid (%d) as a result of ORA-609", c.PID())))
		},
	})
}

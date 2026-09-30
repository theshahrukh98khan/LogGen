package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// AWS CloudTrail controls.
//
// CloudTrail is not a syslog source. A trail writes gzipped JSON files to S3,
// each holding a {"Records":[ ... ]} array of Record objects, and every shipper
// that forwards CloudTrail to a SIEM forwards one Record per line as bare JSON.
// These controls therefore render a single Record object, compacted onto one
// line, and mark the payload Raw so the sender emits it with no syslog header
// at all. A "<PRI>Mmm dd ..." prefix in front of "{" is the usual reason a JSON
// decoder drops a CloudTrail record, so the header is never added.
//
// Sources, all AWS's own documentation:
//
//	https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
//	https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
//	https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html
//	https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
//
// CONFIRMED against those pages, field by field:
//
//   - The top-level record fields and their exact spelling: eventVersion,
//     userIdentity, eventTime, eventSource, eventName, awsRegion,
//     sourceIPAddress, userAgent, errorCode, errorMessage, requestParameters,
//     responseElements, additionalEventData, requestID (capital ID),
//     eventID (lower d), readOnly, eventType, managementEvent,
//     recipientAccountId, eventCategory, resources, tlsDetails and
//     sessionCredentialFromConsole. Note the deliberate inconsistency AWS ships
//     with: "requestID" and "recipientAccountId" do not capitalise the same
//     way, and parsers that normalise them break.
//   - Field order. The records below follow the order AWS prints in its own
//     examples: errorCode and errorMessage sit between userAgent and
//     requestParameters; additionalEventData sits after responseElements;
//     requestID precedes eventID; tlsDetails and sessionCredentialFromConsole
//     come last.
//   - eventTime is UTC in "2006-01-02T15:04:05Z"; sessionContext creationDate
//     uses the same extended form in the current examples.
//   - eventVersion 1.09 is what AWS's current error-code example carries; the
//     reference page states the current version is 1.11.
//   - eventType values AwsApiCall, AwsConsoleSignIn and AwsServiceEvent, and
//     eventCategory "Management".
//   - The userIdentity shapes for Root, IAMUser and AssumedRole, including the
//     empty "sessionIssuer": {} and "webIdFederationData": {} objects that AWS
//     emits for an IAM user session, and the populated sessionIssuer for an
//     assumed role. mfaAuthenticated is the *string* "true"/"false", not a
//     boolean; so is sessionCredentialFromConsole.
//   - Console sign-in: eventSource "signin.amazonaws.com", eventName
//     "ConsoleLogin", requestParameters null, responseElements
//     {"ConsoleLogin":"Success"|"Failure"}, additionalEventData carrying
//     LoginTo, MobileVersion, MFAUsed and, when MFA was used, MFAIdentifier,
//     and errorMessage "Failed authentication" on a failure. Sign-in records
//     carry no requestID, which is reproduced here.
//   - The failed-call shape, from the UpdateTrail/TrailNotFoundException
//     example: errorCode and errorMessage present, responseElements null.
//   - requestParameters and responseElements for CreateUser, AddUserToGroup,
//     CreateRole, EnableMFADevice, StartInstances, StopInstances and
//     CreateKeyPair, which are quoted verbatim on the pages above.
//
// INFERRED, and worth checking against a live trail before a decoder is
// written against them:
//
//   - The requestParameters and responseElements bodies for the APIs AWS does
//     not print a CloudTrail example for: CreateAccessKey, CreateLoginProfile,
//     AttachUserPolicy, PutUserPolicy, UpdateAssumeRolePolicy,
//     DeactivateMFADevice, StopLogging, DeleteTrail, UpdateTrail,
//     DeleteDetector, StopConfigurationRecorder, ScheduleKeyDeletion,
//     DeleteFlowLogs, PutBucketPolicy, PutBucketAcl,
//     DeletePublicAccessBlock, AuthorizeSecurityGroupIngress,
//     ModifySnapshotAttribute, AssumeRole and RunInstances. The key names come
//     from each service's own API reference, lower-camel-cased the way
//     CloudTrail records them, and the nested EC2 "items" wrapper is the shape
//     corroborated by published Athena queries against real CloudTrail data
//     (requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp).
//   - The S3 requestParameters convention of carrying "Host" and an empty
//     subresource marker alongside bucketName. AWS documents that S3 records
//     carry bucketName and Host; the subresource marker is inferred.
//   - AccessDenied error messages. The wording AWS returns changes between
//     services and over time, so these are representative rather than exact.
//   - No Wazuh rule IDs are claimed. Wazuh decodes CloudTrail through its own
//     AWS module rather than through syslog, so asserting rule numbers here
//     would be a guess.
//
// The AWS account ID is derived from the estate's domain so every record in a
// run agrees on it, and can be overridden per control.

const (
	ctEventVersion = "1.11"
	ctTypeAPICall  = "AwsApiCall"
	ctTypeSignIn   = "AwsConsoleSignIn"
)

// ---------------------------------------------------------------------------
// Ordered JSON
// ---------------------------------------------------------------------------

// CloudTrail records have a conventional field order, and a Go map does not
// preserve one. ctObj is an ordered object so the rendered record reads the way
// AWS prints it.
type ctObj []ctKV

// ctKV is one key/value pair in an ordered object.
type ctKV struct {
	K string
	V any
}

func ctkv(k string, v any) ctKV { return ctKV{K: k, V: v} }

// MarshalJSON renders the pairs in declaration order.
func (o ctObj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, p := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := ctMarshal(p.K)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		v, err := ctMarshal(p.V)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// ctMarshal encodes without HTML escaping. CloudTrail writes "&" and "<" in
// console LoginTo URLs and in policy documents literally; encoding/json's
// default would turn them into & and <, which no real record shows.
func ctMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// ctRender compacts a record onto one line.
func ctRender(o ctObj) string {
	b, err := ctMarshal(o)
	if err != nil {
		return `{"error":"cloudtrail render failed"}`
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

// ctIDAlphabet is the uppercase base32 alphabet AWS unique identifiers and
// access key IDs are drawn from.
const ctIDAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// ctUniqueID returns an AWS unique identifier such as AIDA... for a user or
// AROA... for a role. They are 21 characters including the four-letter prefix.
func ctUniqueID(c *core.Ctx, prefix string) string { return prefix + ctRandID(c, 17) }

// ctAccessKey returns a long-term (AKIA) or temporary (ASIA) access key ID.
// Access key IDs are 20 characters including the prefix.
func ctAccessKey(c *core.Ctx, temporary bool) string {
	prefix := "AKIA"
	if temporary {
		prefix = "ASIA"
	}
	return prefix + ctRandID(c, 16)
}

func ctRandID(c *core.Ctx, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ctIDAlphabet[c.Rand().Intn(len(ctIDAlphabet))]
	}
	return string(b)
}

// ctUUID returns a lowercase version 4 UUID, the form eventID and requestID
// take. The variant and version nibbles are fixed because a rule that filters
// on them would otherwise never match a generated record.
func ctUUID(c *core.Ctx) string {
	return fmt.Sprintf("%s-%s-4%s-%s%s-%s",
		c.HexLower(8), c.HexLower(4), c.HexLower(3),
		string("89ab"[c.Rand().Intn(4)]), c.HexLower(3), c.HexLower(12))
}

// ctAccount derives a stable twelve-digit AWS account ID from the estate's
// domain, so every CloudTrail record in a run names the same account.
func ctAccount(c *core.Ctx) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(c.Env.Domain)))
	return strconv.FormatUint(h.Sum64()%900000000000+100000000000, 10)
}

// ctTime renders an ISO 8601 UTC timestamp in CloudTrail's form.
func ctTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ctBoolStr renders the string booleans CloudTrail uses for mfaAuthenticated.
func ctBoolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ctSvcHost is the clientProvidedHostHeader for a service endpoint. IAM and
// STS are global, so their endpoints carry no Region.
func ctSvcHost(service, region string) string {
	switch service {
	case "iam", "sts":
		return service + ".amazonaws.com"
	default:
		return service + "." + region + ".amazonaws.com"
	}
}

// ctCLIAgent renders the userAgent the AWS CLI reports, in the shape AWS's own
// examples show, including the trailing "command/<service>.<operation>".
func ctCLIAgent(command string) string {
	return "aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 " +
		"exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/" + command
}

// ctConsoleLoginTo builds the LoginTo URL additionalEventData carries.
func ctConsoleLoginTo(c *core.Ctx, region string) string {
	return "https://console.aws.amazon.com/console/home?hashArgs=%23&isauthcode=true" +
		"&state=hashArgsFromTB_" + region + "_" + c.HexLower(12)
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

// ctSession builds the sessionContext block an IAM user or root session
// carries when the call was made from the console.
func ctSession(c *core.Ctx, mfa bool) ctObj {
	return ctObj{
		ctkv("sessionIssuer", ctObj{}),
		ctkv("webIdFederationData", ctObj{}),
		ctkv("attributes", ctObj{
			ctkv("creationDate", ctTime(c.Now.Add(-time.Duration(c.Int(5, 120))*time.Minute))),
			ctkv("mfaAuthenticated", ctBoolStr(mfa)),
		}),
	}
}

// ctRootIdentity is the userIdentity for the account root user. principalId is
// the account number itself, which is how a root call is spotted.
func ctRootIdentity(c *core.Ctx, account, accessKey string, session bool, mfa bool) ctObj {
	id := ctObj{
		ctkv("type", "Root"),
		ctkv("principalId", account),
		ctkv("arn", "arn:aws:iam::"+account+":root"),
		ctkv("accountId", account),
		ctkv("accessKeyId", accessKey),
	}
	if session {
		id = append(id, ctkv("sessionContext", ctSession(c, mfa)))
	}
	return id
}

// ctUserIdentity is the userIdentity for a long-lived IAM user.
func ctUserIdentity(c *core.Ctx, account, user, accessKey string, session bool, mfa bool) ctObj {
	id := ctObj{
		ctkv("type", "IAMUser"),
		ctkv("principalId", ctUniqueID(c, "AIDA")),
		ctkv("arn", "arn:aws:iam::"+account+":user/"+user),
		ctkv("accountId", account),
		ctkv("accessKeyId", accessKey),
		ctkv("userName", user),
	}
	if session {
		id = append(id, ctkv("sessionContext", ctSession(c, mfa)))
	}
	return id
}

// ctRoleIdentity is the userIdentity for temporary credentials obtained by
// assuming a role. The role's unique id is generated once and reused in both
// principalId and sessionIssuer.principalId, because a record where those two
// disagree is not a record any real trail produces.
func ctRoleIdentity(c *core.Ctx, account, role, sessionName, accessKey string, mfa bool) ctObj {
	roleID := ctUniqueID(c, "AROA")
	return ctObj{
		ctkv("type", "AssumedRole"),
		ctkv("principalId", roleID+":"+sessionName),
		ctkv("arn", "arn:aws:sts::"+account+":assumed-role/"+role+"/"+sessionName),
		ctkv("accountId", account),
		ctkv("accessKeyId", accessKey),
		ctkv("sessionContext", ctObj{
			ctkv("sessionIssuer", ctObj{
				ctkv("type", "Role"),
				ctkv("principalId", roleID),
				ctkv("arn", "arn:aws:iam::"+account+":role/"+role),
				ctkv("accountId", account),
				ctkv("userName", role),
			}),
			ctkv("webIdFederationData", ctObj{}),
			ctkv("attributes", ctObj{
				ctkv("creationDate", ctTime(c.Now.Add(-time.Duration(c.Int(5, 120))*time.Minute))),
				ctkv("mfaAuthenticated", ctBoolStr(mfa)),
			}),
		}),
	}
}

// ---------------------------------------------------------------------------
// Record assembly
// ---------------------------------------------------------------------------

// ctSpec is one record to render.
type ctSpec struct {
	identity  ctObj
	source    string // eventSource, e.g. iam.amazonaws.com
	name      string // eventName
	region    string
	srcIP     string
	userAgent string
	account   string // recipientAccountId

	errorCode  string
	errorMsg   string
	request    any // requestParameters; nil renders as null
	response   any // responseElements;  nil renders as null
	additional ctObj
	resources  []any

	requestID string // reuse when responseElements repeats it; blank generates one
	readOnly  bool
	eventType string
	host      string // clientProvidedHostHeader; blank omits tlsDetails
	console   bool   // sessionCredentialFromConsole
}

// ctRecord renders one CloudTrail Record in AWS's own field order.
func ctRecord(c *core.Ctx, s ctSpec) string {
	if s.eventType == "" {
		s.eventType = ctTypeAPICall
	}

	rec := ctObj{
		ctkv("eventVersion", ctEventVersion),
		ctkv("userIdentity", s.identity),
		ctkv("eventTime", ctTime(c.Now)),
		ctkv("eventSource", s.source),
		ctkv("eventName", s.name),
		ctkv("awsRegion", s.region),
		ctkv("sourceIPAddress", s.srcIP),
		ctkv("userAgent", s.userAgent),
	}
	if s.errorCode != "" {
		rec = append(rec, ctkv("errorCode", s.errorCode))
	}
	if s.errorMsg != "" {
		rec = append(rec, ctkv("errorMessage", s.errorMsg))
	}
	rec = append(rec,
		ctkv("requestParameters", s.request),
		ctkv("responseElements", s.response),
	)
	if len(s.additional) > 0 {
		rec = append(rec, ctkv("additionalEventData", s.additional))
	}
	// Console sign-in records carry no requestID.
	if s.eventType != ctTypeSignIn {
		id := s.requestID
		if id == "" {
			id = ctUUID(c)
		}
		rec = append(rec, ctkv("requestID", id))
	}
	rec = append(rec,
		ctkv("eventID", ctUUID(c)),
		ctkv("readOnly", s.readOnly),
		ctkv("eventType", s.eventType),
		ctkv("managementEvent", true),
		ctkv("recipientAccountId", s.account),
	)
	if len(s.resources) > 0 {
		rec = append(rec, ctkv("resources", s.resources))
	}
	rec = append(rec, ctkv("eventCategory", "Management"))
	if s.host != "" {
		rec = append(rec, ctkv("tlsDetails", ctObj{
			ctkv("tlsVersion", "TLSv1.2"),
			ctkv("cipherSuite", "ECDHE-RSA-AES128-GCM-SHA256"),
			ctkv("clientProvidedHostHeader", s.host),
		}))
	}
	if s.console {
		rec = append(rec, ctkv("sessionCredentialFromConsole", "true"))
	}
	return ctRender(rec)
}

// ---------------------------------------------------------------------------
// Payload and registration
// ---------------------------------------------------------------------------

// cloudtrailPayload wraps a rendered record. Raw is set so the sender ships the
// bare JSON object with no syslog header, which is how a CloudTrail forwarder
// delivers it and the only shape a JSON decoder will accept.
func cloudtrailPayload(severity int, record string) core.Payload {
	return core.Payload{
		Kind:     core.SourceAWSCloudTrail,
		Host:     "cloudtrail",
		Facility: core.FacLocal0,
		Severity: severity,
		Message:  record,
		Raw:      true,
	}
}

// ctBase is the per-record context every control needs.
type ctBase struct {
	account string
	region  string
	srcIP   string
	user    string
}

// ctBaseOf resolves the shared parameters once, so a value used twice in a
// record is the same value both times.
func ctBaseOf(c *core.Ctx, external bool) ctBase {
	ip := c.InternalIP()
	if external {
		ip = c.ExternalIP()
	}
	return ctBase{
		account: c.P("account", ctAccount(c)),
		region:  c.P("region", "us-east-1"),
		srcIP:   c.P("srcip", ip),
		user:    c.P("user", c.User()),
	}
}

var (
	ctpAccount = param("account", "AWS account ID", "auto")
	ctpRegion  = param("region", "AWS Region", "us-east-1")
	ctpSrcIP   = param("srcip", "Source IP address", "auto")
	ctpUser    = param("user", "IAM user name", "auto")
)

// ctStdParams is the parameter set nearly every control offers.
func ctStdParams(extra ...core.Param) []core.Param {
	return append([]core.Param{ctpAccount, ctpRegion, ctpSrcIP, ctpUser}, extra...)
}

// ctCase is one registered control.
type ctCase struct {
	id       string
	group    string
	name     string
	desc     string
	event    string // eventName, shown as the control's event id
	source   string // eventSource, shown as the control's channel
	severity string
	sev      int // syslog severity, carried for completeness
	mitre    []string
	params   []core.Param
	build    func(c *core.Ctx) string
}

func registerCT(cs ctCase) {
	Register(core.Definition{
		Control: core.Control{
			ID:       "aws-cloudtrail-" + cs.id,
			Source:   core.SourceAWSCloudTrail,
			Group:    cs.group,
			Name:     cs.name,
			Desc:     cs.desc,
			EventID:  cs.event,
			Channel:  cs.source,
			Severity: cs.severity,
			Mitre:    cs.mitre,
			Params:   cs.params,
		},
		Build: func(c *core.Ctx) core.Payload {
			return cloudtrailPayload(cs.sev, cs.build(c))
		},
	})
}

func init() {
	registerCloudTrailRoot()
	registerCloudTrailSignIn()
	registerCloudTrailIAM()
	registerCloudTrailEvasion()
	registerCloudTrailStorage()
	registerCloudTrailNetwork()
	registerCloudTrailAssumeRole()
	registerCloudTrailDenied()
}

// ---------------------------------------------------------------------------
// Root account activity
// ---------------------------------------------------------------------------

const (
	grpCTRoot     = "Root account"
	grpCTSignIn   = "Console sign-in"
	grpCTIAM      = "IAM identity changes"
	grpCTEvasion  = "Defence evasion"
	grpCTStorage  = "Storage exposure"
	grpCTNetwork  = "Network exposure"
	grpCTAssume   = "Role assumption"
	grpCTDenied   = "Unauthorized API calls"
	signinSource  = "signin.amazonaws.com"
	signinHostFmt = "%s.signin.aws.amazon.com"
)

// ctSignIn renders a ConsoleLogin record. outcome is "Success" or "Failure".
func ctSignIn(c *core.Ctx, identity ctObj, b ctBase, outcome string, mfa bool, mfaARN string) string {
	add := ctObj{
		ctkv("LoginTo", ctConsoleLoginTo(c, b.region)),
		ctkv("MobileVersion", "No"),
	}
	if mfa && mfaARN != "" {
		add = append(add, ctkv("MFAIdentifier", mfaARN))
	}
	add = append(add, ctkv("MFAUsed", map[bool]string{true: "Yes", false: "No"}[mfa]))

	spec := ctSpec{
		identity:   identity,
		source:     signinSource,
		name:       "ConsoleLogin",
		region:     b.region,
		srcIP:      b.srcIP,
		userAgent:  c.UserAgent(),
		account:    b.account,
		request:    nil,
		response:   ctObj{ctkv("ConsoleLogin", outcome)},
		additional: add,
		eventType:  ctTypeSignIn,
		host:       fmt.Sprintf(signinHostFmt, b.region),
	}
	if outcome == "Failure" {
		spec.errorMsg = "Failed authentication"
	}
	return ctRecord(c, spec)
}

func registerCloudTrailRoot() {
	registerCT(ctCase{
		id: "root-console-login", group: grpCTRoot,
		name:  "Root console sign-in without MFA",
		desc:  "The account root user signed in to the console with no MFA. Root should not be used at all; without MFA it is an emergency.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctSignIn(c, ctRootIdentity(c, b.account, "", false, false), b, "Success", false, "")
		},
	})

	registerCT(ctCase{
		id: "root-console-login-mfa", group: grpCTRoot,
		name:  "Root console sign-in with MFA",
		desc:  "The account root user signed in with MFA. Legitimate for break-glass work, and still worth an alert every time.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelHigh, sev: core.SevCrit,
		mitre:  []string{"T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctSignIn(c, ctRootIdentity(c, b.account, "", false, false), b,
				"Success", true, "arn:aws:iam::"+b.account+":mfa/root-account-mfa-device")
		},
	})

	registerCT(ctCase{
		id: "root-console-login-failure", group: grpCTRoot,
		name:  "Root console sign-in failure",
		desc:  "A failed authentication against the root user. Repeated failures are a credential stuffing attempt against the account's most privileged identity.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1110.001", "T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctSignIn(c, ctRootIdentity(c, b.account, "", false, false), b, "Failure", false, "")
		},
	})

	registerCT(ctCase{
		id: "root-access-key-created", group: grpCTRoot,
		name:  "Root created an access key",
		desc:  "The root user minted a long-lived access key. Root access keys cannot be scoped and are the classic persistence step after a root compromise.",
		event: "CreateAccessKey", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1098.001", "T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			newKey := ctAccessKey(c, false)
			return ctRecord(c, ctSpec{
				identity:  ctRootIdentity(c, b.account, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "CreateAccessKey",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: c.UserAgent(),
				account:   b.account,
				request:   nil,
				response: ctObj{ctkv("accessKey", ctObj{
					ctkv("accessKeyId", newKey),
					ctkv("status", "Active"),
					ctkv("userName", "root"),
					ctkv("createDate", ctTime(c.Now)),
				})},
				host:    ctSvcHost("iam", b.region),
				console: true,
			})
		},
	})

	registerCT(ctCase{
		id: "root-mfa-deactivated", group: grpCTRoot,
		name:  "Root MFA device deactivated",
		desc:  "The root user's MFA device was removed, which strips the last control on the account's most privileged identity.",
		event: "DeactivateMFADevice", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1556.006", "T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctRecord(c, ctSpec{
				identity:  ctRootIdentity(c, b.account, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "DeactivateMFADevice",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: c.UserAgent(),
				account:   b.account,
				request: ctObj{
					ctkv("userName", "AWS ROOT USER"),
					ctkv("serialNumber", "arn:aws:iam::"+b.account+":mfa/root-account-mfa-device"),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
				console:  true,
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Console sign-in
// ---------------------------------------------------------------------------

func registerCloudTrailSignIn() {
	registerCT(ctCase{
		id: "console-login-mfa", group: grpCTSignIn,
		name:  "IAM user console sign-in with MFA",
		desc:  "A successful console sign-in that used MFA. The baseline a sign-in from a new country or a new user agent is measured against.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelInfo, sev: core.SevInfo,
		mitre:  []string{"T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			id := ctUserIdentity(c, b.account, b.user, "", false, true)
			return ctSignIn(c, id, b, "Success", true, "arn:aws:iam::"+b.account+":mfa/"+b.user)
		},
	})

	registerCT(ctCase{
		id: "console-login-no-mfa", group: grpCTSignIn,
		name:  "IAM user console sign-in without MFA",
		desc:  "A successful console sign-in with no second factor, which is a policy violation in most estates and the shape a stolen password produces.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelMedium, sev: core.SevWarning,
		mitre:  []string{"T1078.004"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctSignIn(c, ctUserIdentity(c, b.account, b.user, "", false, false), b, "Success", false, "")
		},
	})

	registerCT(ctCase{
		id: "console-login-failure", group: grpCTSignIn,
		name:  "IAM user console sign-in failure",
		desc:  "A failed console authentication. Counted per user and per source address, this is the password spray detection.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelMedium, sev: core.SevWarning,
		mitre:  []string{"T1110.003"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			// A failed sign-in carries no arn, and an empty accessKeyId.
			id := ctObj{
				ctkv("type", "IAMUser"),
				ctkv("principalId", ctUniqueID(c, "AIDA")),
				ctkv("accountId", b.account),
				ctkv("accessKeyId", ""),
				ctkv("userName", b.user),
			}
			return ctSignIn(c, id, b, "Failure", false, "")
		},
	})

	registerCT(ctCase{
		id: "console-login-federated", group: grpCTSignIn,
		name:  "Federated console sign-in",
		desc:  "A single sign-on user reached the console through an assumed role. mfaAuthenticated is false for federated sessions even when the IdP enforced MFA, which is a common false positive.",
		event: "ConsoleLogin", source: signinSource,
		severity: core.SevLabelInfo, sev: core.SevInfo,
		mitre:  []string{"T1078.004"},
		params: ctStdParams(param("role", "Role name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			role := c.P("role", c.Pick("SSO-Developer", "SSO-ReadOnly", "AWSReservedSSO_AdministratorAccess"))
			id := ctRoleIdentity(c, b.account, role, b.user, ctAccessKey(c, true), false)
			return ctSignIn(c, id, b, "Success", false, "")
		},
	})
}

// ---------------------------------------------------------------------------
// IAM identity changes
// ---------------------------------------------------------------------------

const ctAdminPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

func registerCloudTrailIAM() {
	registerCT(ctCase{
		id: "iam-create-user", group: grpCTIAM,
		name:  "IAM user created",
		desc:  "A new IAM user was created. Outside a provisioning pipeline this is how an intruder makes a second way in.",
		event: "CreateUser", source: "iam.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1136.003"},
		params: ctStdParams(param("target", "New user name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-deploy2", "backup-admin", "ops-temp", "aws-support-tmp"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "CreateUser",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.create-user"),
				account:   b.account,
				request:   ctObj{ctkv("userName", target)},
				response: ctObj{ctkv("user", ctObj{
					ctkv("path", "/"),
					ctkv("arn", "arn:aws:iam::"+b.account+":user/"+target),
					ctkv("userId", ctUniqueID(c, "AIDA")),
					ctkv("createDate", c.Now.UTC().Format("Jan 2, 2006 3:04:05 PM")),
					ctkv("userName", target),
				})},
				host: ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-create-access-key", group: grpCTIAM,
		name:  "Access key created for an IAM user",
		desc:  "A long-lived access key was issued. Creating a key for an account other than your own is the standard persistence move after a console compromise.",
		event: "CreateAccessKey", source: "iam.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1098.001"},
		params: ctStdParams(param("target", "Key owner", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-deploy2", "backup-admin", "ops-temp"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "CreateAccessKey",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.create-access-key"),
				account:   b.account,
				request:   ctObj{ctkv("userName", target)},
				response: ctObj{ctkv("accessKey", ctObj{
					ctkv("accessKeyId", ctAccessKey(c, false)),
					ctkv("status", "Active"),
					ctkv("userName", target),
					ctkv("createDate", ctTime(c.Now)),
				})},
				host: ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-create-login-profile", group: grpCTIAM,
		name:  "Console password set on an IAM user",
		desc:  "CreateLoginProfile gave console access to an account that previously had only programmatic access, a well-known privilege escalation path.",
		event: "CreateLoginProfile", source: "iam.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1098"},
		params: ctStdParams(param("target", "Target user", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-sql", "svc-backup", "ci-runner"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "CreateLoginProfile",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.create-login-profile"),
				account:   b.account,
				request: ctObj{
					ctkv("userName", target),
					ctkv("passwordResetRequired", false),
				},
				response: ctObj{ctkv("loginProfile", ctObj{
					ctkv("userName", target),
					ctkv("createDate", ctTime(c.Now)),
					ctkv("passwordResetRequired", false),
				})},
				host: ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-attach-admin-policy", group: grpCTIAM,
		name:  "AdministratorAccess attached to a user",
		desc:  "AttachUserPolicy bound the AWS-managed AdministratorAccess policy to a user. This is full control of the account in one API call.",
		event: "AttachUserPolicy", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1098.003"},
		params: ctStdParams(param("target", "Target user", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-deploy2", "ops-temp", "backup-admin"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "AttachUserPolicy",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.attach-user-policy"),
				account:   b.account,
				request: ctObj{
					ctkv("userName", target),
					ctkv("policyArn", ctAdminPolicyARN),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-put-user-policy-wildcard", group: grpCTIAM,
		name:  "Inline policy granting Action *",
		desc:  "PutUserPolicy wrote an inline policy allowing every action on every resource. Inline policies are easy to miss in a permissions review, which is why they are used.",
		event: "PutUserPolicy", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1098.003"},
		params: ctStdParams(param("target", "Target user", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-deploy2", "ops-temp", "ci-runner"))
			doc := `{"Version":"2012-10-17","Statement":[{"Sid":"FullAccess","Effect":"Allow","Action":"*","Resource":"*"}]}`
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "PutUserPolicy",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.put-user-policy"),
				account:   b.account,
				request: ctObj{
					ctkv("userName", target),
					ctkv("policyName", "inline-admin"),
					ctkv("policyDocument", doc),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-update-assume-role-policy", group: grpCTIAM,
		name:  "Role trust policy widened",
		desc:  "UpdateAssumeRolePolicy rewrote a role's trust document so another principal can assume it. The privilege escalation that leaves no trace in the role's attached policies.",
		event: "UpdateAssumeRolePolicy", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1098.003"},
		params: ctStdParams(param("role", "Role name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			role := c.P("role", c.Pick("OrganizationAccountAccessRole", "DeploymentRole", "EC2AdminRole"))
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` +
				fmt.Sprintf("%d", c.Int(100000000000, 999999999999)) +
				`:root"},"Action":"sts:AssumeRole"}]}`
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "UpdateAssumeRolePolicy",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.update-assume-role-policy"),
				account:   b.account,
				request: ctObj{
					ctkv("roleName", role),
					ctkv("policyDocument", doc),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-add-user-to-admin-group", group: grpCTIAM,
		name:  "User added to an administrators group",
		desc:  "AddUserToGroup put an account into a group that carries administrative policies. Same outcome as attaching the policy, different API.",
		event: "AddUserToGroup", source: "iam.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1098.003"},
		params: ctStdParams(param("target", "Target user", "auto"), param("group", "Group name", "Admin")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			target := c.P("target", c.Pick("svc-deploy2", "ops-temp", "backup-admin"))
			group := c.P("group", "Admin")
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "AddUserToGroup",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.add-user-to-group"),
				account:   b.account,
				request: ctObj{
					ctkv("groupName", group),
					ctkv("userName", target),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "iam-create-cross-account-role", group: grpCTIAM,
		name:  "Role created trusting an external account",
		desc:  "CreateRole with a trust policy naming an AWS account that is not yours. Persistent cross-account access that survives password and key rotation.",
		event: "CreateRole", source: "iam.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1098.003", "T1136.003"},
		params: ctStdParams(param("role", "Role name", "auto"), param("external", "External account ID", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			role := c.P("role", c.Pick("SupportAccessRole", "ThirdPartyAudit", "vendor-access"))
			external := c.P("external", fmt.Sprintf("%d", c.Int(100000000000, 999999999999)))
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` +
				external + `:root"},"Action":["sts:AssumeRole"]}]}`
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "iam.amazonaws.com",
				name:      "CreateRole",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.create-role"),
				account:   b.account,
				request: ctObj{
					ctkv("roleName", role),
					ctkv("description", "Third party access"),
					ctkv("assumeRolePolicyDocument", doc),
				},
				response: ctObj{ctkv("role", ctObj{
					ctkv("assumeRolePolicyDocument", doc),
					ctkv("arn", "arn:aws:iam::"+b.account+":role/"+role),
					ctkv("roleId", ctUniqueID(c, "AROA")),
					ctkv("createDate", c.Now.UTC().Format("Jan 2, 2006 3:04:05 PM")),
					ctkv("roleName", role),
					ctkv("path", "/"),
				})},
				host: ctSvcHost("iam", b.region),
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Defence evasion
// ---------------------------------------------------------------------------

func registerCloudTrailEvasion() {
	registerCT(ctCase{
		id: "stop-logging", group: grpCTEvasion,
		name:  "CloudTrail logging stopped",
		desc:  "StopLogging suspended delivery for a trail. Everything after this call is invisible, so it is the single highest value CloudTrail alert.",
		event: "StopLogging", source: "cloudtrail.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1562.008"},
		params: ctStdParams(param("trail", "Trail name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			trail := c.P("trail", c.Pick("org-trail", "management-events", "security-audit-trail"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "cloudtrail.amazonaws.com",
				name:      "StopLogging",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("cloudtrail.stop-logging"),
				account:   b.account,
				request: ctObj{
					ctkv("name", "arn:aws:cloudtrail:"+b.region+":"+b.account+":trail/"+trail),
				},
				response: nil,
				host:     ctSvcHost("cloudtrail", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "delete-trail", group: grpCTEvasion,
		name:  "CloudTrail trail deleted",
		desc:  "DeleteTrail removed the trail entirely. Louder than StopLogging and just as final.",
		event: "DeleteTrail", source: "cloudtrail.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1562.008"},
		params: ctStdParams(param("trail", "Trail name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			trail := c.P("trail", c.Pick("org-trail", "management-events", "security-audit-trail"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "cloudtrail.amazonaws.com",
				name:      "DeleteTrail",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("cloudtrail.delete-trail"),
				account:   b.account,
				request: ctObj{
					ctkv("name", "arn:aws:cloudtrail:"+b.region+":"+b.account+":trail/"+trail),
				},
				response: nil,
				host:     ctSvcHost("cloudtrail", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "update-trail-narrowed", group: grpCTEvasion,
		name:  "Trail narrowed to one Region",
		desc:  "UpdateTrail turned off multi-Region and global service event logging. Quieter than stopping the trail: the trail still reports healthy while activity elsewhere goes unrecorded.",
		event: "UpdateTrail", source: "cloudtrail.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1562.008"},
		params: ctStdParams(param("trail", "Trail name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			trail := c.P("trail", c.Pick("org-trail", "management-events", "security-audit-trail"))
			arn := "arn:aws:cloudtrail:" + b.region + ":" + b.account + ":trail/" + trail
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "cloudtrail.amazonaws.com",
				name:      "UpdateTrail",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("cloudtrail.update-trail"),
				account:   b.account,
				request: ctObj{
					ctkv("name", trail),
					ctkv("isMultiRegionTrail", false),
					ctkv("includeGlobalServiceEvents", false),
				},
				response: ctObj{
					ctkv("name", trail),
					ctkv("trailARN", arn),
					ctkv("includeGlobalServiceEvents", false),
					ctkv("isMultiRegionTrail", false),
					ctkv("logFileValidationEnabled", false),
				},
				host: ctSvcHost("cloudtrail", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "guardduty-detector-deleted", group: grpCTEvasion,
		name:  "GuardDuty detector deleted",
		desc:  "DeleteDetector switched off threat detection for the Region. The account stops producing findings and nothing else changes visibly.",
		event: "DeleteDetector", source: "guardduty.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1562.001"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "guardduty.amazonaws.com",
				name:      "DeleteDetector",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("guardduty.delete-detector"),
				account:   b.account,
				request:   ctObj{ctkv("detectorId", c.HexLower(32))},
				response:  nil,
				host:      ctSvcHost("guardduty", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "config-recorder-stopped", group: grpCTEvasion,
		name:  "AWS Config recorder stopped",
		desc:  "StopConfigurationRecorder halted configuration history. Resource changes made afterwards leave no before-and-after record for an investigation.",
		event: "StopConfigurationRecorder", source: "config.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1562.008"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "config.amazonaws.com",
				name:      "StopConfigurationRecorder",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("configservice.stop-configuration-recorder"),
				account:   b.account,
				request:   ctObj{ctkv("configurationRecorderName", "default")},
				response:  nil,
				host:      ctSvcHost("config", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "kms-schedule-key-deletion", group: grpCTEvasion,
		name:  "KMS key scheduled for deletion",
		desc:  "ScheduleKeyDeletion starts the clock on a customer managed key. When it fires, everything the key encrypted becomes unrecoverable, which is destruction disguised as housekeeping.",
		event: "ScheduleKeyDeletion", source: "kms.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1485"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			keyID := ctUUID(c)
			keyARN := "arn:aws:kms:" + b.region + ":" + b.account + ":key/" + keyID
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "kms.amazonaws.com",
				name:      "ScheduleKeyDeletion",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("kms.schedule-key-deletion"),
				account:   b.account,
				request: ctObj{
					ctkv("keyId", keyARN),
					ctkv("pendingWindowInDays", 7),
				},
				response: ctObj{
					ctkv("keyId", keyARN),
					ctkv("deletionDate", ctTime(c.Now.Add(7*24*time.Hour))),
					ctkv("keyState", "PendingDeletion"),
				},
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::KMS::Key"),
					ctkv("ARN", keyARN),
				}},
				host: ctSvcHost("kms", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "delete-flow-logs", group: grpCTEvasion,
		name:  "VPC flow logs deleted",
		desc:  "DeleteFlowLogs removed network telemetry for a VPC, so lateral movement and exfiltration inside it stop being visible.",
		event: "DeleteFlowLogs", source: "ec2.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1562.008"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			flowLogID := "fl-" + c.HexLower(17)
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "ec2.amazonaws.com",
				name:      "DeleteFlowLogs",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("ec2.delete-flow-logs"),
				account:   b.account,
				request: ctObj{ctkv("FlowLogIdSet", ctObj{
					ctkv("items", []any{ctObj{ctkv("flowLogId", flowLogID)}}),
				})},
				response: ctObj{
					ctkv("requestId", ctUUID(c)),
					ctkv("unsuccessful", ctObj{}),
				},
				host: ctSvcHost("ec2", b.region),
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Storage exposure
// ---------------------------------------------------------------------------

func registerCloudTrailStorage() {
	registerCT(ctCase{
		id: "s3-public-bucket-policy", group: grpCTStorage,
		name:  "S3 bucket policy opened to everyone",
		desc:  "PutBucketPolicy wrote a statement with Principal \"*\", which makes the bucket readable by the internet.",
		event: "PutBucketPolicy", source: "s3.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1530"},
		params: ctStdParams(param("bucket", "Bucket name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			bucket := c.P("bucket", c.Pick("corp-backups", "customer-exports", "finance-reports", "app-artifacts"))
			policy := ctObj{
				ctkv("Version", "2012-10-17"),
				ctkv("Statement", []any{ctObj{
					ctkv("Sid", "PublicRead"),
					ctkv("Effect", "Allow"),
					ctkv("Principal", "*"),
					ctkv("Action", []any{"s3:GetObject"}),
					ctkv("Resource", []any{"arn:aws:s3:::" + bucket + "/*"}),
				}}),
			}
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "s3.amazonaws.com",
				name:      "PutBucketPolicy",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("s3api.put-bucket-policy"),
				account:   b.account,
				request: ctObj{
					ctkv("bucketName", bucket),
					ctkv("Host", bucket+".s3."+b.region+".amazonaws.com"),
					ctkv("policy", ""),
					ctkv("bucketPolicy", policy),
				},
				response: nil,
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::S3::Bucket"),
					ctkv("ARN", "arn:aws:s3:::"+bucket),
				}},
				host: "s3." + b.region + ".amazonaws.com",
			})
		},
	})

	registerCT(ctCase{
		id: "s3-public-bucket-acl", group: grpCTStorage,
		name:  "S3 bucket ACL set to public-read",
		desc:  "PutBucketAcl granted the AllUsers group read access. The older route to a public bucket, and one that bucket policy checks miss.",
		event: "PutBucketAcl", source: "s3.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1530"},
		params: ctStdParams(param("bucket", "Bucket name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			bucket := c.P("bucket", c.Pick("corp-backups", "customer-exports", "finance-reports"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "s3.amazonaws.com",
				name:      "PutBucketAcl",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("s3api.put-bucket-acl"),
				account:   b.account,
				request: ctObj{
					ctkv("bucketName", bucket),
					ctkv("Host", bucket+".s3."+b.region+".amazonaws.com"),
					ctkv("acl", ""),
					ctkv("x-amz-acl", "public-read"),
					ctkv("AccessControlPolicy", ctObj{
						ctkv("AccessControlList", ctObj{
							ctkv("Grant", []any{ctObj{
								ctkv("Grantee", ctObj{
									ctkv("xsi:type", "Group"),
									ctkv("URI", "http://acs.amazonaws.com/groups/global/AllUsers"),
								}),
								ctkv("Permission", "READ"),
							}}),
						}),
					}),
				},
				response: nil,
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::S3::Bucket"),
					ctkv("ARN", "arn:aws:s3:::"+bucket),
				}},
				host: "s3." + b.region + ".amazonaws.com",
			})
		},
	})

	registerCT(ctCase{
		id: "s3-public-access-block-removed", group: grpCTStorage,
		name:  "S3 public access block removed",
		desc:  "DeletePublicAccessBlock stripped the guardrail that stops a bucket from ever becoming public. Almost always the step immediately before an exposure.",
		event: "DeletePublicAccessBlock", source: "s3.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1530", "T1562"},
		params: ctStdParams(param("bucket", "Bucket name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			bucket := c.P("bucket", c.Pick("corp-backups", "customer-exports", "finance-reports"))
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "s3.amazonaws.com",
				name:      "DeletePublicAccessBlock",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("s3api.delete-public-access-block"),
				account:   b.account,
				request: ctObj{
					ctkv("bucketName", bucket),
					ctkv("Host", bucket+".s3."+b.region+".amazonaws.com"),
					ctkv("publicAccessBlock", ""),
				},
				response: nil,
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::S3::Bucket"),
					ctkv("ARN", "arn:aws:s3:::"+bucket),
				}},
				host: "s3." + b.region + ".amazonaws.com",
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Network exposure
// ---------------------------------------------------------------------------

// ctIngressRule builds the requestParameters for AuthorizeSecurityGroupIngress.
// EC2 wraps repeated members in an "items" array, which is the shape published
// Athena queries against real CloudTrail data address as
// requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp.
func ctIngressRule(groupID, proto string, port int, cidr, desc string) ctObj {
	return ctObj{
		ctkv("groupId", groupID),
		ctkv("ipPermissions", ctObj{
			ctkv("items", []any{ctObj{
				ctkv("ipProtocol", proto),
				ctkv("fromPort", port),
				ctkv("toPort", port),
				ctkv("groups", ctObj{}),
				ctkv("ipRanges", ctObj{
					ctkv("items", []any{ctObj{
						ctkv("cidrIp", cidr),
						ctkv("description", desc),
					}}),
				}),
				ctkv("ipv6Ranges", ctObj{}),
				ctkv("prefixListIds", ctObj{}),
			}}),
		}),
	}
}

func registerCloudTrailNetwork() {
	ingress := func(id, name, desc, ruleDesc string, port int) ctCase {
		return ctCase{
			id: id, group: grpCTNetwork,
			name: name, desc: desc,
			event: "AuthorizeSecurityGroupIngress", source: "ec2.amazonaws.com",
			severity: core.SevLabelHigh, sev: core.SevErr,
			mitre:  []string{"T1562.007"},
			params: ctStdParams(param("cidr", "Source CIDR", "0.0.0.0/0")),
			build: func(c *core.Ctx) string {
				b := ctBaseOf(c, false)
				cidr := c.P("cidr", "0.0.0.0/0")
				groupID := "sg-" + c.HexLower(17)
				return ctRecord(c, ctSpec{
					identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
					source:    "ec2.amazonaws.com",
					name:      "AuthorizeSecurityGroupIngress",
					region:    b.region,
					srcIP:     b.srcIP,
					userAgent: ctCLIAgent("ec2.authorize-security-group-ingress"),
					account:   b.account,
					request:   ctIngressRule(groupID, "tcp", port, cidr, ruleDesc),
					response: ctObj{
						ctkv("requestId", ctUUID(c)),
						ctkv("_return", true),
					},
					host: ctSvcHost("ec2", b.region),
				})
			},
		}
	}

	registerCT(ingress("sg-open-ssh",
		"Security group opened SSH to the internet",
		"AuthorizeSecurityGroupIngress allowed tcp/22 from 0.0.0.0/0. Within minutes the host is being brute forced by the internet's background noise.",
		"temp access", 22))

	registerCT(ingress("sg-open-rdp",
		"Security group opened RDP to the internet",
		"AuthorizeSecurityGroupIngress allowed tcp/3389 from 0.0.0.0/0, which is the exposure most ransomware intrusions start from.",
		"remote support", 3389))

	registerCT(ctCase{
		id: "snapshot-made-public", group: grpCTNetwork,
		name:  "EBS snapshot shared publicly",
		desc:  "ModifySnapshotAttribute added the \"all\" group to a snapshot's create volume permission. Anyone in AWS can now restore the disk and read whatever was on it.",
		event: "ModifySnapshotAttribute", source: "ec2.amazonaws.com",
		severity: core.SevLabelCritical, sev: core.SevAlert,
		mitre:  []string{"T1537"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			snap := "snap-" + c.HexLower(17)
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), true, false),
				source:    "ec2.amazonaws.com",
				name:      "ModifySnapshotAttribute",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("ec2.modify-snapshot-attribute"),
				account:   b.account,
				request: ctObj{
					ctkv("snapshotId", snap),
					ctkv("attributeType", "CREATE_VOLUME_PERMISSION"),
					ctkv("createVolumePermission", ctObj{
						ctkv("add", ctObj{
							ctkv("items", []any{ctObj{ctkv("group", "all")}}),
						}),
					}),
				},
				response: ctObj{
					ctkv("requestId", ctUUID(c)),
					ctkv("_return", true),
				},
				host: ctSvcHost("ec2", b.region),
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Role assumption
// ---------------------------------------------------------------------------

func registerCloudTrailAssumeRole() {
	registerCT(ctCase{
		id: "assume-role", group: grpCTAssume,
		name:  "Role assumed from an external address",
		desc:  "An sts:AssumeRole call from outside the estate. The session name is attacker-chosen, which is why it is worth baselining.",
		event: "AssumeRole", source: "sts.amazonaws.com",
		severity: core.SevLabelMedium, sev: core.SevWarning,
		mitre:  []string{"T1548.005", "T1078.004"},
		params: ctStdParams(param("role", "Role name", "auto"), param("session", "Role session name", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			role := c.P("role", c.Pick("DeploymentRole", "EC2AdminRole", "DataEngineerRole"))
			session := c.P("session", c.Pick("session1", "temp", b.user+"-cli"))
			roleARN := "arn:aws:iam::" + b.account + ":role/" + role
			roleID := ctUniqueID(c, "AROA")
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), false, false),
				source:    "sts.amazonaws.com",
				name:      "AssumeRole",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("sts.assume-role"),
				account:   b.account,
				request: ctObj{
					ctkv("roleArn", roleARN),
					ctkv("roleSessionName", session),
					ctkv("durationSeconds", 3600),
				},
				response: ctObj{
					ctkv("credentials", ctObj{
						ctkv("accessKeyId", ctAccessKey(c, true)),
						ctkv("expiration", c.Now.Add(time.Hour).UTC().Format("Jan 2, 2006 3:04:05 PM")),
						ctkv("sessionToken", "<sensitiveDataRemoved>"),
					}),
					ctkv("assumedRoleUser", ctObj{
						ctkv("assumedRoleId", roleID+":"+session),
						ctkv("arn", "arn:aws:sts::"+b.account+":assumed-role/"+role+"/"+session),
					}),
				},
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::IAM::Role"),
					ctkv("ARN", roleARN),
				}},
				host: ctSvcHost("sts", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "assume-role-chain", group: grpCTAssume,
		name:  "Role chaining",
		desc:  "An already-assumed role called AssumeRole again to reach a second role. Chaining is how a foothold walks up to administrator while every individual call looks ordinary.",
		event: "AssumeRole", source: "sts.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1548.005", "T1098.003"},
		params: ctStdParams(param("role", "Role being assumed", "auto"), param("from", "Role already held", "auto")),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			from := c.P("from", c.Pick("EC2InstanceRole", "LambdaExecutionRole", "CIRunnerRole"))
			target := c.P("role", c.Pick("OrganizationAccountAccessRole", "SecurityAuditRole", "BreakGlassAdmin"))
			session := b.user + "-chain"
			targetARN := "arn:aws:iam::" + b.account + ":role/" + target
			targetID := ctUniqueID(c, "AROA")
			return ctRecord(c, ctSpec{
				identity:  ctRoleIdentity(c, b.account, from, "i-"+c.HexLower(17), ctAccessKey(c, true), false),
				source:    "sts.amazonaws.com",
				name:      "AssumeRole",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("sts.assume-role"),
				account:   b.account,
				request: ctObj{
					ctkv("roleArn", targetARN),
					ctkv("roleSessionName", session),
					ctkv("durationSeconds", 3600),
				},
				response: ctObj{
					ctkv("credentials", ctObj{
						ctkv("accessKeyId", ctAccessKey(c, true)),
						ctkv("expiration", c.Now.Add(time.Hour).UTC().Format("Jan 2, 2006 3:04:05 PM")),
						ctkv("sessionToken", "<sensitiveDataRemoved>"),
					}),
					ctkv("assumedRoleUser", ctObj{
						ctkv("assumedRoleId", targetID+":"+session),
						ctkv("arn", "arn:aws:sts::"+b.account+":assumed-role/"+target+"/"+session),
					}),
				},
				resources: []any{ctObj{
					ctkv("accountId", b.account),
					ctkv("type", "AWS::IAM::Role"),
					ctkv("ARN", targetARN),
				}},
				host: ctSvcHost("sts", b.region),
			})
		},
	})
}

// ---------------------------------------------------------------------------
// Unauthorized API calls
// ---------------------------------------------------------------------------

func registerCloudTrailDenied() {
	registerCT(ctCase{
		id: "denied-attach-policy", group: grpCTDenied,
		name:  "AccessDenied attaching an admin policy",
		desc:  "A principal tried to grant itself AdministratorAccess and was refused. A single denial is noise; a burst of them across IAM actions is a privilege escalation sweep.",
		event: "AttachUserPolicy", source: "iam.amazonaws.com",
		severity: core.SevLabelHigh, sev: core.SevErr,
		mitre:  []string{"T1098.003"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, false)
			akid := ctAccessKey(c, false)
			arn := "arn:aws:iam::" + b.account + ":user/" + b.user
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, akid, true, false),
				source:    "iam.amazonaws.com",
				name:      "AttachUserPolicy",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("iam.attach-user-policy"),
				account:   b.account,
				errorCode: "AccessDenied",
				errorMsg: "User: " + arn + " is not authorized to perform: iam:AttachUserPolicy on resource: " +
					arn + " because no identity-based policy allows the iam:AttachUserPolicy action",
				request: ctObj{
					ctkv("userName", b.user),
					ctkv("policyArn", ctAdminPolicyARN),
				},
				response: nil,
				host:     ctSvcHost("iam", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "denied-run-instances", group: grpCTDenied,
		name:  "UnauthorizedOperation launching instances",
		desc:  "EC2 refused a RunInstances call. Repeated against expensive instance types from stolen keys, this is cryptomining being attempted.",
		event: "RunInstances", source: "ec2.amazonaws.com",
		severity: core.SevLabelMedium, sev: core.SevWarning,
		mitre:  []string{"T1078.004", "T1496"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), false, false),
				source:    "ec2.amazonaws.com",
				name:      "RunInstances",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: ctCLIAgent("ec2.run-instances"),
				account:   b.account,
				errorCode: "Client.UnauthorizedOperation",
				errorMsg:  "You are not authorized to perform this operation. Encoded authorization failure message: " + ctRandID(c, 40),
				request: ctObj{
					ctkv("instancesSet", ctObj{
						ctkv("items", []any{ctObj{
							ctkv("imageId", "ami-"+c.HexLower(17)),
							ctkv("minCount", 1),
							ctkv("maxCount", 8),
						}}),
					}),
					ctkv("instanceType", c.Pick("p3.16xlarge", "c5.24xlarge", "g4dn.12xlarge")),
				},
				response: nil,
				host:     ctSvcHost("ec2", b.region),
			})
		},
	})

	registerCT(ctCase{
		id: "denied-list-buckets", group: grpCTDenied,
		name:  "AccessDenied enumerating S3",
		desc:  "A refused ListBuckets call. Enumeration from credentials that have never touched S3 before is what a leaked key looks like in its first minutes.",
		event: "ListBuckets", source: "s3.amazonaws.com",
		severity: core.SevLabelMedium, sev: core.SevWarning,
		mitre:  []string{"T1580", "T1530"},
		params: ctStdParams(),
		build: func(c *core.Ctx) string {
			b := ctBaseOf(c, true)
			arn := "arn:aws:iam::" + b.account + ":user/" + b.user
			return ctRecord(c, ctSpec{
				identity:  ctUserIdentity(c, b.account, b.user, ctAccessKey(c, false), false, false),
				source:    "s3.amazonaws.com",
				name:      "ListBuckets",
				region:    b.region,
				srcIP:     b.srcIP,
				userAgent: "[aws-cli/2.13.5 Python/3.11.4 Linux/5.15.0 exe/x86_64.ubuntu.22 prompt/off command/s3api.list-buckets]",
				account:   b.account,
				errorCode: "AccessDenied",
				errorMsg: "User: " + arn + " is not authorized to perform: s3:ListAllMyBuckets " +
					"because no identity-based policy allows the s3:ListAllMyBuckets action",
				request: ctObj{
					ctkv("Host", "s3."+b.region+".amazonaws.com"),
				},
				response: nil,
				readOnly: true,
				host:     "s3." + b.region + ".amazonaws.com",
			})
		},
	})
}

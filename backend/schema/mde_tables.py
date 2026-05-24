"""
mde_tables.py — Source of truth for Microsoft Defender for Endpoint table schemas.

Every column name, type, nullable flag, and ActionType enumeration in this file
mirrors real MDE Advanced Hunting exactly. No other file in the codebase invents
column names — all transpilers, validators, and ingest normalizers reference this
module. This is the guarantee that detections written here are portable to real
Microsoft Sentinel and MDE environments.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class MdeColumn:
    name: str           # Exact MDE column name — case-sensitive
    dtype: str          # DuckDB type string: TIMESTAMP, STRING, INT, BIGINT, BOOLEAN, JSON
    nullable: bool      # True if MDE documents the field as nullable
    description: str    # What this field contains in MDE context


@dataclass(frozen=True)
class MdeTable:
    name: str                        # Exact MDE table name — PascalCase
    columns: tuple[MdeColumn, ...]   # Ordered tuple, not list — frozen dataclass requires it
    description: str                 # What log source this table represents in MDE
    required_for_ingest: frozenset[str] = field(default_factory=frozenset)  # Columns that must be present (excl. ReportId — generated on default)


# ---------------------------------------------------------------------------
# Table definitions
# Nullable rule: only columns explicitly marked "-- nullable" in CLAUDE.md are
# nullable=True. Every other column is nullable=False.
# dtype rule: STRING (not VARCHAR), INT (not INTEGER), per spec type mapping.
# ---------------------------------------------------------------------------

_DEVICE_PROCESS_EVENTS = MdeTable(
    name="DeviceProcessEvents",
    description="Process creation and injection events from MDE sensor",
    columns=(
        MdeColumn("Timestamp",                       "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                        "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                      "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                      "STRING",    False, "ProcessCreated | ProcessInjected | OpenProcessApiCall | CreateRemoteThreadApiCall"),
        MdeColumn("FileName",                        "STRING",    False, "Process image filename (no path)"),
        MdeColumn("FolderPath",                      "STRING",    False, "Full path to process binary"),
        MdeColumn("SHA256",                          "STRING",    False, "SHA-256 hash of process binary"),
        MdeColumn("MD5",                             "STRING",    False, "MD5 hash of process binary"),
        MdeColumn("ProcessId",                       "INT",       False, "PID of the new process"),
        MdeColumn("ProcessCommandLine",              "STRING",    False, "Full command line of the new process"),
        MdeColumn("AccountDomain",                   "STRING",    False, "Domain of the account running the process"),
        MdeColumn("AccountName",                     "STRING",    False, "Username running the process"),
        MdeColumn("AccountSid",                      "STRING",    False, "SID of the account"),
        MdeColumn("LogonId",                         "STRING",    False, "Logon session identifier"),
        MdeColumn("InitiatingProcessId",             "INT",       False, "PID of the parent process"),
        MdeColumn("InitiatingProcessFileName",       "STRING",    False, "Filename of the parent process"),
        MdeColumn("InitiatingProcessCommandLine",    "STRING",    False, "Command line of the parent process"),
        MdeColumn("InitiatingProcessParentFileName", "STRING",    False, "Grandparent process filename"),
        MdeColumn("InitiatingProcessAccountName",    "STRING",    False, "Username of the parent process owner"),
        MdeColumn("InitiatingProcessSHA256",         "STRING",    False, "SHA-256 of the parent process binary"),
        MdeColumn("ReportId",                        "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_NETWORK_EVENTS = MdeTable(
    name="DeviceNetworkEvents",
    description="Network connection events observed by the MDE sensor",
    columns=(
        MdeColumn("Timestamp",                    "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                     "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                   "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                   "STRING",    False, "ConnectionSuccess | ConnectionFailed | ConnectionFound | InboundConnectionAccepted | ListeningConnectionCreated"),
        MdeColumn("RemoteIP",                     "STRING",    False, "Remote IP address"),
        MdeColumn("RemotePort",                   "INT",       False, "Remote TCP/UDP port"),
        MdeColumn("RemoteUrl",                    "STRING",    False, "Remote URL if available"),
        MdeColumn("LocalIP",                      "STRING",    False, "Local IP address"),
        MdeColumn("LocalPort",                    "INT",       False, "Local TCP/UDP port"),
        MdeColumn("Protocol",                     "STRING",    False, "Network protocol (TCP/UDP)"),
        MdeColumn("InitiatingProcessFileName",    "STRING",    False, "Process that initiated the connection"),
        MdeColumn("InitiatingProcessCommandLine", "STRING",    False, "Command line of initiating process"),
        MdeColumn("InitiatingProcessAccountName","STRING",    False, "Account running the initiating process"),
        MdeColumn("InitiatingProcessId",          "INT",       False, "PID of initiating process"),
        MdeColumn("InitiatingProcessSHA256",      "STRING",    False, "SHA-256 of initiating process"),
        MdeColumn("ReportId",                     "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_FILE_EVENTS = MdeTable(
    name="DeviceFileEvents",
    description="File creation, modification, deletion, and rename events",
    columns=(
        MdeColumn("Timestamp",                    "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                     "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                   "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                   "STRING",    False, "FileCreated | FileModified | FileDeleted | FileRenamed | FileCopied"),
        MdeColumn("FileName",                     "STRING",    False, "Name of the affected file"),
        MdeColumn("FolderPath",                   "STRING",    False, "Full path to the file"),
        MdeColumn("SHA256",                       "STRING",    False, "SHA-256 of the file"),
        MdeColumn("MD5",                          "STRING",    False, "MD5 of the file"),
        MdeColumn("FileSize",                     "BIGINT",    False, "File size in bytes"),
        MdeColumn("InitiatingProcessFileName",    "STRING",    False, "Process that performed the file operation"),
        MdeColumn("InitiatingProcessCommandLine", "STRING",    False, "Command line of initiating process"),
        MdeColumn("InitiatingProcessAccountName","STRING",    False, "Account running the initiating process"),
        MdeColumn("InitiatingProcessId",          "INT",       False, "PID of initiating process"),
        MdeColumn("InitiatingProcessSHA256",      "STRING",    False, "SHA-256 of initiating process"),
        MdeColumn("ReportId",                     "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_REGISTRY_EVENTS = MdeTable(
    name="DeviceRegistryEvents",
    description="Windows Registry key and value modification events",
    columns=(
        MdeColumn("Timestamp",                    "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                     "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                   "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                   "STRING",    False, "RegistryKeyCreated | RegistryKeyDeleted | RegistryValueSet | RegistryValueDeleted"),
        MdeColumn("RegistryKey",                  "STRING",    False, "Full registry key path"),
        MdeColumn("RegistryValueName",            "STRING",    False, "Registry value name"),
        MdeColumn("RegistryValueData",            "STRING",    False, "Registry value data"),
        MdeColumn("InitiatingProcessFileName",    "STRING",    False, "Process that modified the registry"),
        MdeColumn("InitiatingProcessCommandLine", "STRING",    False, "Command line of initiating process"),
        MdeColumn("InitiatingProcessAccountName","STRING",    False, "Account running the initiating process"),
        MdeColumn("InitiatingProcessId",          "INT",       False, "PID of initiating process"),
        MdeColumn("ReportId",                     "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_LOGON_EVENTS = MdeTable(
    name="DeviceLogonEvents",
    description="Authentication events — interactive, network, and remote logons",
    columns=(
        MdeColumn("Timestamp",        "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",         "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",       "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",       "STRING",    False, "LogonSuccess | LogonFailed | LogonAttempted"),
        MdeColumn("AccountDomain",    "STRING",    False, "Domain of the authenticating account"),
        MdeColumn("AccountName",      "STRING",    False, "Username"),
        MdeColumn("AccountSid",       "STRING",    False, "SID of the account"),
        MdeColumn("LogonType",        "INT",       False, "2=Interactive 3=Network 10=RemoteInteractive"),
        MdeColumn("LogonTypeName",    "STRING",    False, "Human-readable logon type"),
        MdeColumn("IsLocalAdmin",     "BOOLEAN",   False, "True if account is a local admin"),
        MdeColumn("FailureReason",    "STRING",    True,  "Reason for logon failure"),       # -- nullable
        MdeColumn("RemoteIP",         "STRING",    True,  "Source IP for network/remote logons"),  # -- nullable
        MdeColumn("RemoteDeviceName", "STRING",    True,  "Source device name"),              # -- nullable
        MdeColumn("ReportId",         "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_EVENTS = MdeTable(
    name="DeviceEvents",
    description="Miscellaneous device telemetry — antivirus, PowerShell, browser events",
    columns=(
        MdeColumn("Timestamp",                    "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                     "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                   "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                   "STRING",    False, "AntivirusDetection | AntivirusActionTaken | PowerShellCommand | BrowserLaunchedToOpenUrl | SafeBrowsingUrlWarning | SmartScreenUrlWarning | SmartScreenAppWarning"),
        MdeColumn("FileName",                     "STRING",    True,  "Relevant filename"),              # -- nullable
        MdeColumn("FolderPath",                   "STRING",    True,  "Relevant folder path"),           # -- nullable
        MdeColumn("SHA256",                       "STRING",    True,  "File hash if applicable"),        # -- nullable
        MdeColumn("ProcessCommandLine",           "STRING",    True,  "Command line if applicable"),     # -- nullable
        MdeColumn("AccountName",                  "STRING",    True,  "Account context"),                # -- nullable
        MdeColumn("AdditionalFields",             "JSON",      False, "ActionType-specific structured fields"),
        MdeColumn("InitiatingProcessFileName",    "STRING",    False, "Initiating process filename"),
        MdeColumn("InitiatingProcessCommandLine", "STRING",    False, "Initiating process command line"),
        MdeColumn("InitiatingProcessAccountName","STRING",    False, "Account of initiating process"),
        MdeColumn("InitiatingProcessId",          "INT",       False, "PID of initiating process"),
        MdeColumn("ReportId",                     "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId",
    }),
)

_DEVICE_ALERT_EVENTS = MdeTable(
    name="DeviceAlertEvents",
    description="MDE-generated alert events linked to devices",
    columns=(
        MdeColumn("Timestamp",        "TIMESTAMP", False, "UTC alert timestamp"),
        MdeColumn("DeviceId",         "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",       "STRING",    False, "Device hostname"),
        MdeColumn("AlertId",          "STRING",    False, "Unique alert identifier"),
        MdeColumn("Title",            "STRING",    False, "Alert title"),
        MdeColumn("Severity",         "STRING",    False, "Informational | Low | Medium | High"),
        MdeColumn("ServiceSource",    "STRING",    False, "MDE | MDO | MDI | MCAS"),
        MdeColumn("DetectionSource",  "STRING",    False, "Detection engine that fired"),
        MdeColumn("AttackTechniques", "STRING[]",  False, "MITRE ATT&CK technique IDs"),
        MdeColumn("ReportId",         "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "AlertId", "Title", "Severity", "ReportId",
    }),
)

_IDENTITY_LOGON_EVENTS = MdeTable(
    name="IdentityLogonEvents",
    description="Identity-layer authentication events (Azure AD, on-prem AD)",
    columns=(
        MdeColumn("Timestamp",              "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("AccountUpn",             "STRING",    False, "User principal name"),
        MdeColumn("AccountObjectId",        "STRING",    False, "Azure AD object ID"),
        MdeColumn("AccountDisplayName",     "STRING",    False, "Display name"),
        MdeColumn("AccountDomain",          "STRING",    False, "Account domain"),
        MdeColumn("DeviceName",             "STRING",    True,  "Source device"),              # -- nullable
        MdeColumn("IPAddress",              "STRING",    False, "Source IP address"),
        MdeColumn("Port",                   "INT",       False, "Source port"),
        MdeColumn("DestinationDeviceName",  "STRING",    True,  "Target device"),              # -- nullable
        MdeColumn("DestinationIPAddress",   "STRING",    True,  "Target IP"),                  # -- nullable
        MdeColumn("DestinationPort",        "INT",       True,  "Target port"),                # -- nullable
        MdeColumn("Protocol",               "STRING",    False, "Authentication protocol"),
        MdeColumn("FailureReason",          "STRING",    True,  "Failure reason"),             # -- nullable
        MdeColumn("LogonType",              "STRING",    False, "Logon type string"),
        MdeColumn("ActionType",             "STRING",    False, "LogonSuccess | LogonFailed"),
        MdeColumn("Application",            "STRING",    True,  "Application context"),        # -- nullable
        MdeColumn("ReportId",               "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "AccountUpn", "ActionType", "ReportId",
    }),
)

_CLOUD_APP_EVENTS = MdeTable(
    name="CloudAppEvents",
    description="Microsoft 365 and cloud application activity events",
    columns=(
        MdeColumn("Timestamp",          "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("Application",        "STRING",    False, "Microsoft Teams | SharePoint | Exchange | etc."),
        MdeColumn("ActionType",         "STRING",    False, "Application-specific action type"),
        MdeColumn("AccountObjectId",    "STRING",    False, "Azure AD object ID"),
        MdeColumn("AccountDisplayName", "STRING",    False, "Display name"),
        MdeColumn("AccountDomain",      "STRING",    False, "Account domain"),
        MdeColumn("IPAddress",          "STRING",    False, "Source IP"),
        MdeColumn("CountryCode",        "STRING",    True,  "ISO country code"),   # -- nullable
        MdeColumn("City",               "STRING",    True,  "City"),               # -- nullable
        MdeColumn("ISP",                "STRING",    True,  "Internet service provider"),  # -- nullable
        MdeColumn("DeviceType",         "STRING",    True,  "Device type"),        # -- nullable
        MdeColumn("OSPlatform",         "STRING",    True,  "OS platform"),        # -- nullable
        MdeColumn("AdditionalFields",   "JSON",      False, "Event-specific structured fields"),
        MdeColumn("ReportId",           "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "Application", "ActionType", "AccountObjectId", "ReportId",
    }),
)

_AWS_CLOUDTRAIL_EVENTS = MdeTable(
    name="AWSCloudTrailEvents",
    description="AWS CloudTrail API call events — management, data, auth, and insight events",
    columns=(
        MdeColumn("Timestamp",          "TIMESTAMP", False, "UTC event timestamp (eventTime normalized)"),
        MdeColumn("ReportId",           "STRING",    False, "CloudTrail eventID — unique per event"),
        MdeColumn("ActionType",         "STRING",    False, "ApiCall | DataAccess | DataWrite | ManagementRead | ManagementWrite | AuthAttempt | TokenIssued | ConfigChange | InsightEvent"),
        MdeColumn("AccountId",          "STRING",    False, "AWS account ID (12-digit string)"),
        MdeColumn("AccountName",        "STRING",    True,  "Account alias if available"),
        MdeColumn("UserIdentityType",   "STRING",    False, "Root | IAMUser | AssumedRole | FederatedUser | Service | SamlUser | WebIdentityUser"),
        MdeColumn("UserIdentityArn",    "STRING",    False, "Full ARN of the calling principal"),
        MdeColumn("UserIdentityName",   "STRING",    True,  "Extracted username or role name"),
        MdeColumn("SessionName",        "STRING",    True,  "roleSessionName for AssumedRole calls"),
        MdeColumn("EventSource",        "STRING",    False, "AWS service endpoint (e.g. s3.amazonaws.com)"),
        MdeColumn("EventName",          "STRING",    False, "API operation name (e.g. GetObject, CreateUser)"),
        MdeColumn("EventCategory",      "STRING",    False, "Management | Data | Insight"),
        MdeColumn("AWSRegion",          "STRING",    False, "AWS region (e.g. us-east-1)"),
        MdeColumn("SourceIPAddress",    "STRING",    False, "Caller IP or internal AWS service name"),
        MdeColumn("UserAgent",          "STRING",    False, "AWS CLI, console, or SDK identifier"),
        MdeColumn("RequestParameters",  "JSON",      True,  "Raw requestParameters blob"),
        MdeColumn("ResponseElements",   "JSON",      True,  "Raw responseElements blob"),
        MdeColumn("ErrorCode",          "STRING",    True,  "Error code on failed API calls"),
        MdeColumn("ErrorMessage",       "STRING",    True,  "Error message on failed API calls"),
        MdeColumn("ReadOnly",           "BOOLEAN",   False, "True for Describe/List/Get operations"),
        MdeColumn("MFAAuthenticated",   "BOOLEAN",   True,  "Whether MFA was used in the session"),
        MdeColumn("SharedEventID",      "STRING",    True,  "Links cross-account delivery of the same event"),
        MdeColumn("AdditionalFields",   "JSON",      False, "Full raw CloudTrail event for full-fidelity querying"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "AccountId", "ActionType", "EventSource", "EventName", "ReportId",
    }),
)

_CLOUDFLARE_HTTP_EVENTS = MdeTable(
    name="CloudflareHttpEvents",
    description="One row per HTTP/S request processed by Cloudflare edge (Logpush HTTP Requests dataset)",
    columns=(
        MdeColumn("Timestamp",              "TIMESTAMP", False, "Edge start timestamp (nanosecond epoch → UTC)"),
        MdeColumn("ReportId",               "STRING",    False, "Cloudflare RayID"),
        MdeColumn("ActionType",             "STRING",    False, "HttpRequest | HttpBlocked | HttpChallenged | HttpManagedChallenge | BotDetected | DDoSMitigation | RateLimited"),
        MdeColumn("ClientIP",               "STRING",    False, "Source IP of the request"),
        MdeColumn("ClientPort",             "INT",       True,  "Source port"),
        MdeColumn("ClientCountry",          "STRING",    True,  "2-letter ISO country code"),
        MdeColumn("ClientASN",              "INT",       True,  "Client ASN number"),
        MdeColumn("ClientASNDescription",   "STRING",    True,  "ASN organisation name"),
        MdeColumn("ClientRequestMethod",    "STRING",    False, "HTTP method (GET, POST, etc.)"),
        MdeColumn("ClientRequestHost",      "STRING",    False, "Host header value"),
        MdeColumn("ClientRequestURI",       "STRING",    False, "Full URI path including query string"),
        MdeColumn("ClientRequestUserAgent", "STRING",    False, "User-Agent header"),
        MdeColumn("ClientRequestReferer",   "STRING",    True,  "Referer header"),
        MdeColumn("ClientRequestBytes",     "BIGINT",    True,  "Request body size in bytes"),
        MdeColumn("ClientSSLProtocol",      "STRING",    True,  "TLS version (TLSv1.2, TLSv1.3, none)"),
        MdeColumn("ClientSSLCipher",        "STRING",    True,  "Cipher suite negotiated"),
        MdeColumn("EdgeResponseStatus",     "INT",       False, "HTTP response status code from edge"),
        MdeColumn("EdgeResponseBytes",      "BIGINT",    False, "Response size in bytes"),
        MdeColumn("EdgeColoCode",           "STRING",    True,  "Cloudflare PoP code (e.g. DFW, LHR)"),
        MdeColumn("EdgeServerIP",           "STRING",    True,  "Cloudflare edge server IP"),
        MdeColumn("OriginIP",               "STRING",    True,  "Origin server IP"),
        MdeColumn("OriginResponseStatus",   "INT",       True,  "Origin HTTP status before Cloudflare"),
        MdeColumn("OriginResponseTime",     "INT",       True,  "Origin response time in nanoseconds"),
        MdeColumn("CacheCacheStatus",       "STRING",    True,  "HIT | MISS | EXPIRED | BYPASS | etc."),
        MdeColumn("CacheTieredFill",        "BOOLEAN",   True,  "Whether a tiered cache fill occurred"),
        MdeColumn("FirewallMatchesActions", "STRING[]",  True,  "List of firewall actions taken"),
        MdeColumn("FirewallMatchesRuleIDs", "STRING[]",  True,  "Matching firewall rule IDs"),
        MdeColumn("BotScore",               "INT",       True,  "Cloudflare bot score 0-99"),
        MdeColumn("BotScoreSrc",            "STRING",    True,  "Bot scoring source (Verified Bot, Heuristics, etc.)"),
        MdeColumn("ThreatScore",            "INT",       True,  "Legacy threat score 0-100"),
        MdeColumn("WorkerSubrequest",       "BOOLEAN",   True,  "True if this is a Worker subrequest"),
        MdeColumn("ZoneName",               "STRING",    True,  "Cloudflare zone (domain)"),
        MdeColumn("AdditionalFields",       "JSON",      False, "Full raw Cloudflare HTTP log entry"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "ClientIP", "ClientRequestHost",
    }),
)

_CLOUDFLARE_FIREWALL_EVENTS = MdeTable(
    name="CloudflareFirewallEvents",
    description="One row per Cloudflare firewall rule match (Logpush Firewall Events dataset)",
    columns=(
        MdeColumn("Timestamp",               "TIMESTAMP", False, "Event timestamp from Cloudflare Datetime field"),
        MdeColumn("ReportId",                "STRING",    False, "Cloudflare RayID"),
        MdeColumn("ActionType",              "STRING",    False, "FirewallBlock | FirewallChallenge | FirewallManagedChallenge | FirewallAllow | FirewallLog | FirewallSkip | RateLimitBlock | WAFBlock | CountryBlock | L4Block"),
        MdeColumn("ClientIP",                "STRING",    False, "Source IP of the request"),
        MdeColumn("ClientCountry",           "STRING",    True,  "2-letter ISO country code"),
        MdeColumn("ClientASN",               "INT",       True,  "Client ASN number"),
        MdeColumn("ClientRequestMethod",     "STRING",    True,  "HTTP method"),
        MdeColumn("ClientRequestHost",       "STRING",    True,  "Host header value"),
        MdeColumn("ClientRequestURI",        "STRING",    True,  "Full URI path"),
        MdeColumn("ClientRequestUserAgent",  "STRING",    True,  "User-Agent header"),
        MdeColumn("EdgeColoCode",            "STRING",    True,  "Cloudflare PoP code"),
        MdeColumn("FirewallAction",          "STRING",    False, "block | challenge | managed_challenge | allow | log | skip"),
        MdeColumn("FirewallRuleID",          "STRING",    False, "Rule identifier that matched"),
        MdeColumn("FirewallRuleDescription", "STRING",    True,  "Human-readable rule name"),
        MdeColumn("FirewallSource",          "STRING",    False, "firewallrules | rateLimit | bic | hot | l4 | waf | country"),
        MdeColumn("MatchIndex",              "INT",       True,  "Order of match within the request"),
        MdeColumn("Metadata",               "JSON",      True,  "Additional rule-specific metadata"),
        MdeColumn("OriginResponseStatus",    "INT",       True,  "Origin HTTP status"),
        MdeColumn("SampledRate",             "FLOAT",     True,  "Cloudflare sampling rate for this event"),
        MdeColumn("ZoneName",                "STRING",    True,  "Cloudflare zone (domain)"),
        MdeColumn("AdditionalFields",        "JSON",      False, "Full raw firewall event"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "ClientIP",
    }),
)

_CLOUDFLARE_DNS_EVENTS = MdeTable(
    name="CloudflareDnsEvents",
    description="One row per DNS query handled by Cloudflare Gateway or 1.1.1.1 resolver",
    columns=(
        MdeColumn("Timestamp",         "TIMESTAMP", False, "Query timestamp (UTC)"),
        MdeColumn("ReportId",          "STRING",    False, "UUID generated at ingest"),
        MdeColumn("ActionType",        "STRING",    False, "DnsQuery | DnsBlock | DnsNXDomain | DnsServFail | DnsThreatMatch | DnsPolicyMatch"),
        MdeColumn("SourceIP",          "STRING",    False, "Client IP making the DNS query"),
        MdeColumn("SourcePort",        "INT",       True,  "Client source port"),
        MdeColumn("DeviceID",          "STRING",    True,  "Cloudflare Gateway device ID"),
        MdeColumn("DeviceName",        "STRING",    True,  "Device hostname"),
        MdeColumn("UserID",            "STRING",    True,  "Cloudflare Access user ID"),
        MdeColumn("AccountName",       "STRING",    True,  "Cloudflare account name"),
        MdeColumn("QueryName",         "STRING",    False, "DNS name being queried"),
        MdeColumn("QueryType",         "STRING",    False, "A | AAAA | MX | TXT | CNAME | PTR | SOA | etc."),
        MdeColumn("QueryTypeName",     "STRING",    True,  "Human-readable DNS record type name"),
        MdeColumn("ResponseCode",      "STRING",    False, "NOERROR | NXDOMAIN | SERVFAIL | REFUSED"),
        MdeColumn("ResolvedIPs",       "STRING[]",  True,  "List of resolved IP addresses"),
        MdeColumn("ResolverDecision",  "STRING",    True,  "Cloudflare Gateway resolver decision"),
        MdeColumn("ThreatCategory",    "STRING",    True,  "Cloudflare threat classification"),
        MdeColumn("ThreatIndicator",   "STRING",    True,  "Matched threat indicator value"),
        MdeColumn("PolicyName",        "STRING",    True,  "Gateway policy that matched"),
        MdeColumn("PolicyID",          "STRING",    True,  "Gateway policy ID"),
        MdeColumn("Blocked",           "BOOLEAN",   False, "True if the query was blocked"),
        MdeColumn("ResponseDurationMs","INT",       True,  "Query resolution time in milliseconds"),
        MdeColumn("ZoneName",          "STRING",    True,  "Cloudflare zone"),
        MdeColumn("Location",          "STRING",    True,  "Cloudflare Gateway location name"),
        MdeColumn("AdditionalFields",  "JSON",      False, "Full raw DNS log entry"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "SourceIP", "QueryName",
    }),
)

_ZSCALER_WEB_EVENTS = MdeTable(
    name="ZscalerWebEvents",
    description="One row per HTTP/S transaction proxied through Zscaler Internet Access (ZIA)",
    columns=(
        MdeColumn("Timestamp",            "TIMESTAMP", False, "Transaction timestamp (UTC)"),
        MdeColumn("ReportId",             "STRING",    False, "UUID generated at ingest"),
        MdeColumn("ActionType",           "STRING",    False, "WebAllow | WebBlock | WebCautioned | MalwareDetected | DlpViolation | SslBypass | SslBlock | FileBlocked | AppControlBlock | QuarantinedFile"),
        MdeColumn("UserName",             "STRING",    False, "Authenticated Zscaler username"),
        MdeColumn("Department",           "STRING",    True,  "Zscaler department or group"),
        MdeColumn("Location",             "STRING",    True,  "Zscaler location name (office, branch, VPN)"),
        MdeColumn("ClientIP",             "STRING",    False, "Source IP of the user device"),
        MdeColumn("Protocol",             "STRING",    False, "HTTP | HTTPS | FTP"),
        MdeColumn("RequestMethod",        "STRING",    False, "HTTP method (GET, POST, etc.)"),
        MdeColumn("RequestURL",           "STRING",    False, "Full URL including query string"),
        MdeColumn("RequestHost",          "STRING",    False, "Extracted hostname from URL"),
        MdeColumn("RequestSize",          "BIGINT",    True,  "Request size in bytes"),
        MdeColumn("ResponseCode",         "INT",       False, "HTTP response status code"),
        MdeColumn("ResponseSize",         "BIGINT",    True,  "Response size in bytes"),
        MdeColumn("ResponseTime",         "INT",       True,  "Response time in milliseconds"),
        MdeColumn("ContentType",          "STRING",    True,  "Response Content-Type header"),
        MdeColumn("FileType",             "STRING",    True,  "Zscaler file type classification"),
        MdeColumn("FileName",             "STRING",    True,  "Filename if a file download was detected"),
        MdeColumn("FileSHA256",           "STRING",    True,  "SHA256 of downloaded file"),
        MdeColumn("MalwareClass",         "STRING",    True,  "Zscaler malware classification"),
        MdeColumn("MalwareName",          "STRING",    True,  "Specific malware name if detected"),
        MdeColumn("ThreatCategory",       "STRING",    True,  "Zscaler threat category"),
        MdeColumn("PolicyName",           "STRING",    True,  "Zscaler policy that triggered the action"),
        MdeColumn("RuleLabel",            "STRING",    True,  "Specific rule within the policy"),
        MdeColumn("URLCategory",          "STRING",    True,  "Zscaler URL category"),
        MdeColumn("CloudApplicationName", "STRING",    True,  "Detected cloud app (Microsoft 365, Dropbox, etc.)"),
        MdeColumn("CloudApplicationRisk", "STRING",    True,  "App risk score: Critical | High | Medium | Low"),
        MdeColumn("SSLDecrypted",         "BOOLEAN",   False, "True if SSL inspection was applied"),
        MdeColumn("DeviceOwner",          "STRING",    True,  "Managed | Unmanaged"),
        MdeColumn("DeviceName",           "STRING",    True,  "Endpoint hostname if available"),
        MdeColumn("ServerIP",             "STRING",    True,  "Destination server IP"),
        MdeColumn("ServerPort",           "INT",       True,  "Destination port"),
        MdeColumn("BytesIn",              "BIGINT",    True,  "Bytes received"),
        MdeColumn("BytesOut",             "BIGINT",    True,  "Bytes sent"),
        MdeColumn("DurationMs",           "INT",       True,  "Session duration in milliseconds"),
        MdeColumn("AdditionalFields",     "JSON",      False, "Full raw Zscaler web log entry"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "ClientIP", "UserName",
    }),
)

_ZSCALER_DNS_EVENTS = MdeTable(
    name="ZscalerDnsEvents",
    description="One row per DNS query processed by Zscaler DNS Security",
    columns=(
        MdeColumn("Timestamp",       "TIMESTAMP", False, "Event timestamp (UTC)"),
        MdeColumn("ReportId",        "STRING",    False, "UUID generated at ingest"),
        MdeColumn("ActionType",      "STRING",    False, "DnsAllow | DnsBlock | DnsThreatMatch | DnsNXDomain | DnsServFail | DnsSinkhole"),
        MdeColumn("UserName",        "STRING",    True,  "Authenticated Zscaler username"),
        MdeColumn("Department",      "STRING",    True,  "Zscaler department or group"),
        MdeColumn("Location",        "STRING",    True,  "Zscaler location name"),
        MdeColumn("ClientIP",        "STRING",    False, "Source IP"),
        MdeColumn("QueryName",       "STRING",    False, "DNS name queried"),
        MdeColumn("QueryType",       "STRING",    False, "A | AAAA | MX | TXT | CNAME | etc."),
        MdeColumn("ResponseCode",    "STRING",    False, "NOERROR | NXDOMAIN | SERVFAIL | REFUSED"),
        MdeColumn("ResolvedIPs",     "STRING[]",  True,  "Resolved IP addresses"),
        MdeColumn("CategoryName",    "STRING",    True,  "Zscaler URL category of the domain"),
        MdeColumn("ThreatName",      "STRING",    True,  "Threat name if domain is malicious"),
        MdeColumn("ThreatCategory",  "STRING",    True,  "Zscaler threat category"),
        MdeColumn("PolicyName",      "STRING",    True,  "Zscaler policy that matched"),
        MdeColumn("DeviceName",      "STRING",    True,  "Endpoint hostname"),
        MdeColumn("DeviceOwner",     "STRING",    True,  "Managed | Unmanaged"),
        MdeColumn("DnsDurationMs",   "INT",       True,  "Resolution time in milliseconds"),
        MdeColumn("DoHStatus",       "BOOLEAN",   True,  "True if DNS-over-HTTPS was used"),
        MdeColumn("AdditionalFields","JSON",      False, "Full raw Zscaler DNS log entry"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "ClientIP", "QueryName",
    }),
)

_PROOFPOINT_MESSAGE_EVENTS = MdeTable(
    name="ProofpointMessageEvents",
    description="One row per email message processed by Proofpoint TAP — filtering verdict and threat intel",
    columns=(
        MdeColumn("Timestamp",              "TIMESTAMP", False, "Message processing timestamp (UTC)"),
        MdeColumn("ReportId",               "STRING",    False, "Proofpoint GUID — unique per message event"),
        MdeColumn("NetworkMessageId",       "STRING",    False, "RFC 2822 Message-ID stripped of angle brackets — join key with MDO tables"),
        MdeColumn("ActionType",             "STRING",    False, "Delivered | Quarantined | Blocked | SpamFiltered | BulkFiltered | PhishFiltered | MalwareBlocked | ImpostorBlocked | SandboxBlocked"),
        MdeColumn("SenderFromAddress",      "STRING",    False, "5321.MailFrom (envelope sender)"),
        MdeColumn("SenderFromDomain",       "STRING",    False, "Domain part of envelope sender"),
        MdeColumn("SenderIP",               "STRING",    False, "Sending MTA IP address"),
        MdeColumn("SenderReputation",       "STRING",    False, "Proofpoint sender reputation: VeryMalicious | Malicious | Suspicious | Unknown | NeutralOrGood"),
        MdeColumn("RecipientEmailAddress",  "STRING",    False, "Primary recipient (first in list)"),
        MdeColumn("RecipientEmailAddresses","STRING[]",  False, "All envelope recipients"),
        MdeColumn("Subject",                "STRING",    False, "Email subject line"),
        MdeColumn("MessageSize",            "INT",       False, "Total message size in bytes"),
        MdeColumn("SpamScore",              "FLOAT",     False, "Proofpoint spam score 0–100"),
        MdeColumn("PhishScore",             "FLOAT",     False, "Proofpoint phish score 0–100"),
        MdeColumn("ImpostorScore",          "FLOAT",     False, "Proofpoint impostor (BEC) score 0–100"),
        MdeColumn("MalwareScore",           "FLOAT",     False, "Proofpoint malware score 0–100"),
        MdeColumn("SpamVerdict",            "STRING",    False, "Positive | Negative | Neutral"),
        MdeColumn("PhishVerdict",           "STRING",    False, "Positive | Negative | Neutral"),
        MdeColumn("MalwareVerdict",         "STRING",    False, "Positive | Negative | Neutral"),
        MdeColumn("BulkVerdict",            "STRING",    False, "Positive | Negative | Neutral"),
        MdeColumn("DispositionAction",      "STRING",    False, "deliver | quarantine | discard"),
        MdeColumn("QuarantineFolder",       "STRING",    True,  "Proofpoint quarantine folder name"),     # -- nullable
        MdeColumn("QuarantineRule",         "STRING",    True,  "Quarantine rule that triggered"),        # -- nullable
        MdeColumn("PolicyRoutes",           "STRING[]",  False, "Ordered list of Proofpoint policy routes applied"),
        MdeColumn("ModulesRun",             "STRING[]",  False, "Detection modules that processed the message"),
        MdeColumn("ThreatsInfoMap",         "JSON",      False, "Array of threat objects: sha256, md5, threatType, threatStatus, threatUrl"),
        MdeColumn("AttachmentCount",        "INT",       False, "Number of attachments"),
        MdeColumn("AttachmentNames",        "STRING[]",  True,  "Attachment filenames"),                  # -- nullable
        MdeColumn("AttachmentTypes",        "STRING[]",  True,  "Attachment MIME types"),                 # -- nullable
        MdeColumn("AttachmentSHA256",       "STRING[]",  True,  "SHA-256 hashes of attachments"),         # -- nullable
        MdeColumn("UrlCount",               "INT",       False, "Number of URLs in message body"),
        MdeColumn("HeaderFrom",             "STRING",    False, "5322.From display header"),
        MdeColumn("HeaderReplyTo",          "STRING",    True,  "Reply-To header if present"),             # -- nullable
        MdeColumn("XOriginatingIP",         "STRING",    True,  "X-Originating-IP header if present"),    # -- nullable
        MdeColumn("DKIM",                   "STRING",    False, "pass | fail | none"),
        MdeColumn("DMARC",                  "STRING",    False, "pass | fail | none"),
        MdeColumn("SPF",                    "STRING",    False, "pass | fail | softfail | none"),
        MdeColumn("AdditionalFields",       "JSON",      False, "Full raw Proofpoint TAP message event"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "NetworkMessageId", "ActionType",
        "SenderFromAddress", "RecipientEmailAddress",
    }),
)

_PROOFPOINT_CLICK_EVENTS = MdeTable(
    name="ProofpointClickEvents",
    description="One row per URL click tracked by Proofpoint TAP URL Defense rewriting",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "Click event timestamp (UTC)"),
        MdeColumn("ReportId",              "STRING",    False, "Proofpoint click GUID"),
        MdeColumn("NetworkMessageId",      "STRING",    False, "Message-ID of the email containing the clicked URL — join key"),
        MdeColumn("ActionType",            "STRING",    False, "UrlClicked | UrlBlocked | UrlPermitted | SmartSearchBlock"),
        MdeColumn("RecipientEmailAddress", "STRING",    False, "Recipient who clicked the URL"),
        MdeColumn("SenderFromAddress",     "STRING",    False, "Sender of the email containing the URL"),
        MdeColumn("SenderIP",              "STRING",    False, "Sending MTA IP"),
        MdeColumn("Url",                   "STRING",    False, "Original URL (pre-rewrite)"),
        MdeColumn("UrlDomain",             "STRING",    False, "Extracted domain from URL"),
        MdeColumn("ThreatURL",             "STRING",    True,  "Proofpoint threat intelligence URL for this indicator"),  # -- nullable
        MdeColumn("ThreatStatus",          "STRING",    False, "active | falsePositive | cleared"),
        MdeColumn("Classification",        "STRING",    False, "phish | malware | spam | malware-sandbox | ransomware"),
        MdeColumn("ThreatTime",            "TIMESTAMP", True,  "Time Proofpoint first observed this threat"),             # -- nullable
        MdeColumn("UserAgent",             "STRING",    True,  "Browser User-Agent string at time of click"),             # -- nullable
        MdeColumn("ClickIP",               "STRING",    False, "IP address from which the click originated"),
        MdeColumn("Blocked",               "BOOLEAN",   False, "True if Proofpoint blocked the click"),
        MdeColumn("CampaignId",            "STRING",    True,  "Proofpoint campaign identifier if clustered"),            # -- nullable
        MdeColumn("AdditionalFields",      "JSON",      False, "Full raw Proofpoint TAP click event"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "NetworkMessageId", "ActionType",
        "RecipientEmailAddress", "Url",
    }),
)

_ABNORMAL_THREAT_EVENTS = MdeTable(
    name="AbnormalThreatEvents",
    description="One row per threat detected by Abnormal Security AI email analysis",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "Threat detection timestamp (UTC)"),
        MdeColumn("ReportId",              "STRING",    False, "Abnormal threat ID"),
        MdeColumn("NetworkMessageId",      "STRING",    True,  "RFC 2822 Message-ID if available — join key with Proofpoint and MDO tables"),  # -- nullable
        MdeColumn("ActionType",            "STRING",    False, "ThreatDetected | ThreatRemediated | ThreatReleased | FalsePositive"),
        MdeColumn("AttackType",            "STRING",    False, "BEC | Phishing | Malware | Spam | SocialEngineering | AccountTakeover | ReputationHijacking"),
        MdeColumn("AttackStrategy",        "STRING",    False, "Proofpoint-style attack strategy label (e.g. NaivetyExploitation, ImpersonationOfKnownBrand)"),
        MdeColumn("AttackVector",          "STRING",    False, "Email | Link | Attachment | SocialEngineering"),
        MdeColumn("ThreatStatus",          "STRING",    False, "Active | Remediated | Released | FalsePositive"),
        MdeColumn("AbNormalScore",         "FLOAT",     False, "Abnormal Security model confidence score 0.0–1.0"),
        MdeColumn("SenderFromAddress",     "STRING",    False, "Envelope sender address"),
        MdeColumn("SenderFromDomain",      "STRING",    False, "Domain part of sender"),
        MdeColumn("SenderDisplayName",     "STRING",    False, "Display name shown in From header"),
        MdeColumn("SenderIP",              "STRING",    True,  "Sending MTA IP if available"),                            # -- nullable
        MdeColumn("IsSenderKnown",         "BOOLEAN",   False, "True if sender has prior legitimate correspondence"),
        MdeColumn("ReplyToAddress",        "STRING",    True,  "Reply-To address if different from sender"),              # -- nullable
        MdeColumn("RecipientEmailAddress", "STRING",    False, "Primary recipient email address"),
        MdeColumn("RecipientName",         "STRING",    False, "Recipient display name"),
        MdeColumn("RecipientIsVIP",        "BOOLEAN",   False, "True if recipient is marked as VIP in Abnormal"),
        MdeColumn("ImpersonatedParty",     "STRING",    True,  "Entity being impersonated (e.g. Microsoft, CEO)"),        # -- nullable
        MdeColumn("ImpersonatedEmail",     "STRING",    True,  "Email address being impersonated"),                       # -- nullable
        MdeColumn("Subject",               "STRING",    False, "Email subject line"),
        MdeColumn("SubjectModified",       "BOOLEAN",   False, "True if Abnormal modified the subject during remediation"),
        MdeColumn("SuspiciousContent",     "STRING[]",  False, "List of suspicious content indicators identified"),
        MdeColumn("RemediationStatus",     "STRING",    False, "Auto-remediated | ManualRemediation | Pending | NotRemediated"),
        MdeColumn("RemediationTimestamp",  "TIMESTAMP", True,  "When remediation action was taken"),                      # -- nullable
        MdeColumn("AttachmentCount",       "INT",       True,  "Number of attachments"),                                  # -- nullable
        MdeColumn("AttachmentNames",       "STRING[]",  True,  "Attachment filenames"),                                   # -- nullable
        MdeColumn("AttachmentSHA256",      "STRING[]",  True,  "SHA-256 hashes of attachments"),                          # -- nullable
        MdeColumn("UrlCount",              "INT",       True,  "Number of URLs in message"),                              # -- nullable
        MdeColumn("SuspiciousUrls",        "STRING[]",  True,  "URLs flagged as suspicious by Abnormal"),                 # -- nullable
        MdeColumn("CampaignId",            "STRING",    True,  "Abnormal campaign identifier if clustered"),              # -- nullable
        MdeColumn("AdditionalFields",      "JSON",      False, "Full raw Abnormal threat payload"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType", "SenderFromAddress", "RecipientEmailAddress",
    }),
)

_ABNORMAL_CASE_EVENTS = MdeTable(
    name="AbnormalCaseEvents",
    description="One row per Abnormal Security case lifecycle event (case open, update, close)",
    columns=(
        MdeColumn("Timestamp",              "TIMESTAMP", False, "Case event timestamp (UTC)"),
        MdeColumn("ReportId",               "STRING",    False, "Abnormal case ID"),
        MdeColumn("ActionType",             "STRING",    False, "CaseOpened | CaseUpdated | CaseClosed | ThreatAdded | AnalystComment"),
        MdeColumn("CaseSeverity",           "STRING",    False, "High | Medium | Low"),
        MdeColumn("CaseStatus",             "STRING",    False, "New | Investigating | Closed"),
        MdeColumn("CaseType",               "STRING",    False, "AccountTakeover | BEC | Phishing | Malware | Policy"),
        MdeColumn("ThreatCount",            "INT",       False, "Number of threats included in the case"),
        MdeColumn("AffectedEmployeeCount",  "INT",       False, "Number of employees affected by threats in this case"),
        MdeColumn("AffectedAccountCount",   "INT",       False, "Number of distinct email accounts involved"),
        MdeColumn("FirstObservedTimestamp", "TIMESTAMP", False, "Timestamp of the earliest threat in the case"),
        MdeColumn("LastObservedTimestamp",  "TIMESTAMP", False, "Timestamp of the most recent threat in the case"),
        MdeColumn("RemediationStatus",      "STRING",    False, "Auto-remediated | ManualRemediation | Pending | NotRemediated"),
        MdeColumn("RemediationTimestamp",   "TIMESTAMP", True,  "When case remediation completed"),                       # -- nullable
        MdeColumn("AnalystAssigned",        "STRING",    True,  "Email of analyst assigned to the case"),                 # -- nullable
        MdeColumn("ResolutionReason",       "STRING",    True,  "Resolution notes or reason when case is closed"),        # -- nullable
        MdeColumn("AdditionalFields",       "JSON",      False, "Full raw Abnormal case payload"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ReportId", "ActionType",
    }),
)


# ---------------------------------------------------------------------------
# Core device telemetry — additional tables
# ---------------------------------------------------------------------------

_DEVICE_IMAGE_LOAD_EVENTS = MdeTable(
    name="DeviceImageLoadEvents",
    description="DLL and module load events — critical for detecting DLL hijacking and reflective injection",
    columns=(
        MdeColumn("Timestamp",                       "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                        "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                      "STRING",    False, "Device hostname"),
        MdeColumn("ActionType",                      "STRING",    False, "ImageLoaded"),
        MdeColumn("FileName",                        "STRING",    False, "Name of the loaded module or DLL"),
        MdeColumn("FolderPath",                      "STRING",    False, "Full path to the loaded module"),
        MdeColumn("SHA1",                            "STRING",    False, "SHA-1 hash of the loaded file"),
        MdeColumn("SHA256",                          "STRING",    False, "SHA-256 hash of the loaded file"),
        MdeColumn("MD5",                             "STRING",    False, "MD5 hash of the loaded file"),
        MdeColumn("IsSigned",                        "BOOLEAN",   False, "Whether the file carries a digital signature"),
        MdeColumn("IsCodeSigningCertValid",           "BOOLEAN",   True,  "Whether the code signing certificate chain is valid"),
        MdeColumn("Signer",                          "STRING",    True,  "Entity that signed the file"),
        MdeColumn("SignerHash",                      "STRING",    True,  "Hash of the signing certificate"),
        MdeColumn("Issuer",                          "STRING",    True,  "Certificate issuing CA"),
        MdeColumn("IssuerHash",                      "STRING",    True,  "Hash of the issuer certificate"),
        MdeColumn("InitiatingProcessFileName",       "STRING",    False, "Process that triggered the load"),
        MdeColumn("InitiatingProcessId",             "INT",       False, "PID of the initiating process"),
        MdeColumn("InitiatingProcessCommandLine",    "STRING",    False, "Command line of the initiating process"),
        MdeColumn("InitiatingProcessAccountName",    "STRING",    False, "Account running the initiating process"),
        MdeColumn("InitiatingProcessSHA256",         "STRING",    False, "SHA-256 of the initiating process binary"),
        MdeColumn("InitiatingProcessParentId",       "INT",       True,  "PID of the initiating process parent"),
        MdeColumn("InitiatingProcessParentFileName", "STRING",    True,  "Filename of the initiating process parent"),
        MdeColumn("ReportId",                        "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ActionType", "FileName", "ReportId",
    }),
)

_DEVICE_INFO = MdeTable(
    name="DeviceInfo",
    description="Device inventory snapshot — OS, domain join state, sensor version, and merged device identifiers",
    columns=(
        MdeColumn("Timestamp",          "TIMESTAMP", False, "UTC snapshot timestamp"),
        MdeColumn("DeviceId",           "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",         "STRING",    False, "Device hostname"),
        MdeColumn("ClientVersion",      "STRING",    False, "MDE sensor version installed on the device"),
        MdeColumn("PublicIP",           "STRING",    True,  "Last observed public IP"),
        MdeColumn("OSArchitecture",     "STRING",    False, "x64 | x86 | arm64"),
        MdeColumn("OSPlatform",         "STRING",    False, "Windows10 | Windows11 | WindowsServer2019 | macOS | Linux | etc."),
        MdeColumn("OSBuild",            "INT",       True,  "OS build number"),
        MdeColumn("OSVersion",          "STRING",    True,  "OS version string"),
        MdeColumn("OSDistribution",     "STRING",    True,  "Linux distribution name, if applicable"),
        MdeColumn("OSVersionInfo",      "STRING",    True,  "Additional OS version detail string"),
        MdeColumn("IsAzureADJoined",    "BOOLEAN",   False, "True if device is Azure AD joined"),
        MdeColumn("AadDeviceId",        "STRING",    True,  "Azure AD device object ID"),
        MdeColumn("LoggedOnUsers",      "JSON",      True,  "JSON array of currently logged-on user objects"),
        MdeColumn("RegistryDeviceTag",  "STRING",    True,  "Device tag written via registry"),
        MdeColumn("DeviceCategory",     "STRING",    True,  "Endpoint | Server | NetworkDevice | IoT | etc."),
        MdeColumn("DeviceType",         "STRING",    True,  "Workstation | Server | DomainController | etc."),
        MdeColumn("DeviceSubtype",      "STRING",    True,  "Additional device subtype classification"),
        MdeColumn("MergedDeviceIds",    "STRING[]",  True,  "Previous DeviceId values merged into this record"),
        MdeColumn("MergedToDeviceId",   "STRING",    True,  "DeviceId this record was merged into, if applicable"),
        MdeColumn("ReportId",           "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "ReportId",
    }),
)

_DEVICE_NETWORK_INFO = MdeTable(
    name="DeviceNetworkInfo",
    description="Network adapter configuration snapshot — MAC, IPs, DNS, gateway per adapter per device",
    columns=(
        MdeColumn("Timestamp",              "TIMESTAMP", False, "UTC snapshot timestamp"),
        MdeColumn("DeviceId",               "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",             "STRING",    False, "Device hostname"),
        MdeColumn("NetworkAdapterId",       "STRING",    False, "Unique identifier for this network adapter"),
        MdeColumn("NetworkAdapterName",     "STRING",    False, "Adapter name (e.g. Ethernet0, Wi-Fi)"),
        MdeColumn("MacAddress",             "STRING",    False, "MAC address of the adapter"),
        MdeColumn("NetworkAdapterType",     "STRING",    False, "Ethernet | WiFi | Loopback | Tunnel | etc."),
        MdeColumn("NetworkAdapterStatus",   "STRING",    False, "Up | Down | NotPresent | Disconnected"),
        MdeColumn("TunnelType",             "STRING",    True,  "VPN tunnel type if adapter is a tunnel"),
        MdeColumn("IPv4Dhcp",               "STRING",    True,  "IPv4 DHCP server address"),
        MdeColumn("IPv6Dhcp",               "STRING",    True,  "IPv6 DHCP server address"),
        MdeColumn("DefaultGateways",        "STRING[]",  True,  "Default gateway IP addresses for this adapter"),
        MdeColumn("IPAddresses",            "JSON",      True,  "JSON array of IP address and subnet configurations"),
        MdeColumn("DNSAddresses",           "STRING[]",  True,  "Configured DNS server addresses"),
        MdeColumn("ConnectedNetworks",      "JSON",      True,  "Network profile objects connected via this adapter"),
        MdeColumn("NetworkAdapterVendor",   "STRING",    True,  "Hardware vendor of the network adapter"),
        MdeColumn("ReportId",               "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "NetworkAdapterId", "MacAddress", "ReportId",
    }),
)

_DEVICE_FILE_CERTIFICATE_INFO = MdeTable(
    name="DeviceFileCertificateInfo",
    description="Code-signing certificate details for files observed on devices — enables allow/block by cert chain",
    columns=(
        MdeColumn("Timestamp",                       "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("DeviceId",                        "STRING",    False, "Unique device identifier"),
        MdeColumn("DeviceName",                      "STRING",    False, "Device hostname"),
        MdeColumn("SHA1",                            "STRING",    False, "SHA-1 of the signed file — join key to other Device tables"),
        MdeColumn("IsSigned",                        "BOOLEAN",   False, "Whether the file carries a digital signature"),
        MdeColumn("SignatureType",                   "STRING",    False, "Embedded | Catalog | None"),
        MdeColumn("IsCodeSigningCertValid",           "BOOLEAN",   True,  "Whether the signing certificate chain is valid"),
        MdeColumn("Signer",                          "STRING",    True,  "Signer entity name"),
        MdeColumn("SignerHash",                      "STRING",    True,  "Hash of the signing certificate"),
        MdeColumn("Issuer",                          "STRING",    True,  "Issuing CA name"),
        MdeColumn("IssuerHash",                      "STRING",    True,  "Hash of the issuer certificate"),
        MdeColumn("CertificateSerialNumber",         "STRING",    True,  "Certificate serial number"),
        MdeColumn("CrlDistributionPointUrls",        "STRING[]",  True,  "Certificate revocation list (CRL) URLs"),
        MdeColumn("CertificateCreationTime",         "TIMESTAMP", True,  "Certificate valid-from timestamp"),
        MdeColumn("CertificateExpirationTime",       "TIMESTAMP", True,  "Certificate valid-until timestamp"),
        MdeColumn("CertificateCountersignatureTime", "TIMESTAMP", True,  "Authenticode countersignature timestamp"),
        MdeColumn("IsRootSignerMicrosoft",           "BOOLEAN",   True,  "True if the certificate root is Microsoft"),
        MdeColumn("IsTestSigningEnabled",            "BOOLEAN",   True,  "True if test signing mode is active on the device"),
        MdeColumn("ReportId",                        "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "DeviceId", "DeviceName", "SHA1", "IsSigned", "ReportId",
    }),
)


# ---------------------------------------------------------------------------
# Microsoft Defender for Office 365 (MDO) email tables
#
# Email flows through this organization in three stages:
#   1. Proofpoint (initial gateway) — ProofpointMessageEvents / ProofpointClickEvents
#   2. Abnormal Security (post-gateway AI) — AbnormalThreatEvents / AbnormalCaseEvents
#   3. MDO (Exchange Online, final disposition) — EmailEvents / EmailPostDeliveryEvents / etc.
#
# NetworkMessageId (RFC 2822 Message-ID) is the primary join key across all three
# layers. An email blocked by Proofpoint will never appear in EmailEvents.
# ---------------------------------------------------------------------------

_EMAIL_EVENTS = MdeTable(
    name="EmailEvents",
    description="MDO email events — one row per message received by Exchange Online after gateway filtering",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "Email receipt timestamp (UTC)"),
        MdeColumn("NetworkMessageId",      "STRING",    False, "RFC 2822 Message-ID — primary join key across all email tables"),
        MdeColumn("InternetMessageId",     "STRING",    False, "Internet message ID (matches NetworkMessageId in most cases)"),
        MdeColumn("SenderFromAddress",     "STRING",    False, "5322.From header address"),
        MdeColumn("SenderFromDomain",      "STRING",    False, "Domain extracted from 5322.From"),
        MdeColumn("SenderDisplayName",     "STRING",    False, "Display name shown in the From header"),
        MdeColumn("SenderIPv4",            "STRING",    True,  "Sending MTA IPv4 address"),
        MdeColumn("SenderIPv6",            "STRING",    True,  "Sending MTA IPv6 address"),
        MdeColumn("SenderMailFromAddress", "STRING",    False, "5321.MailFrom (envelope sender)"),
        MdeColumn("SenderMailFromDomain",  "STRING",    False, "Domain of the envelope sender"),
        MdeColumn("RecipientEmailAddress", "STRING",    False, "Primary recipient email address"),
        MdeColumn("RecipientObjectId",     "STRING",    True,  "Azure AD object ID of the recipient"),
        MdeColumn("Subject",               "STRING",    False, "Email subject line"),
        MdeColumn("ConfidenceLevel",       "STRING",    False, "None | Low | Normal | High — MDO confidence in the verdict"),
        MdeColumn("DeliveryAction",        "STRING",    False, "Delivered | Blocked | Replaced | Quarantined"),
        MdeColumn("DeliveryLocation",      "STRING",    False, "Inbox | JunkFolder | DeletedItems | Quarantine | External | Failed | Dropped | Forwarded"),
        MdeColumn("EmailActionPolicy",     "STRING",    True,  "Anti-spam or anti-phish policy that determined the final action"),
        MdeColumn("EmailActionPolicyGuid", "STRING",    True,  "GUID of the governing policy"),
        MdeColumn("AttachmentCount",       "INT",       False, "Number of attachments on the message"),
        MdeColumn("UrlCount",              "INT",       False, "Number of URLs found in the message body"),
        MdeColumn("EmailLanguage",         "STRING",    True,  "Detected language of the email body"),
        MdeColumn("AuthenticationDetails", "JSON",      False, "SPF, DKIM, DMARC, and CompAuth verdicts as a JSON object"),
        MdeColumn("ThreatNames",           "STRING[]",  True,  "Threat names identified by MDO engines"),
        MdeColumn("ThreatTypes",           "STRING[]",  True,  "Phish | Malware | Spam | etc."),
        MdeColumn("DetectionMethods",      "JSON",      True,  "MDO detection engines and signals that flagged this message"),
        MdeColumn("OrgLevelPolicy",        "STRING",    True,  "Org-level policy that determined the action"),
        MdeColumn("OrgLevelAction",        "STRING",    True,  "Action taken at the org level"),
        MdeColumn("UserLevelPolicy",       "STRING",    True,  "User-level policy override if applicable"),
        MdeColumn("UserLevelAction",       "STRING",    True,  "Action taken at the user level"),
        MdeColumn("Directionality",        "STRING",    False, "Inbound | Outbound | Intraorg"),
        MdeColumn("Connectors",            "STRING",    True,  "Inbound connector name used for delivery"),
        MdeColumn("ReportId",              "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress",
        "DeliveryAction", "Directionality", "ReportId",
    }),
)

_EMAIL_ATTACHMENT_INFO = MdeTable(
    name="EmailAttachmentInfo",
    description="MDO attachment metadata — one row per attachment per message; join to EmailEvents on NetworkMessageId",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "Email receipt timestamp (UTC)"),
        MdeColumn("NetworkMessageId",      "STRING",    False, "Message-ID — join key to EmailEvents"),
        MdeColumn("SenderFromAddress",     "STRING",    False, "Sender email address"),
        MdeColumn("RecipientEmailAddress", "STRING",    False, "Recipient email address"),
        MdeColumn("FileName",              "STRING",    False, "Attachment filename"),
        MdeColumn("FileType",              "STRING",    True,  "File extension or detected MIME type"),
        MdeColumn("SHA256",                "STRING",    True,  "SHA-256 of the attachment — join to DeviceFileEvents for endpoint correlation"),
        MdeColumn("MalwareFamily",         "STRING",    True,  "Malware family name if MDO identified malware"),
        MdeColumn("ThreatNames",           "STRING[]",  True,  "Threat names identified by MDO"),
        MdeColumn("ThreatTypes",           "STRING[]",  True,  "Phish | Malware | etc."),
        MdeColumn("DetectionMethods",      "JSON",      True,  "Detection methods that flagged this attachment"),
        MdeColumn("ReportId",              "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "NetworkMessageId", "FileName", "ReportId",
    }),
)

_EMAIL_POST_DELIVERY_EVENTS = MdeTable(
    name="EmailPostDeliveryEvents",
    description="MDO post-delivery actions — ZAP, admin remediations, and retroactive policy enforcement",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "Time the post-delivery action occurred (UTC)"),
        MdeColumn("NetworkMessageId",      "STRING",    False, "Message-ID — join key to EmailEvents"),
        MdeColumn("InternetMessageId",     "STRING",    False, "Internet message ID"),
        MdeColumn("SenderFromAddress",     "STRING",    False, "Sender email address"),
        MdeColumn("RecipientEmailAddress", "STRING",    False, "Recipient email address"),
        MdeColumn("RecipientObjectId",     "STRING",    True,  "Azure AD object ID of the recipient"),
        MdeColumn("DeliveryLocation",      "STRING",    False, "Mailbox folder where the message resided before the action"),
        MdeColumn("Action",                "STRING",    False, "Deleted | Moved | Replaced | Cleared"),
        MdeColumn("ActionType",            "STRING",    False, "ZAP | ManualRemediation | AdminActionRetroactivelyApplied | SystemTimeTravel"),
        MdeColumn("ActionTrigger",         "STRING",    False, "ZAP | Admin | AutoRemediation | SystemTimeTravel"),
        MdeColumn("ActionResult",          "STRING",    False, "Success | Failed | Blocked | Replaced"),
        MdeColumn("DeliveryTimestamp",     "TIMESTAMP", True,  "When the message was originally delivered to the mailbox"),
        MdeColumn("ReportId",              "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "NetworkMessageId", "Action", "ActionType", "ActionResult", "ReportId",
    }),
)

_EMAIL_URL_INFO = MdeTable(
    name="EmailUrlInfo",
    description="MDO URL extraction — one row per URL per message; join to UrlClickEvents on Url + NetworkMessageId",
    columns=(
        MdeColumn("Timestamp",        "TIMESTAMP", False, "Email receipt timestamp (UTC)"),
        MdeColumn("NetworkMessageId", "STRING",    False, "Message-ID — join key to EmailEvents and UrlClickEvents"),
        MdeColumn("Url",              "STRING",    False, "Full URL found in the message"),
        MdeColumn("UrlDomain",        "STRING",    False, "Domain extracted from the URL"),
        MdeColumn("UrlLocation",      "STRING",    True,  "Body | Attachment | Header — where in the message the URL appeared"),
        MdeColumn("UrlChain",         "STRING[]",  True,  "Redirect chain if the URL redirects through intermediate URLs"),
        MdeColumn("ReportId",         "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "NetworkMessageId", "Url", "UrlDomain", "ReportId",
    }),
)

_URL_CLICK_EVENTS = MdeTable(
    name="UrlClickEvents",
    description="MDO Safe Links click events — every URL click detonated through Safe Links rewriting",
    columns=(
        MdeColumn("Timestamp",         "TIMESTAMP", False, "Click event timestamp (UTC)"),
        MdeColumn("Url",               "STRING",    False, "URL that was clicked (pre-rewrite original)"),
        MdeColumn("ActionType",        "STRING",    False, "ClickAllowed | ClickBlocked | UrlErrorPage | UrlScanPending | ClickAllowedByTenantAdmin | ClickBlockedByTenantAdmin"),
        MdeColumn("AccountUpn",        "STRING",    False, "UPN of the user who clicked the URL"),
        MdeColumn("NetworkMessageId",  "STRING",    True,  "Message-ID if the URL came from an email — join to EmailEvents"),
        MdeColumn("Workload",          "STRING",    True,  "Email | Teams | Office — surface where the URL was clicked"),
        MdeColumn("IPAddress",         "STRING",    True,  "IP address from which the click originated"),
        MdeColumn("IsClickedThrough",  "BOOLEAN",   False, "True if user clicked through a Safe Links warning page"),
        MdeColumn("UrlChain",          "STRING[]",  True,  "Full redirect chain traversed at click time"),
        MdeColumn("ThreatTypes",       "STRING[]",  True,  "Threat types associated with the URL at click time"),
        MdeColumn("DetectionMethods",  "JSON",      True,  "Detection methods that flagged the URL"),
        MdeColumn("ReportId",          "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "Url", "ActionType", "AccountUpn", "ReportId",
    }),
)


# ---------------------------------------------------------------------------
# Identity tables — on-premises AD + Azure AD events and enrichment
# ---------------------------------------------------------------------------

_IDENTITY_DIRECTORY_EVENTS = MdeTable(
    name="IdentityDirectoryEvents",
    description="Active Directory and Azure AD directory change events — account/group modifications, privilege grants",
    columns=(
        MdeColumn("Timestamp",                "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("ActionType",               "STRING",    False, "AccountCreated | AccountDeleted | AccountModified | GroupModified | MemberAddedToGroup | MemberRemovedFromGroup | PasswordReset | PasswordChanged | SensitiveGroupModified | AdminPrivilegeGranted | AdminPrivilegeRemoved"),
        MdeColumn("Application",              "STRING",    False, "Application or service that reported the event (e.g. Active Directory)"),
        MdeColumn("TargetAccountUpn",         "STRING",    True,  "UPN of the account being modified"),
        MdeColumn("TargetAccountDisplayName", "STRING",    True,  "Display name of the target account"),
        MdeColumn("TargetDeviceName",         "STRING",    True,  "Target device if the action was on a computer object"),
        MdeColumn("DestinationDeviceName",    "STRING",    True,  "Destination domain controller or target server"),
        MdeColumn("DestinationIPAddress",     "STRING",    True,  "Destination IP address"),
        MdeColumn("DestinationPort",          "INT",       True,  "Destination port"),
        MdeColumn("Protocol",                 "STRING",    True,  "Protocol used: Kerberos | LDAP | NTLM | etc."),
        MdeColumn("AccountUpn",               "STRING",    True,  "UPN of the account that initiated the change"),
        MdeColumn("AccountSid",               "STRING",    True,  "SID of the initiating account"),
        MdeColumn("AccountObjectId",          "STRING",    True,  "Azure AD object ID of the initiating account"),
        MdeColumn("AccountDisplayName",       "STRING",    True,  "Display name of the initiating account"),
        MdeColumn("AccountName",              "STRING",    True,  "sAMAccountName of the initiating account"),
        MdeColumn("AccountDomain",            "STRING",    True,  "Domain of the initiating account"),
        MdeColumn("DeviceName",               "STRING",    True,  "Source device hostname"),
        MdeColumn("IPAddress",                "STRING",    True,  "Source IP address"),
        MdeColumn("Port",                     "INT",       True,  "Source port"),
        MdeColumn("Location",                 "STRING",    True,  "Geolocation string"),
        MdeColumn("ISP",                      "STRING",    True,  "Internet service provider"),
        MdeColumn("CountryCode",              "STRING",    True,  "ISO country code of source IP"),
        MdeColumn("City",                     "STRING",    True,  "City of source IP"),
        MdeColumn("AdditionalFields",         "JSON",      True,  "Event-specific details (changed attributes, group name, etc.)"),
        MdeColumn("ReportId",                 "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ActionType", "Application", "ReportId",
    }),
)

_IDENTITY_QUERY_EVENTS = MdeTable(
    name="IdentityQueryEvents",
    description="LDAP, SAMR, and DNS queries against identity infrastructure — key for recon and enumeration detection",
    columns=(
        MdeColumn("Timestamp",             "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("ActionType",            "STRING",    False, "LdapSearch | SamrObjectQuery | SamrListUsers | SamrListGroups | DnsQuery"),
        MdeColumn("Application",           "STRING",    False, "Application that submitted the query"),
        MdeColumn("QueryType",             "STRING",    False, "LDAP | DNS | SAMR — category of query"),
        MdeColumn("QueryTarget",           "STRING",    False, "Query target: LDAP search base, DNS hostname, or SAMR object"),
        MdeColumn("Protocol",              "STRING",    False, "LDAP | DNS | SAMR"),
        MdeColumn("AccountUpn",            "STRING",    True,  "UPN of the querying account"),
        MdeColumn("AccountSid",            "STRING",    True,  "SID of the querying account"),
        MdeColumn("AccountObjectId",       "STRING",    True,  "Azure AD object ID of the querying account"),
        MdeColumn("AccountDisplayName",    "STRING",    True,  "Display name of the querying account"),
        MdeColumn("AccountName",           "STRING",    True,  "sAMAccountName of the querying account"),
        MdeColumn("AccountDomain",         "STRING",    True,  "Domain of the querying account"),
        MdeColumn("DeviceName",            "STRING",    True,  "Source device hostname"),
        MdeColumn("IPAddress",             "STRING",    True,  "Source IP address"),
        MdeColumn("Port",                  "INT",       True,  "Source port"),
        MdeColumn("DestinationDeviceName", "STRING",    True,  "Target DC, DNS server, or domain"),
        MdeColumn("DestinationIPAddress",  "STRING",    True,  "Target IP address"),
        MdeColumn("DestinationPort",       "INT",       True,  "Target port"),
        MdeColumn("AdditionalFields",      "JSON",      True,  "Query-specific detail: filter, scope, response size, etc."),
        MdeColumn("ReportId",              "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ActionType", "QueryType", "QueryTarget", "ReportId",
    }),
)

_IDENTITY_INFO = MdeTable(
    name="IdentityInfo",
    description="Identity attribute snapshot — HR data, MFA state, directory roles, and email aliases per account",
    columns=(
        MdeColumn("Timestamp",          "TIMESTAMP", False, "Last update timestamp for this identity record (UTC)"),
        MdeColumn("AccountUpn",         "STRING",    False, "User principal name — primary identifier"),
        MdeColumn("AccountObjectId",    "STRING",    False, "Azure AD object ID"),
        MdeColumn("AccountDisplayName", "STRING",    False, "Display name from directory"),
        MdeColumn("AccountDomain",      "STRING",    False, "Account domain"),
        MdeColumn("AccountName",        "STRING",    False, "sAMAccountName"),
        MdeColumn("AccountSid",         "STRING",    True,  "On-premises AD SID"),
        MdeColumn("GivenName",          "STRING",    True,  "First name"),
        MdeColumn("Surname",            "STRING",    True,  "Last name"),
        MdeColumn("Department",         "STRING",    True,  "Department from directory"),
        MdeColumn("JobTitle",           "STRING",    True,  "Job title"),
        MdeColumn("OfficeLocation",     "STRING",    True,  "Office location string"),
        MdeColumn("City",               "STRING",    True,  "City"),
        MdeColumn("Country",            "STRING",    True,  "Country"),
        MdeColumn("IsAccountEnabled",   "BOOLEAN",   False, "True if the account is enabled in the directory"),
        MdeColumn("Manager",            "STRING",    True,  "UPN of the account manager"),
        MdeColumn("Phone",              "STRING",    True,  "Phone number"),
        MdeColumn("MFAEnabled",         "BOOLEAN",   True,  "True if MFA is enforced for this account"),
        MdeColumn("AssignedRoles",      "STRING[]",  True,  "Azure AD directory roles assigned to the account"),
        MdeColumn("EmailAddress",       "STRING",    True,  "Primary SMTP address"),
        MdeColumn("ProxyAddresses",     "STRING[]",  True,  "All email aliases (proxy addresses)"),
        MdeColumn("Tags",               "STRING[]",  True,  "Custom identity tags, e.g. HVA, Executive, ServiceAccount"),
        MdeColumn("OnPremSid",          "STRING",    True,  "On-premises AD SID (explicit alias for AccountSid in hybrid environments)"),
        MdeColumn("CloudSid",           "STRING",    True,  "Azure AD SID"),
        MdeColumn("ReportId",           "STRING",    False, "Unique record identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "AccountUpn", "AccountObjectId", "IsAccountEnabled", "ReportId",
    }),
)

_IDENTITY_ACCOUNT_INFO = MdeTable(
    name="IdentityAccountInfo",
    description="Account object snapshot — SIDs, license state, account type, and lifecycle attributes from Azure AD and on-prem AD",
    columns=(
        MdeColumn("Timestamp",          "TIMESTAMP", False, "Record update timestamp (UTC)"),
        MdeColumn("AccountObjectId",    "STRING",    False, "Azure AD object ID — primary key for this table"),
        MdeColumn("AccountUpn",         "STRING",    False, "User principal name"),
        MdeColumn("AccountDisplayName", "STRING",    False, "Display name"),
        MdeColumn("AccountDomain",      "STRING",    False, "Account domain"),
        MdeColumn("AccountName",        "STRING",    False, "sAMAccountName"),
        MdeColumn("AccountSid",         "STRING",    True,  "On-premises AD SID"),
        MdeColumn("OnPremSid",          "STRING",    True,  "On-premises AD SID (canonical field name in hybrid environments)"),
        MdeColumn("IsAccountEnabled",   "BOOLEAN",   False, "True if the account is enabled"),
        MdeColumn("IsLicensed",         "BOOLEAN",   True,  "True if the account has at least one M365 license"),
        MdeColumn("AssignedLicenses",   "STRING[]",  True,  "License SKU names assigned to the account"),
        MdeColumn("Department",         "STRING",    True,  "Department"),
        MdeColumn("JobTitle",           "STRING",    True,  "Job title"),
        MdeColumn("Manager",            "STRING",    True,  "Manager UPN"),
        MdeColumn("OfficeLocation",     "STRING",    True,  "Office location"),
        MdeColumn("AccountType",        "STRING",    True,  "User | ServiceAccount | Computer | SharedMailbox | Guest"),
        MdeColumn("AdditionalFields",   "JSON",      True,  "Additional account attributes not in core schema"),
        MdeColumn("ReportId",           "STRING",    False, "Unique record identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "AccountObjectId", "AccountUpn", "IsAccountEnabled", "ReportId",
    }),
)

_IDENTITY_EVENTS = MdeTable(
    name="IdentityEvents",
    description="General identity events — catch-all for identity-related actions not covered by DirectoryEvents or QueryEvents",
    columns=(
        MdeColumn("Timestamp",                "TIMESTAMP", False, "UTC event timestamp"),
        MdeColumn("ActionType",               "STRING",    False, "Event type — varies by Application"),
        MdeColumn("Application",              "STRING",    False, "Application or service that reported the event"),
        MdeColumn("TargetAccountUpn",         "STRING",    True,  "UPN of the target account"),
        MdeColumn("TargetAccountDisplayName", "STRING",    True,  "Display name of the target account"),
        MdeColumn("AccountUpn",               "STRING",    True,  "UPN of the initiating account"),
        MdeColumn("AccountSid",               "STRING",    True,  "SID of the initiating account"),
        MdeColumn("AccountObjectId",          "STRING",    True,  "Azure AD object ID of the initiating account"),
        MdeColumn("AccountDisplayName",       "STRING",    True,  "Display name of the initiating account"),
        MdeColumn("AccountName",              "STRING",    True,  "sAMAccountName of the initiating account"),
        MdeColumn("AccountDomain",            "STRING",    True,  "Domain of the initiating account"),
        MdeColumn("DeviceName",               "STRING",    True,  "Source device hostname"),
        MdeColumn("IPAddress",                "STRING",    True,  "Source IP address"),
        MdeColumn("Port",                     "INT",       True,  "Source port"),
        MdeColumn("DestinationDeviceName",    "STRING",    True,  "Target device hostname"),
        MdeColumn("DestinationIPAddress",     "STRING",    True,  "Target IP address"),
        MdeColumn("DestinationPort",          "INT",       True,  "Target port"),
        MdeColumn("Protocol",                 "STRING",    True,  "Protocol used"),
        MdeColumn("AdditionalFields",         "JSON",      True,  "Event-specific additional detail"),
        MdeColumn("ReportId",                 "STRING",    False, "Unique event identifier"),
    ),
    required_for_ingest=frozenset({
        "Timestamp", "ActionType", "Application", "ReportId",
    }),
)


# ---------------------------------------------------------------------------
# Registry — single source of truth for all table definitions
# ---------------------------------------------------------------------------

MDE_TABLES: dict[str, MdeTable] = {
    t.name: t
    for t in [
        # Core MDE device telemetry
        _DEVICE_PROCESS_EVENTS,
        _DEVICE_NETWORK_EVENTS,
        _DEVICE_FILE_EVENTS,
        _DEVICE_REGISTRY_EVENTS,
        _DEVICE_LOGON_EVENTS,
        _DEVICE_EVENTS,
        _DEVICE_ALERT_EVENTS,
        _DEVICE_IMAGE_LOAD_EVENTS,
        _DEVICE_INFO,
        _DEVICE_NETWORK_INFO,
        _DEVICE_FILE_CERTIFICATE_INFO,
        # MDO email tables
        _EMAIL_EVENTS,
        _EMAIL_ATTACHMENT_INFO,
        _EMAIL_POST_DELIVERY_EVENTS,
        _EMAIL_URL_INFO,
        _URL_CLICK_EVENTS,
        # Identity tables
        _IDENTITY_LOGON_EVENTS,
        _IDENTITY_DIRECTORY_EVENTS,
        _IDENTITY_QUERY_EVENTS,
        _IDENTITY_INFO,
        _IDENTITY_ACCOUNT_INFO,
        _IDENTITY_EVENTS,
        # Cloud application
        _CLOUD_APP_EVENTS,
        # Third-party security data
        _AWS_CLOUDTRAIL_EVENTS,
        _CLOUDFLARE_HTTP_EVENTS,
        _CLOUDFLARE_FIREWALL_EVENTS,
        _CLOUDFLARE_DNS_EVENTS,
        _ZSCALER_WEB_EVENTS,
        _ZSCALER_DNS_EVENTS,
        _PROOFPOINT_MESSAGE_EVENTS,
        _PROOFPOINT_CLICK_EVENTS,
        _ABNORMAL_THREAT_EVENTS,
        _ABNORMAL_CASE_EVENTS,
    ]
}


# ---------------------------------------------------------------------------
# ActionType enumerations — exact MDE values only. No invented strings.
# Empty list = ActionType is freeform or not applicable for that table.
# ---------------------------------------------------------------------------

ACTION_TYPES: dict[str, list[str]] = {
    # Core device telemetry
    "DeviceImageLoadEvents": [
        "ImageLoaded",
    ],
    "DeviceInfo": [],           # Snapshot table — no ActionType enumeration
    "DeviceNetworkInfo": [],    # Snapshot table — no ActionType enumeration
    "DeviceFileCertificateInfo": [],  # Lookup table — no ActionType enumeration
    # MDO email tables
    "EmailEvents": [
        "Delivered",
        "Blocked",
        "Replaced",
        "Quarantined",
    ],
    "EmailAttachmentInfo": [],  # Metadata per attachment — no ActionType
    "EmailPostDeliveryEvents": [
        "ZAP",
        "ManualRemediation",
        "AdminActionRetroactivelyApplied",
        "SystemTimeTravel",
    ],
    "EmailUrlInfo": [],         # URL metadata per message — no ActionType
    "UrlClickEvents": [
        "ClickAllowed",
        "ClickBlocked",
        "UrlErrorPage",
        "UrlScanPending",
        "ClickAllowedByTenantAdmin",
        "ClickBlockedByTenantAdmin",
    ],
    # Identity tables
    "IdentityDirectoryEvents": [
        "AccountCreated",
        "AccountDeleted",
        "AccountModified",
        "GroupModified",
        "MemberAddedToGroup",
        "MemberRemovedFromGroup",
        "PasswordReset",
        "PasswordChanged",
        "SensitiveGroupModified",
        "AdminPrivilegeGranted",
        "AdminPrivilegeRemoved",
    ],
    "IdentityQueryEvents": [
        "LdapSearch",
        "SamrObjectQuery",
        "SamrListUsers",
        "SamrListGroups",
        "DnsQuery",
    ],
    "IdentityInfo": [],         # Snapshot/enrichment table — no ActionType enumeration
    "IdentityAccountInfo": [],  # Snapshot/enrichment table — no ActionType enumeration
    "IdentityEvents": [],       # Freeform — ActionType varies by Application
    "DeviceProcessEvents": [
        "ProcessCreated",
        "ProcessInjected",
        "OpenProcessApiCall",
        "CreateRemoteThreadApiCall",
    ],
    "DeviceNetworkEvents": [
        "ConnectionSuccess",
        "ConnectionFailed",
        "ConnectionFound",
        "InboundConnectionAccepted",
        "ListeningConnectionCreated",
    ],
    "DeviceFileEvents": [
        "FileCreated",
        "FileModified",
        "FileDeleted",
        "FileRenamed",
        "FileCopied",
    ],
    "DeviceRegistryEvents": [
        "RegistryKeyCreated",
        "RegistryKeyDeleted",
        "RegistryValueSet",
        "RegistryValueDeleted",
    ],
    "DeviceLogonEvents": [
        "LogonSuccess",
        "LogonFailed",
        "LogonAttempted",
    ],
    "DeviceEvents": [
        "AntivirusDetection",
        "AntivirusActionTaken",
        "PowerShellCommand",
        "BrowserLaunchedToOpenUrl",
        "SafeBrowsingUrlWarning",
        "SmartScreenUrlWarning",
        "SmartScreenAppWarning",
    ],
    "DeviceAlertEvents": [],   # AlertId is the key identifier — no ActionType enum
    "IdentityLogonEvents": [
        "LogonSuccess",
        "LogonFailed",
    ],
    "CloudAppEvents": [],       # ActionType is freeform in CloudAppEvents
    "AWSCloudTrailEvents": [
        "ApiCall",
        "DataAccess",
        "DataWrite",
        "ManagementRead",
        "ManagementWrite",
        "AuthAttempt",
        "TokenIssued",
        "ConfigChange",
        "InsightEvent",
    ],
    "CloudflareHttpEvents": [
        "HttpRequest",
        "HttpBlocked",
        "HttpChallenged",
        "HttpManagedChallenge",
        "BotDetected",
        "DDoSMitigation",
        "RateLimited",
    ],
    "CloudflareFirewallEvents": [
        "FirewallBlock",
        "FirewallChallenge",
        "FirewallManagedChallenge",
        "FirewallAllow",
        "FirewallLog",
        "FirewallSkip",
        "RateLimitBlock",
        "WAFBlock",
        "CountryBlock",
        "L4Block",
    ],
    "CloudflareDnsEvents": [
        "DnsQuery",
        "DnsBlock",
        "DnsNXDomain",
        "DnsServFail",
        "DnsThreatMatch",
        "DnsPolicyMatch",
    ],
    "ZscalerWebEvents": [
        "WebAllow",
        "WebBlock",
        "WebCautioned",
        "MalwareDetected",
        "DlpViolation",
        "SslBypass",
        "SslBlock",
        "FileBlocked",
        "AppControlBlock",
        "QuarantinedFile",
    ],
    "ZscalerDnsEvents": [
        "DnsAllow",
        "DnsBlock",
        "DnsThreatMatch",
        "DnsNXDomain",
        "DnsServFail",
        "DnsSinkhole",
    ],
    "ProofpointMessageEvents": [
        "Delivered",
        "Quarantined",
        "Blocked",
        "SpamFiltered",
        "BulkFiltered",
        "PhishFiltered",
        "MalwareBlocked",
        "ImpostorBlocked",
        "SandboxBlocked",
    ],
    "ProofpointClickEvents": [
        "UrlClicked",
        "UrlBlocked",
        "UrlPermitted",
        "SmartSearchBlock",
    ],
    "AbnormalThreatEvents": [
        "ThreatDetected",
        "ThreatRemediated",
        "ThreatReleased",
        "FalsePositive",
    ],
    "AbnormalCaseEvents": [
        "CaseOpened",
        "CaseUpdated",
        "CaseClosed",
        "ThreatAdded",
        "AnalystComment",
    ],
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def get_table(table_name: str) -> MdeTable:
    """Return the MdeTable for the given name.

    Raises KeyError with a descriptive message if the table is not registered.
    Never returns None — callers depend on a valid MdeTable or an exception.
    """
    try:
        return MDE_TABLES[table_name]
    except KeyError:
        valid = sorted(MDE_TABLES.keys())
        raise KeyError(
            f"Unknown MDE table '{table_name}'. "
            f"Valid tables: {valid}"
        )


def get_column_names(table_name: str) -> set[str]:
    """Return the set of valid column names for the given table.

    Used by the KQL transpiler to validate column references.
    Case-sensitive — 'DeviceName' and 'devicename' are not the same.
    """
    return {c.name for c in get_table(table_name).columns}


def validate_columns(table_name: str, columns: list[str]) -> list[str]:
    """Return column names that are NOT valid for the given table.

    Empty list means all columns are valid.
    Used by:
      - KQL transpiler: warn on unknown columns during transpilation
      - Detection rule validator: reject mde_portable rules with invalid columns
      - Test suite: assert FP-XXXX rules use only real MDE columns
    """
    table = MDE_TABLES.get(table_name)
    if table is None:
        return list(columns)  # Unknown table — treat all columns as invalid
    valid = {c.name for c in table.columns}
    return [c for c in columns if c not in valid]


def get_duckdb_view_sql(storage_root: str) -> list[str]:
    """Generate CREATE OR REPLACE VIEW statements for all MDE tables.

    Each view reads all Parquet files matching the hive-style partition path:
      {storage_root}/{TableName}/{year}/{month}/{day}/data.parquet

    union_by_name=True handles schema evolution across files written at different
    times — new columns are added as NULL rather than causing a schema mismatch.

    Returns one SQL string per table. Called once at DuckDB pool startup.
    """
    statements = []
    for table_name in MDE_TABLES:
        # Forward slashes work on both Windows and Linux in DuckDB glob patterns
        glob_path = f"{storage_root}/{table_name}/*/*/*/data.parquet".replace("\\", "/")
        sql = (
            f"CREATE OR REPLACE VIEW {table_name} AS\n"
            f"SELECT * FROM read_parquet(\n"
            f"  '{glob_path}',\n"
            f"  union_by_name=True\n"
            f");"
        )
        statements.append(sql)
    return statements


# ---------------------------------------------------------------------------
# Self-validation — runs at import time to catch schema drift immediately
# ---------------------------------------------------------------------------

def _validate_registry() -> None:
    """Assert internal consistency of MDE_TABLES and ACTION_TYPES.

    Checks:
    - Every table in ACTION_TYPES is in MDE_TABLES
    - Every table in MDE_TABLES has at least one column
    - Every table has a 'Timestamp' column of type TIMESTAMP
    - Every table has a 'ReportId' column of type STRING
    - No two columns in a table share the same name

    Raises AssertionError with a descriptive message if any check fails.
    This catches schema drift during development immediately at import time.
    """
    for table_name, table in MDE_TABLES.items():
        assert len(table.columns) > 0, \
            f"{table_name} has no columns"
        column_names = [c.name for c in table.columns]
        assert "Timestamp" in column_names, \
            f"{table_name} missing Timestamp column"
        assert "ReportId" in column_names, \
            f"{table_name} missing ReportId column"
        assert len(column_names) == len(set(column_names)), \
            f"{table_name} has duplicate column names: {column_names}"
        for req_col in table.required_for_ingest:
            assert req_col in column_names, \
                f"{table_name}.required_for_ingest references unknown column: {req_col}"

    for table_name in ACTION_TYPES:
        assert table_name in MDE_TABLES, \
            f"ACTION_TYPES references unknown table: {table_name}"


_validate_registry()  # Fail fast — schema errors surface immediately at import

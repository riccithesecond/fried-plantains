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
)


# ---------------------------------------------------------------------------
# Registry — single source of truth for all table definitions
# ---------------------------------------------------------------------------

MDE_TABLES: dict[str, MdeTable] = {
    t.name: t
    for t in [
        _DEVICE_PROCESS_EVENTS,
        _DEVICE_NETWORK_EVENTS,
        _DEVICE_FILE_EVENTS,
        _DEVICE_REGISTRY_EVENTS,
        _DEVICE_LOGON_EVENTS,
        _DEVICE_EVENTS,
        _DEVICE_ALERT_EVENTS,
        _IDENTITY_LOGON_EVENTS,
        _CLOUD_APP_EVENTS,
        _AWS_CLOUDTRAIL_EVENTS,
        _CLOUDFLARE_HTTP_EVENTS,
        _CLOUDFLARE_FIREWALL_EVENTS,
        _CLOUDFLARE_DNS_EVENTS,
        _ZSCALER_WEB_EVENTS,
        _ZSCALER_DNS_EVENTS,
    ]
}


# ---------------------------------------------------------------------------
# ActionType enumerations — exact MDE values only. No invented strings.
# Empty list = ActionType is freeform or not applicable for that table.
# ---------------------------------------------------------------------------

ACTION_TYPES: dict[str, list[str]] = {
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

    for table_name in ACTION_TYPES:
        assert table_name in MDE_TABLES, \
            f"ACTION_TYPES references unknown table: {table_name}"


_validate_registry()  # Fail fast — schema errors surface immediately at import

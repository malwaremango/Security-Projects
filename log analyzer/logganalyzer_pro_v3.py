"""
Python Log Analyzer Pro
Copyright malwaremango
@author: usah5

Verktøyet brukes til å analysere loggfiler og finne
mistenkelig aktivitet som malware, brute-force og
uautoriserte innlogginger.
"""

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import os
import re
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from Evtx.Evtx import Evtx
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


CONFIG_FILE = "log_analyzer_config.json"
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 2
MAX_UI_CARDS = 150
EVTX_BATCH_SIZE = 250

MITRE_TECHNIQUES = {
    "malware": {"technique_id": "T1204", "name": "User Execution"},
    "user_execution": {"technique_id": "T1204", "name": "User Execution"},
    "T1204": {"technique_id": "T1204", "name": "User Execution"},
    "file_tampering": {"technique_id": "T1565", "name": "Data Manipulation"},
    "unauthorized_access": {"technique_id": "T1078", "name": "Valid Accounts"},
    "security_breach": {"technique_id": "T1190", "name": "Exploit Public-Facing Application"},
    "advanced_malware": {"technique_id": "T1014", "name": "Rootkit"},
    "phishing": {"technique_id": "T1566", "name": "Phishing"},
    "data_leakage": {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel"},
    "brute_force": {"technique_id": "T1110", "name": "Brute Force"},
    "credential_dumping": {"technique_id": "T1003", "name": "OS Credential Dumping"},
    "suspicious_execution": {"technique_id": "T1059", "name": "Command and Scripting Interpreter"},
    "javascript_activity": {"technique_id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
    "wmi_execution": {"technique_id": "T1047", "name": "Windows Management Instrumentation"},
    "T1047": {"technique_id": "T1047", "name": "Windows Management Instrumentation"},
    "file_and_directory_discovery": {"technique_id": "T1083", "name": "File and Directory Discovery"},
    "T1083": {"technique_id": "T1083", "name": "File and Directory Discovery"},
    "suspicious_persistence": {"technique_id": "T1053", "name": "Scheduled Task/Job"},
    "dll_side_loading": {"technique_id": "T1574.002", "name": "Hijack Execution Flow: DLL Side-Loading"},
    "T1574.002": {"technique_id": "T1574.002", "name": "Hijack Execution Flow: DLL Side-Loading"},
    "services_file_permissions": {"technique_id": "T1574.010", "name": "Hijack Execution Flow: Services File Permissions Weakness"},
    "T1574.010": {"technique_id": "T1574.010", "name": "Hijack Execution Flow: Services File Permissions Weakness"},
    "suspicious_network": {"technique_id": "T1071", "name": "Application Layer Protocol"},
    "account_manipulation": {"technique_id": "T1098", "name": "Account Manipulation"},
    "security_tool": {"technique_id": "T1588", "name": "Obtain Capabilities"},
    "log_integrity": {"technique_id": "T1070", "name": "Indicator Removal"},
    "authentication_logons": {"technique_id": "T1078", "name": "Valid Accounts"},
    "account_management": {"technique_id": "T1136", "name": "Create Account"},
    "kerberos_ad": {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
    "process_execution": {"technique_id": "T1543", "name": "Create or Modify System Process"},
    "object_share_access": {"technique_id": "T1021", "name": "Remote Services"},
    "policy_firewall": {"technique_id": "T1562", "name": "Impair Defenses"},
    "Mimikatz": {"technique_id": "T1003", "name": "OS Credential Dumping"},
    "ProcDump": {"technique_id": "T1003", "name": "OS Credential Dumping"},
    "PsExec": {"technique_id": "T1570", "name": "Lateral Tool Transfer"},
    "BloodHound": {"technique_id": "T1087", "name": "Account Discovery"},
    "SharpHound": {"technique_id": "T1087", "name": "Account Discovery"},
    "Rubeus": {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
    "LaZagne": {"technique_id": "T1555", "name": "Credentials from Password Stores"},
}


def get_technique_info(key_or_label):
    if not key_or_label:
        return ("T0000", "Unmapped Activity")
    if key_or_label in MITRE_TECHNIQUES:
        info = MITRE_TECHNIQUES[key_or_label]
        return (info["technique_id"], info["name"])
    cleaned = key_or_label.replace("Security Tool:", "").replace("Malware:", "").strip()
    if cleaned in MITRE_TECHNIQUES:
        info = MITRE_TECHNIQUES[cleaned]
        return (info["technique_id"], info["name"])
    normalized = key_or_label.lower().strip().replace(" ", "_")
    if normalized in MITRE_TECHNIQUES:
        info = MITRE_TECHNIQUES[normalized]
        return (info["technique_id"], info["name"])
    if key_or_label.startswith("Security Tool:"):
        return ("T1588", "Obtain Capabilities")
    if key_or_label.startswith("Malware:"):
        return ("T1204", "User Execution")
    return ("T0000", key_or_label.replace("_", " ").title())


patterns = {
    "malware": r"\bmalware\b|\bvirus\b|\btrojan\b|\bransomware\b|\bworm\b|\bspyware\b|\badware\b|\brootkit\b|\bbotnet\b",
    "file_tampering": r"file tampering|unauthorized file modification|file integrity",
    "unauthorized_access": r"unauthorized access|login failure|invalid login|access denied|failed login|authentication failure|authentication failed",
    "security_breach": r"security breach|data breach|intrusion detected|unauthorized entry",
    "advanced_malware": r"zero-day|advanced persistent threat|\bapt\b|rootkit",
    "phishing": r"phishing|spear phishing|fraudulent email|credential harvesting",
    "data_leakage": r"data leakage|data exfiltration|information leak|data theft",
    "credential_dumping": r"mimikatz|sekurlsa|lsadump|kerberos::|privilege::debug|token::elevate|samdump|procdump.*lsass|comsvcs\.dll",
    "suspicious_execution": r"powershell.*-enc(?:odedcommand)?|frombase64string|downloadstring|invoke-expression|invoke-mimikatz|rundll32.*javascript:|regsvr32.*scrobj",
    "wmi_execution": r"\bwmic\b|win32_process|process call create|wmiprvse\.exe|windows management instrumentation",
    "file_and_directory_discovery": r"file and directory discovery|\b(?:dir|tree|get-childitem|gci)\b.*(?:/s\b|-recurse|system32|users\\|appdata)|\bfind\s+/\s+-name\b",
    "suspicious_persistence": r"scheduled task created|new service installed|registry run key|startup folder|persistence mechanism",
    "dll_side_loading": r"dll side-loading|dll sideloading|side-load|hijack execution flow|dll hijack",
    "services_file_permissions": r"services file permissions weakness|service binary permissions|weak service permissions|icacls.*service|subinacl.*service",
    "suspicious_network": r"command and control|c2 connection|reverse shell|suspicious outbound connection",
    "account_manipulation": r"new user created|user account created|account added to administrators|privilege escalation|password changed",
    "log_integrity": r"event logging service shutdown|security event log cleared|audit log cleared|audit log full",
    "authentication_logons": r"successful logon|failed logon|user logoff|explicit credentials logon|special admin privileges assigned",
    "account_management": r"user account created|user account enabled|user account deleted|added to security group|user account locked out",
    "kerberos_ad": r"kerberos tgt requested|kerberos service ticket requested|kerberos pre-auth failed|ntlm credential validation",
    "process_execution": r"new process created|new service installed|scheduled task created",
    "object_share_access": r"file registry handle requested|object accessed|network share accessed|detailed network share check",
    "policy_firewall": r"system audit policy changed|windows firewall rule added|windows firewall rule deleted",
}

malware_names = [
    "Emotet", "TrickBot", "QakBot", "Dridex", "Zeus", "SpyEye",
    "WannaCry", "NotPetya", "LockBit", "BlackCat", "REvil", "Conti",
    "Ryuk", "Maze", "Sodinokibi", "DarkSide", "BlackMatter",
    "Agent Tesla", "Formbook", "Lokibot", "RedLine", "Raccoon",
    "AsyncRAT", "NjRAT", "Quasar", "Remcos", "NanoCore",
    "PlugX", "ShadowPad", "Gh0st", "Poison Ivy",
    "Mirai", "Gafgyt", "Mozi", "Hajime",
    "Stuxnet", "Flame", "Duqu", "Equation Group",
]

security_tools = [
    "Cobalt Strike", "Metasploit", "Mimikatz", "BloodHound",
    "Impacket", "Rubeus", "LaZagne", "PowerSploit",
    "SharpHound", "PsExec", "ProcDump",
]

COMPILED_MALWARE_PATTERNS = {
    name: re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE) for name in malware_names
}
COMPILED_TOOL_PATTERNS = {
    name: re.compile(re.escape(name), re.IGNORECASE) for name in security_tools
}

severity = {
    "malware": "HIGH",
    "advanced_malware": "CRITICAL",
    "unauthorized_access": "HIGH",
    "security_breach": "CRITICAL",
    "phishing": "MEDIUM",
    "data_leakage": "CRITICAL",
    "file_tampering": "MEDIUM",
    "brute_force": "HIGH",
    "credential_dumping": "HIGH",
    "suspicious_execution": "HIGH",
    "javascript_activity": "MEDIUM",
    "wmi_execution": "MEDIUM",
    "file_and_directory_discovery": "LOW",
    "suspicious_persistence": "HIGH",
    "dll_side_loading": "HIGH",
    "services_file_permissions": "HIGH",
    "suspicious_network": "HIGH",
    "account_manipulation": "MEDIUM",
    "security_tool": "MEDIUM",
    "log_integrity": "CRITICAL",
    "authentication_logons": "LOW",
    "account_management": "MEDIUM",
    "kerberos_ad": "MEDIUM",
    "process_execution": "MEDIUM",
    "object_share_access": "LOW",
    "policy_firewall": "HIGH",
}

severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

remedies = {
    "malware": "Isoler berørt system og kjør full malware-skanning.",
    "file_tampering": "Kontroller filintegritet og gjenopprett berørte filer fra backup.",
    "unauthorized_access": "Kontroller kontoaktivitet, tilbakestill passord og vurder MFA.",
    "security_breach": "Isoler berørte systemer og start en hendelsesundersøkelse.",
    "advanced_malware": "Isoler systemet og bruk avanserte endpoint- og threat hunting-verktøy.",
    "phishing": "Undersøk avsender, kontoaktivitet og forbedre e-postfiltrering.",
    "data_leakage": "Finn lekkasjekilden og vurder DLP, tilgangskontroll og logging.",
    "brute_force": "Blokker eller begrens kilde-IP og vurder MFA/rate limiting.",
    "credential_dumping": "Isoler berørt maskin, kontroller LSASS-tilgang og tilbakestill berørte kontoer.",
    "suspicious_execution": "Undersøk prosessens kommandolinje, skriptaktivitet og tilhørende prosesser.",
    "javascript_activity": "Kontroller prosessen som opprettet JavaScript-filen, filens hash/signatur og eventuell kjøring.",
    "wmi_execution": "Undersøk WMI-kommandoer, foreldreprosess og eventuelle prosesser startet via WMI.",
    "file_and_directory_discovery": "Kartlegg hvilken prosess og bruker som søkte etter filer/mapper, og se etter videre aktivitet.",
    "suspicious_persistence": "Undersøk nye tjenester, planlagte oppgaver og registerendringer.",
    "dll_side_loading": "Undersøk om en legitim prosess laster en uautorisert eller mistenkelig DLL fra feil mappe.",
    "services_file_permissions": "Kontroller og stram inn filrettigheter på tjenestens binærfiler og tilhørende mapper.",
    "suspicious_network": "Undersøk nettverkstrafikk, tilkoblinger og mistenkelige IP-adresser.",
    "account_manipulation": "Kontroller kontoendringer, gruppemedlemskap og tilgangsrettigheter.",
    "security_tool": "Undersøk om sikkerhetsverktøyet er autorisert og hvem som startet det.",
    "log_integrity": "Undersøk umiddelbart hvorfor sikkerhetsloggen ble tømt, full eller stoppet.",
    "authentication_logons": "Gjennomgå innloggingsmønstre, eksplisitt legitimasjon og tildeling av privilegier.",
    "account_management": "Verifiser om kontoopprettelse, aktivering, sletting eller gruppeendringer er autorisert.",
    "kerberos_ad": "Kontroller autentiseringslogger for unormale billettforespørsler eller feil.",
    "process_execution": "Undersøk nye prosesser, installerte tjenester og planlagte oppgaver.",
    "object_share_access": "Kontroller tilgang til sensitive filer, registernøkler og delte nettverksressurser.",
    "policy_firewall": "Verifiser endringer i revisjonspolicy og brannmurregler.",
}

WINDOWS_EVENT_HINTS = {
    "1100": "Event logging service shutdown",
    "1102": "Security event log cleared audit log cleared",
    "1104": "Audit log full",
    "4624": "Successful logon",
    "4625": "Failed login authentication failure failed logon",
    "4634": "User logoff",
    "4648": "Explicit credentials logon",
    "4672": "Special admin privileges assigned",
    "4720": "User account created new user created",
    "4722": "User account enabled",
    "4726": "User account deleted",
    "4732": "Account added to administrators added to security group",
    "4740": "User account locked out",
    "4768": "Kerberos TGT requested",
    "4769": "Kerberos service ticket requested",
    "4771": "Failed login authentication failure kerberos pre-auth failed",
    "4776": "Failed login authentication failure ntlm credential validation",
    "4688": "New process created",
    "4697": "New service installed",
    "4698": "Scheduled task created",
    "4656": "File registry handle requested",
    "4663": "Object accessed",
    "5140": "Network share accessed",
    "5145": "Detailed network share check",
    "4719": "System audit policy changed",
    "4946": "Windows firewall rule added",
    "4948": "Windows firewall rule deleted",
}

WINDOWS_EVENT_ID_CONTEXT_RE = re.compile(
    r"(?:<\s*EventID[^>]*>\s*(\d{3,5})\s*<\s*/\s*EventID\s*>"
    r"|\bEvent[_\s-]?ID\s*[:=]\s*['\"]?(\d{3,5})['\"]?)",
    re.IGNORECASE,
)


def extract_windows_event_ids(line):
    found = []
    for match in WINDOWS_EVENT_ID_CONTEXT_RE.finditer(line):
        eid = match.group(1) or match.group(2)
        if eid and eid not in found:
            found.append(eid)
    return found


def enrich_with_event_hints(line):
    event_ids = extract_windows_event_ids(line)
    if not event_ids:
        return line
    hints = [WINDOWS_EVENT_HINTS[eid] for eid in event_ids if eid in WINDOWS_EVENT_HINTS]
    if not hints:
        return line
    return f"{line} | {' ; '.join(hints)}"


IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
SYSTEM_TIME_ATTR_RE = re.compile(
    r"""SystemTime\s*=\s*['"](\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)['"]""",
    re.IGNORECASE,
)
ISO_PATTERN = re.compile(
    r"(?<!\S)(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?!\S)"
)
TIMESTAMP_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})"),
    re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})"),
]
APACHE_CLF_PATTERN = re.compile(
    r"\b(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s*[+-]\d{4})?)\b"
)
SYSLOG_PATTERN = re.compile(
    r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b"
)


@dataclass
class FindingEvaluation:
    status: str
    confidence: str
    reasons: list


EXECUTION_EVIDENCE_RE = re.compile(
    r"(?:\b(?:NewProcessName|CommandLine|ProcessName|Image|ParentImage)\s*[:=]"
    r"|\b(?:Executed|Launched|Started|Invoked|Ran)\b"
    r"|\b(?:powershell|pwsh|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe)\b"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b)",
    re.IGNORECASE,
)
PRIVILEGED_USER_RE = re.compile(
    r"\b(?:root|administrator|system|domain admin|enterprise admins|sudo)\b",
    re.IGNORECASE,
)
OFF_HOURS_RE = re.compile(r"\b(?:0[0-5]|2[23]):\d{2}(?::\d{2})?\b")


def evaluate_execution_context(category, raw_line, timestamp=None):
    base_key = category.split(":", 1)[0].strip().lower().replace(" ", "_")
    reasons = []
    has_exec = bool(EXECUTION_EVIDENCE_RE.search(raw_line))
    has_priv_user = bool(PRIVILEGED_USER_RE.search(raw_line))
    has_off_hours = (
        timestamp is not None and (timestamp.hour >= 22 or timestamp.hour < 6)
    ) or bool(OFF_HOURS_RE.search(raw_line))

    if has_exec:
        reasons.append("prosess-/kommandolinje- eller nettverkskontekst")
    if has_priv_user:
        reasons.append("privilegert bruker/konto")
    if has_off_hours:
        reasons.append("utenfor normal arbeidstid (22:00–06:00)")

    if base_key == "javascript_activity":
        is_invoked = bool(
            re.search(r"\b(?:cscript|wscript|node|rundll32|mshta)\b.*\.js\b", raw_line, re.IGNORECASE)
            or re.search(r"\b(?:executed|started|ran)\b", raw_line, re.IGNORECASE)
        )
        if is_invoked:
            reasons.append("skriptmotor/kjøring observert")
            return FindingEvaluation("confirmed", "High", reasons)
        reasons.append("fil-/regelindikator uten bekreftet skriptkjøring")
        return FindingEvaluation("indicator", "Low", reasons)

    if base_key in {"security_tool", "process_execution", "wmi_execution"}:
        if has_exec and (has_priv_user or has_off_hours):
            return FindingEvaluation("confirmed", "High", reasons)
        if has_exec:
            return FindingEvaluation("confirmed", "Medium", reasons)
        reasons.append("kun omtale/indikator uten bekreftet prosesskjøring")
        return FindingEvaluation("indicator", "Low", reasons)

    if has_exec and has_priv_user:
        return FindingEvaluation("confirmed", "High", reasons)
    if has_exec or has_priv_user or has_off_hours:
        return FindingEvaluation("indicator", "Medium", reasons)

    reasons.append("grunnleggende mønsterindikator")
    return FindingEvaluation("indicator", "Low", reasons)


def escalate_severity(base_sev, status, confidence):
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = order.index(base_sev) if base_sev in order else 1
    if status == "indicator" and confidence == "Low" and idx > 0:
        idx -= 1
    elif status == "confirmed" and confidence == "High" and idx < len(order) - 1:
        idx += 1
    return order[idx]


def create_empty_analysis():
    return {
        "files": [],
        "counts": defaultdict(int),
        "malware": defaultdict(int),
        "ips": defaultdict(lambda: {"activity": defaultdict(int), "total": 0, "severity": "LOW"}),
        "brute_force": [],
        "attack_scenarios": [],
        "timeline": [],
        "details": [],
        "total_lines": 0,
        "log_types": [],
        "finding_stats": {
            "confirmed": 0,
            "indicator": 0,
            "by_category": defaultdict(lambda: {"confirmed": 0, "indicator": 0, "high_conf": 0}),
        },
    }


last_analysis = create_empty_analysis()


def load_patterns():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            patterns.update(data.get("patterns", {}))
            remedies.update(data.get("remedies", {}))
        except Exception as e:
            print("Kunne ikke laste konfigurasjon:", e)


def save_patterns():
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"patterns": patterns, "remedies": remedies}, f, indent=2, ensure_ascii=False)


def detect_log_type(line, source_file=""):
    lower = line.lower()
    if source_file.lower().endswith(".evtx") or "<event" in lower or "schemas.microsoft.com/win/2004/08/events/event" in lower:
        return "Windows Event Log (.evtx)"
    if "cef:" in lower:
        return "CEF / SIEM Security Log"
    if "sshd" in lower or "authentication failure" in lower:
        return "Linux auth.log / SSH"
    if "apache" in lower or "http/1." in lower:
        return "Apache / Web Server"
    if "iis" in lower:
        return "IIS / Web Server"
    if "windows event" in lower or "eventid" in lower or "<eventid" in lower:
        return "Windows Event Log"
    if "firewall" in lower or "iptables" in lower:
        return "Firewall"
    if "scada" in lower or "modbus" in lower or "plc" in lower:
        return "SCADA / ICS"
    if "nginx" in lower:
        return "Nginx / Web Server"
    return "Generic"


def _parse_iso_dt(raw):
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    raw = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw)
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    except ValueError:
        return None


def extract_timestamp(line, reference_year=None):
    m_sys_time = SYSTEM_TIME_ATTR_RE.search(line)
    if m_sys_time:
        dt = _parse_iso_dt(m_sys_time.group(1))
        if dt is not None:
            return dt

    m_iso = ISO_PATTERN.search(line)
    if m_iso:
        dt = _parse_iso_dt(m_iso.group(1))
        if dt is not None:
            return dt

    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            date_part, time_part = match.group(1), match.group(2)
            try:
                fmt = "%Y-%m-%d %H:%M" if len(time_part) == 5 else "%Y-%m-%d %H:%M:%S"
                return datetime.strptime(f"{date_part} {time_part}", fmt)
            except ValueError:
                pass

    m_clf = APACHE_CLF_PATTERN.search(line)
    if m_clf:
        raw_clf = m_clf.group(1).strip()
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
            try:
                return datetime.strptime(raw_clf, fmt).replace(tzinfo=None)
            except ValueError:
                pass

    m_sys = SYSLOG_PATTERN.search(line)
    if m_sys:
        year = reference_year or datetime.now().year
        month_str, day_str, time_str = m_sys.groups()
        try:
            return datetime.strptime(f"{year} {month_str} {int(day_str):02d} {time_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return None


def identify_activity(line, compiled_patterns, malware_patterns, tool_patterns):
    activities = []
    searchable_line = enrich_with_event_hints(line)
    lower_line = searchable_line.lower()

    for name, pattern in compiled_patterns.items():
        if pattern.search(lower_line):
            activities.append(name)
    for name, pattern in malware_patterns.items():
        if pattern.search(searchable_line):
            activities.append(f"Malware: {name}")
    for name, pattern in tool_patterns.items():
        if pattern.search(searchable_line):
            activities.append(f"Security Tool: {name}")

    has_javascript_rule = bool(re.search(r"\bT1059\.007\b|technique_name\s*=\s*JavaScript", line, re.IGNORECASE))
    is_file_create_event = bool(re.search(r"\bEventID\s*[:=]\s*11\b|\bEvent ID\s*[:=]?\s*11\b|<\s*EventID[^>]*>\s*11\s*<", line, re.IGNORECASE))
    has_script_file = bool(re.search(r"(?:\.js|\.jse)(?:\b|$|\[\d+\])", line, re.IGNORECASE))
    has_file_create_context = bool(re.search(r"\b(?:TargetFilename|TargetObject|Created|FileName|Description)\s*[:=]", line, re.IGNORECASE))
    if has_javascript_rule or (is_file_create_event and has_script_file and has_file_create_context):
        activities.append("javascript_activity")

    if re.search(r"\bT1574\.002\b|technique_name\s*=\s*DLL Side-Loading", line, re.IGNORECASE):
        activities.append("dll_side_loading")
    if re.search(r"\bT1574\.010\b|Services File Permissions Weakness", line, re.IGNORECASE):
        activities.append("services_file_permissions")
    if re.search(r"\bT1047\b|Windows Management Instrumentation", line, re.IGNORECASE):
        activities.append("wmi_execution")
    if re.search(r"\bT1083\b|File and Directory Discovery", line, re.IGNORECASE):
        activities.append("file_and_directory_discovery")

    return list(dict.fromkeys(activities))


def detect_brute_force(login_attempts):
    incidents = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    for ip, attempts in login_attempts.items():
        if not any(item[0] for item in attempts):
            continue
        attempts = sorted(attempts, key=lambda x: x[0] if x[0] else datetime.min)
        start_index = 0
        for end_index in range(len(attempts)):
            current_time = attempts[end_index][0]
            if current_time is None:
                continue
            while (
                start_index < end_index
                and attempts[start_index][0] is not None
                and current_time - attempts[start_index][0] > window
            ):
                start_index += 1
            if end_index - start_index + 1 >= BRUTE_FORCE_THRESHOLD:
                relevant = attempts[start_index:end_index + 1]
                incidents.append({
                    "ip": ip,
                    "attempts": len(relevant),
                    "window": BRUTE_FORCE_WINDOW_MINUTES,
                    "severity": "HIGH",
                    "start": relevant[0][0],
                    "end": relevant[-1][0],
                    "lines": [item[1] for item in relevant],
                    "file": relevant[0][2],
                })
                start_index = end_index + 1

    return incidents


def get_top_attack_keys(target_analysis=None):
    data = target_analysis or last_analysis
    counts = data["counts"]
    malware = data["malware"]
    ranked = [(key, val) for key, val in counts.items() if val > 0]
    if malware:
        ranked.append(("malware", sum(malware.values())))
    ranked.sort(key=lambda x: x[1], reverse=True)
    return [key for key, _ in ranked[:5]]


def _has_confirmed_activity(category_key, target_analysis=None):
    data = target_analysis or last_analysis
    stats = data["finding_stats"]["by_category"].get(category_key)
    return bool(stats and stats["confirmed"] > 0)


def detect_attack_scenarios(target_analysis=None):
    data = target_analysis or last_analysis
    counts = data["counts"]
    malware = data["malware"]
    brute_force = data["brute_force"]
    top_keys = set(get_top_attack_keys(data))
    scenarios = []

    malware_total = len(malware) + counts.get("malware", 0) + counts.get("advanced_malware", 0)
    has_malware = malware_total > 0
    has_susp_exec = counts.get("suspicious_execution", 0) > 0
    has_wmi = counts.get("wmi_execution", 0) > 0
    has_sec_tool = counts.get("security_tool", 0) > 0
    has_dll_hijack = counts.get("dll_side_loading", 0) > 0
    has_svc_perms = counts.get("services_file_permissions", 0) > 0
    has_cred_dump = counts.get("credential_dumping", 0) > 0
    has_persistence = counts.get("suspicious_persistence", 0) > 0
    has_discovery = counts.get("file_and_directory_discovery", 0) > 0
    has_unauth = counts.get("unauthorized_access", 0) > 0 or len(brute_force) > 0
    has_phishing = counts.get("phishing", 0) > 0
    has_acct_manip = counts.get("account_manipulation", 0) > 0 or counts.get("account_management", 0) > 0
    has_data_leak = counts.get("data_leakage", 0) > 0
    has_susp_net = counts.get("suspicious_network", 0) > 0

    if has_malware or (has_susp_exec and (has_sec_tool or has_dll_hijack or has_wmi)):
        indicators, techs = [], []
        confirmed_chain = (
            _has_confirmed_activity("malware", data)
            or _has_confirmed_activity("suspicious_execution", data)
            or _has_confirmed_activity("wmi_execution", data)
            or _has_confirmed_activity("security_tool", data)
        )
        if has_malware:
            indicators.append(f"Malware ({malware_total} treff)")
            techs.append("T1204")
        if has_susp_exec:
            indicators.append(f"Suspicious Execution ({counts['suspicious_execution']} treff)")
            techs.append("T1059")
        if has_wmi:
            indicators.append(f"WMI Execution ({counts['wmi_execution']} treff)")
            techs.append("T1047")
        if has_sec_tool:
            indicators.append(f"Security Tool ({counts['security_tool']} treff)")
            techs.append("T1588")
        if has_dll_hijack:
            indicators.append(f"DLL Side-Loading ({counts['dll_side_loading']} treff)")
            techs.append("T1574.002")

        top_overlap = sum(
            1 for k in ["malware", "suspicious_execution", "wmi_execution", "security_tool", "dll_side_loading"]
            if (k in top_keys and counts.get(k, 0) > 0) or (k == "malware" and has_malware and "malware" in top_keys)
        )
        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)) or "T1204",
            "name": "Malware / Suspicious Execution Chain",
            "severity": "CRITICAL" if (has_malware and confirmed_chain) else ("HIGH" if has_malware or confirmed_chain else "MEDIUM"),
            "confidence": "Høy" if top_overlap >= 1 and (has_malware or confirmed_chain) else "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": "En angriper har trolig kjørt eller forsøkt å kjøre skadelig kode eller mistenkelige skript/prosesser på systemet.",
            "action": "Isoler berørt maskin, inspiser prosesshierarki og kjør full sikkerhetsskanning.",
        })

    if has_unauth or has_phishing or has_acct_manip:
        indicators, techs = [], []
        if counts.get("unauthorized_access", 0) > 0:
            indicators.append(f"Unauthorized Access ({counts['unauthorized_access']} treff)")
            techs.append("T1078")
        if brute_force:
            indicators.append(f"Brute Force ({len(brute_force)} hendelser)")
            techs.append("T1110")
        if has_phishing:
            indicators.append(f"Phishing ({counts['phishing']} treff)")
            techs.append("T1566")
        if has_acct_manip:
            total_acct = counts.get("account_manipulation", 0) + counts.get("account_management", 0)
            indicators.append(f"Account Changes ({total_acct} treff)")
            techs.append("T1098")

        top_overlap = sum(
            1 for k in ["unauthorized_access", "brute_force", "phishing", "account_manipulation", "account_management"]
            if k in top_keys and counts.get(k, 0) > 0
        )
        if top_overlap > 0 or (has_unauth and has_acct_manip):
            scenarios.append({
                "technique_id": " / ".join(dict.fromkeys(techs)) or "T1078",
                "name": "Initial Access / Unauthorized Account Activity",
                "severity": "HIGH" if (has_unauth or has_acct_manip) else "MEDIUM",
                "confidence": "Høy" if top_overlap >= 2 else "Middels",
                "top_match": top_overlap,
                "indicators": ", ".join(indicators),
                "description": "Uautorisert tilgang, phishing eller kontorelaterte endringer indikerer forsøk på innledende tilgang eller kontokompromittering.",
                "action": "Kontroller berørte kontoer, blokker mistenkelige kilder, tilbakestill passord og vurder MFA.",
            })

    if has_data_leak or has_susp_net:
        indicators, techs = [], []
        if has_data_leak:
            indicators.append(f"Data Leakage ({counts['data_leakage']} treff)")
            techs.append("T1041")
        if has_susp_net:
            indicators.append(f"Suspicious Network ({counts['suspicious_network']} treff)")
            techs.append("T1071")

        top_overlap = sum(
            1 for k in ["data_leakage", "suspicious_network"]
            if k in top_keys and counts.get(k, 0) > 0
        )
        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)),
            "name": "Command & Control / Data Exfiltration",
            "severity": "CRITICAL" if has_data_leak else "HIGH",
            "confidence": "Høy" if top_overlap > 0 and (has_data_leak and has_susp_net) else "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": "Mistenkelig utgående nettverkstrafikk eller mulig dataeksfiltrering mot ekstern destinasjon.",
            "action": "Undersøk nettverkstrafikk, blokker uautoriserte eksterne forbindelser og kontroller sensitiv data.",
        })

    if has_cred_dump and (has_persistence or has_dll_hijack or has_svc_perms):
        indicators = [f"Credential Dumping ({counts['credential_dumping']} treff)"]
        techs = ["T1003"]
        if has_persistence:
            indicators.append(f"Suspicious Persistence ({counts['suspicious_persistence']} treff)")
            techs.append("T1053")
        if has_dll_hijack:
            indicators.append(f"DLL Side-Loading ({counts['dll_side_loading']} treff)")
            techs.append("T1574.002")
        if has_svc_perms:
            indicators.append(f"Services File Permissions ({counts['services_file_permissions']} treff)")
            techs.append("T1574.010")
        if has_sec_tool:
            indicators.append(f"Security Tool ({counts['security_tool']} treff)")
            techs.append("T1588")

        top_overlap = sum(
            1 for k in ["credential_dumping", "suspicious_persistence", "dll_side_loading"]
            if k in top_keys
        )
        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)),
            "name": "Post-Exploitation: Credential Theft & Persistence",
            "severity": "CRITICAL",
            "confidence": "Høy" if len(techs) >= 3 else "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": "En angriper har trolig fått fotfeste på systemet og forsøker å hente ut legitimasjon og etablere vedvarende tilgang.",
            "action": "Isoler berørt maskin, kontroller LSASS-tilgang, tjenester og oppgaver, og tilbakestill berørte kontoer.",
        })

    if has_discovery and (has_susp_exec or has_wmi or has_susp_net):
        indicators = [f"File & Directory Discovery ({counts['file_and_directory_discovery']} treff)"]
        techs = ["T1083"]
        if has_wmi:
            indicators.append(f"WMI Execution ({counts['wmi_execution']} treff)")
            techs.append("T1047")
        if has_susp_exec:
            indicators.append(f"Suspicious Execution ({counts['suspicious_execution']} treff)")
            techs.append("T1059")
        if has_susp_net:
            indicators.append(f"Suspicious Network ({counts['suspicious_network']} treff)")
            techs.append("T1071")

        top_overlap = sum(
            1 for k in ["file_and_directory_discovery", "wmi_execution", "suspicious_execution", "suspicious_network"]
            if k in top_keys and counts.get(k, 0) > 0
        )
        confirmed_exec = _has_confirmed_activity("suspicious_execution", data) or _has_confirmed_activity("wmi_execution", data)
        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)),
            "name": "Discovery & Execution",
            "severity": "HIGH" if confirmed_exec else "MEDIUM",
            "confidence": "Høy" if (top_overlap >= 2 and confirmed_exec) else "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": "Kartlegging av filer og mapper kombinert med prosess- eller nettverksaktivitet.",
            "action": "Undersøk hvilken prosess og bruker som utførte kartleggingen, og sjekk videre aktivitet.",
        })

    scenarios.sort(
        key=lambda s: (
            severity_rank.get(s["severity"], 0),
            s["top_match"],
            1 if s["confidence"] == "Høy" else 0,
        ),
        reverse=True,
    )
    return scenarios


def analyze_lines(lines, source_file, target_analysis=None, compiled_patterns=None):
    data = target_analysis if target_analysis is not None else last_analysis
    if compiled_patterns is None:
        compiled_patterns = {k: re.compile(v, re.IGNORECASE) for k, v in patterns.items()}
    login_attempts = defaultdict(list)

    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue

        data["total_lines"] += 1
        log_type = detect_log_type(line, source_file=source_file)
        if log_type not in data["log_types"]:
            data["log_types"].append(log_type)

        ts = extract_timestamp(line)
        ips = IP_PATTERN.findall(line)
        ip_display = ", ".join(dict.fromkeys(ips)) if ips else "ingen detektert"
        activities = identify_activity(
            line, compiled_patterns, COMPILED_MALWARE_PATTERNS, COMPILED_TOOL_PATTERNS
        )

        if not activities:
            continue

        for act in activities:
            base_key = act.split(":", 1)[0].strip().lower().replace(" ", "_")
            eval_res = evaluate_execution_context(act, line, ts)

            if act.startswith("Malware:"):
                mal_name = act.split(":", 1)[1].strip()
                data["malware"][mal_name] += 1
                base_sev = severity.get("malware", "HIGH")
                rem = remedies.get("malware", remedies["suspicious_execution"])
            elif act.startswith("Security Tool:"):
                data["counts"]["security_tool"] += 1
                base_sev = severity.get("security_tool", "MEDIUM")
                rem = remedies.get("security_tool", remedies["suspicious_execution"])
            else:
                data["counts"][act] += 1
                base_sev = severity.get(act, "MEDIUM")
                rem = remedies.get(act, "Undersøk hendelsen nærmere.")

            final_sev = escalate_severity(base_sev, eval_res.status, eval_res.confidence)
            tech_id, tech_name = get_technique_info(act)

            data["finding_stats"][eval_res.status] += 1
            cat_stats = data["finding_stats"]["by_category"][base_key]
            cat_stats[eval_res.status] += 1
            if eval_res.confidence == "High":
                cat_stats["high_conf"] += 1

            if act == "unauthorized_access":
                for ip in ips or ["ingen detektert"]:
                    login_attempts[ip].append((ts, line, source_file))

            for ip in ips:
                ip_entry = data["ips"][ip]
                ip_entry["activity"][act] += 1
                ip_entry["total"] += 1
                if severity_rank.get(final_sev, 0) > severity_rank.get(ip_entry["severity"], 0):
                    ip_entry["severity"] = final_sev

            if ts is not None:
                data["timeline"].append({
                    "timestamp": ts,
                    "activity": act,
                    "status": eval_res.status,
                    "confidence": eval_res.confidence,
                    "severity": final_sev,
                    "ips": ip_display,
                    "file": source_file,
                })

            data["details"].append({
                "file": source_file,
                "timestamp": ts.isoformat(sep=" ") if ts else "N/A",
                "log_type": log_type,
                "activity": act,
                "status": eval_res.status,
                "confidence": eval_res.confidence,
                "reasons": ", ".join(eval_res.reasons),
                "severity": final_sev,
                "technique_id": tech_id,
                "technique_name": tech_name,
                "ips": ip_display,
                "remedy": rem,
                "line": line,
            })

    bf_incidents = detect_brute_force(login_attempts)
    for inc in bf_incidents:
        data["counts"]["brute_force"] += 1
        data["finding_stats"]["confirmed"] += 1
        data["finding_stats"]["by_category"]["brute_force"]["confirmed"] += 1
        data["finding_stats"]["by_category"]["brute_force"]["high_conf"] += 1
    data["brute_force"].extend(bf_incidents)
    data["attack_scenarios"] = detect_attack_scenarios(data)


def iter_evtx_records(filepath):
    with Evtx(filepath) as log:
        for record in log.records():
            try:
                yield record.xml()
            except Exception:
                continue


def load_evtx_lines(filepath):
    return list(iter_evtx_records(filepath))


def reset_analysis():
    global last_analysis
    last_analysis = create_empty_analysis()


class ScrollableTab(tk.Frame):
    def __init__(self, parent, bg_page="#F4F6F9"):
        super().__init__(parent, bg=bg_page)
        self.canvas = tk.Canvas(self, bg=bg_page, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg_page, padx=20, pady=16)

        self.inner.bind("<Configure>", self._sync_scrollregion)
        self._win_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(self._win_id, width=e.width),
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _sync_scrollregion(self, _e=None):
        self.canvas.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_mousewheel(self, event):
        if event.delta:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        elif event.num == 4:
            self.canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(3, "units")

    def _bind_wheel(self, _e):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _unbind_wheel(self, _e):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")


class LogAnalyzerV3App:
    BG_HEADER = "#1E293B"
    BG_PAGE = "#F4F6F9"
    BG_CARD = "#FFFFFF"
    BG_BANNER = "#2C3E50"
    BG_REMEDY = "#FEF9E7"
    BORDER_REMEDY = "#F3E5AB"
    BORDER_CARD = "#CBD5E1"
    ACCENT_BLUE = "#1D70B8"
    ACCENT_DARK = "#2C3E50"
    ACCENT_GREEN = "#2E9E5B"
    ACCENT_RED = "#B91C1C"
    TEXT_DARK = "#1E293B"
    TEXT_MUTED = "#5A6778"

    def __init__(self, root):
        self.root = root
        self.root.title("Python Log Analyzer Pro v3 © malwaremango")
        self.root.geometry("1280x820")
        self.root.configure(bg=self.BG_PAGE)
        self.scan_generation = 0
        self._handling_new_scan_tab = False
        self.activity_chart_canvas = None

        load_patterns()
        self._configure_styles()
        self._build_header()
        self._build_notebook()
        self.new_scan(auto_analyze=False)

    def _configure_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Pro.TNotebook",
            background=self.BG_PAGE,
            borderwidth=0,
            tabmargins=[0, 0, 0, 0],
        )
        style.configure(
            "Pro.TNotebook.Tab",
            background="#E2E6EC",
            foreground=self.TEXT_DARK,
            padding=[18, 9],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "Pro.TNotebook.Tab",
            background=[("selected", self.ACCENT_BLUE)],
            foreground=[("selected", "#FFFFFF")],
        )
        style.configure(
            "Pro.Treeview",
            background=self.BG_CARD,
            fieldbackground=self.BG_CARD,
            foreground=self.TEXT_DARK,
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Pro.Treeview.Heading",
            background="#E9EDF2",
            foreground=self.TEXT_DARK,
            font=("Segoe UI", 9, "bold"),
        )

    def _build_header(self):
        header = tk.Frame(self.root, bg=self.BG_HEADER, padx=16, pady=12)
        header.pack(fill=tk.X)

        logo_canvas = tk.Canvas(header, width=40, height=40, bg=self.BG_HEADER, highlightthickness=0)
        logo_canvas.pack(side=tk.LEFT, padx=(0, 12))
        logo_canvas.create_oval(4, 4, 34, 34, outline="#38BDF8", width=3)
        logo_canvas.create_oval(11, 11, 27, 27, outline="#0284C7", width=2)
        logo_canvas.create_line(26, 26, 36, 36, fill="#38BDF8", width=3)

        title_block = tk.Frame(header, bg=self.BG_HEADER)
        title_block.pack(side=tk.LEFT)

        tk.Label(
            title_block,
            text="Python Log Analyzer Pro v3 © malwaremango",
            bg=self.BG_HEADER,
            fg="#FFFFFF",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor=tk.W)

        tk.Label(
            title_block,
            text="Security monitoring and log analysis",
            bg=self.BG_HEADER,
            fg="#CBD5E1",
            font=("Segoe UI", 9),
        ).pack(anchor=tk.W)

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root, style="Pro.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_overview = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_potential = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_log_analysis = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_ip_analysis = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_timeline = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_details = tk.Frame(self.notebook, bg=self.BG_PAGE, padx=20, pady=16)
        self.tab_log_types = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_custom = ScrollableTab(self.notebook, self.BG_PAGE)
        self.tab_new_scan = tk.Frame(self.notebook, bg=self.BG_PAGE)

        self.notebook.add(self.tab_overview, text="Attack Overview")
        self.notebook.add(self.tab_potential, text="Potential Attacks")
        self.notebook.add(self.tab_log_analysis, text="Log Analysis")
        self.notebook.add(self.tab_ip_analysis, text="IP Analysis")
        self.notebook.add(self.tab_timeline, text="Attack Timeline")
        self.notebook.add(self.tab_details, text="Details")
        self.notebook.add(self.tab_log_types, text="Log Types")
        self.notebook.add(self.tab_custom, text="Custom Patterns")
        self.notebook.add(self.tab_new_scan, text="+ New Scan")
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self._build_overview_tab()
        self._build_potential_attacks_tab()
        self._build_log_analysis_tab()
        self._build_ip_analysis_tab()
        self._build_timeline_tab()
        self._build_details_tab()
        self._build_log_types_tab()
        self._build_custom_patterns_tab()

    def _make_action_button(self, parent, text, bg_color, command):
        return tk.Button(
            parent,
            text=text,
            bg=bg_color,
            fg="#FFFFFF",
            activebackground=bg_color,
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 9, "bold"),
            padx=18,
            pady=10,
            command=command,
        )

    def _add_tab_header(self, parent, title, subtitle, banner_text=None):
        tk.Label(
            parent,
            text=title,
            bg=self.BG_PAGE,
            fg=self.TEXT_DARK,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor=tk.W)

        tk.Label(
            parent,
            text=subtitle,
            bg=self.BG_PAGE,
            fg=self.ACCENT_RED if banner_text else self.TEXT_MUTED,
            font=("Segoe UI", 10),
        ).pack(anchor=tk.W, pady=(2, 12))

        if banner_text is not None:
            banner = tk.Frame(parent, bg=self.BG_BANNER, padx=16, pady=12)
            banner.pack(fill=tk.X, pady=(0, 14))
            lbl = tk.Label(
                banner,
                text=banner_text,
                bg=self.BG_BANNER,
                fg="#FFFFFF",
                font=("Segoe UI", 12, "bold"),
            )
            lbl.pack(anchor=tk.W)
            return lbl
        return None

    def _create_finding_card(self, parent, title, triggers, assessment, action_text, badge_text=""):
        card = tk.Frame(
            parent,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        card.pack(fill=tk.X, pady=(0, 12))

        top_row = tk.Frame(card, bg=self.BG_CARD)
        top_row.pack(fill=tk.X)

        icon_canvas = tk.Canvas(top_row, width=26, height=24, bg=self.BG_CARD, highlightthickness=0)
        icon_canvas.pack(side=tk.LEFT, padx=(0, 8))
        icon_canvas.create_polygon(13, 3, 24, 22, 2, 22, outline=self.ACCENT_RED, fill="", width=2)
        icon_canvas.create_line(13, 9, 13, 15, fill=self.ACCENT_RED, width=2)
        icon_canvas.create_oval(11.5, 17.5, 14.5, 20.5, fill=self.ACCENT_RED, outline=self.ACCENT_RED)

        tk.Label(
            top_row,
            text=title,
            bg=self.BG_CARD,
            fg=self.ACCENT_RED,
            font=("Segoe UI", 13, "bold"),
        ).pack(side=tk.LEFT)

        if badge_text:
            tk.Label(
                top_row,
                text=badge_text,
                bg="#E2E8F0",
                fg=self.TEXT_DARK,
                font=("Segoe UI", 8, "bold"),
                padx=8,
                pady=2,
            ).pack(side=tk.RIGHT)

        if triggers:
            tk.Label(
                card,
                text=f"Utløsende hendelser: {triggers}",
                bg=self.BG_CARD,
                fg=self.ACCENT_BLUE,
                font=("Segoe UI", 10, "bold"),
                anchor="w",
                justify=tk.LEFT,
                wraplength=1120,
            ).pack(fill=tk.X, pady=(6, 4))

        if assessment:
            tk.Label(
                card,
                text=f"Vurdering: {assessment}",
                bg=self.BG_CARD,
                fg=self.TEXT_DARK,
                font=("Segoe UI", 10),
                anchor="w",
                justify=tk.LEFT,
                wraplength=1120,
            ).pack(fill=tk.X, pady=(0, 8))

        if action_text:
            remedy_box = tk.Frame(
                card,
                bg=self.BG_REMEDY,
                highlightbackground=self.BORDER_REMEDY,
                highlightthickness=1,
                padx=12,
                pady=8,
            )
            remedy_box.pack(fill=tk.X)
            tk.Label(
                remedy_box,
                text=f"Anbefalt tiltak: {action_text}",
                bg=self.BG_REMEDY,
                fg="#7C4A03",
                font=("Segoe UI", 9, "bold"),
                anchor="w",
                justify=tk.LEFT,
                wraplength=1090,
            ).pack(fill=tk.X)

    def _build_overview_tab(self):
        p = self.tab_overview.inner
        self._add_tab_header(
            p,
            "Security Overview",
            "Analyse loggfiler og identifiser mistenkelig aktivitet.",
        )

        btn_row = tk.Frame(p, bg=self.BG_PAGE)
        btn_row.pack(anchor=tk.W, pady=(0, 14))

        self._make_action_button(
            btn_row, "+ Ny skann", self.ACCENT_BLUE, lambda: self.new_scan(auto_analyze=True)
        ).pack(side=tk.LEFT, padx=(0, 10))
        self._make_action_button(
            btn_row, "📁 Analyser loggfiler", self.ACCENT_DARK, self.select_and_analyze
        ).pack(side=tk.LEFT, padx=(0, 10))
        self._make_action_button(
            btn_row, "Eksporter CSV", self.ACCENT_GREEN, self.export_csv
        ).pack(side=tk.LEFT)

        self.overview_status_var = tk.StringVar(
            value="Ingen loggfiler analysert ennå. Klikk «+ Ny skann» eller «Analyser loggfiler» for å starte."
        )
        self.overview_banner_lbl = tk.Label(
            p,
            textvariable=self.overview_status_var,
            bg=self.BG_BANNER,
            fg="#FFFFFF",
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=10,
            anchor="w",
        )
        self.overview_banner_lbl.pack(fill=tk.X, pady=(0, 14))

        self.overview_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.overview_cards_container.pack(fill=tk.BOTH, expand=True)

    def _build_potential_attacks_tab(self):
        p = self.tab_potential.inner
        self.scenarios_banner_lbl = self._add_tab_header(
            p,
            "Potential Attacks",
            "Potensielle angrepsscenarier basert på korrelerte funn",
            "Identifiserte angrepsscenarier: 0",
        )
        self.scenarios_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.scenarios_cards_container.pack(fill=tk.BOTH, expand=True)

    def _build_log_analysis_tab(self):
        p = self.tab_log_analysis.inner
        self.log_analysis_banner_lbl = self._add_tab_header(
            p,
            "Log Analysis",
            "Kategorier, malware-treff og sikkerhetsverktøy identifisert i loggene",
            "Analyserte kategorier: 0",
        )
        self.log_analysis_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.log_analysis_cards_container.pack(fill=tk.BOTH, expand=True)

        self.activity_chart_container = tk.Frame(
            p,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=12,
            pady=12,
        )
        self.activity_chart_container.pack(fill=tk.X, pady=(12, 0))

    def _update_activity_chart(self):
        if self.activity_chart_canvas is not None:
            self.activity_chart_canvas.get_tk_widget().destroy()
            self.activity_chart_canvas = None
        self._clear_children(self.activity_chart_container)

        chart_counts = defaultdict(int)
        for cat, cnt in last_analysis["counts"].items():
            if cnt > 0:
                label = cat.replace("_", " ").title()
                chart_counts[label] += cnt
        if last_analysis["malware"]:
            chart_counts["Malware"] += sum(last_analysis["malware"].values())

        if not chart_counts:
            tk.Label(
                self.activity_chart_container,
                text="Ingen aktivitet å vise i graf ennå.",
                bg=self.BG_CARD,
                fg=self.TEXT_MUTED,
                font=("Segoe UI", 9),
                pady=12,
            ).pack()
            return

        labels = list(chart_counts.keys())
        values = [chart_counts[lbl] for lbl in labels]

        fig = Figure(figsize=(8.6, 3.3), dpi=100, facecolor="#FFFFFF")
        ax = fig.add_subplot(111)
        ax.bar(labels, values, color="#1F77B4", width=0.6)
        ax.set_title("Suspicious Activity Detected", fontsize=10, pad=8)
        ax.tick_params(axis="x", labelsize=7.5, rotation=22)
        ax.tick_params(axis="y", labelsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for tick in ax.get_xticklabels():
            tick.set_ha("right")
        fig.tight_layout()

        self.activity_chart_canvas = FigureCanvasTkAgg(fig, master=self.activity_chart_container)
        self.activity_chart_canvas.draw()
        self.activity_chart_canvas.get_tk_widget().pack(fill=tk.X, expand=True)

    def _build_ip_analysis_tab(self):
        p = self.tab_ip_analysis.inner
        self.ip_banner_lbl = self._add_tab_header(
            p,
            "IP Analysis",
            "Brute-force-hendelser og IP-adresser knyttet til mistenkelig aktivitet",
            "Registrerte IP-adresser: 0",
        )
        self.ip_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.ip_cards_container.pack(fill=tk.BOTH, expand=True)

    def _build_timeline_tab(self):
        p = self.tab_timeline.inner
        self.timeline_banner_lbl = self._add_tab_header(
            p,
            "Attack Timeline",
            "Kronologisk oversikt over registrerte hendelser",
            "Tidslinjehendelser: 0",
        )
        self._make_action_button(p, "Åpne tidsakse-graf", self.ACCENT_BLUE, self.show_timeline_chart).pack(
            anchor=tk.W, pady=(0, 12)
        )
        self.timeline_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.timeline_cards_container.pack(fill=tk.BOTH, expand=True)

    def _build_details_tab(self):
        self._add_tab_header(
            self.tab_details,
            "Details",
            "Detaljerte funn med søk, kategori- og alvorlighetsfilter, MITRE-teknikk og anbefalt tiltak",
        )

        search_bar = tk.Frame(self.tab_details, bg=self.BG_BANNER, padx=14, pady=10)
        search_bar.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            search_bar,
            text="Søk i funn:",
            bg=self.BG_BANNER,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.details_search_var = tk.StringVar()
        self.details_search_var.trace_add("write", lambda *_: self._apply_details_filter())

        tk.Entry(
            search_bar,
            textvariable=self.details_search_var,
            bg=self.BG_CARD,
            fg=self.TEXT_DARK,
            relief=tk.FLAT,
            bd=0,
            font=("Segoe UI", 9),
            width=26,
        ).pack(side=tk.LEFT, padx=(0, 12), ipady=4)

        tk.Label(
            search_bar,
            text="Aktivitet:",
            bg=self.BG_BANNER,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.activity_filter_var = tk.StringVar(value="Alle")
        self.activity_filter_combo = ttk.Combobox(
            search_bar,
            textvariable=self.activity_filter_var,
            values=["Alle"],
            state="readonly",
            width=22,
            font=("Segoe UI", 9),
        )
        self.activity_filter_combo.pack(side=tk.LEFT, padx=(0, 12))
        self.activity_filter_combo.bind("<<ComboboxSelected>>", lambda *_: self._apply_details_filter())

        tk.Label(
            search_bar,
            text="Alvorlighetsgrad:",
            bg=self.BG_BANNER,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.severity_filter_var = tk.StringVar(value="Alle")
        self.severity_filter_combo = ttk.Combobox(
            search_bar,
            textvariable=self.severity_filter_var,
            values=["Alle", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            state="readonly",
            width=13,
            font=("Segoe UI", 9),
        )
        self.severity_filter_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.severity_filter_combo.bind("<<ComboboxSelected>>", lambda *_: self._apply_details_filter())

        tk.Button(
            search_bar,
            text="Nullstill",
            bg=self.ACCENT_BLUE,
            fg="#FFFFFF",
            activebackground=self.ACCENT_BLUE,
            activeforeground="#FFFFFF",
            relief=tk.FLAT,
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            command=self._reset_details_filters,
        ).pack(side=tk.LEFT, padx=(0, 12))

        self.details_count_var = tk.StringVar(value="Viser 0 av 0 funn")
        tk.Label(
            search_bar,
            textvariable=self.details_count_var,
            bg=self.BG_BANNER,
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT)

        cols = ("timestamp", "activity", "status", "confidence", "severity", "technique_id", "ips", "file")
        self.tree = ttk.Treeview(self.tab_details, columns=cols, show="headings", style="Pro.Treeview", height=13)
        headers = {
            "timestamp": "Tidspunkt",
            "activity": "Aktivitet",
            "status": "Status",
            "confidence": "Confidence",
            "severity": "Alvorlighet",
            "technique_id": "MITRE ID",
            "ips": "IP-adresser",
            "file": "Fil",
        }
        widths = {
            "timestamp": 155,
            "activity": 195,
            "status": 95,
            "confidence": 100,
            "severity": 105,
            "technique_id": 105,
            "ips": 145,
            "file": 165,
        }
        for col in cols:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor=tk.W)

        scroll = ttk.Scrollbar(self.tab_details, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_finding)

        detail_card = tk.Frame(
            self.tab_details,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=14,
            pady=10,
        )
        detail_card.pack(fill=tk.X, pady=(10, 0))

        tk.Label(
            detail_card,
            text="Detaljer:",
            bg=self.BG_CARD,
            fg=self.ACCENT_BLUE,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor=tk.W, pady=(0, 4))

        self.detail_box = tk.Text(
            detail_card,
            height=5,
            bg=self.BG_REMEDY,
            fg=self.TEXT_DARK,
            relief=tk.FLAT,
            bd=0,
            font=("Consolas", 9),
            wrap=tk.WORD,
            padx=10,
            pady=6,
        )
        self.detail_box.pack(fill=tk.X)

    def _reset_details_filters(self):
        if hasattr(self, "details_search_var"):
            self.details_search_var.set("")
        if hasattr(self, "activity_filter_var"):
            self.activity_filter_var.set("Alle")
        if hasattr(self, "severity_filter_var"):
            self.severity_filter_var.set("Alle")
        self._apply_details_filter()

    def _sync_details_filter_options(self):
        if not hasattr(self, "activity_filter_combo"):
            return
        activities = sorted(
            {str(d.get("activity", "")).strip() for d in last_analysis["details"] if d.get("activity")}
        )
        options = ["Alle"] + activities
        self.activity_filter_combo["values"] = options
        if self.activity_filter_var.get() not in options:
            self.activity_filter_var.set("Alle")
        if hasattr(self, "severity_filter_var") and not self.severity_filter_var.get():
            self.severity_filter_var.set("Alle")

    def _build_log_types_tab(self):
        p = self.tab_log_types.inner
        self.log_types_banner_lbl = self._add_tab_header(
            p,
            "Log Types",
            "Gjenkjente loggformater og kilder fra siste analyse",
            "Gjenkjente loggtyper: 0",
        )
        self.log_types_cards_container = tk.Frame(p, bg=self.BG_PAGE)
        self.log_types_cards_container.pack(fill=tk.BOTH, expand=True)

    def _build_custom_patterns_tab(self):
        p = self.tab_custom.inner
        self._add_tab_header(
            p,
            "Custom Patterns",
            "Tilpass søkemønstre og anbefalte tiltak i JSON-konfigurasjonen",
            f"Konfigurasjonsfil: {CONFIG_FILE}",
        )
        self._make_action_button(p, "Lagre konfigurasjon", self.ACCENT_GREEN, self._save_config).pack(
            anchor=tk.W, pady=(0, 12)
        )
        card = tk.Frame(
            p,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=14,
            pady=12,
        )
        card.pack(fill=tk.BOTH, expand=True)
        self.custom_box = tk.Text(
            card,
            height=22,
            bg=self.BG_CARD,
            fg=self.TEXT_DARK,
            relief=tk.FLAT,
            bd=0,
            font=("Consolas", 9),
        )
        self.custom_box.pack(fill=tk.BOTH, expand=True)
        self._refresh_custom_patterns()

    def _on_tab_changed(self, _event):
        if self._handling_new_scan_tab:
            return
        selected = self.notebook.select()
        if selected == str(self.tab_new_scan):
            self._handling_new_scan_tab = True
            try:
                self.notebook.select(self.tab_overview)
            finally:
                self._handling_new_scan_tab = False
            self.new_scan(auto_analyze=True)

    def _save_config(self):
        try:
            parsed = json.loads(self.custom_box.get("1.0", tk.END))
            if "patterns" in parsed:
                patterns.clear()
                patterns.update(parsed["patterns"])
            if "remedies" in parsed:
                remedies.update(parsed["remedies"])
            save_patterns()
            messagebox.showinfo("Konfigurasjon", f"Regler lagret til {CONFIG_FILE}")
        except Exception as exc:
            messagebox.showerror("Ugyldig JSON", f"Kunne ikke lagre konfigurasjon:\n{exc}")

    # ------------------------------------------------------
    # Ny skann
    # ------------------------------------------------------
    def new_scan(self, auto_analyze=True):
        self.scan_generation += 1
        reset_analysis()

        if hasattr(self, "details_search_var"):
            self.details_search_var.set("")
        if hasattr(self, "activity_filter_var"):
            self.activity_filter_var.set("Alle")
        if hasattr(self, "severity_filter_var"):
            self.severity_filter_var.set("Alle")

        self.refresh_all_views()
        self.overview_status_var.set("Klar for ny skann...")
        self.notebook.select(self.tab_overview)

        if auto_analyze:
            self.root.after(100, self.select_and_analyze)

    def select_and_analyze(self):
        filepaths = filedialog.askopenfilenames(
            title="Velg loggfiler",
            filetypes=[("Loggfiler", "*.log *.txt *.evtx *.xml *.json"), ("Alle filer", "*.*")],
        )
        if not filepaths:
            return

        self.scan_generation += 1
        current_gen = self.scan_generation
        self.overview_status_var.set("Laster og analyserer loggfiler...")
        self.root.update_idletasks()

        def worker():
            temp_analysis = create_empty_analysis()
            temp_analysis["files"] = list(filepaths)
            compiled = {k: re.compile(v, re.IGNORECASE) for k, v in patterns.items()}
            errors = []

            for idx, path in enumerate(filepaths, start=1):
                fname = os.path.basename(path)
                self.root.after(
                    0,
                    lambda g=current_gen, i=idx, n=len(filepaths), name=fname: (
                        self.overview_status_var.set(f"Leser fil {i}/{n}: {name}...")
                        if g == self.scan_generation else None
                    ),
                )
                ext = os.path.splitext(path)[1].lower()
                try:
                    if ext == ".evtx":
                        batch = []
                        processed_count = 0
                        for xml_line in iter_evtx_records(path):
                            if current_gen != self.scan_generation:
                                return
                            batch.append(xml_line)
                            if len(batch) >= EVTX_BATCH_SIZE:
                                analyze_lines(
                                    batch,
                                    fname,
                                    target_analysis=temp_analysis,
                                    compiled_patterns=compiled,
                                )
                                processed_count += len(batch)
                                batch.clear()
                                self.root.after(
                                    0,
                                    lambda g=current_gen, name=fname, c=processed_count: (
                                        self.overview_status_var.set(f"Analyserer {name}: {c} poster...")
                                        if g == self.scan_generation else None
                                    ),
                                )
                                time.sleep(0.005)
                        if batch:
                            analyze_lines(
                                batch,
                                fname,
                                target_analysis=temp_analysis,
                                compiled_patterns=compiled,
                            )
                            batch.clear()
                    else:
                        with open(path, "r", encoding="utf-8", errors="replace") as f:
                            lines = f.readlines()
                        analyze_lines(lines, fname, target_analysis=temp_analysis, compiled_patterns=compiled)
                except Exception as exc:
                    errors.append(f"{fname}: {exc}")

            def apply_result():
                if current_gen != self.scan_generation:
                    return
                global last_analysis
                last_analysis = temp_analysis
                self._finish_analysis(errors)

            self.root.after(0, apply_result)

        threading.Thread(target=worker, daemon=True).start()

    def _finish_analysis(self, errors):
        self.refresh_all_views()
        if errors:
            messagebox.showwarning("Feil ved lesing", "\n".join(errors))

    def _refresh_custom_patterns(self):
        self.custom_box.delete("1.0", tk.END)
        self.custom_box.insert(
            tk.END,
            json.dumps({"patterns": patterns, "remedies": remedies}, indent=2, ensure_ascii=False),
        )

    @staticmethod
    def _clear_children(frame):
        for w in frame.winfo_children():
            w.destroy()

    def refresh_all_views(self):
        stats = last_analysis["finding_stats"]
        self.overview_status_var.set(
            f"Linjer: {last_analysis['total_lines']}  |  "
            f"Funn: {len(last_analysis['details'])} (Confirmed: {stats['confirmed']}, Indicator: {stats['indicator']})  |  "
            f"Scenarier: {len(last_analysis['attack_scenarios'])}  |  "
            f"Brute-force: {len(last_analysis['brute_force'])}"
        )

        self._clear_children(self.overview_cards_container)
        files_str = ", ".join(os.path.basename(f) for f in last_analysis["files"]) or "Ingen filer valgt"
        top_cats = ", ".join(
            f"{k} ({v})"
            for k, v in sorted(last_analysis["counts"].items(), key=lambda kv: kv[1], reverse=True)[:6]
        ) or "Ingen kategoritreff registrert"
        self._create_finding_card(
            self.overview_cards_container,
            "Sammendrag av siste logganalyse",
            top_cats,
            f"Analyserte {last_analysis['total_lines']} linjer på tvers av {len(last_analysis['files'])} fil(er) ({files_str}). "
            f"Registrerte {len(last_analysis['details'])} funn ({stats['confirmed']} bekreftede og {stats['indicator']} indikatorer).",
            "Gjennomgå «Potential Attacks» for korrelerte scenarier, «Attack Timeline» for tidsforløp og «Details» for enkelthendelser.",
            badge_text=f"FUNN: {len(last_analysis['details'])}",
        )

        self._clear_children(self.scenarios_cards_container)
        scenarios = last_analysis["attack_scenarios"]
        self.scenarios_banner_lbl.config(text=f"Identifiserte angrepsscenarier: {len(scenarios)}")
        if not scenarios:
            self._create_finding_card(
                self.scenarios_cards_container,
                "Ingen korrelerte angrepsscenarier identifisert",
                "Ingen mønstre over terskel",
                "Det er ikke funnet tilstrekkelige korrelerte indikatorer til å danne et angrepsscenario i siste analyse.",
                "Kontroller «Details» og «Log Analysis» for enkeltfunn eller juster regler under «Custom Patterns».",
                badge_text="0 SCENARIER",
            )
        else:
            for sc in scenarios:
                self._create_finding_card(
                    self.scenarios_cards_container,
                    f"{sc['name']} ({sc['technique_id']})",
                    sc["indicators"],
                    sc["description"],
                    sc["action"],
                    badge_text=f"{sc['severity']} · CONF: {sc['confidence'].upper()}",
                )

        self._clear_children(self.log_analysis_cards_container)
        total_cats = len(last_analysis["counts"]) + len(last_analysis["malware"])
        self.log_analysis_banner_lbl.config(
            text=f"Totalt linjer analysert: {last_analysis['total_lines']}  |  Analyserte kategorier: {total_cats}"
        )
        for k, v in sorted(last_analysis["counts"].items(), key=lambda kv: kv[1], reverse=True):
            cat_s = stats["by_category"].get(k, {"confirmed": 0, "indicator": 0})
            tech_id, tech_name = get_technique_info(k)
            self._create_finding_card(
                self.log_analysis_cards_container,
                f"{k} ({tech_id} – {tech_name})",
                f"{v} treff (Confirmed: {cat_s['confirmed']}, Indicator: {cat_s['indicator']})",
                f"Alvorlighetsgrad registrert som {severity.get(k, 'MEDIUM')} for kategori «{k}».",
                remedies.get(k, "Undersøk hendelsen nærmere."),
                badge_text=f"TREFF: {v}",
            )
        for mal_name, c in sorted(last_analysis["malware"].items(), key=lambda kv: kv[1], reverse=True):
            self._create_finding_card(
                self.log_analysis_cards_container,
                f"Malware: {mal_name} (T1204 – User Execution)",
                f"{c} treff",
                f"Kjent skadevare-navn «{mal_name}» ble identifisert i logggrunnlaget.",
                remedies.get("malware", "Isoler berørt system og kjør full malware-skanning."),
                badge_text="HIGH · MALWARE",
            )
        self._update_activity_chart()
        self.tab_log_analysis._sync_scrollregion()

        self._clear_children(self.ip_cards_container)
        self.ip_banner_lbl.config(
            text=f"Brute-force-hendelser: {len(last_analysis['brute_force'])}  |  IP-adresser: {len(last_analysis['ips']) or 'ingen detektert'}"
        )
        for bf in last_analysis["brute_force"]:
            bf_ip = bf["ip"] if bf["ip"] and bf["ip"] != "unknown" else "ingen detektert"
            self._create_finding_card(
                self.ip_cards_container,
                f"Brute-force fra {bf_ip}",
                f"{bf['attempts']} mislykkede forsøk innen {bf['window']} min ({bf['start']} -> {bf['end']})",
                f"Kilde-IP ({bf_ip}) overskred terskelen for brute-force i filen {bf['file']}.",
                remedies.get("brute_force", "Blokker eller begrens kilde-IP og vurder MFA/rate limiting."),
                badge_text="HIGH · BRUTE FORCE",
            )
        if not last_analysis["ips"]:
            self._create_finding_card(
                self.ip_cards_container,
                "IP-adresse: ingen detektert",
                "Ingen IP-adresser funnet i loggene",
                "Det ble ikke detektert noen IP-adresser i de analyserte logglinjene.",
                "Sjekk om hendelsene er lokale systemhendelser uten nettverks-IP.",
                badge_text="INGEN IP",
            )
        else:
            for ip, info in sorted(last_analysis["ips"].items(), key=lambda kv: kv[1]["total"], reverse=True):
                acts = ", ".join(f"{k} ({v})" for k, v in info["activity"].items())
                self._create_finding_card(
                    self.ip_cards_container,
                    f"IP-adresse: {ip}",
                    acts,
                    f"Totalt {info['total']} registrerte treff knyttet til {ip}.",
                    "Kontroller kilde-IP mot kjente tjenester og blokker ved uautorisert aktivitet.",
                    badge_text=f"{info['severity']} · {info['total']} TREFF",
                )
        self.tab_ip_analysis._sync_scrollregion()

        self._clear_children(self.timeline_cards_container)
        sorted_tl = sorted(last_analysis["timeline"], key=lambda x: x["timestamp"])
        self.timeline_banner_lbl.config(text=f"Tidslinjehendelser: {len(sorted_tl)}")
        if not sorted_tl:
            self._create_finding_card(
                self.timeline_cards_container,
                "Ingen tidslinjehendelser registrert",
                f"Analyserte linjer: {last_analysis['total_lines']} | Matchede funn: {len(last_analysis['details'])}",
                "Enten manglet tidsstempel på linjene, eller ingen linjer matchet gjeldende søkemønstre.",
                "Sjekk «Details» for enkelthendelser eller legg til flere søkemønstre under «Custom Patterns».",
                badge_text="0 HENDELSER",
            )
        else:
            for ev in sorted_tl[:MAX_UI_CARDS]:
                base_key = ev["activity"].split(":", 1)[0].strip().lower().replace(" ", "_")
                ev_ips = ev.get("ips") or "ingen detektert"
                self._create_finding_card(
                    self.timeline_cards_container,
                    f"{ev['timestamp'].isoformat(sep=' ')} — {ev['activity']}",
                    f"Fil: {ev['file']}  |  IP: {ev_ips}  |  Status: {ev['status']} ({ev['confidence']})",
                    f"Hendelse registrert på tidslinjen med alvorlighetsgrad {ev['severity']}.",
                    remedies.get(base_key, "Undersøk hendelsen i «Details»."),
                    badge_text=ev["severity"],
                )
            if len(sorted_tl) > MAX_UI_CARDS:
                self._create_finding_card(
                    self.timeline_cards_container,
                    f"Viser de {MAX_UI_CARDS} første tidslinjehendelsene",
                    f"Totalt {len(sorted_tl)} hendelser registrert",
                    "Resten av hendelsene er tilgjengelige i «Details» og ved CSV-eksport for å holde grensesnittet raskt.",
                    "Bruk søkefeltet i «Details» eller eksporter til CSV for å se alle.",
                    badge_text="BEGRENSET VISNING",
                )
        self.tab_timeline._sync_scrollregion()

        self._sync_details_filter_options()
        self._apply_details_filter()
        self.detail_box.delete("1.0", tk.END)

        self._clear_children(self.log_types_cards_container)
        self.log_types_banner_lbl.config(text=f"Gjenkjente loggtyper: {len(last_analysis['log_types'])}")
        for lt in last_analysis["log_types"]:
            self._create_finding_card(
                self.log_types_cards_container,
                lt,
                f"Kilder: {', '.join(os.path.basename(f) for f in last_analysis['files']) or '-'}",
                f"Loggformatet «{lt}» ble gjenkjent under parsing av logglinjene.",
                "Sikre at tidsstempler og relevante hendelseslogger fra denne kilden videresendes komplett.",
                badge_text="LOG TYPE",
            )

    def _apply_details_filter(self):
        query = self.details_search_var.get().strip().lower() if hasattr(self, "details_search_var") else ""
        selected_activity = self.activity_filter_var.get() if hasattr(self, "activity_filter_var") else "Alle"
        selected_severity = self.severity_filter_var.get() if hasattr(self, "severity_filter_var") else "Alle"

        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        shown = 0
        total = len(last_analysis["details"])
        for i, d in enumerate(last_analysis["details"]):
            act_val = str(d.get("activity", ""))
            sev_val = str(d.get("severity", ""))
            if selected_activity and selected_activity != "Alle" and act_val != selected_activity:
                continue
            if selected_severity and selected_severity != "Alle" and sev_val.upper() != selected_severity.upper():
                continue

            ip_val = d.get("ips") if d.get("ips") and d.get("ips") != "-" else "ingen detektert"
            haystack = " ".join(
                str(val)
                for val in (
                    d.get("timestamp", ""),
                    act_val,
                    d.get("status", ""),
                    d.get("confidence", ""),
                    sev_val,
                    d.get("technique_id", ""),
                    d.get("technique_name", ""),
                    ip_val,
                    d.get("file", ""),
                    d.get("reasons", ""),
                    d.get("remedy", ""),
                    d.get("line", ""),
                )
            ).lower()
            if query and query not in haystack:
                continue

            self.tree.insert(
                "",
                tk.END,
                iid=str(i),
                values=(
                    d["timestamp"], act_val, d["status"], d["confidence"],
                    sev_val, d["technique_id"], ip_val, d["file"],
                ),
            )
            shown += 1

        if hasattr(self, "details_count_var"):
            self.details_count_var.set(f"Viser {shown} av {total} funn")

    def _on_select_finding(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx < 0 or idx >= len(last_analysis["details"]):
            return
        d = last_analysis["details"][idx]
        ip_val = d.get("ips") if d.get("ips") and d.get("ips") != "-" else "ingen detektert"
        self.detail_box.delete("1.0", tk.END)
        self.detail_box.insert(
            tk.END,
            f"Aktivitet: {d['activity']} | IP: {ip_val} | Status: {d['status']} | Confidence: {d['confidence']} | "
            f"Alvorlighet: {d['severity']} | MITRE: {d['technique_id']} ({d['technique_name']})\n"
            f"Årsaker: {d['reasons'] or '-'}\n"
            f"Anbefalt tiltak: {d['remedy']}\n"
            f"Linje: {d['line']}",
        )

    def export_csv(self):
        if not last_analysis["details"]:
            messagebox.showinfo("Ingen funn", "Det er ingen funn å eksportere.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV-fil", "*.csv")],
            initialfile="log_analysis_findings.csv",
        )
        if not path:
            return

        fields = [
            "file", "timestamp", "log_type", "activity", "status", "confidence",
            "reasons", "severity", "technique_id", "technique_name", "ips", "remedy", "line",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(last_analysis["details"])

        messagebox.showinfo("Eksportert", f"Lagret til:\n{path}")

    def show_timeline_chart(self):
        events = [e for e in last_analysis["timeline"] if e["timestamp"] is not None]
        if not events:
            messagebox.showinfo("Ingen tidsstempler", "Ingen hendelser med tidsstempel funnet.")
            return

        buckets = defaultdict(int)
        for ev in events:
            t_bucket = ev["timestamp"].replace(second=0, microsecond=0)
            buckets[t_bucket] += 1

        xs = sorted(buckets.keys())
        ys = [buckets[x] for x in xs]

        win = tk.Toplevel(self.root)
        win.title("Attack Timeline – Hendelser over tid")
        win.geometry("940x460")
        win.configure(bg=self.BG_CARD)

        toolbar = tk.Frame(win, bg=self.BG_PAGE, padx=10, pady=8)
        toolbar.pack(fill=tk.X)

        fig = Figure(figsize=(9.2, 4.0), dpi=100, facecolor="#FFFFFF")
        ax = fig.add_subplot(111)
        ax.plot(xs, ys, marker="o", color=self.ACCENT_BLUE, linewidth=2)
        ax.set_title("Hendelser over tid", fontsize=11, pad=10)
        ax.set_xlabel("Tidspunkt", fontsize=9)
        ax.set_ylabel("Antall funn", fontsize=9)
        ax.tick_params(axis="x", labelsize=8, rotation=25)
        ax.tick_params(axis="y", labelsize=8)
        ax.grid(True, linestyle="--", alpha=0.4)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for tick in ax.get_xticklabels():
            tick.set_ha("right")
        fig.tight_layout()

        def save_chart_png():
            out_path = filedialog.asksaveasfilename(
                parent=win,
                defaultextension=".png",
                filetypes=[("PNG-bilde", "*.png")],
                initialfile="attack_timeline.png",
            )
            if out_path:
                fig.savefig(out_path, dpi=150)
                messagebox.showinfo("Lagret", f"Tidsakse-graf lagret til:\n{out_path}", parent=win)

        self._make_action_button(toolbar, "Lagre som PNG", self.ACCENT_GREEN, save_chart_png).pack(
            side=tk.LEFT
        )

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerV3App(root)
    root.mainloop()

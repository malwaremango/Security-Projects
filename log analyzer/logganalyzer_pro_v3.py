"""
Python Log Analyzer Pro
Copyright malwaremango
@author: usah5

Verktøyet brukes til å analysere loggfiler og finne
mistenkelig aktivitet som malware, brute-force og
uautoriserte innlogginger.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import re
import json
import os
import csv
from collections import defaultdict
from datetime import datetime, timedelta

import matplotlib.pyplot as plt


# Innstillinger
CONFIG_FILE = "log_analyzer_config.json"

# Hvor mange mislykkede innlogginger som skal regnes som brute-force
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 2


# MITRE ATT&CK-teknikk-ID og navn for kategorier og verktøy
MITRE_TECHNIQUES = {
    "malware": {
        "technique_id": "T1204",
        "name": "User Execution"
    },
    "user_execution": {
        "technique_id": "T1204",
        "name": "User Execution"
    },
    "T1204": {
        "technique_id": "T1204",
        "name": "User Execution"
    },
    "file_tampering": {
        "technique_id": "T1565",
        "name": "Data Manipulation"
    },
    "unauthorized_access": {
        "technique_id": "T1078",
        "name": "Valid Accounts"
    },
    "security_breach": {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application"
    },
    "advanced_malware": {
        "technique_id": "T1014",
        "name": "Rootkit"
    },
    "phishing": {
        "technique_id": "T1566",
        "name": "Phishing"
    },
    "data_leakage": {
        "technique_id": "T1041",
        "name": "Exfiltration Over C2 Channel"
    },
    "brute_force": {
        "technique_id": "T1110",
        "name": "Brute Force"
    },
    "credential_dumping": {
        "technique_id": "T1003",
        "name": "OS Credential Dumping"
    },
    "suspicious_execution": {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter"
    },
    "javascript_activity": {
        "technique_id": "T1059.007",
        "name": "Command and Scripting Interpreter: JavaScript"
    },
    "wmi_execution": {
        "technique_id": "T1047",
        "name": "Windows Management Instrumentation"
    },
    "T1047": {
        "technique_id": "T1047",
        "name": "Windows Management Instrumentation"
    },
    "file_and_directory_discovery": {
        "technique_id": "T1083",
        "name": "File and Directory Discovery"
    },
    "T1083": {
        "technique_id": "T1083",
        "name": "File and Directory Discovery"
    },
    "suspicious_persistence": {
        "technique_id": "T1053",
        "name": "Scheduled Task/Job"
    },
    "dll_side_loading": {
        "technique_id": "T1574.002",
        "name": "Hijack Execution Flow: DLL Side-Loading"
    },
    "T1574.002": {
        "technique_id": "T1574.002",
        "name": "Hijack Execution Flow: DLL Side-Loading"
    },
    "services_file_permissions": {
        "technique_id": "T1574.010",
        "name": "Hijack Execution Flow: Services File Permissions Weakness"
    },
    "T1574.010": {
        "technique_id": "T1574.010",
        "name": "Hijack Execution Flow: Services File Permissions Weakness"
    },
    "suspicious_network": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol"
    },
    "account_manipulation": {
        "technique_id": "T1098",
        "name": "Account Manipulation"
    },
    "security_tool": {
        "technique_id": "T1588",
        "name": "Obtain Capabilities"
    },
    "log_integrity": {
        "technique_id": "T1070",
        "name": "Indicator Removal"
    },
    "authentication_logons": {
        "technique_id": "T1078",
        "name": "Valid Accounts"
    },
    "account_management": {
        "technique_id": "T1136",
        "name": "Create Account"
    },
    "kerberos_ad": {
        "technique_id": "T1558",
        "name": "Steal or Forge Kerberos Tickets"
    },
    "process_execution": {
        "technique_id": "T1543",
        "name": "Create or Modify System Process"
    },
    "object_share_access": {
        "technique_id": "T1021",
        "name": "Remote Services"
    },
    "policy_firewall": {
        "technique_id": "T1562",
        "name": "Impair Defenses"
    },
    "Mimikatz": {
        "technique_id": "T1003",
        "name": "OS Credential Dumping"
    },
    "ProcDump": {
        "technique_id": "T1003",
        "name": "OS Credential Dumping"
    },
    "PsExec": {
        "technique_id": "T1570",
        "name": "Lateral Tool Transfer"
    },
    "BloodHound": {
        "technique_id": "T1087",
        "name": "Account Discovery"
    },
    "SharpHound": {
        "technique_id": "T1087",
        "name": "Account Discovery"
    },
    "Rubeus": {
        "technique_id": "T1558",
        "name": "Steal or Forge Kerberos Tickets"
    },
    "LaZagne": {
        "technique_id": "T1555",
        "name": "Credentials from Password Stores"
    }
}


def get_technique_info(key_or_label):
    """Returnerer (technique_id, name) for en kategori, label eller verktøy."""
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


# Søkemønstre som brukes når loggene analyseres
patterns = {
    "malware":
        r"\bmalware\b|\bvirus\b|\btrojan\b|\bransomware\b|\bworm\b|"
        r"\bspyware\b|\badware\b|\brootkit\b|\bbotnet\b",

    "file_tampering":
        r"file tampering|unauthorized file modification|file integrity",

    "unauthorized_access":
        r"unauthorized access|login failure|invalid login|access denied|"
        r"failed login|authentication failure|authentication failed",

    "security_breach":
        r"security breach|data breach|intrusion detected|unauthorized entry",

    "advanced_malware":
        r"zero-day|advanced persistent threat|\bapt\b|rootkit",

    "phishing":
        r"phishing|spear phishing|fraudulent email|credential harvesting",

    "data_leakage":
        r"data leakage|data exfiltration|information leak|data theft",

    "credential_dumping":
        r"mimikatz|sekurlsa|lsadump|kerberos::|"
        r"privilege::debug|token::elevate|"
        r"samdump|procdump.*lsass|comsvcs\.dll",

    "suspicious_execution":
        r"powershell.*-enc(?:odedcommand)?|"
        r"frombase64string|downloadstring|"
        r"invoke-expression|invoke-mimikatz|"
        r"rundll32.*javascript:|regsvr32.*scrobj",

    "wmi_execution":
        r"\bwmic\b|win32_process|process call create|wmiprvse\.exe|windows management instrumentation",

    "file_and_directory_discovery":
        r"file and directory discovery|\b(?:dir|tree|get-childitem|gci)\b.*(?:/s\b|-recurse|system32|users\\|appdata)|\bfind\s+/\s+-name\b",

    "suspicious_persistence":
        r"scheduled task created|new service installed|"
        r"registry run key|startup folder|"
        r"persistence mechanism",

    "dll_side_loading":
        r"dll side-loading|dll sideloading|side-load|hijack execution flow|dll hijack",

    "services_file_permissions":
        r"services file permissions weakness|service binary permissions|weak service permissions|icacls.*service|subinacl.*service",

    "suspicious_network":
        r"command and control|c2 connection|"
        r"reverse shell|suspicious outbound connection",

    "account_manipulation":
        r"new user created|user account created|"
        r"account added to administrators|"
        r"privilege escalation|password changed",

    "log_integrity":
        r"event logging service shutdown|security event log cleared|"
        r"audit log cleared|audit log full",

    "authentication_logons":
        r"successful logon|failed logon|user logoff|"
        r"explicit credentials logon|special admin privileges assigned",

    "account_management":
        r"user account created|user account enabled|user account deleted|"
        r"added to security group|user account locked out",

    "kerberos_ad":
        r"kerberos tgt requested|kerberos service ticket requested|"
        r"kerberos pre-auth failed|ntlm credential validation|\b(?:4768|4769|4771|4776)\b",

    "process_execution":
        r"new process created|new service installed|scheduled task created|\b(?:4688|4697|4698)\b",

    "object_share_access":
        r"file registry handle requested|object accessed|"
        r"network share accessed|detailed network share check|\b(?:4656|4663|5140|5145)\b",

    "policy_firewall":
        r"system audit policy changed|windows firewall rule added|"
        r"windows firewall rule deleted|\b(?:4719|4946|4948)\b"
}


# Kjente malware-navn vi ser etter i loggen
malware_names = [
    "Emotet", "TrickBot", "QakBot", "Dridex", "Zeus", "SpyEye",
    "WannaCry", "NotPetya", "LockBit", "BlackCat", "REvil", "Conti",
    "Ryuk", "Maze", "Sodinokibi", "DarkSide", "BlackMatter",
    "Agent Tesla", "Formbook", "Lokibot", "RedLine", "Raccoon",
    "AsyncRAT", "NjRAT", "Quasar", "Remcos", "NanoCore",
    "PlugX", "ShadowPad", "Gh0st", "Poison Ivy",
    "Mirai", "Gafgyt", "Mozi", "Hajime",
    "Stuxnet", "Flame", "Duqu", "Equation Group"
]


# Dette er verktøy som kan brukes av angripere,
# men de er ikke nødvendigvis malware i seg selv.
security_tools = [
    "Cobalt Strike",
    "Metasploit",
    "Mimikatz",
    "BloodHound",
    "Impacket",
    "Rubeus",
    "LaZagne",
    "PowerSploit",
    "SharpHound",
    "PsExec",
    "ProcDump"
]


# Hvor alvorlig de forskjellige funnene er
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
    "policy_firewall": "HIGH"
}


# Brukes når vi skal sammenligne alvorlighetsgrad
severity_rank = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


# Forslag til hva brukeren bør gjøre når noe blir funnet
remedies = {
    "malware":
        "Isoler berørt system og kjør full malware-skanning.",

    "file_tampering":
        "Kontroller filintegritet og gjenopprett berørte filer fra backup.",

    "unauthorized_access":
        "Kontroller kontoaktivitet, tilbakestill passord og vurder MFA.",

    "security_breach":
        "Isoler berørte systemer og start en hendelsesundersøkelse.",

    "advanced_malware":
        "Isoler systemet og bruk avanserte endpoint- og threat hunting-verktøy.",

    "phishing":
        "Undersøk avsender, kontoaktivitet og forbedre e-postfiltrering.",

    "data_leakage":
        "Finn lekkasjekilden og vurder DLP, tilgangskontroll og logging.",

    "brute_force":
        "Blokker eller begrens kilde-IP og vurder MFA/rate limiting.",

    "credential_dumping":
        "Undersøk mulig credential dumping. Kontroller LSASS-tilgang, "
        "kontoaktivitet og eventuelle kompromitterte legitimasjonsdata.",

    "suspicious_execution":
        "Undersøk prosessens kommandolinje, skriptaktivitet "
        "og tilhørende prosesser.",

    "javascript_activity":
        "Kontroller prosessen som opprettet JavaScript-filen, filens hash/signatur "
        "og om det finnes tilhørende skriptkjøring. Filopprettelse alene bekrefter ikke kjøring.",

    "wmi_execution":
        "Undersøk WMI-kommandoer, foreldreprosess og eventuelle eksterne eller lokale prosesser startet via WMI.",

    "file_and_directory_discovery":
        "Kartlegg hvilken prosess og bruker som søkte etter filer/mapper, og se etter påfølgende datainnsamling eller eksfiltrering.",

    "suspicious_persistence":
        "Undersøk nye tjenester, planlagte oppgaver og "
        "registerendringer.",

    "dll_side_loading":
        "Undersøk om en legitim prosess laster en uautorisert eller mistenkelig DLL fra feil mappe.",

    "services_file_permissions":
        "Kontroller og stram inn filrettigheter på tjenestens binærfiler og tilhørende mapper.",

    "suspicious_network":
        "Undersøk nettverkstrafikk, tilkoblinger og mistenkelige IP-adresser.",

    "account_manipulation":
        "Kontroller kontoendringer, gruppemedlemskap og tilgangsrettigheter.",

    "security_tool":
        "Undersøk om sikkerhetsverktøyet er autorisert og hvem som startet det.",

    "log_integrity":
        "Undersøk umiddelbart hvorfor sikkerhetsloggen ble tømt, full eller stoppet.",

    "authentication_logons":
        "Gjennomgå innloggingsmønstre, eksplisitt legitimasjon og tildeling av privilegier.",

    "account_management":
        "Verifiser om kontoopprettelse, aktivering, sletting eller gruppeendringer er autorisert.",

    "kerberos_ad":
        "Kontroller autentiseringslogger for unormale billettforespørsler eller feil.",

    "process_execution":
        "Undersøk nye prosesser, installerte tjenester og planlagte oppgaver.",

    "object_share_access":
        "Kontroller tilgang til sensitive filer, registernøkler og delte nettverksressurser.",

    "policy_firewall":
        "Verifiser endringer i revisjonspolicy og brannmurregler."
}


# Mapping av viktige Windows Event ID-er til søkbare beskrivelser
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
    "4948": "Windows firewall rule deleted"
}


# Regex for å finne IPv4-adresser
IP_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
    r"){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


# Vi støtter noen vanlige dato- og tidsformater
TIMESTAMP_PATTERNS = [
    re.compile(
        r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})"
    ),
    re.compile(
        r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})"
    )
]


# Her lagrer vi resultatene fra siste analyse
last_analysis = {
    "files": [],
    "counts": defaultdict(int),
    "malware": defaultdict(int),
    "ips": defaultdict(lambda: {
        "activity": defaultdict(int),
        "total": 0,
        "severity": "LOW"
    }),
    "brute_force": [],
    "attack_scenarios": [],
    "timeline": [],
    "details": [],
    "total_lines": 0,
    "log_types": []
}


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
        json.dump(
            {"patterns": patterns, "remedies": remedies},
            f,
            indent=2,
            ensure_ascii=False
        )


def detect_log_type(line):
    lower = line.lower()

    if "sshd" in lower or "authentication failure" in lower:
        return "Linux auth.log / SSH"

    if "apache" in lower or "http/1." in lower:
        return "Apache / Web Server"

    if "iis" in lower:
        return "IIS / Web Server"

    if "windows event" in lower or "eventid" in lower:
        return "Windows Event Log"

    if "firewall" in lower or "iptables" in lower:
        return "Firewall"

    if "scada" in lower or "modbus" in lower or "plc" in lower:
        return "SCADA / ICS"

    if "nginx" in lower:
        return "Nginx / Web Server"

    return "Generic"


def extract_timestamp(line):
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            date_part = match.group(1)
            time_part = match.group(2)
            try:
                if len(time_part) == 5:
                    return datetime.strptime(
                        f"{date_part} {time_part}",
                        "%Y-%m-%d %H:%M"
                    )
                return datetime.strptime(
                    f"{date_part} {time_part}",
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                pass
    return None


def identify_activity(line, compiled_patterns, malware_patterns):
    activities = []
    lower_line = line.lower()

    for name, pattern in compiled_patterns.items():
        if pattern.search(lower_line):
            activities.append(name)

    for name, pattern in malware_patterns.items():
        if pattern.search(line):
            activities.append(f"Malware: {name}")

    for name in security_tools:
        tool_pattern = re.compile(re.escape(name), re.IGNORECASE)
        if tool_pattern.search(line):
            activities.append(f"Security Tool: {name}")

    # MITRE ATT&CK T1059.007: JavaScript.
    has_javascript_rule = bool(re.search(
        r"\bT1059\.007\b|technique_name\s*=\s*JavaScript",
        line,
        re.IGNORECASE
    ))

    is_file_create_event = bool(re.search(
        r"\bEventID\s*[:=]\s*11\b|\bEvent ID\s*[:=]?\s*11\b",
        line,
        re.IGNORECASE
    ))
    has_script_file = bool(re.search(
        r"(?:\.js|\.jse)(?:\b|$|\[\d+\])",
        line,
        re.IGNORECASE
    ))
    has_file_create_context = bool(re.search(
        r"\b(?:TargetFilename|TargetObject|Created|FileName|Description)\s*[:=]",
        line,
        re.IGNORECASE
    ))

    if has_javascript_rule or (
        is_file_create_event and has_script_file and has_file_create_context
    ):
        activities.append("javascript_activity")

    # MITRE ATT&CK T1574.002: DLL Side-Loading
    if re.search(
        r"\bT1574\.002\b|technique_name\s*=\s*DLL Side-Loading",
        line,
        re.IGNORECASE
    ):
        activities.append("dll_side_loading")

    # MITRE ATT&CK T1574.010: Services File Permissions Weakness
    if re.search(
        r"\bT1574\.010\b|Services File Permissions Weakness",
        line,
        re.IGNORECASE
    ):
        activities.append("services_file_permissions")

    # MITRE ATT&CK T1047: Windows Management Instrumentation
    if re.search(
        r"\bT1047\b|Windows Management Instrumentation",
        line,
        re.IGNORECASE
    ):
        activities.append("wmi_execution")

    # MITRE ATT&CK T1083: File and Directory Discovery
    if re.search(
        r"\bT1083\b|File and Directory Discovery",
        line,
        re.IGNORECASE
    ):
        activities.append("file_and_directory_discovery")

    return list(dict.fromkeys(activities))


def detect_brute_force(login_attempts):
    incidents = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    for ip, attempts in login_attempts.items():
        if not any(item[0] for item in attempts):
            continue

        attempts = sorted(
            attempts,
            key=lambda x: x[0] if x[0] else datetime.min
        )

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

            current_count = end_index - start_index + 1

            if current_count >= BRUTE_FORCE_THRESHOLD:
                relevant_attempts = attempts[start_index:end_index + 1]
                incidents.append({
                    "ip": ip,
                    "attempts": current_count,
                    "window": BRUTE_FORCE_WINDOW_MINUTES,
                    "severity": "HIGH",
                    "start": relevant_attempts[0][0],
                    "end": relevant_attempts[-1][0],
                    "lines": [item[1] for item in relevant_attempts],
                    "file": relevant_attempts[0][2]
                })
                start_index = end_index + 1

    return incidents


def get_top_attack_keys():
    """Returnerer nøklene til de mest fremtredende angrepene i Top Attacks."""
    counts = last_analysis["counts"]
    malware = last_analysis["malware"]
    ranked = []

    for key, val in counts.items():
        if val > 0:
            ranked.append((key, val))

    if malware:
        ranked.append(("malware", sum(malware.values())))

    ranked.sort(key=lambda x: x[1], reverse=True)
    return [key for key, _ in ranked[:5]]


def detect_attack_scenarios():
    """
    Korrelerer funn på tvers av kategorier og tilpasser scenariene
    slik at indikatorene og teknikkene samsvarer med faktiske funn og Top Attacks.
    """
    counts = last_analysis["counts"]
    malware = last_analysis["malware"]
    brute_force = last_analysis["brute_force"]
    top_keys = set(get_top_attack_keys())
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
    has_js = counts.get("javascript_activity", 0) > 0
    has_unauth = counts.get("unauthorized_access", 0) > 0 or len(brute_force) > 0
    has_phishing = counts.get("phishing", 0) > 0
    has_acct_manip = (
        counts.get("account_manipulation", 0) > 0
        or counts.get("account_management", 0) > 0
    )
    has_log_tamper = (
        counts.get("log_integrity", 0) > 0
        or counts.get("file_tampering", 0) > 0
    )
    has_data_leak = counts.get("data_leakage", 0) > 0
    has_susp_net = counts.get("suspicious_network", 0) > 0

    # 1. Malware / Execution Chain (kun teknikker som faktisk har treff)
    if has_malware or (has_susp_exec and (has_sec_tool or has_dll_hijack or has_wmi)):
        indicators = []
        techs = []

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
            "severity": "CRITICAL" if has_malware else "HIGH",
            "confidence": "Høy" if top_overlap >= 1 and has_malware else "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": (
                "Funn som samsvarer med toppaktivitet knyttet til skadevare og/eller "
                "mistenkelig prosess- og skriptkjøring."
            ),
            "action": (
                "Isoler berørt vert, inspiser prosesshierarki og kjør full sikkerhetsskanning."
            )
        })

    # 2. Unauthorized Access / Phishing / Account Compromise
    if has_unauth or has_phishing or has_acct_manip:
        indicators = []
        techs = []

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
                "description": (
                    "Uautorisert tilgang, phishing eller kontorelaterte hendelser som "
                    "er blant de mest fremtredende funnene i loggen."
                ),
                "action": (
                    "Kontroller berørte kontoer, blokker mistenkelige kilder, tilbakestill passord og vurder MFA."
                )
            })

    # 3. Command & Control / Data Exfiltration (kun faktiske treff)
    if has_data_leak or has_susp_net:
        indicators = []
        techs = []

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
            "description": (
                "Indikatorer på mistenkelig nettverkskommunikasjon eller mulig dataeksfiltrering."
            ),
            "action": (
                "Undersøk nettverkstrafikk og blokker uautoriserte eksterne forbindelser."
            )
        })

    # 4. Post-Exploitation: krever credential dumping + minst én faktisk persistence/hijack-mekanisme
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
            "description": (
                "Kombinasjon av legitimasjonsuthenting og vedvarende mekanismer eller kapring "
                "etter innledende tilgang."
            ),
            "action": (
                "Isoler berørt system, undersøk prosesser og legitimasjon, og tilbakestill berørte kontoer."
            )
        })

    # 5. Discovery & Execution
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
            if k in top_keys
        )

        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)),
            "name": "Discovery & Execution Activity",
            "severity": "MEDIUM",
            "confidence": "Middels",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": (
                "Kartlegging av filer og mapper kombinert med skript-, WMI- eller nettverksaktivitet."
            ),
            "action": (
                "Undersøk hvilke stier som ble kartlagt og sjekk for uautorisert filtilgang eller dataflyt."
            )
        })

    # 6. JavaScript-indikator
    if has_js:
        scenarios.append({
            "technique_id": "T1059.007",
            "name": "Command and Scripting Interpreter: JavaScript",
            "severity": "MEDIUM",
            "confidence": "Lav",
            "top_match": 1 if "javascript_activity" in top_keys else 0,
            "indicators": f"JavaScript-relatert regel eller filopprettelse ({counts['javascript_activity']} treff)",
            "description": (
                "Indikator på JavaScript-regel eller filopprettelse; bekrefter ikke kjøring alene."
            ),
            "action": (
                "Kontroller prosess, kommandolinje, hash/signatur og tilhørende prosess- eller nettverkshendelser."
            )
        })

    # 7. Defense Evasion: Log / File Tampering
    if has_log_tamper:
        indicators = []
        techs = []
        if counts.get("log_integrity", 0) > 0:
            indicators.append(f"Log Integrity ({counts['log_integrity']} treff)")
            techs.append("T1070")
        if counts.get("file_tampering", 0) > 0:
            indicators.append(f"File Tampering ({counts['file_tampering']} treff)")
            techs.append("T1565")

        top_overlap = sum(1 for k in ["log_integrity", "file_tampering"] if k in top_keys)

        scenarios.append({
            "technique_id": " / ".join(dict.fromkeys(techs)),
            "name": "Defense Evasion: Log Clearing / Tampering",
            "severity": "CRITICAL",
            "confidence": "Høy",
            "top_match": top_overlap,
            "indicators": ", ".join(indicators),
            "description": (
                "Tegn på sletting eller manipulering av logger og filer som kan påvirke hendelsesoversikten."
            ),
            "action": (
                "Sikre ekstern loggføring og undersøk hvem som endret eller tømte loggene."
            )
        })

    scenarios.sort(
        key=lambda x: (x.get("top_match", 0), severity_rank.get(x["severity"], 0)),
        reverse=True
    )
    return scenarios


def local_name(tag):
    """Return XML tag name without its namespace."""
    return tag.rsplit("}", 1)[-1]


def read_evtx_file(log_file):
    """
    Read an EVTX file and convert each Windows event
    into searchable text for the existing analyzer.
    """
    with Evtx(log_file) as evtx:
        for event_number, record in enumerate(evtx.records(), start=1):
            try:
                xml_data = record.xml()
                root = ET.fromstring(xml_data)

                system = None
                event_data = None

                for element in root.iter():
                    name = local_name(element.tag)
                    if name == "System":
                        system = element
                    elif name == "EventData":
                        event_data = element

                event_id = ""
                provider = ""
                computer = ""
                timestamp = ""
                channel = ""

                if system is not None:
                    for element in system.iter():
                        name = local_name(element.tag)
                        if name == "EventID":
                            event_id = (element.text or "").strip()
                        elif name == "Provider":
                            provider = element.attrib.get("Name", "")
                        elif name == "Computer":
                            computer = element.text or ""
                        elif name == "Channel":
                            channel = element.text or ""
                        elif name == "TimeCreated":
                            timestamp = element.attrib.get("SystemTime", "")

                fields = []
                if event_data is not None:
                    for element in event_data:
                        if local_name(element.tag) == "Data":
                            field_name = element.attrib.get("Name", "Data")
                            field_value = element.text or ""
                            fields.append(f"{field_name}={field_value}")

                user_data = []
                for element in root.iter():
                    if local_name(element.tag) == "UserData":
                        for child in element.iter():
                            if child is element:
                                continue
                            value = child.text
                            if value and value.strip():
                                user_data.append(
                                    f"{local_name(child.tag)}={value.strip()}"
                                )

                formatted_timestamp = ""
                if timestamp:
                    try:
                        parsed_time = datetime.fromisoformat(
                            timestamp.replace("Z", "+00:00")
                        )
                        formatted_timestamp = parsed_time.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    except ValueError:
                        formatted_timestamp = timestamp

                parts = [
                    f"Timestamp: {formatted_timestamp}",
                    f"EventID: {event_id}",
                    f"Provider: {provider}",
                    f"Computer: {computer}",
                    f"Channel: {channel}"
                ]

                parts.extend(fields)
                parts.extend(user_data)

                additional_data = []
                for element in root.iter():
                    if element.text and element.text.strip():
                        additional_data.append(element.text.strip())
                    for attribute, value in element.attrib.items():
                        if value and value.strip():
                            additional_data.append(f"{attribute}={value.strip()}")

                parts.extend(additional_data)

                if event_id in WINDOWS_EVENT_HINTS:
                    parts.append(WINDOWS_EVENT_HINTS[event_id])

                parts = list(dict.fromkeys(parts))
                yield event_number, " | ".join(parts)

            except ET.ParseError:
                continue


def read_log_lines(log_file):
    if log_file.lower().endswith(".evtx"):
        yield from read_evtx_file(log_file)
    else:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                yield line_number, line


def detect_file_type(log_file):
    if log_file.lower().endswith(".evtx"):
        return "Windows Event Log (EVTX)"

    scores = defaultdict(int)
    try:
        for i, (line_num, line) in enumerate(read_log_lines(log_file)):
            if i >= 100:
                break
            log_type = detect_log_type(line)
            scores[log_type] += 1
    except Exception:
        return "Unknown"

    if not scores:
        return "Unknown"

    return max(scores, key=scores.get)


def analyze_log(log_file):
    counts = defaultdict(int)
    found_malware = defaultdict(int)
    detailed_matches = []
    timeline = []
    login_attempts = defaultdict(list)
    total = 0

    compiled = {
        key: re.compile(value, re.IGNORECASE)
        for key, value in patterns.items()
    }

    malware_patterns = {
        name: re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
        for name in malware_names
    }

    filename = os.path.basename(log_file)
    log_type = detect_file_type(log_file)

    for line_num, line in read_log_lines(log_file):
        total += 1

        timestamp = extract_timestamp(line)
        ips = IP_PATTERN.findall(line)
        activities = identify_activity(line, compiled, malware_patterns)

        for activity in activities:
            tech_id, tech_name = get_technique_info(activity)
            tech_label = f"[{tech_id}] {tech_name}"

            if activity.startswith("Malware:"):
                malware_name = activity.replace("Malware:", "").strip()
                found_malware[malware_name] += 1
                detailed_matches.append(
                    (filename, f"{activity} {tech_label}", line_num, "HIGH")
                )
            elif activity.startswith("Security Tool:"):
                counts["security_tool"] += 1
                level = "HIGH" if "Mimikatz" in activity else "MEDIUM"
                detailed_matches.append(
                    (filename, f"{activity} {tech_label}", line_num, level)
                )
            else:
                counts[activity] += 1
                detailed_matches.append(
                    (
                        filename,
                        f"{activity.replace('_', ' ').title()} {tech_label}",
                        line_num,
                        severity.get(activity, "LOW")
                    )
                )

        for ip in ips:
            last_analysis["ips"][ip]["total"] += 1
            for activity in activities:
                if activity.startswith("Malware:") or activity.startswith("Security Tool:"):
                    activity_name = activity
                else:
                    activity_name = activity.replace("_", " ").title()

                last_analysis["ips"][ip]["activity"][activity_name] += 1

                if activity.startswith("Malware:"):
                    current_severity = "HIGH"
                elif activity.startswith("Security Tool:"):
                    current_severity = "HIGH" if "Mimikatz" in activity else "MEDIUM"
                else:
                    current_severity = severity.get(activity, "LOW")

                old_rank = severity_rank[last_analysis["ips"][ip]["severity"]]
                new_rank = severity_rank[current_severity]
                if new_rank > old_rank:
                    last_analysis["ips"][ip]["severity"] = current_severity

        failed_login = re.search(
            r"failed login|login failure|"
            r"authentication failure|"
            r"authentication failed|invalid login",
            line,
            re.IGNORECASE
        )

        if failed_login and ips:
            for ip in ips:
                login_attempts[ip].append((timestamp, line_num, filename))

        if activities:
            for activity in activities:
                tech_id, tech_name = get_technique_info(activity)
                if activity.startswith("Malware:") or activity.startswith("Security Tool:"):
                    base_name = activity
                else:
                    base_name = activity.replace("_", " ").title()
                event_name = f"{base_name} [{tech_id} {tech_name}]"

                if activity.startswith("Malware:"):
                    event_severity = "HIGH"
                elif activity.startswith("Security Tool:"):
                    event_severity = "HIGH" if "Mimikatz" in activity else "MEDIUM"
                else:
                    event_severity = severity.get(activity, "LOW")

                timeline.append({
                    "timestamp": timestamp,
                    "event": event_name,
                    "severity": event_severity,
                    "file": filename,
                    "line": line_num
                })

    brute_force = detect_brute_force(login_attempts)

    return (
        counts,
        found_malware,
        total,
        detailed_matches,
        timeline,
        brute_force,
        log_type
    )


# ------------------------------------------------------
# Ny skann
# ------------------------------------------------------

def new_scan():
    last_analysis["files"] = []
    last_analysis["counts"] = defaultdict(int)
    last_analysis["malware"] = defaultdict(int)
    last_analysis["ips"] = defaultdict(
        lambda: {
            "activity": defaultdict(int),
            "total": 0,
            "severity": "LOW"
        }
    )
    last_analysis["brute_force"] = []
    last_analysis["attack_scenarios"] = []
    last_analysis["timeline"] = []
    last_analysis["details"] = []
    last_analysis["total_lines"] = 0
    last_analysis["log_types"] = []

    search_var.set("")
    filter_var.set("All")

    img_label.config(image="")
    img_label.image = None

    update_results()
    update_file_details()
    update_attack_overview()
    update_potential_attacks()
    update_ip_table()
    update_timeline()
    update_log_type()

    status_var.set("Klar for ny skann...")
    notebook.select(tab_overview)
    root.after(100, run_analysis)


def run_analysis():
    log_files = filedialog.askopenfilenames(
        title="Velg loggfil(er)",
        filetypes=[
            ("Log Files", "*.log *.evtx"),
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )

    if not log_files:
        status_var.set("Ny skann avbrutt")
        return

    status_var.set("Analyserer loggfil(er)...")
    root.update()

    last_analysis["files"] = list(log_files)
    last_analysis["counts"] = defaultdict(int)
    last_analysis["malware"] = defaultdict(int)
    last_analysis["ips"] = defaultdict(
        lambda: {
            "activity": defaultdict(int),
            "total": 0,
            "severity": "LOW"
        }
    )
    last_analysis["brute_force"] = []
    last_analysis["attack_scenarios"] = []
    last_analysis["timeline"] = []
    last_analysis["details"] = []
    last_analysis["total_lines"] = 0
    last_analysis["log_types"] = []

    all_details = []

    for log_file in log_files:
        (
            counts,
            found_malware,
            total,
            detailed_matches,
            timeline,
            brute_force,
            log_type
        ) = analyze_log(log_file)

        last_analysis["total_lines"] += total
        last_analysis["log_types"].append({
            "file": os.path.basename(log_file),
            "type": log_type
        })
        all_details.extend(detailed_matches)

        for key, value in counts.items():
            last_analysis["counts"][key] += value

        for key, value in found_malware.items():
            last_analysis["malware"][key] += value

        last_analysis["timeline"].extend(timeline)
        last_analysis["brute_force"].extend(brute_force)

    if last_analysis["brute_force"]:
        last_analysis["counts"]["brute_force"] = len(last_analysis["brute_force"])
        tech_id, tech_name = get_technique_info("brute_force")
        for incident in last_analysis["brute_force"]:
            all_details.append(
                (
                    incident["file"],
                    f"Brute Force [{tech_id}] {tech_name}",
                    incident["lines"][0],
                    "HIGH"
                )
            )
            ip = incident["ip"]
            last_analysis["ips"][ip]["activity"]["Brute Force"] += incident["attempts"]
            last_analysis["ips"][ip]["severity"] = "HIGH"

    last_analysis["details"] = all_details
    last_analysis["timeline"].sort(
        key=lambda x: (
            x["timestamp"] is None,
            x["timestamp"] or datetime.min
        )
    )

    last_analysis["attack_scenarios"] = detect_attack_scenarios()

    primary_file = log_files[0]
    base, _ = os.path.splitext(primary_file)
    report = base + "_security_report.txt"
    create_incident_report(report, log_files)

    graph = None
    if last_analysis["counts"]:
        graph = base + "_graph.png"
        plt.figure(figsize=(10, 5))
        labels = [
            key.replace("_", " ").title()
            for key in last_analysis["counts"].keys()
        ]
        values = list(last_analysis["counts"].values())
        plt.bar(labels, values)
        plt.title("Suspicious Activity Detected")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig(graph, dpi=100)
        plt.close()
        show_graph(graph)

    update_results()
    update_file_details()
    update_attack_overview()
    update_potential_attacks()
    update_ip_table()
    update_timeline()
    update_log_type()

    status_var.set("Analyse fullført")

    msg = (
        f"Analyse fullført!\n\n"
        f"Filer analysert: {len(log_files)}\n"
        f"Linjer analysert: {last_analysis['total_lines']}\n\n"
        f"Rapport:\n{report}"
    )
    if graph:
        msg += f"\n\nGraf:\n{graph}"

    if (
        last_analysis["counts"]
        or last_analysis["malware"]
        or last_analysis["brute_force"]
    ):
        messagebox.showwarning(
            "Sikkerhetsadvarsel",
            "⚠ Mistenkelig aktivitet ble funnet!"
        )

    messagebox.showinfo("Analyse ferdig", msg)


def create_incident_report(path, log_files):
    counts = last_analysis["counts"]
    malware = last_analysis["malware"]
    scenarios = last_analysis["attack_scenarios"]

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for name, count in counts.items():
        level = severity.get(name, "LOW")
        severity_counts[level] += count

    severity_counts["HIGH"] += len(last_analysis["brute_force"])

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("       SECURITY INCIDENT REPORT\n")
        f.write("=" * 50 + "\n\n")
        f.write(
            f"Analysis date:\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )
        f.write(f"Files analyzed:\n{len(log_files)}\n\n")
        f.write(f"Lines analyzed:\n{last_analysis['total_lines']}\n\n")

        f.write("-" * 40 + "\n")
        f.write("LOG TYPES\n")
        f.write("-" * 40 + "\n")
        for item in last_analysis["log_types"]:
            f.write(f"{item['file']}: {item['type']}\n")
        f.write("\n")

        f.write("-" * 40 + "\n")
        f.write("RISK SUMMARY\n")
        f.write("-" * 40 + "\n")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            f.write(f"{level}: {severity_counts[level]}\n")
        f.write("\n")

        f.write("-" * 40 + "\n")
        f.write("POTENTIAL ATTACK SCENARIOS\n")
        f.write("-" * 40 + "\n")
        if scenarios:
            for sc in scenarios:
                f.write(
                    f"Scenario: {sc['name']} "
                    f"[{sc.get('technique_id', 'T0000')}] [{sc['severity']}]\n"
                )
                f.write(f"Confidence: {sc['confidence']}\n")
                f.write(f"Indicators: {sc['indicators']}\n")
                f.write(f"Assessment: {sc['description']}\n")
                f.write(f"Recommended action: {sc['action']}\n\n")
        else:
            f.write("No multi-stage attack scenarios identified.\n\n")

        f.write("-" * 40 + "\n")
        f.write("BRUTE FORCE DETECTION\n")
        f.write("-" * 40 + "\n")
        if last_analysis["brute_force"]:
            for incident in last_analysis["brute_force"]:
                f.write(f"IP: {incident['ip']}\n")
                f.write(f"Failed attempts: {incident['attempts']}\n")
                f.write(f"Time window: {incident['window']} minutes\n")
                f.write(f"Severity: {incident['severity']}\n\n")
        else:
            f.write("No brute-force attacks detected.\n")
        f.write("\n")

        f.write("-" * 40 + "\n")
        f.write("TOP THREATS\n")
        f.write("-" * 40 + "\n")
        threats = []
        for name, count in counts.items():
            tech_id, tech_name = get_technique_info(name)
            threats.append((f"{name.replace('_', ' ').title()} [{tech_id} {tech_name}]", count))
        for name, count in malware.items():
            tech_id, tech_name = get_technique_info(name)
            threats.append((f"{name} [{tech_id} {tech_name}]", count))
        if last_analysis["brute_force"]:
            tech_id, tech_name = get_technique_info("brute_force")
            threats.append(
                (
                    f"Brute Force [{tech_id} {tech_name}]",
                    sum(x["attempts"] for x in last_analysis["brute_force"])
                )
            )
        threats.sort(key=lambda x: x[1], reverse=True)
        for index, (name, count) in enumerate(threats[:10], start=1):
            f.write(f"{index}. {name:<45} {count}\n")
        f.write("\n")

        f.write("-" * 40 + "\n")
        f.write("TOP SOURCE IP ADDRESSES\n")
        f.write("-" * 40 + "\n")
        sorted_ips = sorted(
            last_analysis["ips"].items(),
            key=lambda x: x[1]["total"],
            reverse=True
        )
        for ip, data in sorted_ips[:10]:
            f.write(f"{ip:<18} {data['total']} events [{data['severity']}]\n")
        f.write("\n")

        f.write("-" * 40 + "\n")
        f.write("RECOMMENDED ACTIONS\n")
        f.write("-" * 40 + "\n")
        recommended = set()
        for name in counts:
            if name in remedies:
                recommended.add((severity.get(name, "LOW"), remedies[name]))
        if last_analysis["brute_force"]:
            recommended.add(("HIGH", remedies["brute_force"]))
        for level, action in sorted(recommended, key=lambda x: -severity_rank[x[0]]):
            f.write(f"[{level}]\n")
            f.write(f"{action}\n\n")


def show_graph(path):
    try:
        img = tk.PhotoImage(file=path)
        if img.width() > 700:
            img = img.subsample(2, 2)
        img_label.config(image=img)
        img_label.image = img
    except Exception as e:
        print("Kunne ikke vise graf:", e)


def update_attack_overview():
    for widget in overview_frame.winfo_children():
        widget.destroy()

    counts = last_analysis["counts"]
    malware = last_analysis["malware"]
    scenarios = last_analysis["attack_scenarios"]

    risk_frame = tk.Frame(overview_frame, bg="#ecf0f1")
    risk_frame.pack(fill="x", pady=10)

    risk_values = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for name, count in counts.items():
        level = severity.get(name, "LOW")
        risk_values[level] += count

    risk_values["HIGH"] += len(last_analysis["brute_force"])

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        card = tk.Frame(risk_frame, bg="white", relief="solid", bd=1)
        card.pack(side="left", fill="x", expand=True, padx=5)

        tk.Label(
            card,
            text=level,
            font=("Segoe UI", 10, "bold"),
            bg="white",
            fg="#2c3e50"
        ).pack(pady=(10, 2))

        tk.Label(
            card,
            text=str(risk_values[level]),
            font=("Segoe UI", 22, "bold"),
            bg="white",
            fg="#c0392b" if level in ["CRITICAL", "HIGH"] else "#f39c12"
        ).pack(pady=(0, 10))

    if scenarios:
        scenario_frame = tk.LabelFrame(
            overview_frame,
            text="   POTENTIAL ATTACK SCENARIOS   ",
            font=("Segoe UI", 10, "bold"),
            bg="#ecf0f1",
            fg="#c0392b"
        )
        scenario_frame.pack(fill="x", pady=(5, 10))

        for sc in scenarios[:3]:
            card = tk.Frame(scenario_frame, bg="white", relief="solid", bd=1)
            card.pack(fill="x", padx=8, pady=4)

            top = tk.Frame(card, bg="white")
            top.pack(fill="x", padx=10, pady=(6, 2))

            tk.Label(
                top,
                text=f"⚠  [{sc.get('technique_id', 'T0000')}] {sc['name']}",
                font=("Segoe UI", 10, "bold"),
                bg="white",
                fg="#c0392b"
            ).pack(side="left")

            tk.Label(
                top,
                text=sc["severity"],
                font=("Segoe UI", 8, "bold"),
                bg="#c0392b" if sc["severity"] == "CRITICAL" else "#e67e22",
                fg="white",
                padx=8,
                pady=1
            ).pack(side="right")

            tk.Label(
                card,
                text=f"Indikatorer: {sc['indicators']}",
                font=("Segoe UI", 9, "bold"),
                bg="white",
                fg="#2c3e50",
                anchor="w",
                justify="left"
            ).pack(fill="x", padx=10)

            tk.Label(
                card,
                text=sc["description"],
                font=("Segoe UI", 9),
                bg="white",
                fg="#555",
                wraplength=920,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(2, 6))

    attack_frame = tk.LabelFrame(
        overview_frame,
        text="   TOP ATTACKS   ",
        font=("Segoe UI", 10, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    )
    attack_frame.pack(fill="both", expand=True, pady=10)

    attacks = []
    for name, count in counts.items():
        tech_id, tech_name = get_technique_info(name)
        attacks.append(
            (
                f"{name.replace('_', ' ').title()}  •  [{tech_id}] {tech_name}",
                count,
                severity.get(name, "LOW")
            )
        )
    for name, count in malware.items():
        tech_id, tech_name = get_technique_info(name)
        attacks.append((f"{name}  •  [{tech_id}] {tech_name}", count, "HIGH"))
    if last_analysis["brute_force"]:
        tech_id, tech_name = get_technique_info("brute_force")
        attacks.append(
            (
                f"Brute Force  •  [{tech_id}] {tech_name}",
                sum(x["attempts"] for x in last_analysis["brute_force"]),
                "HIGH"
            )
        )
    attacks.sort(key=lambda x: x[1], reverse=True)

    for name, count, level in attacks[:10]:
        row = tk.Frame(attack_frame, bg="white", relief="solid", bd=1)
        row.pack(fill="x", padx=8, pady=3)

        tk.Label(
            row,
            text=name,
            font=("Segoe UI", 10, "bold"),
            bg="white",
            fg="#2c3e50"
        ).pack(side="left", padx=10, pady=7)

        tk.Label(
            row,
            text=level,
            font=("Segoe UI", 9, "bold"),
            bg="#34495e",
            fg="white",
            padx=8
        ).pack(side="right", padx=10)

        tk.Label(
            row,
            text=str(count),
            font=("Segoe UI", 10, "bold"),
            bg="white",
            fg="#2980b9"
        ).pack(side="right", padx=10)


def update_potential_attacks():
    for widget in potential_attacks_frame.winfo_children():
        widget.destroy()

    scenarios = last_analysis["attack_scenarios"]

    header = tk.Frame(potential_attacks_frame, bg="#2c3e50")
    header.pack(fill="x", pady=(0, 10))

    tk.Label(
        header,
        text=f"   Identifiserte angrepsscenarier: {len(scenarios)}",
        font=("Segoe UI", 11, "bold"),
        bg="#2c3e50",
        fg="white",
        pady=8
    ).pack(anchor="w")

    if not scenarios:
        tk.Label(
            potential_attacks_frame,
            text="Ingen sammensatte angrepsscenarier identifisert for denne skannen.",
            font=("Segoe UI", 11),
            fg="#7f8c8d",
            bg="#ecf0f1"
        ).pack(pady=30)
        return

    for sc in scenarios:
        card = tk.Frame(potential_attacks_frame, bg="white", relief="solid", bd=1)
        card.pack(fill="x", pady=6, padx=6)

        top = tk.Frame(card, bg="white")
        top.pack(fill="x", padx=12, pady=(10, 4))

        tk.Label(
            top,
            text=f"⚠  [{sc.get('technique_id', 'T0000')}] {sc['name']}",
            font=("Segoe UI", 12, "bold"),
            bg="white",
            fg="#c0392b"
        ).pack(side="left")

        tk.Label(
            top,
            text=sc["severity"],
            font=("Segoe UI", 9, "bold"),
            bg="#c0392b" if sc["severity"] == "CRITICAL" else "#e67e22",
            fg="white",
            padx=10,
            pady=2
        ).pack(side="right")

        tk.Label(
            top,
            text=f"Sannsynlighet: {sc['confidence']}",
            font=("Segoe UI", 9, "bold"),
            bg="#ecf0f1",
            fg="#2c3e50",
            padx=8,
            pady=2
        ).pack(side="right", padx=8)

        tk.Label(
            card,
            text=f"Utløsende hendelser: {sc['indicators']}",
            font=("Segoe UI", 10, "bold"),
            bg="white",
            fg="#2980b9",
            wraplength=920,
            justify="left"
        ).pack(anchor="w", padx=12, pady=(2, 4))

        tk.Label(
            card,
            text=f"Vurdering: {sc['description']}",
            font=("Segoe UI", 10),
            bg="white",
            fg="#2c3e50",
            wraplength=920,
            justify="left"
        ).pack(anchor="w", padx=12, pady=(0, 6))

        tk.Label(
            card,
            text=f"Anbefalt tiltak: {sc['action']}",
            font=("Segoe UI", 9, "bold"),
            bg="#fef9e7",
            fg="#7d6608",
            wraplength=920,
            justify="left",
            padx=8,
            pady=6
        ).pack(fill="x", padx=12, pady=(0, 10))


def update_results():
    for widget in results_frame.winfo_children():
        widget.destroy()

    total = last_analysis["total_lines"]
    counts = last_analysis["counts"]
    malware = last_analysis["malware"]
    scenarios = last_analysis["attack_scenarios"]

    header = tk.Frame(results_frame, bg="#2c3e50")
    header.pack(fill="x", pady=(0, 10))

    tk.Label(
        header,
        text=f"   Totalt linjer analysert: {total}",
        font=("Segoe UI", 11, "bold"),
        bg="#2c3e50",
        fg="white",
        pady=8
    ).pack(anchor="w")

    if (
        not counts
        and not malware
        and not last_analysis["brute_force"]
    ):
        tk.Label(
            results_frame,
            text="✓ Ingen mistenkelig aktivitet funnet",
            font=("Segoe UI", 12),
            fg="#27ae60",
            bg="#ecf0f1"
        ).pack(pady=20)
        return

    if scenarios:
        section = tk.LabelFrame(
            results_frame,
            text="   ⚠ Potensielle angrepsscenarier   ",
            font=("Segoe UI", 10, "bold"),
            bg="#ecf0f1",
            fg="#c0392b"
        )
        section.pack(fill="x", pady=(0, 12), padx=2)

        for sc in scenarios:
            card = tk.Frame(section, bg="white", relief="solid", bd=1)
            card.pack(fill="x", pady=4, padx=6)

            top = tk.Frame(card, bg="white")
            top.pack(fill="x", padx=10, pady=(8, 2))

            tk.Label(
                top,
                text=f"[{sc.get('technique_id', 'T0000')}] {sc['name']}",
                font=("Segoe UI", 11, "bold"),
                bg="white",
                fg="#c0392b"
            ).pack(side="left")

            tk.Label(
                top,
                text=sc["severity"],
                font=("Segoe UI", 9, "bold"),
                bg="#c0392b" if sc["severity"] == "CRITICAL" else "#e67e22",
                fg="white",
                padx=8
            ).pack(side="right")

            tk.Label(
                card,
                text=f"Indikatorer: {sc['indicators']}",
                font=("Segoe UI", 9, "bold"),
                bg="white",
                fg="#2980b9",
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 2))

            tk.Label(
                card,
                text=sc["description"],
                font=("Segoe UI", 9),
                bg="white",
                fg="#2c3e50",
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 4))

            tk.Label(
                card,
                text=f"Tiltak: {sc['action']}",
                font=("Segoe UI", 9, "italic"),
                bg="white",
                fg="#555",
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 8))

    if last_analysis["brute_force"]:
        section = tk.LabelFrame(
            results_frame,
            text="   ⚠ Brute Force Detected   ",
            font=("Segoe UI", 10, "bold"),
            bg="#ecf0f1",
            fg="#c0392b"
        )
        section.pack(fill="x", pady=(0, 12), padx=2)

        for incident in last_analysis["brute_force"]:
            row = tk.Frame(section, bg="white", relief="solid", bd=1)
            row.pack(fill="x", pady=4, padx=6)

            text = (
                f"IP: {incident['ip']}\n"
                f"Failed attempts: {incident['attempts']}\n"
                f"Time window: {incident['window']} minutes\n"
                f"Severity: {incident['severity']}"
            )
            tk.Label(
                row,
                text=text,
                font=("Segoe UI", 10),
                bg="white",
                fg="#2c3e50",
                justify="left"
            ).pack(anchor="w", padx=10, pady=8)

    if malware:
        section = tk.LabelFrame(
            results_frame,
            text="   Oppdagede Malware   ",
            font=("Segoe UI", 10, "bold"),
            bg="#ecf0f1",
            fg="#c0392b"
        )
        section.pack(fill="x", pady=(0, 12), padx=2)

        for name, count in sorted(malware.items(), key=lambda x: -x[1]):
            tech_id, tech_name = get_technique_info(name)
            row = tk.Frame(section, bg="white", relief="solid", bd=1)
            row.pack(fill="x", pady=3, padx=6)

            tk.Label(
                row,
                text=f"🦠   {name}  [{tech_id}] {tech_name}",
                font=("Segoe UI", 11, "bold"),
                bg="white",
                fg="#c0392b"
            ).pack(side="left", padx=10, pady=6)

            tk.Label(
                row,
                text=f"{count} treff",
                font=("Segoe UI", 10),
                bg="#e74c3c",
                fg="white",
                padx=8,
                pady=2
            ).pack(side="right", padx=10)

    if counts:
        section = tk.LabelFrame(
            results_frame,
            text="   Kategorier   ",
            font=("Segoe UI", 10, "bold"),
            bg="#ecf0f1",
            fg="#2c3e50"
        )
        section.pack(fill="x", pady=5, padx=2)

        for name, count in counts.items():
            level = severity.get(name, "LOW")
            tech_id, tech_name = get_technique_info(name)
            card = tk.Frame(section, bg="white", relief="solid", bd=1)
            card.pack(fill="x", pady=4, padx=6)

            top = tk.Frame(card, bg="white")
            top.pack(fill="x", padx=10, pady=(8, 2))

            tk.Label(
                top,
                text=f"{name.replace('_', ' ').title()}  •  [{tech_id}] {tech_name}",
                font=("Segoe UI", 11, "bold"),
                bg="white",
                fg="#2c3e50"
            ).pack(side="left")

            tk.Label(
                top,
                text=level,
                font=("Segoe UI", 9, "bold"),
                bg="#34495e",
                fg="white",
                padx=8
            ).pack(side="right")

            tk.Label(
                top,
                text=f"{count} treff",
                font=("Segoe UI", 10),
                bg="white",
                fg="#2980b9"
            ).pack(side="right", padx=10)

            tk.Label(
                card,
                text=remedies.get(name, ""),
                font=("Segoe UI", 9),
                bg="white",
                fg="#555",
                wraplength=650,
                justify="left"
            ).pack(anchor="w", padx=10, pady=(0, 8))


def update_ip_table():
    for row in ip_tree.get_children():
        ip_tree.delete(row)

    sorted_ips = sorted(
        last_analysis["ips"].items(),
        key=lambda x: x[1]["total"],
        reverse=True
    )

    for ip, data in sorted_ips:
        activities = ", ".join(
            f"{name} ({count})"
            for name, count in data["activity"].items()
        )
        ip_tree.insert(
            "",
            "end",
            values=(ip, activities, data["total"], data["severity"])
        )


def update_timeline():
    for row in timeline_tree.get_children():
        timeline_tree.delete(row)

    for event in last_analysis["timeline"]:
        if event["timestamp"]:
            timestamp = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = "Unknown"

        timeline_tree.insert(
            "",
            "end",
            values=(
                timestamp,
                event["event"],
                event["severity"],
                event["file"],
                event["line"]
            )
        )


def update_log_type():
    for row in log_type_tree.get_children():
        log_type_tree.delete(row)

    for item in last_analysis["log_types"]:
        log_type_tree.insert(
            "",
            "end",
            values=(item["file"], item["type"])
        )


def update_file_details(detailed_matches=None):
    for row in tree.get_children():
        tree.delete(row)

    if detailed_matches is None:
        detailed_matches = last_analysis["details"]

    search = search_var.get().lower().strip()
    selected_filter = filter_var.get()

    for filename, attack, line_num, level in detailed_matches:
        text = f"{filename} {attack} {line_num} {level}".lower()

        if search and search not in text:
            continue

        if selected_filter != "All":
            if selected_filter not in attack and selected_filter != level:
                continue

        tree.insert(
            "",
            "end",
            values=(filename, attack, level, line_num)
        )


def apply_filter(*args):
    update_file_details(last_analysis["details"])


def export_csv():
    if not last_analysis["details"]:
        messagebox.showinfo("Eksport", "Det finnes ingen resultater å eksportere.")
        return

    path = filedialog.asksaveasfilename(
        title="Lagre CSV",
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")]
    )
    if not path:
        return

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Attack", "Severity", "Line"])
        for item in last_analysis["details"]:
            writer.writerow(item)

    messagebox.showinfo("Eksport", f"CSV lagret:\n{path}")


def add_pattern():
    name = simpledialog.askstring("Nytt mønster", "Navn på mønsteret:")
    if not name:
        return

    regex = simpledialog.askstring("Nytt mønster", "Regex-mønster:")
    if not regex:
        return

    tech_id = simpledialog.askstring(
        "MITRE ATT&CK Teknikk-ID",
        "Teknikk-ID (f.eks. T1003) [valgfritt]:",
        initialvalue="T0000"
    ) or "T0000"

    tech_name = simpledialog.askstring(
        "MITRE ATT&CK Teknikknavn",
        "Teknikknavn [valgfritt]:",
        initialvalue=name.replace("_", " ").title()
    ) or name.replace("_", " ").title()

    try:
        re.compile(regex)
        patterns[name] = regex
        remedies[name] = "Egendefinert mønster – ingen remedy satt."
        severity[name] = "MEDIUM"
        MITRE_TECHNIQUES[name] = {
            "technique_id": tech_id.strip(),
            "name": tech_name.strip()
        }
        save_patterns()
        messagebox.showinfo("Suksess", f"Mønsteret '{name}' ble lagt til!")
    except re.error:
        messagebox.showerror("Feil", "Ugyldig regex-mønster.")


# Lager selve vinduet og alle fanene
def create_gui():
    global root
    global results_frame
    global potential_attacks_frame
    global img_label
    global status_var
    global tree
    global overview_frame
    global ip_tree
    global timeline_tree
    global log_type_tree
    global search_var
    global filter_var
    global notebook
    global tab_overview

    root = tk.Tk()
    root.title("Log Analyzer Pro")
    root.geometry("1150x820")
    root.configure(bg="#ecf0f1")
    root.minsize(900, 650)

    style = ttk.Style()
    style.theme_use("clam")

    style.configure("TNotebook", background="#ecf0f1", borderwidth=0)
    style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[14, 8])
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#2980b9"), ("!selected", "#bdc3c7")],
        foreground=[("selected", "white"), ("!selected", "#2c3e50")]
    )
    style.configure(
        "Treeview.Heading",
        font=("Segoe UI", 10, "bold"),
        background="#2c3e50",
        foreground="white"
    )
    style.configure("Treeview", font=("Segoe UI", 9), rowheight=26)

    header = tk.Frame(root, bg="#1a252f", height=70)
    header.pack(fill="x")
    header.pack_propagate(False)

    left_header = tk.Frame(header, bg="#1a252f")
    left_header.pack(side="left", padx=20)

    logo_canvas = tk.Canvas(left_header, width=42, height=42, bg="#1a252f", highlightthickness=0)
    logo_canvas.pack(side="left", padx=(0, 12), pady=12)
    logo_canvas.create_oval(4, 4, 38, 38, outline="#3498db", width=3)
    logo_canvas.create_oval(12, 12, 30, 30, outline="#3498db", width=2)
    logo_canvas.create_line(28, 28, 38, 38, fill="#e74c3c", width=3)

    title_frame = tk.Frame(left_header, bg="#1a252f")
    title_frame.pack(side="left")

    tk.Label(
        title_frame,
        text="Python Log Analyzer Pro v3 © malwaremango",
        font=("Segoe UI", 16, "bold"),
        bg="#1a252f",
        fg="white"
    ).pack(anchor="w")

    tk.Label(
        title_frame,
        text="Security monitoring and log analysis",
        font=("Segoe UI", 9),
        bg="#1a252f",
        fg="#95a5a6"
    ).pack(anchor="w")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=12, pady=12)

    tab_overview = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_overview, text="   Attack Overview   ")

    overview_frame = tk.Frame(tab_overview, bg="#ecf0f1")
    overview_frame.pack(fill="both", expand=True, padx=15, pady=15)

    tk.Label(
        overview_frame,
        text="Security Overview",
        font=("Segoe UI", 18, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(anchor="w")

    tk.Label(
        overview_frame,
        text="Analyse loggfiler og identifiser mistenkelig aktivitet.",
        font=("Segoe UI", 9),
        bg="#ecf0f1",
        fg="#7f8c8d"
    ).pack(anchor="w")

    overview_buttons = tk.Frame(overview_frame, bg="#ecf0f1")
    overview_buttons.pack(fill="x", pady=15)

    tk.Button(
        overview_buttons,
        text="＋  Ny skann",
        command=new_scan,
        font=("Segoe UI", 11, "bold"),
        bg="#2980b9",
        fg="white",
        activebackground="#3498db",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(side="left", padx=(0, 10))

    tk.Button(
        overview_buttons,
        text="📂  Analyser loggfiler",
        command=run_analysis,
        font=("Segoe UI", 11, "bold"),
        bg="#34495e",
        fg="white",
        activebackground="#465c71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(side="left", padx=(0, 10))

    tk.Button(
        overview_buttons,
        text="Eksporter CSV",
        command=export_csv,
        font=("Segoe UI", 10),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=15,
        pady=10,
        cursor="hand2"
    ).pack(side="left")

    tab_potential = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_potential, text="   Potential Attacks   ")

    pa_container = tk.LabelFrame(
        tab_potential,
        text="   Potensielle angrepsscenarier basert på korrelerte funn   ",
        font=("Segoe UI", 10, "bold"),
        bg="#ecf0f1",
        fg="#c0392b",
        padx=8,
        pady=8
    )
    pa_container.pack(fill="both", expand=True, padx=10, pady=10)

    pa_canvas = tk.Canvas(pa_container, bg="#ecf0f1", highlightthickness=0)
    pa_scrollbar = ttk.Scrollbar(pa_container, orient="vertical", command=pa_canvas.yview)
    potential_attacks_frame = tk.Frame(pa_canvas, bg="#ecf0f1")
    potential_attacks_frame.bind(
        "<Configure>",
        lambda e: pa_canvas.configure(scrollregion=pa_canvas.bbox("all"))
    )
    pa_canvas.create_window((0, 0), window=potential_attacks_frame, anchor="nw")
    pa_canvas.configure(yscrollcommand=pa_scrollbar.set)
    pa_canvas.pack(side="left", fill="both", expand=True)
    pa_scrollbar.pack(side="right", fill="y")

    tab1 = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab1, text="   Log Analysis   ")

    results_container = tk.LabelFrame(
        tab1,
        text="   Resultater   ",
        font=("Segoe UI", 10, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50",
        padx=8,
        pady=8
    )
    results_container.pack(fill="both", expand=True)

    canvas = tk.Canvas(results_container, bg="#ecf0f1", highlightthickness=0)
    scrollbar = ttk.Scrollbar(results_container, orient="vertical", command=canvas.yview)
    results_frame = tk.Frame(canvas, bg="#ecf0f1")
    results_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=results_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    img_label = tk.Label(tab1, bg="#ecf0f1")
    img_label.pack(pady=8)

    tab_ip = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_ip, text="   IP Analysis   ")

    ip_frame = tk.Frame(tab_ip, bg="#ecf0f1")
    ip_frame.pack(fill="both", expand=True, padx=10, pady=10)

    tk.Label(
        ip_frame,
        text="IP Address Analysis",
        font=("Segoe UI", 15, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(anchor="w", pady=(0, 10))

    ip_tree = ttk.Treeview(
        ip_frame,
        columns=("ip", "activity", "count", "risk"),
        show="headings"
    )
    ip_tree.heading("ip", text="IP Address")
    ip_tree.heading("activity", text="Activity")
    ip_tree.heading("count", text="Events")
    ip_tree.heading("risk", text="Risk")
    ip_tree.column("ip", width=160)
    ip_tree.column("activity", width=500)
    ip_tree.column("count", width=80, anchor="center")
    ip_tree.column("risk", width=100, anchor="center")
    ip_tree.pack(fill="both", expand=True)

    tab_timeline = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_timeline, text="   Attack Timeline   ")

    timeline_frame = tk.Frame(tab_timeline, bg="#ecf0f1")
    timeline_frame.pack(fill="both", expand=True, padx=10, pady=10)

    timeline_tree = ttk.Treeview(
        timeline_frame,
        columns=("time", "event", "severity", "file", "line"),
        show="headings"
    )
    timeline_tree.heading("time", text="Timestamp")
    timeline_tree.heading("event", text="Event")
    timeline_tree.heading("severity", text="Severity")
    timeline_tree.heading("file", text="File")
    timeline_tree.heading("line", text="Line")
    timeline_tree.column("time", width=160)
    timeline_tree.column("event", width=360)
    timeline_tree.column("severity", width=100)
    timeline_tree.column("file", width=180)
    timeline_tree.column("line", width=70)
    timeline_tree.pack(fill="both", expand=True)

    tab_details = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_details, text="   Details   ")

    search_frame = tk.Frame(tab_details, bg="#ecf0f1")
    search_frame.pack(fill="x", padx=10, pady=10)

    tk.Label(
        search_frame,
        text="Search:",
        font=("Segoe UI", 10, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(side="left", padx=(0, 5))

    search_var = tk.StringVar()
    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        font=("Segoe UI", 10),
        width=35
    )
    search_entry.pack(side="left", padx=(0, 10))
    search_var.trace_add("write", apply_filter)

    tk.Label(
        search_frame,
        text="Filter:",
        font=("Segoe UI", 10, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(side="left")

    filter_var = tk.StringVar(value="All")
    filter_box = ttk.Combobox(
        search_frame,
        textvariable=filter_var,
        values=[
            "All",
            "Malware",
            "Security Tool",
            "Brute Force",
            "Phishing",
            "Unauthorized Access",
            "Security Breach",
            "Data Leakage",
            "File Tampering",
            "Credential Dumping",
            "Suspicious Persistence",
            "Dll Side Loading",
            "Services File Permissions",
            "Suspicious Execution",
            "Javascript Activity",
            "Wmi Execution",
            "File And Directory Discovery",
            "Kerberos Ad",
            "Process Execution",
            "Object Share Access",
            "Policy Firewall",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        state="readonly",
        width=26
    )
    filter_box.pack(side="left", padx=5)
    filter_box.bind("<<ComboboxSelected>>", apply_filter)

    tree_frame = tk.Frame(tab_details, bg="#ecf0f1")
    tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    tree = ttk.Treeview(
        tree_frame,
        columns=("file", "attack", "severity", "line"),
        show="headings"
    )
    tree.heading("file", text="Filnavn")
    tree.heading("attack", text="Type aktivitet & teknikk")
    tree.heading("severity", text="Severity")
    tree.heading("line", text="Linje")
    tree.column("file", width=220)
    tree.column("attack", width=420)
    tree.column("severity", width=100, anchor="center")
    tree.column("line", width=80, anchor="center")
    tree.pack(fill="both", expand=True)

    tab_logtype = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_logtype, text="   Log Types   ")

    log_type_tree = ttk.Treeview(
        tab_logtype,
        columns=("file", "type"),
        show="headings"
    )
    log_type_tree.heading("file", text="File")
    log_type_tree.heading("type", text="Detected Log Type")
    log_type_tree.column("file", width=300)
    log_type_tree.column("type", width=300)
    log_type_tree.pack(fill="both", expand=True, padx=20, pady=20)

    tab_custom = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_custom, text="   Custom Patterns   ")

    card = tk.Frame(tab_custom, bg="white", relief="solid", bd=1)
    card.pack(padx=30, pady=40, fill="x")

    tk.Label(
        card,
        text="Legg til eget søkemønster",
        font=("Segoe UI", 14, "bold"),
        bg="white",
        fg="#2c3e50"
    ).pack(pady=(20, 5))

    tk.Label(
        card,
        text="Legg til egne regex-mønstre som lagres permanent.",
        font=("Segoe UI", 9),
        bg="white",
        fg="#7f8c8d"
    ).pack(pady=(0, 15))

    tk.Button(
        card,
        text="＋   Legg til nytt mønster",
        command=add_pattern,
        font=("Segoe UI", 11, "bold"),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(pady=(0, 25))

    tab_new_scan = tk.Frame(notebook, bg="#ecf0f1")
    notebook.add(tab_new_scan, text="   ＋ New Scan  ")

    new_scan_frame = tk.Frame(tab_new_scan, bg="#ecf0f1")
    new_scan_frame.pack(fill="both", expand=True, padx=15, pady=15)

    tk.Label(
        new_scan_frame,
        text="Start ny skann",
        font=("Segoe UI", 18, "bold"),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(anchor="w")

    tk.Label(
        new_scan_frame,
        text="Start en ny analyse av én eller flere loggfiler.",
        font=("Segoe UI", 9),
        bg="#ecf0f1",
        fg="#7f8c8d"
    ).pack(anchor="w", pady=(0, 25))

    new_scan_card = tk.Frame(new_scan_frame, bg="white", relief="solid", bd=1)
    new_scan_card.pack(fill="x", pady=10)

    tk.Label(
        new_scan_card,
        text="Ny sikkerhetsskann",
        font=("Segoe UI", 14, "bold"),
        bg="white",
        fg="#2c3e50"
    ).pack(pady=(25, 5))

    tk.Label(
        new_scan_card,
        text=(
            "Velg loggfiler for å starte en ny analyse. "
            "Resultatene fra forrige skann blir nullstilt."
        ),
        font=("Segoe UI", 10),
        bg="white",
        fg="#7f8c8d",
        wraplength=700
    ).pack(pady=(0, 20))

    tk.Button(
        new_scan_card,
        text="Eksporter CSV",
        command=export_csv,
        font=("Segoe UI", 10, "bold"),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(pady=(0, 15))

    tk.Button(
        new_scan_card,
        text="＋  Start ny skann",
        command=new_scan,
        font=("Segoe UI", 11, "bold"),
        bg="#2980b9",
        fg="white",
        activebackground="#3498db",
        relief="flat",
        padx=25,
        pady=12,
        cursor="hand2"
    ).pack(pady=(0, 30))

    status_var = tk.StringVar(value="Klar")
    tk.Label(
        root,
        textvariable=status_var,
        font=("Segoe UI", 9),
        bg="#34495e",
        fg="white",
        anchor="w",
        padx=12,
        pady=4
    ).pack(fill="x", side="bottom")

    root.mainloop()


# Starter programmet
if __name__ == "__main__":
    load_patterns()
    create_gui()
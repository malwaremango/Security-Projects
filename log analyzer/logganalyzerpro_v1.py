
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
        r"data leakage|data exfiltration|information leak|data theft"
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
    "BloodHound"
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
    "brute_force": "HIGH"
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
        "Blokker eller begrens kilde-IP og vurder MFA/rate limiting."
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
    "timeline": [],
    "details": [],
    "total_lines": 0,
    "log_types": []
}


def load_patterns():

    if os.path.exists(CONFIG_FILE):

        try:

            with open(
                CONFIG_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                data = json.load(f)

            patterns.update(
                data.get(
                    "patterns",
                    {}
                )
            )

            remedies.update(
                data.get(
                    "remedies",
                    {}
                )
            )

        except Exception as e:

            print(
                "Kunne ikke laste konfigurasjon:",
                e
            )


def save_patterns():

    with open(
        CONFIG_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            {
                "patterns": patterns,
                "remedies": remedies
            },
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


def detect_file_type(log_file):

    scores = defaultdict(int)

    try:

        with open(
            log_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            for _ in range(100):

                line = f.readline()

                if not line:
                    break

                log_type = detect_log_type(line)

                scores[log_type] += 1

    except Exception:

        return "Unknown"

    if not scores:
        return "Unknown"

    return max(
        scores,
        key=scores.get
    )


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


def identify_activity(
    line,
    compiled_patterns,
    malware_patterns
):

    activities = []

    for name, pattern in compiled_patterns.items():

        if pattern.search(line):

            activities.append(name)

    for name, pattern in malware_patterns.items():

        if pattern.search(line):

            activities.append(
                f"Malware: {name}"
            )

    for name in security_tools:

        if re.search(
            rf"\b{re.escape(name)}\b",
            line,
            re.IGNORECASE
        ):

            activities.append(
                f"Security Tool: {name}"
            )

    return activities


def detect_brute_force(login_attempts):

    incidents = []

    window = timedelta(
        minutes=BRUTE_FORCE_WINDOW_MINUTES
    )

    for ip, attempts in login_attempts.items():

        if not any(
            item[0]
            for item in attempts
        ):
            continue

        attempts = sorted(
            attempts,
            key=lambda x:
                x[0] if x[0] else datetime.min
        )

        start_index = 0

        for end_index in range(
            len(attempts)
        ):

            current_time = attempts[
                end_index
            ][0]

            if current_time is None:
                continue

            while (
                start_index < end_index
                and attempts[start_index][0] is not None
                and current_time -
                attempts[start_index][0] > window
            ):

                start_index += 1

            current_count = (
                end_index -
                start_index +
                1
            )

            if current_count >= BRUTE_FORCE_THRESHOLD:

                relevant_attempts = attempts[
                    start_index:end_index + 1
                ]

                incidents.append({
                    "ip": ip,
                    "attempts": current_count,
                    "window": BRUTE_FORCE_WINDOW_MINUTES,
                    "severity": "HIGH",
                    "start": relevant_attempts[0][0],
                    "end": relevant_attempts[-1][0],
                    "lines": [
                        item[1]
                        for item in relevant_attempts
                    ],
                    "file": relevant_attempts[0][2]
                })

                start_index = end_index + 1

    return incidents


def analyze_log(log_file):

    counts = defaultdict(int)
    found_malware = defaultdict(int)

    detailed_matches = []
    timeline = []

    login_attempts = defaultdict(list)

    total = 0

    compiled = {
        key: re.compile(
            value,
            re.IGNORECASE
        )
        for key, value in patterns.items()
    }

    malware_patterns = {
        name: re.compile(
            rf"\b{re.escape(name)}\b",
            re.IGNORECASE
        )
        for name in malware_names
    }

    filename = os.path.basename(
        log_file
    )

    log_type = detect_file_type(
        log_file
    )

    with open(
        log_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        for line_num, line in enumerate(
            f,
            start=1
        ):

            total += 1

            timestamp = extract_timestamp(
                line
            )

            ips = IP_PATTERN.findall(
                line
            )

            activities = identify_activity(
                line,
                compiled,
                malware_patterns
            )

            for activity in activities:

                if activity.startswith(
                    "Malware:"
                ):

                    malware_name = activity.replace(
                        "Malware:",
                        ""
                    ).strip()

                    found_malware[
                        malware_name
                    ] += 1

                    detailed_matches.append(
                        (
                            filename,
                            activity,
                            line_num,
                            "HIGH"
                        )
                    )

                elif activity.startswith(
                    "Security Tool:"
                ):

                    detailed_matches.append(
                        (
                            filename,
                            activity,
                            line_num,
                            "MEDIUM"
                        )
                    )

                else:

                    counts[activity] += 1

                    detailed_matches.append(
                        (
                            filename,
                            activity.replace(
                                "_",
                                " "
                            ).title(),
                            line_num,
                            severity.get(
                                activity,
                                "LOW"
                            )
                        )
                    )

            for ip in ips:

                last_analysis[
                    "ips"
                ][ip]["total"] += 1

                for activity in activities:

                    if activity.startswith(
                        "Malware:"
                    ):

                        activity_name = activity

                    elif activity.startswith(
                        "Security Tool:"
                    ):

                        activity_name = activity

                    else:

                        activity_name = activity.replace(
                            "_",
                            " "
                        ).title()

                    last_analysis[
                        "ips"
                    ][ip]["activity"][
                        activity_name
                    ] += 1

                    if activity.startswith(
                        "Malware:"
                    ):

                        current_severity = "HIGH"

                    else:

                        current_severity = severity.get(
                            activity,
                            "LOW"
                        )

                    old_rank = severity_rank[
                        last_analysis[
                            "ips"
                        ][ip]["severity"]
                    ]

                    new_rank = severity_rank[
                        current_severity
                    ]

                    if new_rank > old_rank:

                        last_analysis[
                            "ips"
                        ][ip]["severity"] = (
                            current_severity
                        )

            failed_login = re.search(
                r"failed login|login failure|"
                r"authentication failure|"
                r"authentication failed|invalid login",
                line,
                re.IGNORECASE
            )

            if failed_login and ips:

                for ip in ips:

                    login_attempts[
                        ip
                    ].append(
                        (
                            timestamp,
                            line_num,
                            filename
                        )
                    )

            if activities:

                for activity in activities:

                    if activity.startswith(
                        "Malware:"
                    ):

                        event_name = activity

                    elif activity.startswith(
                        "Security Tool:"
                    ):

                        event_name = activity

                    else:

                        event_name = activity.replace(
                            "_",
                            " "
                        ).title()

                    event_severity = (
                        "HIGH"
                        if activity.startswith(
                            "Malware:"
                        )
                        else severity.get(
                            activity,
                            "LOW"
                        )
                    )

                    timeline.append({
                        "timestamp": timestamp,
                        "event": event_name,
                        "severity": event_severity,
                        "file": filename,
                        "line": line_num
                    })

    brute_force = detect_brute_force(
        login_attempts
    )

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

    # Nullstiller resultatene fra forrige analyse
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
    last_analysis["timeline"] = []
    last_analysis["details"] = []
    last_analysis["total_lines"] = 0
    last_analysis["log_types"] = []

    # Tøm søk og filter
    search_var.set("")
    filter_var.set("All")

    # Fjern grafen fra forrige analyse
    img_label.config(
        image=""
    )

    img_label.image = None

    # Oppdater alle fanene
    update_results()
    update_file_details()
    update_attack_overview()
    update_ip_table()
    update_timeline()
    update_log_type()

    status_var.set(
        "Klar for ny skann..."
    )

    # Gå tilbake til Attack Overview
    notebook.select(
        tab_overview
    )

    # Åpne filvelgeren etter at GUI-et er oppdatert
    root.after(
        100,
        run_analysis
    )


def run_analysis():

    log_files = filedialog.askopenfilenames(
        title="Velg loggfil(er)",
        filetypes=[
            ("Log Files", "*.log"),
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )

    if not log_files:

        status_var.set(
            "Ny skann avbrutt"
        )

        return

    status_var.set(
        "Analyserer loggfil(er)..."
    )

    root.update()

    last_analysis["files"] = list(
        log_files
    )

    last_analysis["counts"] = defaultdict(
        int
    )

    last_analysis["malware"] = defaultdict(
        int
    )

    last_analysis["ips"] = defaultdict(
        lambda: {
            "activity": defaultdict(int),
            "total": 0,
            "severity": "LOW"
        }
    )

    last_analysis["brute_force"] = []
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
        ) = analyze_log(
            log_file
        )

        last_analysis[
            "total_lines"
        ] += total

        last_analysis[
            "log_types"
        ].append(
            {
                "file": os.path.basename(
                    log_file
                ),
                "type": log_type
            }
        )

        all_details.extend(
            detailed_matches
        )

        for key, value in counts.items():

            last_analysis[
                "counts"
            ][key] += value

        for key, value in found_malware.items():

            last_analysis[
                "malware"
            ][key] += value

        last_analysis[
            "timeline"
        ].extend(
            timeline
        )

        last_analysis[
            "brute_force"
        ].extend(
            brute_force
        )

    if last_analysis[
        "brute_force"
    ]:

        last_analysis[
            "counts"
        ]["brute_force"] = len(
            last_analysis[
                "brute_force"
            ]
        )

        for incident in last_analysis[
            "brute_force"
        ]:

            all_details.append(
                (
                    incident["file"],
                    "Brute Force",
                    incident["lines"][0],
                    "HIGH"
                )
            )

            ip = incident["ip"]

            last_analysis[
                "ips"
            ][ip]["activity"][
                "Brute Force"
            ] += incident["attempts"]

            last_analysis[
                "ips"
            ][ip]["severity"] = "HIGH"

    last_analysis[
        "details"
    ] = all_details

    last_analysis[
        "timeline"
    ].sort(
        key=lambda x: (
            x["timestamp"] is None,
            x["timestamp"] or datetime.min
        )
    )

    primary_file = log_files[0]

    base, _ = os.path.splitext(
        primary_file
    )

    report = (
        base +
        "_security_report.txt"
    )

    create_incident_report(
        report,
        log_files
    )

    graph = None

    if last_analysis[
        "counts"
    ]:

        graph = (
            base +
            "_graph.png"
        )

        plt.figure(
            figsize=(10, 5)
        )

        labels = [
            key.replace(
                "_",
                " "
            ).title()
            for key in
            last_analysis[
                "counts"
            ].keys()
        ]

        values = list(
            last_analysis[
                "counts"
            ].values()
        )

        plt.bar(
            labels,
            values
        )

        plt.title(
            "Suspicious Activity Detected"
        )

        plt.xticks(
            rotation=30,
            ha="right"
        )

        plt.tight_layout()

        plt.savefig(
            graph,
            dpi=100
        )

        plt.close()

        show_graph(
            graph
        )

    update_results()
    update_file_details()
    update_attack_overview()
    update_ip_table()
    update_timeline()
    update_log_type()

    status_var.set(
        "Analyse fullført"
    )

    msg = (
        f"Analyse fullført!\n\n"
        f"Filer analysert: "
        f"{len(log_files)}\n"
        f"Linjer analysert: "
        f"{last_analysis['total_lines']}\n\n"
        f"Rapport:\n{report}"
    )

    if graph:

        msg += (
            f"\n\nGraf:\n{graph}"
        )

    if (
        last_analysis["counts"]
        or last_analysis["malware"]
        or last_analysis["brute_force"]
    ):

        messagebox.showwarning(
            "Sikkerhetsadvarsel",
            "⚠ Mistenkelig aktivitet ble funnet!"
        )

    messagebox.showinfo(
        "Analyse ferdig",
        msg
    )


def create_incident_report(
    path,
    log_files
):

    counts = last_analysis[
        "counts"
    ]

    malware = last_analysis[
        "malware"
    ]

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for name, count in counts.items():

        level = severity.get(
            name,
            "LOW"
        )

        severity_counts[
            level
        ] += count

    severity_counts[
        "HIGH"
    ] += len(
        last_analysis[
            "brute_force"
        ]
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "=" * 50 +
            "\n"
        )

        f.write(
            "       SECURITY INCIDENT REPORT\n"
        )

        f.write(
            "=" * 50 +
            "\n\n"
        )

        f.write(
            f"Analysis date:\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        f.write(
            f"Files analyzed:\n"
            f"{len(log_files)}\n\n"
        )

        f.write(
            f"Lines analyzed:\n"
            f"{last_analysis['total_lines']}\n\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "LOG TYPES\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        for item in last_analysis[
            "log_types"
        ]:

            f.write(
                f"{item['file']}: "
                f"{item['type']}\n"
            )

        f.write("\n")

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "RISK SUMMARY\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        for level in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:

            f.write(
                f"{level}: "
                f"{severity_counts[level]}\n"
            )

        f.write("\n")

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "BRUTE FORCE DETECTION\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        if last_analysis[
            "brute_force"
        ]:

            for incident in last_analysis[
                "brute_force"
            ]:

                f.write(
                    f"IP: {incident['ip']}\n"
                )

                f.write(
                    f"Failed attempts: "
                    f"{incident['attempts']}\n"
                )

                f.write(
                    f"Time window: "
                    f"{incident['window']} minutes\n"
                )

                f.write(
                    f"Severity: "
                    f"{incident['severity']}\n"
                )

                f.write("\n")

        else:

            f.write(
                "No brute-force attacks detected.\n"
            )

        f.write("\n")

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "TOP THREATS\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        threats = []

        for name, count in counts.items():

            threats.append(
                (
                    name.replace(
                        "_",
                        " "
                    ).title(),
                    count
                )
            )

        for name, count in malware.items():

            threats.append(
                (
                    name,
                    count
                )
            )

        if last_analysis[
            "brute_force"
        ]:

            threats.append(
                (
                    "Brute Force",
                    sum(
                        x["attempts"]
                        for x in
                        last_analysis[
                            "brute_force"
                        ]
                    )
                )
            )

        threats.sort(
            key=lambda x: x[1],
            reverse=True
        )

        for index, (
            name,
            count
        ) in enumerate(
            threats[:10],
            start=1
        ):

            f.write(
                f"{index}. "
                f"{name:<25} "
                f"{count}\n"
            )

        f.write("\n")

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "TOP SOURCE IP ADDRESSES\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        sorted_ips = sorted(
            last_analysis[
                "ips"
            ].items(),
            key=lambda x:
                x[1]["total"],
            reverse=True
        )

        for ip, data in sorted_ips[:10]:

            f.write(
                f"{ip:<18} "
                f"{data['total']} events "
                f"[{data['severity']}]\n"
            )

        f.write("\n")

        f.write(
            "-" * 40 +
            "\n"
        )

        f.write(
            "RECOMMENDED ACTIONS\n"
        )

        f.write(
            "-" * 40 +
            "\n"
        )

        recommended = set()

        for name in counts:

            if name in remedies:

                recommended.add(
                    (
                        severity.get(
                            name,
                            "LOW"
                        ),
                        remedies[name]
                    )
                )

        if last_analysis[
            "brute_force"
        ]:

            recommended.add(
                (
                    "HIGH",
                    remedies["brute_force"]
                )
            )

        for level, action in sorted(
            recommended,
            key=lambda x:
                -severity_rank[x[0]]
        ):

            f.write(
                f"[{level}]\n"
            )

            f.write(
                f"{action}\n\n"
            )


def show_graph(path):

    try:

        img = tk.PhotoImage(
            file=path
        )

        if img.width() > 700:

            img = img.subsample(
                2,
                2
            )

        img_label.config(
            image=img
        )

        img_label.image = img

    except Exception as e:

        print(
            "Kunne ikke vise graf:",
            e
        )


def update_attack_overview():

    for widget in overview_frame.winfo_children():

        widget.destroy()

    counts = last_analysis[
        "counts"
    ]

    malware = last_analysis[
        "malware"
    ]

    risk_frame = tk.Frame(
        overview_frame,
        bg="#ecf0f1"
    )

    risk_frame.pack(
        fill="x",
        pady=10
    )

    risk_values = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for name, count in counts.items():

        level = severity.get(
            name,
            "LOW"
        )

        risk_values[
            level
        ] += count

    risk_values[
        "HIGH"
    ] += len(
        last_analysis[
            "brute_force"
        ]
    )

    for level in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:

        card = tk.Frame(
            risk_frame,
            bg="white",
            relief="solid",
            bd=1
        )

        card.pack(
            side="left",
            fill="x",
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=level,
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="white",
            fg="#2c3e50"
        ).pack(
            pady=(10, 2)
        )

        tk.Label(
            card,
            text=str(
                risk_values[level]
            ),
            font=(
                "Segoe UI",
                22,
                "bold"
            ),
            bg="white",
            fg=(
                "#c0392b"
                if level in [
                    "CRITICAL",
                    "HIGH"
                ]
                else "#f39c12"
            )
        ).pack(
            pady=(0, 10)
        )

    attack_frame = tk.LabelFrame(
        overview_frame,
        text="   TOP ATTACKS   ",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    )

    attack_frame.pack(
        fill="both",
        expand=True,
        pady=10
    )

    attacks = []

    for name, count in counts.items():

        attacks.append(
            (
                name.replace(
                    "_",
                    " "
                ).title(),
                count,
                severity.get(
                    name,
                    "LOW"
                )
            )
        )

    for name, count in malware.items():

        attacks.append(
            (
                name,
                count,
                "HIGH"
            )
        )

    if last_analysis[
        "brute_force"
    ]:

        attacks.append(
            (
                "Brute Force",
                sum(
                    x["attempts"]
                    for x in
                    last_analysis[
                        "brute_force"
                    ]
                ),
                "HIGH"
            )
        )

    attacks.sort(
        key=lambda x: x[1],
        reverse=True
    )

    for name, count, level in attacks[:10]:

        row = tk.Frame(
            attack_frame,
            bg="white",
            relief="solid",
            bd=1
        )

        row.pack(
            fill="x",
            padx=8,
            pady=3
        )

        tk.Label(
            row,
            text=name,
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="white",
            fg="#2c3e50"
        ).pack(
            side="left",
            padx=10,
            pady=7
        )

        tk.Label(
            row,
            text=level,
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            bg="#34495e",
            fg="white",
            padx=8
        ).pack(
            side="right",
            padx=10
        )

        tk.Label(
            row,
            text=str(count),
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="white",
            fg="#2980b9"
        ).pack(
            side="right",
            padx=10
        )


def update_results():

    for widget in results_frame.winfo_children():

        widget.destroy()

    total = last_analysis[
        "total_lines"
    ]

    counts = last_analysis[
        "counts"
    ]

    malware = last_analysis[
        "malware"
    ]

    header = tk.Frame(
        results_frame,
        bg="#2c3e50"
    )

    header.pack(
        fill="x",
        pady=(0, 10)
    )

    tk.Label(
        header,
        text=(
            f"   Totalt linjer analysert: "
            f"{total}"
        ),
        font=(
            "Segoe UI",
            11,
            "bold"
        ),
        bg="#2c3e50",
        fg="white",
        pady=8
    ).pack(
        anchor="w"
    )

    if (
        not counts
        and not malware
        and not last_analysis[
            "brute_force"
        ]
    ):

        tk.Label(
            results_frame,
            text="✓ Ingen mistenkelig aktivitet funnet",
            font=(
                "Segoe UI",
                12
            ),
            fg="#27ae60",
            bg="#ecf0f1"
        ).pack(
            pady=20
        )

        return

    if last_analysis[
        "brute_force"
    ]:

        section = tk.LabelFrame(
            results_frame,
            text="   ⚠ Brute Force Detected   ",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="#ecf0f1",
            fg="#c0392b"
        )

        section.pack(
            fill="x",
            pady=(0, 12),
            padx=2
        )

        for incident in last_analysis[
            "brute_force"
        ]:

            row = tk.Frame(
                section,
                bg="white",
                relief="solid",
                bd=1
            )

            row.pack(
                fill="x",
                pady=4,
                padx=6
            )

            text = (
                f"IP: {incident['ip']}\n"
                f"Failed attempts: {incident['attempts']}\n"
                f"Time window: "
                f"{incident['window']} minutes\n"
                f"Severity: {incident['severity']}"
            )

            tk.Label(
                row,
                text=text,
                font=(
                    "Segoe UI",
                    10
                ),
                bg="white",
                fg="#2c3e50",
                justify="left"
            ).pack(
                anchor="w",
                padx=10,
                pady=8
            )

    if malware:

        section = tk.LabelFrame(
            results_frame,
            text="   Oppdagede Malware   ",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="#ecf0f1",
            fg="#c0392b"
        )

        section.pack(
            fill="x",
            pady=(0, 12),
            padx=2
        )

        for name, count in sorted(
            malware.items(),
            key=lambda x: -x[1]
        ):

            row = tk.Frame(
                section,
                bg="white",
                relief="solid",
                bd=1
            )

            row.pack(
                fill="x",
                pady=3,
                padx=6
            )

            tk.Label(
                row,
                text=f"🦠   {name}",
                font=(
                    "Segoe UI",
                    11,
                    "bold"
                ),
                bg="white",
                fg="#c0392b"
            ).pack(
                side="left",
                padx=10,
                pady=6
            )

            tk.Label(
                row,
                text=f"{count} treff",
                font=(
                    "Segoe UI",
                    10
                ),
                bg="#e74c3c",
                fg="white",
                padx=8,
                pady=2
            ).pack(
                side="right",
                padx=10
            )

    if counts:

        section = tk.LabelFrame(
            results_frame,
            text="   Kategorier   ",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="#ecf0f1",
            fg="#2c3e50"
        )

        section.pack(
            fill="x",
            pady=5,
            padx=2
        )

        for name, count in counts.items():

            level = severity.get(
                name,
                "LOW"
            )

            card = tk.Frame(
                section,
                bg="white",
                relief="solid",
                bd=1
            )

            card.pack(
                fill="x",
                pady=4,
                padx=6
            )

            top = tk.Frame(
                card,
                bg="white"
            )

            top.pack(
                fill="x",
                padx=10,
                pady=(8, 2)
            )

            tk.Label(
                top,
                text=name.replace(
                    "_",
                    " "
                ).title(),
                font=(
                    "Segoe UI",
                    11,
                    "bold"
                ),
                bg="white",
                fg="#2c3e50"
            ).pack(
                side="left"
            )

            tk.Label(
                top,
                text=level,
                font=(
                    "Segoe UI",
                    9,
                    "bold"
                ),
                bg="#34495e",
                fg="white",
                padx=8
            ).pack(
                side="right"
            )

            tk.Label(
                top,
                text=f"{count} treff",
                font=(
                    "Segoe UI",
                    10
                ),
                bg="white",
                fg="#2980b9"
            ).pack(
                side="right",
                padx=10
            )

            tk.Label(
                card,
                text=remedies.get(
                    name,
                    ""
                ),
                font=(
                    "Segoe UI",
                    9
                ),
                bg="white",
                fg="#555",
                wraplength=650,
                justify="left"
            ).pack(
                anchor="w",
                padx=10,
                pady=(0, 8)
            )


def update_ip_table():

    for row in ip_tree.get_children():

        ip_tree.delete(row)

    sorted_ips = sorted(
        last_analysis[
            "ips"
        ].items(),
        key=lambda x:
            x[1]["total"],
        reverse=True
    )

    for ip, data in sorted_ips:

        activities = ", ".join(
            f"{name} ({count})"
            for name, count in
            data["activity"].items()
        )

        ip_tree.insert(
            "",
            "end",
            values=(
                ip,
                activities,
                data["total"],
                data["severity"]
            )
        )


def update_timeline():

    for row in timeline_tree.get_children():

        timeline_tree.delete(row)

    for event in last_analysis[
        "timeline"
    ]:

        if event["timestamp"]:

            timestamp = event[
                "timestamp"
            ].strftime(
                "%Y-%m-%d %H:%M:%S"
            )

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

    for item in last_analysis[
        "log_types"
    ]:

        log_type_tree.insert(
            "",
            "end",
            values=(
                item["file"],
                item["type"]
            )
        )


def update_file_details(
    detailed_matches=None
):

    for row in tree.get_children():

        tree.delete(row)

    if detailed_matches is None:

        detailed_matches = last_analysis[
            "details"
        ]

    search = search_var.get().lower().strip()
    selected_filter = filter_var.get()

    for filename, attack, line_num, level in detailed_matches:

        text = (
            f"{filename} "
            f"{attack} "
            f"{line_num} "
            f"{level}"
        ).lower()

        if search and search not in text:

            continue

        if selected_filter != "All":

            if (
                selected_filter != attack
                and selected_filter != level
            ):

                continue

        tree.insert(
            "",
            "end",
            values=(
                filename,
                attack,
                level,
                line_num
            )
        )


def apply_filter(*args):

    update_file_details(
        last_analysis[
            "details"
        ]
    )


def export_csv():

    if not last_analysis[
        "details"
    ]:

        messagebox.showinfo(
            "Eksport",
            "Det finnes ingen resultater å eksportere."
        )

        return

    path = filedialog.asksaveasfilename(
        title="Lagre CSV",
        defaultextension=".csv",
        filetypes=[
            ("CSV files", "*.csv")
        ]
    )

    if not path:
        return

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "File",
            "Attack",
            "Severity",
            "Line"
        ])

        for item in last_analysis[
            "details"
        ]:

            writer.writerow(item)

    messagebox.showinfo(
        "Eksport",
        f"CSV lagret:\n{path}"
    )


def add_pattern():

    name = simpledialog.askstring(
        "Nytt mønster",
        "Navn på mønsteret:"
    )

    if not name:
        return

    regex = simpledialog.askstring(
        "Nytt mønster",
        "Regex-mønster:"
    )

    if not regex:
        return

    try:

        re.compile(regex)

        patterns[name] = regex

        remedies[name] = (
            "Egendefinert mønster – "
            "ingen remedy satt."
        )

        severity[name] = "MEDIUM"

        save_patterns()

        messagebox.showinfo(
            "Suksess",
            f"Mønsteret '{name}' ble lagt til!"
        )

    except re.error:

        messagebox.showerror(
            "Feil",
            "Ugyldig regex-mønster."
        )


# Lager selve vinduet og alle fanene
def create_gui():

    global root
    global results_frame
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

    root.title(
        "Log Analyzer Pro"
    )

    root.geometry(
        "1050x800"
    )

    root.configure(
        bg="#ecf0f1"
    )

    root.minsize(
        850,
        650
    )

    style = ttk.Style()

    style.theme_use(
        "clam"
    )

    style.configure(
        "TNotebook",
        background="#ecf0f1",
        borderwidth=0
    )

    style.configure(
        "TNotebook.Tab",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        padding=[
            16,
            8
        ]
    )

    style.map(
        "TNotebook.Tab",
        background=[
            (
                "selected",
                "#2980b9"
            ),
            (
                "!selected",
                "#bdc3c7"
            )
        ],
        foreground=[
            (
                "selected",
                "white"
            ),
            (
                "!selected",
                "#2c3e50"
            )
        ]
    )

    style.configure(
        "Treeview.Heading",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        background="#2c3e50",
        foreground="white"
    )

    style.configure(
        "Treeview",
        font=(
            "Segoe UI",
            9
        ),
        rowheight=26
    )

    # Toppfeltet med navn og logo
    header = tk.Frame(
        root,
        bg="#1a252f",
        height=70
    )

    header.pack(
        fill="x"
    )

    header.pack_propagate(
        False
    )

    left_header = tk.Frame(
        header,
        bg="#1a252f"
    )

    left_header.pack(
        side="left",
        padx=20
    )

    logo_canvas = tk.Canvas(
        left_header,
        width=42,
        height=42,
        bg="#1a252f",
        highlightthickness=0
    )

    logo_canvas.pack(
        side="left",
        padx=(0, 12),
        pady=12
    )

    logo_canvas.create_oval(
        4,
        4,
        38,
        38,
        outline="#3498db",
        width=3
    )

    logo_canvas.create_oval(
        12,
        12,
        30,
        30,
        outline="#3498db",
        width=2
    )

    logo_canvas.create_line(
        28,
        28,
        38,
        38,
        fill="#e74c3c",
        width=3
    )

    title_frame = tk.Frame(
        left_header,
        bg="#1a252f"
    )

    title_frame.pack(
        side="left"
    )

    tk.Label(
        title_frame,
        text="Python Log Analyzer Pro © malwaremango",
        font=(
            "Segoe UI",
            16,
            "bold"
        ),
        bg="#1a252f",
        fg="white"
    ).pack(
        anchor="w"
    )

    tk.Label(
        title_frame,
        text="Security monitoring and log analysis",
        font=(
            "Segoe UI",
            9
        ),
        bg="#1a252f",
        fg="#95a5a6"
    ).pack(
        anchor="w"
    )

    # Alle fanene ligger i denne notebooken
    notebook = ttk.Notebook(
        root
    )

    notebook.pack(
        fill="both",
        expand=True,
        padx=12,
        pady=12
    )

    # ------------------------------------------------------
    # Attack Overview
    # ------------------------------------------------------

    tab_overview = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_overview,
        text="   Attack Overview   "
    )

    overview_frame = tk.Frame(
        tab_overview,
        bg="#ecf0f1"
    )

    overview_frame.pack(
        fill="both",
        expand=True,
        padx=15,
        pady=15
    )

    tk.Label(
        overview_frame,
        text="Security Overview",
        font=(
            "Segoe UI",
            18,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(
        anchor="w"
    )

    tk.Label(
        overview_frame,
        text=(
            "Analyse loggfiler og identifiser "
            "mistenkelig aktivitet."
        ),
        font=(
            "Segoe UI",
            9
        ),
        bg="#ecf0f1",
        fg="#7f8c8d"
    ).pack(
        anchor="w"
    )

    overview_buttons = tk.Frame(
        overview_frame,
        bg="#ecf0f1"
    )

    overview_buttons.pack(
        fill="x",
        pady=15
    )

    # Ny skann-knapp
    tk.Button(
        overview_buttons,
        text="＋  Ny skann",
        command=new_scan,
        font=(
            "Segoe UI",
            11,
            "bold"
        ),
        bg="#2980b9",
        fg="white",
        activebackground="#3498db",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(
        side="left",
        padx=(0, 10)
    )

    # Knapp for vanlig analyse
    tk.Button(
        overview_buttons,
        text="📂  Analyser loggfiler",
        command=run_analysis,
        font=(
            "Segoe UI",
            11,
            "bold"
        ),
        bg="#34495e",
        fg="white",
        activebackground="#465c71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(
        side="left",
        padx=(0, 10)
    )

    # Eksporter resultater
    tk.Button(
        overview_buttons,
        text="Eksporter CSV",
        command=export_csv,
        font=(
            "Segoe UI",
            10
        ),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=15,
        pady=10,
        cursor="hand2"
    ).pack(
        side="left"
    )
    
      
        
        
        
    #-----------------------------------
    # ------------------------------------------------------
    # Log Analysis
    # ------------------------------------------------------

    tab1 = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab1,
        text="   Log Analysis   "
    )

    results_container = tk.LabelFrame(
        tab1,
        text="   Resultater   ",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50",
        padx=8,
        pady=8
    )

    results_container.pack(
        fill="both",
        expand=True
    )

    canvas = tk.Canvas(
        results_container,
        bg="#ecf0f1",
        highlightthickness=0
    )

    scrollbar = ttk.Scrollbar(
        results_container,
        orient="vertical",
        command=canvas.yview
    )

    results_frame = tk.Frame(
        canvas,
        bg="#ecf0f1"
    )

    results_frame.bind(
        "<Configure>",
        lambda e:
        canvas.configure(
            scrollregion=canvas.bbox(
                "all"
            )
        )
    )

    canvas.create_window(
        (0, 0),
        window=results_frame,
        anchor="nw"
    )

    canvas.configure(
        yscrollcommand=scrollbar.set
    )

    canvas.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    img_label = tk.Label(
        tab1,
        bg="#ecf0f1"
    )

    img_label.pack(
        pady=8
    )

    # ------------------------------------------------------
    # IP Analysis
    # ------------------------------------------------------

    tab_ip = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_ip,
        text="   IP Analysis   "
    )

    ip_frame = tk.Frame(
        tab_ip,
        bg="#ecf0f1"
    )

    ip_frame.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    tk.Label(
        ip_frame,
        text="IP Address Analysis",
        font=(
            "Segoe UI",
            15,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(
        anchor="w",
        pady=(0, 10)
    )

    ip_tree = ttk.Treeview(
        ip_frame,
        columns=(
            "ip",
            "activity",
            "count",
            "risk"
        ),
        show="headings"
    )

    ip_tree.heading(
        "ip",
        text="IP Address"
    )

    ip_tree.heading(
        "activity",
        text="Activity"
    )

    ip_tree.heading(
        "count",
        text="Events"
    )

    ip_tree.heading(
        "risk",
        text="Risk"
    )

    ip_tree.column(
        "ip",
        width=160
    )

    ip_tree.column(
        "activity",
        width=500
    )

    ip_tree.column(
        "count",
        width=80,
        anchor="center"
    )

    ip_tree.column(
        "risk",
        width=100,
        anchor="center"
    )

    ip_tree.pack(
        fill="both",
        expand=True
    )

    # ------------------------------------------------------
    # Attack Timeline
    # ------------------------------------------------------

    tab_timeline = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_timeline,
        text="   Attack Timeline   "
    )

    timeline_frame = tk.Frame(
        tab_timeline,
        bg="#ecf0f1"
    )

    timeline_frame.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    timeline_tree = ttk.Treeview(
        timeline_frame,
        columns=(
            "time",
            "event",
            "severity",
            "file",
            "line"
        ),
        show="headings"
    )

    timeline_tree.heading(
        "time",
        text="Timestamp"
    )

    timeline_tree.heading(
        "event",
        text="Event"
    )

    timeline_tree.heading(
        "severity",
        text="Severity"
    )

    timeline_tree.heading(
        "file",
        text="File"
    )

    timeline_tree.heading(
        "line",
        text="Line"
    )

    timeline_tree.column(
        "time",
        width=160
    )

    timeline_tree.column(
        "event",
        width=250
    )

    timeline_tree.column(
        "severity",
        width=100
    )

    timeline_tree.column(
        "file",
        width=180
    )

    timeline_tree.column(
        "line",
        width=70
    )

    timeline_tree.pack(
        fill="both",
        expand=True
    )

    # ------------------------------------------------------
    # Details
    # ------------------------------------------------------

    tab_details = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_details,
        text="   Details   "
    )

    search_frame = tk.Frame(
        tab_details,
        bg="#ecf0f1"
    )

    search_frame.pack(
        fill="x",
        padx=10,
        pady=10
    )

    tk.Label(
        search_frame,
        text="Search:",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(
        side="left",
        padx=(0, 5)
    )

    search_var = tk.StringVar()

    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        font=(
            "Segoe UI",
            10
        ),
        width=35
    )

    search_entry.pack(
        side="left",
        padx=(0, 10)
    )

    search_var.trace_add(
        "write",
        apply_filter
    )

    tk.Label(
        search_frame,
        text="Filter:",
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(
        side="left"
    )

    filter_var = tk.StringVar(
        value="All"
    )

    filter_box = ttk.Combobox(
        search_frame,
        textvariable=filter_var,
        values=[
            "All",
            "Malware",
            "Brute Force",
            "Phishing",
            "Unauthorized Access",
            "Security Breach",
            "Data Leakage",
            "File Tampering",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        state="readonly",
        width=22
    )

    filter_box.pack(
        side="left",
        padx=5
    )

    filter_box.bind(
        "<<ComboboxSelected>>",
        apply_filter
    )

    tree_frame = tk.Frame(
        tab_details,
        bg="#ecf0f1"
    )

    tree_frame.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=(0, 10)
    )

    tree = ttk.Treeview(
        tree_frame,
        columns=(
            "file",
            "attack",
            "severity",
            "line"
        ),
        show="headings"
    )

    tree.heading(
        "file",
        text="Filnavn"
    )

    tree.heading(
        "attack",
        text="Type aktivitet"
    )

    tree.heading(
        "severity",
        text="Severity"
    )

    tree.heading(
        "line",
        text="Linje"
    )

    tree.column(
        "file",
        width=220
    )

    tree.column(
        "attack",
        width=250
    )

    tree.column(
        "severity",
        width=100,
        anchor="center"
    )

    tree.column(
        "line",
        width=80,
        anchor="center"
    )

    tree.pack(
        fill="both",
        expand=True
    )

    # ------------------------------------------------------
    # Log Types
    # ------------------------------------------------------

    tab_logtype = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_logtype,
        text="   Log Types   "
    )

    log_type_tree = ttk.Treeview(
        tab_logtype,
        columns=(
            "file",
            "type"
        ),
        show="headings"
    )

    log_type_tree.heading(
        "file",
        text="File"
    )

    log_type_tree.heading(
        "type",
        text="Detected Log Type"
    )

    log_type_tree.column(
        "file",
        width=300
    )

    log_type_tree.column(
        "type",
        width=300
    )

    log_type_tree.pack(
        fill="both",
        expand=True,
        padx=20,
        pady=20
    )
    

    # ------------------------------------------------------
    # Custom Patterns
    # ------------------------------------------------------

    tab_custom = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_custom,
        text="   Custom Patterns   "
    )

    card = tk.Frame(
        tab_custom,
        bg="white",
        relief="solid",
        bd=1
    )

    card.pack(
        padx=30,
        pady=40,
        fill="x"
    )

    tk.Label(
        card,
        text="Legg til eget søkemønster",
        font=(
            "Segoe UI",
            14,
            "bold"
        ),
        bg="white",
        fg="#2c3e50"
    ).pack(
        pady=(20, 5)
    )

    tk.Label(
        card,
        text=(
            "Legg til egne regex-mønstre "
            "som lagres permanent."
        ),
        font=(
            "Segoe UI",
            9
        ),
        bg="white",
        fg="#7f8c8d"
    ).pack(
        pady=(0, 15)
    )

    tk.Button(
        card,
        text="＋   Legg til nytt mønster",
        command=add_pattern,
        font=(
            "Segoe UI",
            11,
            "bold"
        ),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(
        pady=(0, 25)
    )
    
     # ------------------------------------------------------
    # Ny skann
    # ------------------------------------------------------

    tab_new_scan = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )

    notebook.add(
        tab_new_scan,
        text="   ＋ New Scan  "
    )

    new_scan_frame = tk.Frame(
        tab_new_scan,
        bg="#ecf0f1"
    )

    new_scan_frame.pack(
        fill="both",
        expand=True,
        padx=15,
        pady=15
    )

    tk.Label(
        new_scan_frame,
        text="Start ny skann",
        font=(
            "Segoe UI",
            18,
            "bold"
        ),
        bg="#ecf0f1",
        fg="#2c3e50"
    ).pack(
        anchor="w"
    )

    tk.Label(
        new_scan_frame,
        text=(
            "Start en ny analyse av én eller flere loggfiler."
        ),
        font=(
            "Segoe UI",
            9
        ),
        bg="#ecf0f1",
        fg="#7f8c8d"
    ).pack(
        anchor="w",
        pady=(0, 25)
    )

    new_scan_card = tk.Frame(
        new_scan_frame,
        bg="white",
        relief="solid",
        bd=1
    )

    new_scan_card.pack(
        fill="x",
        pady=10
    )

    tk.Label(
        new_scan_card,
        text="Ny sikkerhetsskann",
        font=(
            "Segoe UI",
            14,
            "bold"
        ),
        bg="white",
        fg="#2c3e50"
    ).pack(
        pady=(25, 5)
    )

    tk.Label(
        new_scan_card,
        text=(
            "Velg loggfiler for å starte en ny analyse. "
            "Resultatene fra forrige skann blir nullstilt."
        ),
        font=(
            "Segoe UI",
            10
        ),
        bg="white",
        fg="#7f8c8d",
        wraplength=700
    ).pack(
        pady=(0, 20)
    )
        
     # Eksporter resultatene fra siste skann
    tk.Button(
        new_scan_card,
        text="Eksporter CSV",
        command=export_csv,
        font=(
            "Segoe UI",
            10,
            "bold"
        ),
        bg="#27ae60",
        fg="white",
        activebackground="#2ecc71",
        relief="flat",
        padx=20,
        pady=10,
        cursor="hand2"
    ).pack(
        pady=(0, 25)
    )    

    tk.Button(
        new_scan_card,
        text="＋  Start ny skann",
        command=new_scan,
        font=(
            "Segoe UI",
            11,
            "bold"
        ),
        bg="#2980b9",
        fg="white",
        activebackground="#3498db",
        relief="flat",
        padx=25,
        pady=12,
        cursor="hand2"
    ).pack(
        pady=(0, 30)
        
   
    )
         

    # ------------------------------------------------------
    # Log Analysis
    # ------------------------------------------------------

    tab1 = tk.Frame(
        notebook,
        bg="#ecf0f1"
    )       
        
        
    # Status nederst i vinduet
    status_var = tk.StringVar(
        value="Klar"
    )

    tk.Label(
        root,
        textvariable=status_var,
        font=(
            "Segoe UI",
            9
        ),
        bg="#34495e",
        fg="white",
        anchor="w",
        padx=12,
        pady=4
    ).pack(
        fill="x",
        side="bottom"
    )

    root.mainloop()


# Starter programmet
if __name__ == "__main__":

    load_patterns()
    create_gui()


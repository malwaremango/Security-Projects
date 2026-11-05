#  Security Projects
Welcome! This repository will be used to host and showcase my upcoming security projects. 

See the descriptions below:


1.. $${\color{red}\text{CyberVault}}$$
==========

Unlock. Exploit. Learn.

CyberVault is a client-side Capture The Flag (CTF) learning platform for
beginner to intermediate cybersecurity practice. Solve knowledge- and
text-based challenges across five categories, earn points, use optional
hints, track progress, and unlock write-ups — all in the browser.


What it is
----------

A single-page web app (one HTML file) that runs entirely in the browser.
Progress, bookmarks, hints used, username, and theme are stored in
localStorage on the device. No backend or account is required for the
demo.

Categories
----------

  • Web        – HTTP, cookies, XSS, SQLi, headers, access control, etc.
  • Crypto     – Caesar, Base64, XOR, ROT13, Vigenère, hashes, classic ciphers
  • Forensics  – magic bytes, tools, memory, steganography, artifacts
  • Reverse    – strings, ELF/PE, calling conventions, packers, analysis concepts
  • OSINT      – DNS, WHOIS, search operators, recon, threat intelligence basics

Challenges use the flag format: CTF{...}


Main features
-------------

  • Browse, search, filter (category / difficulty) and sort challenges
  • Challenge detail panel with description, hints, and flag submission
  • Hints cost points (default −15 per hint); reward is reduced accordingly
  • Instant flag checks and toast notifications
  • Progress dashboard, per-category stats, and recommended next challenge
  • Learning paths (grouped starter sets per category)
  • Bookmarks (star on cards)
  • Write-ups unlocked after solving
  • Local leaderboard (demo scores + your score on this browser)
  • Display name, light / dark (neon) theme
  • Export / import progress as JSON
  • Reset progress
  • Keyboard: "/" focuses search; Escape closes mobile detail; arrows move selection
  • Responsive layout with mobile bottom sheet for challenge details


How to run
----------

1. Open the HTML file in a modern browser (Chrome, Firefox, Edge, Safari).
2. Or serve it with any static file server, for example:

     python -m http.server 8080

   then visit http://localhost:8080

No build step, package manager, or server-side code is required.


Usage tips
----------

  • Click a challenge card (or use the sidebar “Start a Challenge”) to open details.
  • Submit flags in the form CTF{...}. Wrong format is warned in the UI.
  • Unlock hints only when stuck; each costs points from that challenge’s reward.
  • Solved challenges unlock write-ups and appear under My Attempts / Write-ups.
  • Change your display name under Settings so it shows on the local leaderboard.
  • Export progress regularly if you want a backup; import restores solved state,
    bookmarks, and hint usage on this browser.


Technical notes
---------------

  • Pure front-end: HTML, CSS, and JavaScript in one file.
  • State keys in localStorage: ctf_solved, ctf_bookmarks, ctf_used_hints,
    ctf_display_name, ctf_theme.
  • Leaderboard is local/demo only. A shared leaderboard across users needs a backend.
  • Fake community solve counts and average times are deterministic per challenge id
    for demo presentation only.


License / intent
----------------

Educational demo for learning CTF-style concepts. Not a production multi-user
platform. Use for personal practice and teaching. Do not treat flag strings as
real secrets outside this app.


Quick start checklist
---------------------

  [ ] Open the page in a browser
  [ ] Optionally set a username in Settings
  [ ] Solve “First Steps” (or any easy challenge) to confirm flags work
  [ ] Try a hint and confirm points update
  [ ] Bookmark a challenge and check the Bookmarks page
  [ ] Export progress from Settings if you want a backup


Tagline
-------

Think like an attacker. Build like a defender.





# 2. $${\color{limegreen}\text{Python Log Analyzer Pro (Security monitoring tool)}}$$  

Python Log Analyzer Pro is a Python-based security tool for analyzing log files and identifying suspicious activity.

The project was developed as a practical cybersecurity project to detect and investigate activities such as brute-force attacks, unauthorized access, malware-related activity, phishing, and other security events found in log files.

The application uses a graphical user interface built with **Tkinter** and presents analysis results in an organized and easy-to-understand format.

## Features

* Log file analysis
* Brute-force detection
* Failed login detection
* Suspicious activity detection
* IP address analysis
* Attack Timeline
* Log Type overview
* Security event categorization
* Severity classification
* Detailed event information
* Custom security patterns
* Security event reporting
* Graphical data visualization
* CSV export
* New Scan functionality

The tool can detect and categorize events such as:

* Malware
* File tampering
* Unauthorized access
* Security breaches
* APT-related activity
* Phishing
* Data leakage
* Brute-force attacks

## Brute-Force Detection

The tool can identify multiple failed login attempts from the same IP address within a specific time window.

For example:

```text
30 failed login attempts
Source IP: 192.168.1.25
Time window: 2 minutes

Possible brute-force attack detected
```

Instead of only counting individual failed login events, the analyzer looks for patterns that may indicate a coordinated brute-force attack.

## Attack Overview

After a scan has been completed, the application provides an overview of the detected security events.

The overview can include:

* Number of detected events
* Severity levels
* Attack types
* Source IP addresses
* Event timestamps
* Log files associated with the events

This provides a quick way to understand what was found during the analysis.

## Attack Timeline

The Attack Timeline displays security events in chronological order.

This can be useful when investigating an incident and trying to understand how suspicious activity developed over time.

Example:

```text
10:01:12  Failed login
10:01:18  Failed login
10:01:25  Failed login
10:01:31  Failed login
10:01:42  Failed login
10:01:45  Possible brute-force attack
```

## IP Analysis

The IP Analysis section provides an overview of IP addresses found in the analyzed logs.

It can help identify IP addresses that:

* Generate multiple failed login attempts
* Appear in several security events
* Occur unusually frequently
* Are associated with multiple types of suspicious activity

## CSV Export

Analysis results can be exported to a CSV file.

This makes it possible to:

* Save analysis results
* Review the results later
* Import the data into Excel or other analysis tools
* Document security events
* Perform additional analysis

The exported data includes information such as the log file, attack type, severity, and relevant log line.

## New Scan

The application includes a dedicated **New Scan** tab.

This allows the user to start a new analysis without restarting the application.

When a new scan is started, results from the previous analysis are cleared so that the new analysis can be performed separately.

## Technologies

The project is built using:

* **Python**
* **Tkinter** – graphical user interface
* **Matplotlib** – data visualization
* **Regular Expressions (Regex)** – pattern matching
* **JSON** – configuration and settings
* **CSV** – result export

## Project Structure

```text
Python-Log-Analyzer-Pro/
│
├── main.py
├── log_analyzer_config.json
├── README.md
└── ...
```

The project structure may change as additional modules and features are added.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/malwaremango/Security-Projects.git
```

### 2. Navigate to the project directory

```bash
cd python-log-analyzer-pro
```

### 3. Install dependencies

Install the required Python packages:

```bash
pip install matplotlib
```

Tkinter is included with many Python installations. Depending on the operating system, it may need to be installed separately.

### 4. Run the application

```bash
python main.py
```

## Example Log Analysis

The application can analyze log entries containing events such as:

```text
Failed login
Successful login
Unauthorized access
Malware detected
File modification
Phishing attempt
Connection attempt
Privilege escalation
```

The analyzer processes the log content and presents relevant security events through the graphical interface.

## Use Cases

This project can be used for learning and practical work in areas such as:

* Cybersecurity
* Security Operations (SOC)
* Incident Response
* Log Analysis
* Threat Detection
* Network Security
* Security Monitoring

It can also serve as a foundation for developing a more advanced log analysis or SOC monitoring platform.

## Future Improvements

Potential future improvements include:

* Support for additional log formats
* Windows Event Log analysis
* Apache and Nginx log analysis
* IP reputation checks
* Threat intelligence integration
* Advanced anomaly detection
* Automatic incident report generation
* Real-time log monitoring
* JSON and PDF export
* MITRE ATT&CK mapping
* Additional security dashboards

## Disclaimer

This project is intended for **educational purposes, testing, and security analysis**. The files added to the log analyzer are not real and are for testing purposes only (gemini and auth.log)

The results should be treated as an aid during log investigations and should not be used alone to determine whether an actual security incident has occurred.

## Author

**Usman Ahmad**

Cybersecurity / Information Security

This project was developed as a practical cybersecurity project focusing on log analysis, suspicious activity detection, and security monitoring.

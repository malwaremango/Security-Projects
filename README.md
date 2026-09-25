#  Security Project
Welcome! This repository will be used to host and showcase my upcoming security projects. 

See the descriptions below:








# Python Log Analyzer Pro (Security monitoring tool)

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

# SSH Log Analyzer – Failed Login Detector

A simple, defensive command-line tool to analyze SSH authentication logs for failed login attempts and potential brute-force bursts.

This project is suitable for a junior security engineer's portfolio: it demonstrates log parsing, time handling, summarization, and simple defensive suggestions without using external dependencies.

**Disclaimer:** This tool is for educational and defensive use only. Run it on logs for systems you own or are authorized to administer. Always review suggested actions before applying firewall rules or other blocking measures.

## Features

- Parse common SSH "Failed password" syslog lines (Debian/Ubuntu-style and similar).
- Summarize failed attempts per IP and per username.
- Detect bursts (many attempts from one IP within a short time window).
- Export a JSON summary report.
- Export a CSV file listing each failed attempt.
- Print suggested firewall rules as text (do not execute anything automatically).

## Requirements

- Python 3.10 or newer.
- No external dependencies (standard library only).

## Quick Start

Clone or copy the project, then run:

```bash
python analyzer.py sample_auth.log
```

Replace `sample_auth.log` with the path to your auth log (e.g. `/var/log/auth.log` or `/var/log/secure`).

## Usage

Basic analysis:

```bash
python analyzer.py /var/log/auth.log
```

Lower threshold (mark an IP suspicious after 3 failures):

```bash
python analyzer.py /var/log/auth.log --min-failures 3
```

Burst detection (detect 5 failures within a 5-minute window):

```bash
python analyzer.py /var/log/auth.log --min-failures 5 --window-min 5
```

JSON and CSV export:

```bash
python analyzer.py /var/log/auth.log --json-out report.json --csv-out attempts.csv
```

Firewall suggestions (print example iptables rules for IPs with >= 10 failures):

```bash
python analyzer.py /var/log/auth.log --min-failures 10 --firewall-suggest
```

## Sample Output

```
Parsed 123 failed login attempts.
Unique source IPs: 10
Unique usernames: 5

=== Suspicious IPs (failed login attempts) ===
(IPs with at least 5 failures)
203.0.113.5      23 failures
198.51.100.7     7 failures

=== Top attacked usernames ===
root                 50 failures
admin                20 failures
test                  5 failures

=== Bursts (IPs with >= 5 failures within 5 minutes) ===
203.0.113.5      max 23 failures in any 5-minute window
198.51.100.7     max 7 failures in any 5-minute window

(Use this information responsibly; consider manual review before blocking IPs.)
[+] JSON report written to report.json
[+] CSV attempts written to attempts.csv
=== Suggested firewall rules (example, review before using) ===
# IP 203.0.113.5 has >= 23 failed attempts
iptables -A INPUT -s 203.0.113.5 -j DROP
```

## Log Format Supported

This tool focuses on lines like:

```
Jan 10 12:34:56 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2
Jan 10 12:35:01 myhost sshd[2345]: Failed password for invalid user admin from 198.51.100.7 port 51111 ssh2
```

It captures month, day, time, hostname, username (including "invalid user" forms), and IPv4 address.

## How it Handles Timestamps

System syslog timestamps typically omit the year. Use `--year` to specify the year to use when building datetime objects. If omitted, the current year is used.

Example:

```bash
python analyzer.py /var/log/auth.log --year 2025
```

Note: This may be slightly incorrect around year boundaries (Dec/Jan), which is acceptable for short-term analysis.

## Project Files

- `analyzer.py` — main script with parsing, analysis, and reporting.
- `sample_auth.log` — small example log for testing and demonstration.

## Future Improvements

- Support additional log formats and SSH variants from other distros.
- Add GeoIP lookup to enrich attacker IPs with location data.
- Provide a simple web dashboard for visualizing trends.
- Integrate with alerting or SIEM systems for automated notifications.

## License & Safety Notes

This project is provided as-is for educational purposes. Do not use it to interfere with other people's systems. Always follow legal and ethical guidelines when collecting and analyzing logs.

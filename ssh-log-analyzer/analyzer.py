#!/usr/bin/env python3
from __future__ import annotations

"""
SSH Log Analyzer – Failed Login Detector

Defensive / educational tool to parse SSH authentication logs and detect failed
login attempts and potential brute-force bursts.

This copy is placed under the user's workspace path to allow direct execution.
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class FailedAttempt:
    timestamp: datetime
    ip: str
    user: str
    host: str
    raw_line: str


LOG_LINE_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_line(line: str, year: int) -> Optional[FailedAttempt]:
    m = LOG_LINE_REGEX.search(line)
    if not m:
        return None

    month_str = m.group("month")
    day_str = m.group("day")
    time_str = m.group("time")
    host = m.group("host")
    user = m.group("user")
    ip = m.group("ip")

    try:
        month = MONTH_MAP.get(month_str)
        if month is None:
            return None
        day = int(day_str)
        timestamp = datetime.fromisoformat(f"{year:04d}-{month:02d}-{day:02d}T{time_str}")
    except Exception:
        return None

    return FailedAttempt(timestamp=timestamp, ip=ip, user=user, host=host, raw_line=line.rstrip("\n"))


def parse_log_file(path: str, year: Optional[int] = None) -> List[FailedAttempt]:
    attempts: List[FailedAttempt] = []
    if year is None:
        year = datetime.now().year

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    with p.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if "Failed password" not in line:
                continue
            attempt = parse_line(line, year)
            if attempt:
                attempts.append(attempt)
    return attempts


def summarize_attempts(attempts: List[FailedAttempt]) -> Tuple[Counter, Counter]:
    by_ip: Counter = Counter()
    by_user: Counter = Counter()
    for a in attempts:
        by_ip[a.ip] += 1
        by_user[a.user] += 1
    return by_ip, by_user


def detect_bursts(
    attempts: List[FailedAttempt],
    min_failures: int,
    window_minutes: int,
) -> Dict[str, int]:
    if window_minutes <= 0:
        return {}

    by_ip_timestamps: Dict[str, List[datetime]] = defaultdict(list)
    for a in attempts:
        by_ip_timestamps[a.ip].append(a.timestamp)

    result: Dict[str, int] = {}
    window_delta = timedelta(minutes=window_minutes)

    for ip, timestamps in by_ip_timestamps.items():
        if not timestamps:
            continue
        timestamps.sort()
        max_count = 0
        j = 0
        n = len(timestamps)
        for i in range(n):
            while j < n and timestamps[j] - timestamps[i] <= window_delta:
                j += 1
            count = j - i
            if count > max_count:
                max_count = count
        if max_count >= min_failures:
            result[ip] = max_count
    return result


def print_summary(
    attempts: List[FailedAttempt],
    by_ip: Counter,
    by_user: Counter,
    min_failures: int,
    bursts: Dict[str, int],
    window_minutes: Optional[int],
) -> None:
    total_attempts = len(attempts)
    unique_ips = len(by_ip)
    unique_users = len(by_user)

    print()
    print(f"Parsed {total_attempts} failed login attempts.")
    print(f"Unique source IPs: {unique_ips}")
    print(f"Unique usernames: {unique_users}")
    print()

    print("=== Suspicious IPs (failed login attempts) ===")
    print(f"(IPs with at least {min_failures} failures)")
    suspicious = [(ip, cnt) for ip, cnt in by_ip.items() if cnt >= min_failures]
    if suspicious:
        suspicious.sort(key=lambda x: x[1], reverse=True)
        for ip, cnt in suspicious:
            print(f"{ip:16} {cnt} failures")
    else:
        print("No IPs exceed the configured threshold.")
    print()

    print("=== Top attacked usernames ===")
    for user, cnt in by_user.most_common(10):
        print(f"{user:20} {cnt} failures")
    print()

    if window_minutes and window_minutes > 0:
        print(f"=== Bursts (IPs with >= {min_failures} failures within {window_minutes} minutes) ===")
        if bursts:
            for ip, max_count in sorted(bursts.items(), key=lambda kv: kv[1], reverse=True):
                print(f"{ip:16} max {max_count} failures in any {window_minutes}-minute window")
        else:
            print("No burst activity detected with current thresholds.")
        print()

    print("(Use this information responsibly; consider manual review before blocking IPs.)")
    print()


def write_json_report(
    path: str,
    attempts: List[FailedAttempt],
    by_ip: Counter,
    by_user: Counter,
    bursts: Dict[str, int],
    min_failures: int,
    window_minutes: Optional[int],
) -> None:
    payload = {
        "generated_at_utc": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "config": {
            "min_failures": min_failures,
            "window_minutes": window_minutes,
        },
        "summary": {
            "attempts_total": len(attempts),
            "unique_ips": len(by_ip),
            "unique_users": len(by_user),
        },
        "by_ip": dict(by_ip),
        "by_user": dict(by_user),
        "bursts": dict(bursts),
    }
    p = Path(path)
    try:
        with p.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"[+] JSON report written to {path}")
    except Exception as e:
        print(f"[!] Failed to write JSON report to {path}: {e}")


def write_csv_attempts(path: str, attempts: List[FailedAttempt]) -> None:
    p = Path(path)
    try:
        with p.open("w", encoding="utf-8", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["timestamp_iso", "ip", "user", "host"])
            for a in attempts:
                writer.writerow([a.timestamp.isoformat(), a.ip, a.user, a.host])
        print(f"[+] CSV attempts written to {path}")
    except Exception as e:
        print(f"[!] Failed to write CSV to {path}: {e}")


def print_firewall_suggestions(by_ip: Counter, min_failures: int) -> None:
    candidates = [(ip, cnt) for ip, cnt in by_ip.items() if cnt >= min_failures]
    print("=== Suggested firewall rules (example, review before using) ===")
    if not candidates:
        print("No IPs exceed the threshold for firewall suggestions.")
        print()
        return

    candidates.sort(key=lambda x: x[1], reverse=True)
    for ip, cnt in candidates:
        print(f"# IP {ip} has >= {cnt} failed attempts")
        print(f"iptables -A INPUT -s {ip} -j DROP")
        print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="SSH Log Analyzer – Failed Login Detector (defensive/educational tool)"
    )
    parser.add_argument("logfile", help="Path to SSH auth log file (e.g. /var/log/auth.log)")
    parser.add_argument("--year", type=int, default=None, help="Year to assume for syslog timestamps (default: current year)")
    parser.add_argument("--min-failures", type=int, default=5, help="Threshold to consider an IP suspicious (default: 5)")
    parser.add_argument("--window-min", type=int, default=0, help="Window in minutes for burst detection (0 to disable)")
    parser.add_argument("--json-out", type=str, default=None, help="Path to write JSON summary report")
    parser.add_argument("--csv-out", type=str, default=None, help="Path to write CSV of failed attempts")
    parser.add_argument("--firewall-suggest", action="store_true", help="Print example firewall rules for suspicious IPs (text only)")

    args = parser.parse_args(argv)

    try:
        attempts = parse_log_file(args.logfile, year=args.year)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except PermissionError as e:
        print(f"[!] Permission error reading log file: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[!] Failed to read or parse log file: {e}", file=sys.stderr)
        return 4

    if not attempts:
        print("No failed SSH login attempts were detected in the provided log (or file format not recognized).")
        return 0

    by_ip, by_user = summarize_attempts(attempts)
    bursts = detect_bursts(attempts, min_failures=args.min_failures, window_minutes=args.window_min)

    print_summary(
        attempts=attempts,
        by_ip=by_ip,
        by_user=by_user,
        min_failures=args.min_failures,
        bursts=bursts,
        window_minutes=(args.window_min if args.window_min > 0 else None),
    )

    if args.json_out:
        write_json_report(
            args.json_out,
            attempts=attempts,
            by_ip=by_ip,
            by_user=by_user,
            bursts=bursts,
            min_failures=args.min_failures,
            window_minutes=(args.window_min if args.window_min > 0 else None),
        )

    if args.csv_out:
        write_csv_attempts(args.csv_out, attempts)

    if args.firewall_suggest:
        print_firewall_suggestions(by_ip, args.min_failures)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

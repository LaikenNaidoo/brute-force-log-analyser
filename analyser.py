import re
from datetime import datetime, timedelta
from collections import defaultdict

def parse_auth_log(file_path):
    """
    Parses an SSH auth.log file and extracts login attempts.
    """
    log_pattern = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>[\w\-]+)\s+(?P<process>[\w\[\]]+):\s+'
        r'(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+'
        r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)'
    )

    events = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.match(line.strip())
                if match:
                    data = match.groupdict()
                    current_year = datetime.now().year
                    timestamp_str = f"{data['month']} {data['day']} {data['time']} {current_year}"
                    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
                    
                    events.append({
                        'timestamp': timestamp,
                        'status': data['status'],
                        'user': data['user'],
                        'ip': data['ip']
                    })
    except FileNotFoundError:
        print(f"[-] Error: File not found at {file_path}")
    
    return events

def run_detection_rules(events, threshold=5, window_minutes=5):
    """
    Applies Brute-Force detection rules based on time windows.
    """
    ip_failures = defaultdict(list)
    alerts = []

    for event in events:
        if event['status'] == 'Failed':
            ip_failures[event['ip']].append(event['timestamp'])

    # Check for brute-force patterns
    for ip, timestamps in ip_failures.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)
            count = sum(1 for t in timestamps if window_start <= t <= window_end)
            
            if count >= threshold:
                alerts.append({
                    'ip': ip,
                    'severity': 'HIGH',
                    'type': 'Brute-Force Attack',
                    'details': f"{count} failed attempts within {window_minutes} minutes.",
                    'time': window_start
                })
                break  # Prevent duplicate flags for the same continuous window

    return alerts

def generate_markdown_report(events, alerts, output_file="incident_report.md"):
    """
    Generates a structured Markdown incident report.
    """
    report_content = f"""# Incident Report: Automated SSH Log Analysis
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Tool:** Brute-Force Log Analyser (Python 3)  

---

## 1. Summary Counts
* **Total Parsed Auth Events:** {len(events)}
* **Total Security Alerts Triggered:** {len(alerts)}
* **Unique Attacking IPs Flagged:** {len(set(a['ip'] for a in alerts))}

---

## 2. Detected Security Alerts
| Severity | Attack Type | Source IP | Details / Trigger | Timestamp |
| :--- | :--- | :--- | :--- | :--- |
"""
    for alert in alerts:
        report_content += f"| **{alert['severity']}** | {alert['type']} | `{alert['ip']}` | {alert['details']} | {alert['time']} |\n"

    report_content += """
---

## 3. Recommended Containment Actions
1. **Enable Fail2ban:** Automatically ban IP addresses exhibiting repeated authentication failures.
2. **Enforce SSH Key Authentication:** Disable password-based logins entirely to neutralize brute-force vectors.
3. **Review Access Logs:** Inspect account activity for any authenticated sessions originating from flagged IPs.
"""

    with open(output_file, 'w') as f:
        f.write(report_content)
    print(f"[+] Incident report successfully generated: {output_file}")

if __name__ == "__main__":
    log_file = "auth.log"
    print(f"[*] Analyzing log file: {log_file}...")
    
    parsed_events = parse_auth_log(log_file)
    triggered_alerts = run_detection_rules(parsed_events)
    
    generate_markdown_report(parsed_events, triggered_alerts)
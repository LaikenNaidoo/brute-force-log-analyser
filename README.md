# Brute-Force Log Analyser

A small Python tool that reads a Linux SSH authentication log (`auth.log`), flags brute-force login activity, and writes a Markdown incident report with the suspicious IP addresses and recommended containment actions.

Built for the **Tech Mentorship Program 2026, Cybersecurity Track** (focus area: Incident Response).

## 1. Problem

Small teams and beginners often cannot tell from raw SSH logs whether a server is being attacked. Thousands of lines of failed logins are hard to read by eye. This tool does the counting and produces a short, readable report that shows who is attacking, how often, and what to do about it.

## 2. What it does (Version 1)

| Feature | Status |
|---|---|
| Parse SSH `Failed password` and `Accepted password` lines from `auth.log` | Working |
| **Rule 1:** Brute-force detection (many failed logins from one IP inside a time window) | Working |
| Markdown incident report (summary counts, alert table, containment advice) | Working |
| Password-spraying rule (one IP trying many usernames) | Not yet built (future work) |
| Rule: successful login right after repeated failures | Not yet built (future work) |

## 3. Requirements

- Python 3 (no extra packages; the tool only uses the standard library: `re`, `datetime`, `collections`)

## 4. Project files

| File | Purpose |
|---|---|
| `analyser.py` | The tool: log parser, detection rule, report generator |
| `auth.log` | Sample SSH log used as input |
| `incident_report.md` | Sample output produced by the tool |
| `README.md` | This file |

## 5. Setup

```bash
git clone https://github.com/LaikenNaidoo/brute-force-log-analyser.git
cd brute-force-log-analyser
```

## 6. Usage

Run from inside the project folder:

```bash
python3 analyser.py
```

The tool reads `auth.log` from the same folder and writes `incident_report.md` there. To analyse your own log, replace `auth.log` with your file, or change the `log_file` value at the bottom of `analyser.py`.

On success you will see:

```
[*] Analyzing log file: auth.log...
[+] Incident report successfully generated: incident_report.md
```

## 7. How the detection works

1. **Parse:** each line is matched with a regular expression. The tool extracts the timestamp, status (`Failed` or `Accepted`), username and source IP. Lines that do not match are ignored.
2. **Group:** failed attempts are grouped by source IP.
3. **Detect (Rule 1):** for each IP, the tool slides a time window across its failed attempts. If the number of failures inside one window reaches the threshold, the IP is flagged as a brute-force attack with severity **HIGH**.
4. **Report:** the tool writes the summary counts, an alert table, and containment recommendations to `incident_report.md`.

**Default settings** (in `run_detection_rules` in `analyser.py`):

| Setting | Default |
|---|---|
| `threshold` | 5 failed attempts |
| `window_minutes` | 5 minutes |

To change them, edit the arguments, for example `run_detection_rules(events, threshold=10, window_minutes=2)`.

## 8. Sample output

Running the tool on the included sample log produced (see `incident_report.md`):

- Total parsed auth events: 9
- Security alerts triggered: 1
- Flagged IP: `192.168.1.50`, 5 failed attempts within 5 minutes, severity HIGH

This is output from sample data, not from a live attack.

## 9. Safe use and ethics

- Only analyse logs from systems you own or are authorised to review.
- The sample log uses a private address range. Do not publish real credentials, usernames, or IP addresses from systems that are not yours.
- The tool only reads a log file. It does not scan, connect to, or attack any system.

## 10. Test notes

- Tested on the included sample log (`auth.log`); output saved in `incident_report.md`.
- [TO BE COMPLETED BY THE TEAM: results from testing on logs generated in our own lab VM, including what was detected, what was missed, and any false alarms.]

## 11. Known limitations

- Only the brute-force rule is implemented. Password spraying and "success after failures" are not detected yet.
- Only `Failed password` and `Accepted password` lines are parsed. Other SSH events (for example key-based logins or other failure messages) are ignored.
- Log timestamps do not contain a year, so the tool assumes the current year.
- Thresholds are set in the code, not in a configuration file.
- An IP is flagged once, even if it attacks repeatedly later.
- The containment recommendations in the report are fixed text and are not tailored to each alert.
- Works offline on one log file; it is not a live monitoring tool.

## 12. Future work

- Password-spraying detection
- Detection of a successful login after repeated failures
- Configurable thresholds (config file or command-line options)
- Support for more log events and formats
- HTML report and live monitoring

## 13. Team and contributions

| Member | Contribution |
|---|---|
| Laiken Naidoo (Group Leader) | Wrote the technical project report; developed the core Python script for regex-based SSH log parsing; built the sliding time-window detection rule and the automated Markdown report generator |
| Wisdom Osagede | README documentation and compilation of the final technical report |
| [Member name] | [Contribution] |
| [Member name] | [Contribution] |
| [Member name] | [Contribution] |

## 14. Repository

https://github.com/LaikenNaidoo/brute-force-log-analyser

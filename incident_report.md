# Incident Report: Automated SSH Log Analysis
**Generated:** 2026-11-04 23:03:12  
**Tool:** Brute-Force Log Analyser (Python 3)  

---

## 1. Summary Counts
* **Total Parsed Auth Events:** 9
* **Total Security Alerts Triggered:** 1
* **Unique Attacking IPs Flagged:** 1

---

## 2. Detected Security Alerts
| Severity | Attack Type | Source IP | Details / Trigger | Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| **HIGH** | Brute-Force Attack | `192.168.1.50` | 5 failed attempts within 5 minutes. | 2026-10-24 10:15:32 |

---

## 3. Recommended Containment Actions
1. **Enable Fail2ban:** Automatically ban IP addresses exhibiting repeated authentication failures.
2. **Enforce SSH Key Authentication:** Disable password-based logins entirely to neutralize brute-force vectors.
3. **Review Access Logs:** Inspect account activity for any authenticated sessions originating from flagged IPs.

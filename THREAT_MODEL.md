# 🛡️ Threat Model & Security Considerations

This document outlines the potential security risks associated with deploying the **ModSec-MITRE-Mapper** and the mitigations implemented within the tool.

## 1. Asset Identification
*   **Primary Asset:** ModSecurity Audit Logs. These logs contain sensitive HTTP request data, including Session IDs, Cookies, User Agents, and potentially Passwords (if POST data is logged).
*   **Secondary Asset:** The SIEM/Log Aggregator pipeline.
*   **System Asset:** The host server running the analyzer daemon.

## 2. Threat Scenarios

### A. Denial of Service (DoS) via Log Flooding
*   **Threat:** An attacker floods the web server with high-volume traffic. The ModSecurity log grows faster than the analyzer can process it, potentially consuming all system RAM or crashing the service.
*   **Mitigation:**
    *   **Queue Limits:** The tool utilizes a Python `queue.Queue` with a strict `maxsize` (default 5000). If the queue fills up, new logs are dropped rather than crashing the system.
    *   **Efficient Parsing:** The "Smart Classification" logic drops benign traffic early in the parsing chain if configured, reducing processing overhead.

### B. Malicious Input & Command Injection
*   **Threat:** An attacker injects malformed characters or shell commands into HTTP Headers (User-Agent) or POST bodies, hoping the analyzer will execute them when parsing.
*   **Mitigation:**
    *   **Strict Regex:** The `LogParser` uses strict Regular Expressions (`SECTION_HEADER`) to delimit log parts.
    *   **No Eval:** The tool treats all log data purely as strings. It never uses `eval()`, `exec()`, or shell subprocesses on log data.
    *   **Exception Handling:** Every parsing step is wrapped in `try/except` blocks to prevent a single malformed log line from crashing the daemon.

### C. Confidentiality / PII Leakage
*   **Threat:** Users inadvertently submit PII (emails, passwords, credit card numbers) in forms. ModSecurity logs this data (Section C), and this tool extracts it into the `http.post_data` JSON field, forwarding it to the SIEM.
*   **Mitigation:**
    *   **Operational Control:** This tool is a pipeline. PII masking should be handled either at the source (ModSecurity `SecAuditLogParts`) or at the destination (Logstash filters).
    *   **Network Security:** The tool supports TCP. It is recommended to run this over a secure management VLAN or VPN.

### D. Privilege Escalation
*   **Threat:** The tool is run as `root` to read `/var/log/apache2/`. If a vulnerability were found in the Python runtime, an attacker could gain root access.
*   **Mitigation:**
    *   **Least Privilege:** The documentation strongly recommends running the service as a dedicated user (e.g., `modsec_user`) and granting that user read permissions via Access Control Lists (ACLs) or Group ownership, rather than running as root.

## 3. Deployment Best Practices
1.  **Restrict Network Access:** Ensure the SIEM port (default 5000/514) is only accessible from authorized IPs.
2.  **Log Rotation:** Ensure `logrotate` is configured for the ModSecurity audit log to prevent disk exhaustion. The tool automatically handles file rotation (inode tracking).
3.  **Review ModSec Config:** Ensure `SecAuditLogParts` is configured to log Request Bodies (`C`) only if forensic analysis is required, as this increases the risk of PII leakage.
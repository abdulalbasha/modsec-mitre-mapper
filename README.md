# 🛡️ ModSec-MITRE-Mapper

**Next-Gen ModSecurity Log Analyzer, MITRE ATT&CK Mapper & SIEM Forwarder**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg)
![Status](https://img.shields.io/badge/status-production--ready-green)

A high-performance Python daemon that transforms raw ModSecurity `audit.log` files into structured, context-rich JSON events. It distinguishes between **Normal Traffic** and **Attacks**, automatically maps threats to **MITRE ATT&CK** techniques using heuristic analysis, captures POST body data, and forwards everything to your SIEM (Splunk, ELK, Wazuh) in real-time.

## 🚀 Features

- **Smart Classification:** Instantly categorizes events as `ATTACK` or `TRAFFIC`. It scans for ModSecurity tags, severity levels, and rule IDs even in complex or malformed log entries.
- **Forensic Context:** Extracts Source/Dest IP & Ports, Hostnames, URL Paths, User Agents, and **POST Body Data**.
- **Heuristic MITRE Mapping:** Maps vague tags (e.g., `OWASP_CRS/WEB_ATTACK/SQL_INJECTION`) to specific MITRE IDs (`T1190`) and Tactics (`Initial Access`).
- **Intelligent Prioritization:** Prioritizes specific attack messages (e.g., "SQL Injection Detected") over generic blocking messages (e.g., "Anomaly Score Exceeded").
- **Transport Agnostic:** Supports UDP (Fire-and-forget) and TCP (Reliable/Batched).
- **ELK Ready:** Includes pre-built Logstash configuration for Elastic Common Schema (ECS) compliance.

## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/modsec-mitre-mapper.git
   cd modsec-mitre-mapper
   ```
   
2. **Verify Environment**
 
   No external pip packages are required. The tool uses the standard Python 3.8+ library.
   ```bash
   python3 --version
   ```

4. **Permissions**
   
   Make the script executable:
   ```bash
   chmod +x modsec_analyzer.py
   ```

## 🛠️ Usage & Options

### Command Line Arguments

| Argument | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--log-file` | Path | Yes | - | Absolute path to the modsec_audit.log file. |
| `--server` | IP/Host | Yes | - | IP address of your SIEM or Log Collector. |
| `--port` | Int | Yes | - | Port number of the SIEM listener (e.g., 514, 5000). |
| `--protocol` | Char | No | u | u for UDP (Fast), t for TCP (Reliable). |
| `--poll-interval` | Float | No | 0.1 | Seconds to wait before checking for new log lines. |
| `--batch-size` | Int | No | 1 | Number of events to group before sending (TCP only). |

---

### Run Examples

1.  **High-Speed UDP Mode (Recommended for Local/LAN)**
    ```bash
    ./modsec_analyzer.py --log-file /var/log/modsec_audit.log \
                         --server 192.168.1.50 --port 514 \
                         --protocol u
    ```

2.  **Reliable TCP Mode with Batching**
    ```bash
    ./modsec_analyzer.py --log-file /var/log/apache2/modsec_audit.log \
                         --server 10.0.0.5 --port 6514 \
                         --protocol t \
                         --batch-size 10
    ```

### ⚙️ Auto-Run as a Service (Linux Systemd)

To ensure the analyzer runs in the background and starts automatically on boot:

**Create the Service File at `/etc/systemd/system/modsec-mapper.service`:**

```ini
[Unit]
Description=ModSecurity MITRE Mapper Service
After=network.target

[Service]
Type=simple
# Replace 'root' with a user that has read access to logs
User=root
Group=root
# Adjust paths to your script location
ExecStart=/usr/bin/python3 /opt/modsec-mitre-mapper/modsec_analyzer.py \
    --log-file /var/log/modsec_audit.log \
    --server 127.0.0.1 \
    --port 5000 \
    --protocol u
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Enable and Start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable modsec-mapper.service
sudo systemctl start modsec-mapper.service
```

---

### 📊 ELK Stack Integration (Logstash)

This tool includes a Logstash configuration file to map data to the Elastic Common Schema (ECS).

**Copy Config:**
```bash
cp integrations/elk/modsec-logstash.conf /etc/logstash/conf.d/
```

**Edit Config:** Update the Elasticsearch hosts/credentials in the output section.

**Restart Logstash:**
```bash
systemctl restart logstash
```

### 🧩 JSON Output Examples

1.  **Attack Event (SQL Injection via POST)**
    ```json
    {
      "timestamp": "2025-11-22T16:00:00Z",
      "event_type": "ATTACK",
      "network": {
        "source_ip": "192.168.9.100",
        "source_port": 45123,
        "dest_ip": "192.168.2.192",
        "dest_port": 443
      },
      "http": {
        "method": "POST",
        "host_name": "dvwa.internal",
        "url_path": "/login.php",
        "full_uri": "/login.php",
        "user_agent": "Mozilla/5.0...",
        "post_data": "username=admin&password=admin' OR 1=1--"
      },
      "modsec_data": {
        "severity": "CRITICAL",
        "message": "SQL Injection Attack Detected via libinjection",
        "rule_id": "942100",
        "attack_tags": ["OWASP_CRS/WEB_ATTACK/SQL_INJECTION"]
      },
      "mitre_mapping": {
        "primary_technique": "T1190",
        "tactic": "Initial Access",
        "technique_name": "Exploit Public-Facing Application",
        "all_techniques": ["T1190"],
        "categories_detected": ["SQL Injection (SQLi)"]
      }
    }
    ```

2.  **Normal Traffic**
    ```json
    {
      "timestamp": "2025-11-22T16:00:05Z",
      "event_type": "TRAFFIC",
      "network": {
        "source_ip": "192.168.9.100",
        "dest_ip": "192.168.2.192"
      },
      "http": {
        "method": "GET",
        "url_path": "/index.html",
        "post_data": ""
      },
      "modsec_data": {
        "severity": "INFO",
        "message": "",
        "attack_tags": []
      },
      "mitre_mapping": null
    }
    ```

---

### 📈 Benchmark: Speed vs. Usability

| Feature | ModSec-MITRE-Mapper | Elastic Filebeat | Native Console |
| :--- | :--- | :--- | :--- |
| **Intelligence** | Context-Aware (Attack/Traffic) | Dumb Forwarder | None |
| **MITRE Mapping** | Automatic (Edge) | Server-side Pipeline | Manual |
| **POST Data** | Clean Extraction | Raw String | N/A |
| **Setup** | Single Script | YAML Config + Pipelines | Complex DB |
| **Memory** | ~45MB | ~80MB | High |

---

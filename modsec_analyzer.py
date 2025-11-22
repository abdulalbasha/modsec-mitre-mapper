#!/usr/bin/env python3
import sys
import os
import time
import json
import socket
import logging
import argparse
import signal
import re
import threading
import queue
from datetime import datetime
from typing import Dict, List, Optional

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ModSecAnalyzer")

class Config:
    def __init__(self, args):
        self.log_file = args.log_file
        self.server = args.server
        self.port = int(args.port)
        self.protocol = args.protocol
        self.poll_interval = args.poll_interval
        self.batch_size = args.batch_size
        self.mitre_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mitre_definitions.json')

# --- MITRE Mapping Logic ---
class HeuristicMapper:
    def __init__(self, db_path: str):
        self.rules = self._load_rules(db_path)
        self.fallback = {
            "id": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning"
        }

    def _load_rules(self, path: str) -> List[Dict]:
        if not os.path.exists(path): return []
        try:
            with open(path, 'r') as f:
                return json.load(f).get('mappings', [])
        except: return []

    def map_event(self, tags: List[str], message: str, rule_id: str) -> Optional[Dict]:
        if not tags and (rule_id == "UNKNOWN" or not rule_id):
            return None

        search_text = f"{' '.join(tags)} {message} {rule_id}".lower()
        search_text = re.sub(r'[^a-z0-9\s]', ' ', search_text)
        tokens = set(search_text.split())

        best_match = self.fallback
        highest_priority = 0
        matched_categories = []
        all_techniques = set()
        match_found = False

        for rule in self.rules:
            rule_keywords = set(rule['keywords'])
            if not rule_keywords.isdisjoint(tokens):
                match_found = True
                matched_categories.append(rule['category'])
                all_techniques.add(rule['mitre']['id'])
                
                if rule['priority'] > highest_priority:
                    highest_priority = rule['priority']
                    best_match = rule['mitre']

        return {
            "primary_technique": best_match['id'],
            "tactic": best_match['tactic'],
            "technique_name": best_match['name'],
            "all_techniques": list(all_techniques),
            "categories_detected": list(set(matched_categories))
        }

# --- Enhanced Log Parsing Logic ---
class LogParser:
    SECTION_HEADER = re.compile(r'^--([a-zA-Z0-9]+)-([A-Z])--$')

    def parse(self, raw_chunk: str, source_file: str) -> Optional[Dict]:
        if not raw_chunk: return None

        try:
            data = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "network": {
                    "source_ip": "0.0.0.0", "source_port": 0,
                    "dest_ip": "0.0.0.0", "dest_port": 0
                },
                "http": {
                    "host_name": "unknown",
                    "url_domain": "unknown",
                    "url_path": "",
                    "full_uri": "",
                    "method": "UNKNOWN",
                    "user_agent": "",
                    "post_data": ""
                },
                "modsec": {
                    "attack_tags": [], "severity": "INFO", 
                    "rule_id": "UNKNOWN", "message": ""
                },
                "event_type": "TRAFFIC"
            }

            lines = raw_chunk.splitlines()
            section = None
            body_buffer = []

            for line in lines:
                header = self.SECTION_HEADER.match(line)
                if header:
                    if section == 'C' and body_buffer:
                        data['http']['post_data'] = "\n".join(body_buffer).strip()
                        body_buffer = [] 

                    section = header.group(2)
                    continue

                if section == 'A':
                    parts = line.split()
                    if len(parts) >= 7:
                        data['network']['source_ip'] = parts[3]
                        data['network']['source_port'] = int(parts[4])
                        data['network']['dest_ip'] = parts[5]
                        data['network']['dest_port'] = int(parts[6])
                    elif len(parts) >= 4:
                        data['network']['source_ip'] = parts[3]

                elif section == 'B':
                    if line.lower().startswith('host: '):
                        host_val = line[6:].strip()
                        data['http']['host_name'] = host_val
                        data['http']['url_domain'] = host_val
                    elif line.lower().startswith('user-agent: '):
                        data['http']['user_agent'] = line[12:].strip()
                    elif len(line.split()) >= 3 and line[0] != ' ' and ':' not in line.split()[0]:
                        req_parts = line.split()
                        data['http']['method'] = req_parts[0]
                        data['http']['full_uri'] = req_parts[1]
                        data['http']['url_path'] = req_parts[1].split('?')[0]

                elif section == 'C':
                    body_buffer.append(line)

                elif section in ['H', 'K']:
                    # --- UPDATED LOGIC STARTS HERE ---
                    
                    # 1. Always extract tags from ANY line in this section
                    tags = re.findall(r'\[tag "([^"]+)"\]', line)
                    if tags:
                        data['modsec']['attack_tags'].extend(tags)
                        data['event_type'] = "ATTACK" # Tags found = Attack

                    # 2. Extract IDs and Severity from ANY line
                    rid = re.search(r'\[id "([^"]+)"\]', line)
                    if rid: 
                        data['modsec']['rule_id'] = rid.group(1)
                        # Only set event_type to ATTACK if valid rule (not generic 0)
                        if rid.group(1) != "0": data['event_type'] = "ATTACK"

                    sev = re.search(r'\[severity "([^"]+)"\]', line)
                    if sev: data['modsec']['severity'] = sev.group(1)

                    # 3. Smart Message Extraction
                    # We look for "Message:" OR "ModSecurity: Warning" (common in Apache-Error)
                    found_msg = None
                    if "Message: " in line:
                        found_msg = line.split("Message: ")[1].split(" [")[0].strip()
                    elif "ModSecurity: Warning." in line:
                        found_msg = line.split("ModSecurity: ")[1].split(" [")[0].strip()

                    if found_msg:
                        current_msg = data['modsec']['message']
                        
                        # Logic: Prioritize specific messages over generic "Anomaly Score" messages.
                        # If we have no message yet, take this one.
                        if not current_msg:
                            data['modsec']['message'] = found_msg
                        # If the current message IS generic, and new one IS NOT generic, overwrite.
                        elif "Anomaly Score" in current_msg and "Anomaly Score" not in found_msg:
                            data['modsec']['message'] = found_msg
                        # If both are specific (not anomaly), combine them.
                        elif "Anomaly Score" not in current_msg and "Anomaly Score" not in found_msg:
                             # Avoid duplicate concatenation
                             if found_msg not in current_msg:
                                 data['modsec']['message'] += " | " + found_msg
                        
                        # Ensure event is flagged
                        data['event_type'] = "ATTACK"

            if section == 'C' and body_buffer:
                 data['http']['post_data'] = "\n".join(body_buffer).strip()

            return {
                "timestamp": data['timestamp'],
                "event_type": data['event_type'],
                "network": data['network'],
                "http": data['http'],
                "modsec_data": data['modsec'],
                "mitre_mapping": None,
                "metadata": {"log_source": source_file}
            }
        except Exception as e:
            logger.error(f"Parse Error: {e}")
            return None

# --- File Monitoring (Tailing) ---
class LogTailer(threading.Thread):
    def __init__(self, config: Config, out_queue: queue.Queue):
        super().__init__()
        self.config = config
        self.queue = out_queue
        self.running = True

    def run(self):
        logger.info(f"Watching log file: {self.config.log_file}")
        while not os.path.exists(self.config.log_file) and self.running:
            time.sleep(2)

        f = open(self.config.log_file, 'r', errors='replace')
        f.seek(0, 2)
        
        buffer = []
        tx_id = None
        
        while self.running:
            line = f.readline()
            if not line:
                try:
                    if os.stat(self.config.log_file).st_ino != os.fstat(f.fileno()).st_ino:
                        f.close()
                        f = open(self.config.log_file, 'r', errors='replace')
                        continue
                except: pass
                time.sleep(self.config.poll_interval)
                continue

            start_match = re.match(r'^--([a-zA-Z0-9]+)-A--$', line.strip())
            if start_match:
                buffer = [line]
                tx_id = start_match.group(1)
            elif tx_id:
                buffer.append(line)
                if line.strip() == f"--{tx_id}-Z--":
                    self.queue.put("".join(buffer))
                    buffer = []
                    tx_id = None
        f.close()

# --- SIEM Sender ---
class SiemSender(threading.Thread):
    def __init__(self, config: Config, in_queue: queue.Queue):
        super().__init__()
        self.config = config
        self.queue = in_queue
        self.mapper = HeuristicMapper(config.mitre_db_path)
        self.parser = LogParser()
        self.running = True

    def send_payload(self, data: str):
        payload = (data + "\n").encode('utf-8')
        try:
            if self.config.protocol == 'u':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(payload, (self.config.server, self.config.port))
                sock.close()
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.config.server, self.config.port))
                    s.sendall(payload)
        except Exception as e:
            logger.error(f"Network Send Error: {e}")

    def run(self):
        batch = []
        while self.running:
            try:
                raw_log = self.queue.get(timeout=1)
                
                doc = self.parser.parse(raw_log, self.config.log_file)
                if not doc: continue

                if doc['event_type'] == "ATTACK":
                    m_data = doc['modsec_data']
                    doc['mitre_mapping'] = self.mapper.map_event(
                        m_data['attack_tags'], 
                        m_data['message'], 
                        m_data['rule_id']
                    )
                else:
                    doc['mitre_mapping'] = None 

                json_output = json.dumps(doc)
                
                if self.config.batch_size > 1:
                    batch.append(json_output)
                    if len(batch) >= self.config.batch_size:
                        for item in batch: self.send_payload(item)
                        batch = []
                else:
                    self.send_payload(json_output)

            except queue.Empty:
                if batch:
                    for item in batch: self.send_payload(item)
                    batch = []
                continue
            except Exception as e:
                logger.error(f"Processing Exception: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--protocol", default="u", choices=['u', 't'])
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--batch-size", type=int, default=1)
    args = parser.parse_args()
    
    config = Config(args)
    log_queue = queue.Queue(maxsize=5000)
    
    tailer = LogTailer(config, log_queue)
    sender = SiemSender(config, log_queue)
    
    tailer.start()
    sender.start()
    
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        tailer.running = False
        sender.running = False
        tailer.join()
        sender.join()

if __name__ == "__main__":
    main()
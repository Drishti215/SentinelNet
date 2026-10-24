#!/usr/bin/env python3
"""
SentinelNet Pipeline Feeder:
Streams parsed packet events into SQLite (data/sentinel_stress.db)
to drive real-time telemetry on the dashboard.
"""

import os
import random
import sqlite3
import time

DB_PATH = "data/sentinel_stress.db"

def init_db_seeds(conn):
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO network_interfaces (iface_id, mac_address) VALUES ('eth0', '02:42:AC:11:00:02');")
    cur.execute("INSERT OR IGNORE INTO ref_protocols (protocol_id, protocol_name, transport_type) VALUES (6, 'TCP', 'TCP'), (17, 'UDP', 'UDP'), (1, 'ICMP', 'ICMP');")
    conn.commit()

def generate_live_burst(conn, count=50):
    cur = conn.cursor()
    protocols = [6, 17, 1]
    
    ips = [f"192.168.1.{i}" for i in range(10, 30)]
    for ip in ips:
        cur.execute("INSERT OR IGNORE INTO host_registry (ip_address, asn_number, country_code) VALUES (?, ?, ?);",
                    (ip, 15169, "IN"))
    conn.commit()

    print(f"[*] Ingesting {count} packet frames into SQLite pipeline...")
    for _ in range(count):
        src = random.choice(ips)
        dst = "192.168.1.1"
        proto = random.choice(protocols)
        payload_sz = random.randint(64, 1500)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 8080])

        cur.execute("""
            INSERT INTO packet_stream (iface_id, src_ip, dst_ip, src_port, dst_port, protocol_id, payload_size)
            VALUES ('eth0', ?, ?, ?, ?, ?, ?);
        """, (src, dst, src_port, dst_port, proto, payload_sz))
        
        # Trigger an incident ~15% of the time
        if random.random() < 0.15:
            pkt_id = cur.lastrowid
            sig = random.choice(['SIG-1001', 'SIG-1002', 'SIG-1003'])
            action = 'DROP' if sig != 'SIG-1002' else 'BLOCK_IP'
            cur.execute("""
                INSERT INTO threat_incidents (packet_id, signature_id, action_taken)
                VALUES (?, ?, ?);
            """, (pkt_id, sig, action))

    conn.commit()
    print("[+] Ingestion batch committed successfully.")

def main():
    if not os.path.exists("data"):
        os.makedirs("data")

    conn = sqlite3.connect(DB_PATH)
    init_db_seeds(conn)
    generate_live_burst(conn, count=60)
    
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM packet_stream;")
    total_pkts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM threat_incidents;")
    total_threats = cur.fetchone()[0]
    print(f"[STATUS] Database Pipeline Active: {total_pkts} Total Packets | {total_threats} Threats Detected")
    conn.close()

if __name__ == "__main__":
    main()

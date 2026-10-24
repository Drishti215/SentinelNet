-- TRIGGER 1: Automated Quarantine on High-Frequency Malicious Activity
CREATE TRIGGER IF NOT EXISTS trg_detect_frequency_threshold
AFTER INSERT ON threat_incidents
BEGIN
    INSERT INTO threat_frequency_ledger (ip_address, cumulative_hits, last_hit_timestamp)
    VALUES (
        (SELECT src_ip FROM packet_stream WHERE packet_id = NEW.packet_id),
        1,
        CURRENT_TIMESTAMP
    )
    ON CONFLICT(ip_address) DO UPDATE SET
        cumulative_hits = cumulative_hits + 1,
        last_hit_timestamp = CURRENT_TIMESTAMP;

    -- Automatically escalate to blacklist if more than 3 attacks recorded
    INSERT OR IGNORE INTO security_blacklist (ip_address)
    SELECT src_ip
    FROM packet_stream
    WHERE packet_id = NEW.packet_id
      AND (SELECT cumulative_hits FROM threat_frequency_ledger WHERE ip_address = packet_stream.src_ip) >= 3;
END;

-- TRIGGER 2: Prevent Blacklisted Hosts from Generating New Valid Logs
CREATE TRIGGER IF NOT EXISTS trg_block_quarantined_packets
BEFORE INSERT ON packet_stream
WHEN EXISTS (
    SELECT 1 FROM security_blacklist
    WHERE ip_address = NEW.src_ip
)
BEGIN
    SELECT RAISE(ABORT, 'REJECTED: Source IP address is currently quarantined in security_blacklist.');
END;

-- TRIGGER 3: Audit Resource Allocation Grants & Revocations
CREATE TRIGGER IF NOT EXISTS trg_audit_lock_preemption
AFTER UPDATE OF action_taken ON threat_incidents
WHEN NEW.action_taken = 'PREEMPT_RESOURCES'
BEGIN
    INSERT INTO resource_lock_events (process_tag, resource_type, requested_units, decision)
    VALUES (
        'ThreatIncident-' || NEW.incident_id,
        'DB_ROW_EXCLUSIVE_LOCK',
        1,
        'PREEMPTED'
    );
END;

-- SAMPLE SEED DATA & VERIFICATION QUERIES
INSERT OR IGNORE INTO security_blacklist (ip_address)
VALUES ('198.51.100.44');

INSERT INTO resource_lock_events (process_tag, resource_type, requested_units, decision)
VALUES
('Worker-P1', 'IPC_PIPE_HANDLE', 2, 'GRANTED'),
('Worker-P4', 'BUFFER_POOL_SECTOR', 3, 'BLOCKED');

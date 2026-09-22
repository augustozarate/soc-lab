PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    ip TEXT,
    severity TEXT,
    status TEXT,
    risk_score INTEGER,
    campaign_id TEXT,
    created_at TEXT,
    updated_at TEXT,
    last_seen TEXT,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    stage TEXT,
    risk INTEGER,
    created_at TEXT,
    updated_at TEXT,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    status TEXT,
    assignee TEXT,
    severity TEXT,
    ip TEXT,
    created_at TEXT,
    data_json TEXT NOT NULL,

    FOREIGN KEY (incident_id)
        REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processed_alerts (
    dedup_key TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    ip TEXT,
    source_record_id INTEGER,
    source_event_id INTEGER,
    status TEXT NOT NULL,
    owner_task_id TEXT,
    claimed_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_ip
ON incidents(ip);

CREATE INDEX IF NOT EXISTS idx_incidents_severity
ON incidents(severity);

CREATE INDEX IF NOT EXISTS idx_incidents_risk
ON incidents(risk_score);

CREATE INDEX IF NOT EXISTS idx_incidents_campaign
ON incidents(campaign_id);

CREATE INDEX IF NOT EXISTS idx_cases_incident
ON cases(incident_id);

CREATE INDEX IF NOT EXISTS idx_events_type
ON events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_created
ON events(created_at);

CREATE INDEX IF NOT EXISTS idx_processed_alerts_status
ON processed_alerts(status);

CREATE TABLE IF NOT EXISTS response_blocks (
    target TEXT PRIMARY KEY,

    desired_state TEXT NOT NULL
        CHECK (
            desired_state IN (
                'BLOCKED',
                'UNBLOCKED'
            )
        ),

    status TEXT NOT NULL
        CHECK (
            status IN (
                'ACTIVE',
                'EXPIRED',
                'RELEASED',
                'FAILED'
            )
        ),

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,

    execution_mode TEXT,
    backend TEXT,
    rule_name TEXT,

    source_incident_id TEXT,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_blocks_status
ON response_blocks(status);

CREATE INDEX IF NOT EXISTS idx_response_blocks_expires
ON response_blocks(expires_at);


-- ============================================
-- NOTIFICATION DELIVERY DEDUPLICATION
-- ============================================

CREATE TABLE IF NOT EXISTS notification_deliveries (
    dedup_key TEXT NOT NULL,
    channel TEXT NOT NULL,

    incident_id TEXT,
    severity TEXT,

    status TEXT NOT NULL
        CHECK (
            status IN (
                'PENDING',
                'SUCCESS',
                'FAILED',
                'SKIPPED',
                'RATE_LIMITED'
            )
        ),

    backend TEXT,

    attempt_count INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    last_attempt_at TEXT,
    delivered_at TEXT,
    last_error TEXT,
    provider_retry_at TEXT,

    PRIMARY KEY (
        dedup_key,
        channel
    )
);

CREATE INDEX IF NOT EXISTS
idx_notification_deliveries_status_updated
ON notification_deliveries(
    status,
    updated_at
);

CREATE INDEX IF NOT EXISTS
idx_notification_deliveries_incident
ON notification_deliveries(
    incident_id
);

CREATE INDEX IF NOT EXISTS
idx_notification_deliveries_channel_status
ON notification_deliveries(
    channel,
    status
);


-- ============================================
-- NOTIFICATION CHANNEL RATE LIMITS
-- ============================================

CREATE TABLE IF NOT EXISTS notification_rate_limits (
    channel TEXT PRIMARY KEY,

    window_start TEXT NOT NULL,
    delivery_count INTEGER NOT NULL DEFAULT 0,

    updated_at TEXT NOT NULL
);

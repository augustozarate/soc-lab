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
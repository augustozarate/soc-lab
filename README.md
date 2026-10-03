# SOC Lab

A modular Security Operations Center (SOC) laboratory written primarily
in Python for experimenting with security-event ingestion, detection,
enrichment, correlation, incident handling, response workflows and
runtime observability.

> **Project status:** active development.
>
> This repository is intended for laboratory, educational and defensive
> security experimentation. It is not presented as a production-ready
> SOC platform.

## Architecture

SOC Lab uses a modular event-processing architecture for defensive
security experimentation, SOC workflow validation and incident-response
simulation.

At a high level:

    Windows Events ──► Windows Collector ──┐
                                          │
    Linux OpenSSH ─► systemd-journald      │
                         │                 │
                         ▼                 │
                  Linux SSH Collector ─────┘
                         │
                         ▼
                  logs/stream.jsonl
                         │
                         ▼
                     EventReader
              durable byte checkpoint
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
         Rule Engine          Behavior / UEBA
              └──────────┬──────────┘
                         ▼
                       Alerts
                         │
                         ▼
                  MITRE ATT&CK
                         │
                         ▼
                     Incidents
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
     Threat Intel   Correlation   Risk Analysis
           └─────────────┼─────────────┘
                         ▼
                      Campaigns
                         │
                         ▼
                Response / Simulation
                         │
                         ▼
                     Persistence
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
     Persistent Monitor          SOC CLI
                                      │
                                      ▼
                             JSON / Markdown / PDF

The runtime uses specialized pipelines for:

- incident processing
- threat-intelligence enrichment
- correlation
- risk analysis
- AI-assisted analysis
- threat hunting
- response
- persistence

The repository also contains components for:

- detection rules
- MITRE ATT&CK mapping
- event scheduling
- worker execution
- durable event checkpoints
- alert idempotency
- dead-letter handling
- retry policies
- incident and case management
- campaign tracking
- threat graphs
- runtime metrics
- health assessment
- persistent SOC monitoring
- bounded read-only query models
- executive, technical and advanced SOC reporting
- JSON, Markdown and native PDF report export

### Linux SSH ingestion

Linux failed-authentication events can be collected directly from the
OpenSSH systemd journal.

The Linux SSH collector:

- reads systemd-journald using journal cursors
- establishes a first-run baseline without replaying historical events
- persists its cursor atomically
- normalizes supported OpenSSH failed-login records
- generates deterministic event record IDs
- avoids duplicate stream events when a journal entry is replayed
- advances the cursor for processed journal records
- supports both IPv4 and IPv6 source addresses

The collector writes normalized events to:

    logs/stream.jsonl

Its runtime checkpoint is stored in:

    data/linux_ssh_collector_checkpoint.json

Run one collection cycle:

    python collectors/linux_ssh_collector.py --once

Run continuously:

    python collectors/linux_ssh_collector.py --interval 2

### Detection and behavioral analysis

Events can be evaluated by both rule-based detection and behavioral
analysis.

Structured failed-login events use:

    type   = login_failed
    action = login_failed

The current laboratory UEBA brute-force configuration detects five
failed login events from the same source within a 60-second window and
produces a HIGH-severity UEBA_BRUTE_FORCE alert.

Detected brute-force activity can be mapped to:

    MITRE ATT&CK
    Tactic: Credential Access
    Technique: T1110 - Brute Force

### Persistent Monitor

The Persistent Monitor provides a read-only live operational view of SOC
state, including:

- runtime health
- uptime
- queue depth
- event-reader checkpoint lag
- event count
- generated alert count
- task activity
- incident count
- high/critical incident count
- campaign count
- maximum risk
- recent incident feed
- notification-channel status

Monitor refresh is driven by committed runtime event batches rather than
a separate polling thread.

### Automated response

The response engine currently implements:

    BLOCK_IP
    UNBLOCK_IP
    NOTIFY_SOC
    ENABLE_MFA

Response behavior can run in simulation mode for laboratory validation.

Playbooks can reference additional actions such as ISOLATE_HOST and
COLLECT_FORENSICS; those declarations should not be treated as active
response-engine capabilities unless matching implementations are added
and validated.

### Interactive SOC console

Common investigation commands include:

    monitor
    health
    channels
    metrics

    incidents list
    incidents recent
    incidents recent --severity HIGH
    incidents show <incident_id>

    campaign list
    campaign show <campaign_id>
    campaign graph <campaign_id>

    story show <incident_id>
    graph <incident_id>

    ai ask <incident_id> <question>

    report render technical
    report export technical soc-report --format pdf

The CLI also supports composable data operations such as:

    incidents list | util where severity=HIGH
    incidents list | util fields id ip severity risk_score
    incidents list | util sort risk_score | util head 3

For the complete command, pipeline, shortcut and reporting reference,
see docs/CLI_REFERENCE.md.

### Validated Linux SSH flow

A real isolated-lab acceptance scenario has been validated end to end:

    Parrot VM
       │
       │ failed SSH authentication
       ▼
    Ubuntu OpenSSH
       │
       ▼
    systemd-journald
       │
       ▼
    Linux SSH Collector
       │
       ▼
    logs/stream.jsonl
       │
       ▼
    EventReader
       │
       ▼
    Behavior Engine
       │
       │ 5 failures within 60 seconds
       ▼
    UEBA_BRUTE_FORCE
       │
       ▼
    MITRE ATT&CK T1110
       │
       ▼
    HIGH Incident
       │
       ▼
    Campaign Correlation
       │
       ▼
    Simulated Response
       │
       ▼
    SQLite Persistence
       │
       ▼
    Persistent Monitor / CLI / Reporting

The acceptance run completed with the event-reader checkpoint at the end
of the stream and zero checkpoint lag.

## Requirements

The current development baseline is validated on CPython 3.12, 3.13 and 3.14. The latest manual Linux x86_64 validation used:

- Python 3.12.14
- Python 3.13.15
- Python 3.14.7
- PyYAML 6.0.1
- requests 2.31.0
- rich 13.7.1
- python-dotenv 1.x
- reportlab 4.5.1

### Native system dependency

The Threema integration uses `threema.gateway`, which depends on
`libnacl` and therefore requires the native libsodium shared library.

On Debian/Ubuntu systems, install it before creating the Python
environment:

```bash
sudo apt update
sudo apt install libsodium23
```

This dependency is outside Python package metadata, so `pip check`
cannot detect a missing libsodium shared library.

Install the declared runtime dependencies using the tested constraint set:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt -c constraints.txt
```

For a development/test environment, install the development requirements with their matching constraint set:

```bash
python3 -m pip install -r requirements-dev.txt -c constraints-dev.txt
```

The clean-environment contract has been tested using newly created
CPython 3.12, 3.13 and 3.14 virtual environments on Linux x86_64.

Dependency ownership is intentionally split between intent and resolution:

- `requirements.txt` and `requirements-dev.txt` are the human-maintained dependency intent.
- `constraints.txt` and `constraints-dev.txt` capture the exact dependency resolution validated for reproducible installs.
- the constraint files are currently validated for CPython 3.12-3.14 on Linux/WSL2 x86_64 and should not be treated as a universal cross-platform lock.

When direct dependencies are added, removed, or upgraded, regenerate the matching constraint set from a clean environment, verify that the exact resolved versions still satisfy the declared requirements, run `pip check`, and execute the full test suite with warnings treated as errors before committing the refreshed constraints.

## Configuration

Copy the environment template:

```bash
cp .env.example .env
```

The following variables are supported:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ABUSE_KEY` | empty | Optional AbuseIPDB API key |
| `VT_KEY` | empty | Optional VirusTotal API key |
| `THREAT_INTEL_PREFLIGHT_ENABLED` | `true` | Enables external-connectivity preflight |
| `THREAT_INTEL_PREFLIGHT_HOST` | `1.1.1.1` | TCP host used by the connectivity preflight |
| `THREAT_INTEL_PREFLIGHT_PORT` | `443` | TCP port used by the connectivity preflight |
| `THREAT_INTEL_PREFLIGHT_TIMEOUT` | `0.10` | Preflight timeout in seconds |

API credentials must be stored locally and must not be committed to the
repository.

The `.gitignore` configuration excludes `.env` and local environment
variants while explicitly allowing `.env.example`.

### Automated Response

Automated response behavior is configured through the environment template:

- `RESPONSE_MODE` selects response behavior. Keep `simulate` enabled until the enforcement backend has been validated for the target environment.
- `RESPONSE_PROTECTED_IPS` is a comma-separated allowlist of IPv4 targets that automated `BLOCK_IP` actions must never enforce against.
- `RESPONSE_BLOCK_TTL_SECONDS` controls the lifetime, in seconds, of temporary automated IP blocks and must be greater than zero.

The values in `.env.example` are laboratory defaults and examples; review them before enabling enforcement in another environment.

## Threat Intelligence

Threat-intelligence enrichment supports:

- local threat-intelligence memory
- AbuseIPDB
- VirusTotal
- heuristic fallback

External enrichment is designed to degrade gracefully when network
connectivity is unavailable.

The current implementation includes:

- a fast TCP connectivity preflight
- a connectivity circuit breaker
- a single in-flight external probe
- bounded offline failure behavior
- local/heuristic fallback
- configurable preflight endpoint and timeout

HTTP provider responses such as rate limiting or server-side failures
are kept separate from network-connectivity failures so they do not
incorrectly open the connectivity circuit.

## Offline Operation

The runtime can continue processing when external threat-intelligence
providers are unreachable.

When connectivity preflight fails, external lookups are skipped and
enrichment falls back to local or heuristic sources.

Concurrent offline testing has verified that only one worker performs
the connectivity probe while other workers avoid waiting for duplicate
external probes.

This behavior is particularly useful for isolated SOC laboratory
networks.

## Running the SOC Engine

From Linux or WSL:

```bash
./scripts/run_engine.sh
```

The script starts:

```bash
python3 -m engine.orchestration.soc_engine
```

A PowerShell launcher is also available:

```powershell
./scripts/start_soc.ps1
```

It launches the SOC engine through WSL and starts the PowerShell SOC
monitor.

## Runtime Data

Runtime state and telemetry are generated locally.

Examples include:

```text
data/soc.db
data/event_reader_checkpoint.json
data/ai_memory.json
data/threat_intel.json

logs/stream.jsonl
logs/alerts.json
logs/runtime_metrics.json
logs/monitor_snapshot.json
logs/events.log
```

These runtime artifacts are excluded from version control by the
repository ignore policy.

## Runtime Observability

The runtime exposes internal counters, gauges and latency observations.

Current metrics include information such as:

- events read
- alerts generated
- completed tasks
- queue depth
- checkpoint position
- stream size
- checkpoint lag
- per-pipeline latency
- total task latency

Runtime metrics are written to:

```text
logs/runtime_metrics.json
```

## Repository Structure

```text
collectors/     Event collection components
detections/     Detection rules
engine/         Core SOC engine
mitre/          MITRE ATT&CK mappings
modules/        Supporting PowerShell modules
monitor/        SOC monitoring interface
scripts/        Runtime and startup scripts
tests/          Automated regression and behavior tests
```

The `engine/` package contains the core application architecture,
including bootstrap, CLI, correlation, orchestration, services,
storage and telemetry components.

### Read-only query boundaries

Interactive monitoring and query commands are separated from mutable
runtime internals through presentation-layer read models.

Current bounded query paths include:

- recent incident queries
- monitor incident projections
- campaign list/detail queries
- reporting snapshots

Campaign CLI commands such as `campaign list`, `campaign show` and
`campaign graph` read persisted campaign state through
`CampaignQueryReadModel` rather than directly accessing the mutable
`CampaignTracker` dictionaries.

The same read boundary is used when campaign context is required by
incident graph, AI and story CLI paths.

### Reporting

The reporting layer supports three profiles:

- executive
- technical
- advanced

Reports can be rendered as JSON or Markdown and exported as JSON,
Markdown or PDF.

Report projections use explicit allowlists so raw events, payloads,
credentials and provider-specific internal fields are not serialized
directly. Advanced threat-intelligence and hunting data are sourced
from persisted incident state rather than executing live hunting
during report generation.

PDF generation is native, deterministic and export-only at the CLI
boundary.

## Security and Repository Hygiene

The repository is configured to exclude local secrets and generated
runtime state, including:

- `.env` files
- virtual environments
- Python caches
- SQLite runtime databases
- SOC runtime JSON/JSONL files
- runtime logs
- checkpoints
- archived telemetry
- temporary files

Before committing changes, inspect the repository state:

```bash
git status --short
git diff --check
```

Never commit API keys, credentials or runtime data.

## Current Limitations

This project is under active development.

At the current stage:

- automated pytest-based regression coverage is available and is used
  as a merge gate for validated feature work
- external threat-intelligence providers require user-supplied API keys
- external enrichment depends on network availability
- the current reproducibility baseline has been validated with
  CPython 3.12, 3.13 and 3.14 on Linux x86_64
- the project should be treated as a laboratory implementation rather
  than a production SOC deployment

## Development

The project currently uses short-lived feature and fix branches that
are integrated into `main` after validation.

Recent development work has focused on:

- portable runtime paths
- duplicate-event prevention
- non-blocking SOC worker execution
- durable event checkpoints
- alert idempotency
- runtime observability
- offline-resilient threat intelligence
- repository hygiene
- reproducible environment setup
- read-only operator and monitor query boundaries
- bounded incident and campaign read models
- SOC reporting with safe projections and deterministic PDF export

## Responsible Use

Use this project only in systems and environments where you have
authorization to perform security testing, monitoring or simulation.

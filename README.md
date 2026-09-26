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

The runtime is assembled through the application factory and dependency
container.

At a high level, events move through a worker-based processing
architecture containing specialized pipelines for:

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
- SOC monitoring
- bounded read-only query models
- executive, technical and advanced SOC reporting
- JSON, Markdown and native PDF report export

## Requirements

The current development baseline has been validated with:

- Python 3.12.3
- PyYAML 6.0.1
- requests 2.31.0
- rich 13.7.1
- python-dotenv 1.x
- reportlab 4.5.1

Install the declared Python dependencies with:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

The clean-environment contract has been tested using a newly created
Python 3.12.3 virtual environment.

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
  Python 3.12.3
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

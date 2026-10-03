# SOC Lab CLI Reference

This document describes the currently implemented interactive SOC
console, reporting commands, data pipelines, Linux SSH collector
entrypoint and automated response actions.

## Core commands

    help
    help advanced
    operator
    monitor
    health
    channels
    metrics

## Read-only shortcuts

    m -> monitor
    h -> health
    c -> channels
    r -> incidents recent
    1 -> incidents recent --severity CRITICAL
    2 -> incidents recent --severity HIGH

## Incident commands

    incidents
    incidents list
    incidents show <incident_id>
    incidents recent
    incidents recent --limit <n>
    incidents recent --severity <level>
    incidents search field=value

Multiple exact-match filters are supported:

    incidents search severity=HIGH status=NEW

## Campaign commands

    campaign
    campaign list
    campaign show <campaign_id>
    campaign graph <campaign_id>

The plural campaign route also exists internally, but campaign is the
documented user-facing form.

## Story and graph

    story show <incident_id>
    graph <incident_id>
    graph incident <incident_id>
    graph campaign <campaign_id>

## AI-assisted investigation

    ai ask <incident_id> <question>

Example:

    ai ask f45ebcb0 What activity caused this incident?

## Data pipelines

Pipeline stages are separated with:

    |

Examples:

    incidents list | util count
    incidents list | util fields id ip severity risk_score
    incidents list | util sort risk_score
    incidents list | util head 3
    incidents list | util tail 5
    incidents list | util uniq ip
    incidents list | util where severity=HIGH
    incidents list | util where risk_score>80
    incidents list | util where risk_score<50
    incidents list | util json
    incidents list | util table
    incidents list | util pivot ip
    incidents list | util enrich
    incidents list | group severity

## Reporting

Profiles:

    executive
    technical
    advanced

Formats:

    markdown
    json
    pdf

Markdown is the default:

    report render technical

JSON:

    report render technical --format json

PDF is export-only:

    report export technical soc-report --format pdf

Other examples:

    report export technical soc-report
    report export technical soc-report --format json
    report export technical soc-report.pdf --format pdf

Optional report flags:

    --period <label>
    --incidents <n>
    --campaigns <n>
    --cases <n>

The exporter avoids duplicate matching suffixes such as:

    .md.md
    .json.json
    .pdf.pdf

Different existing suffixes remain part of the basename.

## Case queries

Implemented read-only case access:

    case
    case list

The parser also recognizes:

    case create
    case assign

but both currently fall back to the case-list implementation. They must
not be treated as implemented create/assign operations in this release.

## Linux SSH collector

Help:

    python collectors/linux_ssh_collector.py --help

One cycle:

    python collectors/linux_ssh_collector.py --once

Continuous collection:

    python collectors/linux_ssh_collector.py

Custom interval:

    python collectors/linux_ssh_collector.py --interval 1

The collector reads supported OpenSSH failed-authentication records from
systemd-journald and appends normalized events to the SOC stream.

## Automated response actions

These are response-engine actions, not direct interactive console
commands.

Implemented:

    BLOCK_IP
    UNBLOCK_IP
    NOTIFY_SOC
    ENABLE_MFA

Credential Access playbook:

    BLOCK_IP
    NOTIFY_SOC
    ENABLE_MFA

The Execution playbook also declares:

    ISOLATE_HOST
    COLLECT_FORENSICS
    NOTIFY_SOC

ISOLATE_HOST and COLLECT_FORENSICS are playbook declarations and should
not be presented as validated ResponseEngine capabilities unless
matching implementations/backends are added.

## Example investigation workflow

    health
    incidents recent --severity HIGH
    incidents show <incident_id>
    story show <incident_id>
    graph <incident_id>
    campaign list
    campaign show <campaign_id>
    campaign graph <campaign_id>
    report render technical
    report export technical soc-report --format pdf

## Read-only design

Investigation and monitoring commands use bounded presentation/query
models where available instead of directly reading mutable runtime
dictionaries.

## Responsible use

SOC Lab is intended for defensive, educational and authorized security
testing environments.

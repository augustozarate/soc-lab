#!/usr/bin/env python3

import argparse
import sys
import time
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from engine.infrastructure.linux_ssh_collector import (
    JournalCursorCheckpoint,
    JournalSource,
    LinuxSSHCollector,
)


DEFAULT_INTERVAL = 2.0


def build_collector(
    project_root=None,
):

    if project_root is None:

        project_root = (
            Path(__file__)
            .resolve()
            .parents[1]
        )

    else:

        project_root = Path(
            project_root
        )

    stream_path = (
        project_root
        / "logs"
        / "stream.jsonl"
    )

    checkpoint_path = (
        project_root
        / "data"
        / "linux_ssh_collector_checkpoint.json"
    )

    source = JournalSource(
        unit="ssh"
    )

    checkpoint = JournalCursorCheckpoint(
        checkpoint_path
    )

    return LinuxSSHCollector(
        source=source,
        checkpoint=checkpoint,
        stream_path=stream_path,
    )


def run_collector(
    collector,
    *,
    once=False,
    interval=DEFAULT_INTERVAL,
    sleep=time.sleep,
):

    if interval < 0:
        raise ValueError(
            "interval must be non-negative"
        )

    if once:

        return collector.run_once()

    while True:

        collector.run_once()

        sleep(
            interval
        )


def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            "Collect Linux SSH authentication "
            "failures from journald and append "
            "normalized SOC events."
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "Run one collection cycle and exit."
        ),
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=(
            "Polling interval in seconds "
            f"(default: {DEFAULT_INTERVAL})."
        ),
    )

    return parser


def main():

    parser = build_parser()

    args = parser.parse_args()

    collector = build_collector()

    try:

        emitted = run_collector(
            collector,
            once=args.once,
            interval=args.interval,
        )

    except KeyboardInterrupt:

        return 0

    except Exception as exc:

        print(
            "[LINUX-SSH-COLLECTOR] "
            f"ERROR: {exc}"
        )

        return 1

    if args.once:

        print(
            "[LINUX-SSH-COLLECTOR] "
            f"emitted={emitted}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )

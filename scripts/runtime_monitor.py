import argparse
import os
import sys
import time


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(
        0,
        BASE_DIR
    )


from engine.telemetry.runtime_health_assessor import (
    RuntimeHealthAssessor
)
from engine.telemetry.runtime_health_view import (
    RuntimeHealthView
)
from engine.telemetry.runtime_metrics_reader import (
    RuntimeMetricsReader
)


def clear_screen():

    os.system(
        "cls"
        if os.name == "nt"
        else "clear"
    )


def render(
    view,
    health
):

    print(
        "=== SOC RUNTIME HEALTH ==="
    )

    print()

    print(
        "Status:",
        health["status"]
    )

    age = health[
        "snapshot_age_seconds"
    ]

    print(
        "Snapshot age:",
        (
            f"{age:.1f} s"
            if age is not None
            else "N/A"
        )
    )

    reasons = health.get(
        "reasons",
        []
    )

    if reasons:

        print(
            "Reason:",
            "; ".join(reasons)
        )

    print()

    print(
        "Generated:",
        view["generated_at"]
        or "N/A"
    )

    print(
        "Uptime:",
        view["uptime"]
    )

    print()

    print(
        "Queue depth:",
        view["queue_depth"]
    )

    print(
        "Checkpoint lag:",
        view["checkpoint_lag"]
    )

    print()

    print(
        "Events read:",
        view["events_read"]
    )

    print(
        "Alerts generated:",
        view["alerts_generated"]
    )

    print(
        "Tasks completed:",
        view["tasks_completed"]
    )

    print(
        "Task attempt failures:",
        view["task_attempt_failures"]
    )

    print(
        "Tasks deduplicated:",
        view["tasks_deduplicated"]
    )

    print()

    print(
        "Average task latency:",
        view["avg_task_latency"]
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "SOC runtime health monitor"
        )
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help=(
            "Refresh interval in seconds"
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "Render one snapshot and exit"
        )
    )

    args = parser.parse_args()

    metrics_path = os.path.join(
        BASE_DIR,
        "logs",
        "runtime_metrics.json"
    )

    reader = RuntimeMetricsReader(
        metrics_path
    )

    while True:

        snapshot = reader.read()

        view = RuntimeHealthView(
            snapshot
        ).build()

        health = RuntimeHealthAssessor(
            snapshot
        ).assess()

        clear_screen()

        render(
            view,
            health
        )

        if args.once:
            break

        try:

            time.sleep(
                max(
                    0.1,
                    args.interval
                )
            )

        except KeyboardInterrupt:

            print()
            print(
                "Runtime monitor stopped"
            )

            break


if __name__ == "__main__":
    main()

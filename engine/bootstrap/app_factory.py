import os

from engine.bootstrap.container import Container
from engine.orchestration.runtime.soc_runtime import SOCRuntime
from engine.cli.soc_cli import SOCConsole


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "logs"
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)


def create_app():

    container = Container(

        stream_file=os.path.join(
            BASE_DIR,
            "logs",
            "stream.jsonl"
        ),

        detection_path=os.path.join(
            BASE_DIR,
            "detections"
        ),

        mitre_file=os.path.join(
            BASE_DIR,
            "mitre",
            "attack_mapping.yml"
        ),

        dlq_file=os.path.join(
            OUTPUT_DIR,
            "dead_letter.jsonl"
        ),

        db_file=os.path.join(
            DATA_DIR,
            "soc.db"
        ),

        monitor_snapshot_file=os.path.join(
            OUTPUT_DIR,
            "monitor_snapshot.json"
        ),

        event_reader_checkpoint_file=os.path.join(
            DATA_DIR,
            "event_reader_checkpoint.json"
        ),

        event_cache=[]
    )

    cli = SOCConsole(
        container.incident_manager,
        container.case_manager,
        container.simulator,
        container.event_cache,
        container.threat_graph,
        container.campaign_tracker,
        container.ai_analyst
    )

    runtime = SOCRuntime(
        container=container,
        cli=cli,
        watcher=container.rule_watcher,
        scheduler=container.scheduler,
        worker_pool=container.worker_pool,
        logger=print
    )

    return runtime
import os

from engine.bootstrap.container import Container
from engine.orchestration.runtime.soc_runtime import SOCRuntime
from engine.cli.soc_cli import SOCConsole
from engine.presentation.persistent_monitor_session import (
    build_persistent_monitor_session,
)

from engine.presentation.report_application_service import (
    ReportApplicationService,
)
from engine.presentation.report_document import (
    ReportDocumentBuilder,
)
from engine.presentation.report_exporter import (
    ReportExporter,
)
from engine.presentation.report_read_model import (
    ReportReadModel,
)
from engine.presentation.report_renderer import (
    ReportRenderer,
)


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

REPORT_DIR = os.path.join(
    OUTPUT_DIR,
    "reports"
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

        runtime_metrics_file=os.path.join(
            OUTPUT_DIR,
            "runtime_metrics.json"
        ),

        event_reader_checkpoint_file=os.path.join(
            DATA_DIR,
            "event_reader_checkpoint.json"
        ),

        event_cache=[]
    )

    container.report_read_model = (
        ReportReadModel(
            incident_repository=(
                container.incident_repository
            ),
            campaign_repository=(
                container.campaign_repository
            ),
            case_manager=(
                container.case_manager
            ),
        )
    )

    container.report_document_builder = (
        ReportDocumentBuilder(
            read_model=(
                container.report_read_model
            )
        )
    )

    container.report_renderer = (
        ReportRenderer()
    )

    container.report_exporter = (
        ReportExporter(
            REPORT_DIR
        )
    )

    container.report_application_service = (
        ReportApplicationService(
            document_builder=(
                container.report_document_builder
            ),
            renderer=(
                container.report_renderer
            ),
            exporter=(
                container.report_exporter
            ),
        )
    )

    persistent_monitor_session = (
        build_persistent_monitor_session(
            container.monitor_console_controller
        )
    )

    cli = SOCConsole(
        threat_graph=container.threat_graph,
        ai_analyst=container.ai_analyst,
        operator_console_controller=(
            container.operator_console_controller
        ),
        monitor_console_controller=(
            container.monitor_console_controller
        ),
        report_application_service=(
            container.report_application_service
        ),
        campaign_console_controller=(
            container.campaign_console_controller
        ),
        persistent_monitor_session=(
            persistent_monitor_session
        ),
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

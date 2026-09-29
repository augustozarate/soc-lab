from engine.orchestration.event_bus import EventBus

from engine.orchestration.pipeline_orchestrator import (
    PipelineOrchestrator
)

from engine.telemetry.metrics import metrics
from engine.telemetry.audit_logger import audit


def build_core(container):

    container.event_bus = EventBus()

    container.orchestrator = (
        PipelineOrchestrator()
    )

    container.metrics = metrics
    container.audit = audit

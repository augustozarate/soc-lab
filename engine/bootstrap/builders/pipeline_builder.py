from engine.orchestration.pipelines.incident_pipeline import (
    IncidentPipeline
)

from engine.orchestration.pipelines.enrichment_pipeline import (
    EnrichmentPipeline
)

from engine.orchestration.pipelines.correlation_pipeline import (
    CorrelationPipeline
)

from engine.orchestration.pipelines.risk_pipeline import (
    RiskPipeline
)

from engine.orchestration.pipelines.ai_pipeline import (
    AIPipeline
)

from engine.orchestration.pipelines.hunting_pipeline import (
    HuntingPipeline
)

from engine.orchestration.pipelines.response_pipeline import (
    ResponsePipeline
)

from engine.orchestration.pipelines.persistence_pipeline import (
    PersistencePipeline
)


def build_pipelines(container):

    # =====================================
    # INCIDENT
    # =====================================

    container.incident_pipeline = IncidentPipeline(
        incident_manager=container.incident_manager,
        event_bus=container.event_bus
    )

    # =====================================
    # ENRICHMENT
    # =====================================

    container.enrichment_pipeline = EnrichmentPipeline(
        threat_intel=container.threat_intel,
        entity_resolver=container.entity_resolver,
        threat_memory=container.threat_memory
    )

    # =====================================
    # CORRELATION
    # =====================================

    container.correlation_pipeline = CorrelationPipeline(
        threat_graph=container.threat_graph,
        entity_resolver=container.entity_resolver,
        campaign_tracker=container.campaign_tracker,
        campaign_graph=container.campaign_graph,
        incident_manager=container.incident_manager
    )

    # =====================================
    # RISK
    # =====================================

    container.risk_pipeline = RiskPipeline(
        risk_engine=container.risk_engine,
        threat_memory=container.threat_memory,
        event_bus=container.event_bus
    )

    # =====================================
    # AI
    # =====================================

    container.ai_pipeline = AIPipeline(
        ai_analyst=container.ai_analyst,
        threat_graph=container.threat_graph
    )

    # =====================================
    # HUNTING
    # =====================================

    container.hunting_pipeline = HuntingPipeline(
        hunter=container.hunter,
        threat_graph=container.threat_graph,
        auditor=container.audit
    )

    # =====================================
    # RESPONSE
    # =====================================

    container.response_pipeline = ResponsePipeline(
        response_policy_engine=container.response_policy_engine,
        response_engine=container.response_engine,
        soar=container.soar,
        case_manager=container.case_manager,
        event_bus=container.event_bus
    )

    # =====================================
    # PERSISTENCE
    # =====================================

    container.persistence_pipeline = PersistencePipeline(
        incident_repository=container.incident_repository,
        campaign_repository=container.campaign_repository
    )

    # =====================================
    # REGISTER
    # =====================================

    pipelines = [
        container.incident_pipeline,
        container.enrichment_pipeline,
        container.correlation_pipeline,
        container.risk_pipeline,
        container.ai_pipeline,
        container.hunting_pipeline,
        container.response_pipeline,
        container.persistence_pipeline
    ]

    for pipeline in pipelines:
        container.orchestrator.register(
            pipeline
        )
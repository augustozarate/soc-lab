from engine.suppression_engine import (
    SuppressionEngine
)

from engine.services.incident_manager import (
    IncidentManager
)

from engine.services.soar_engine import (
    SOAREngine
)

from engine.services.threat_intel import (
    ThreatIntel
)

from engine.services.risk_engine import (
    RiskEngine
)

from engine.services.threat_memory import (
    ThreatMemory
)

from engine.services.case_manager import (
    CaseManager
)

from engine.services.response_engine import (
    ResponseEngine
)

from engine.services.campaign_tracker import (
    CampaignTracker
)

from engine.services.ai_analyst import (
    AIAnalyst
)

from engine.services.threat_hunter import (
    ThreatHunter
)

from engine.services.response_policy_engine import (
    ResponsePolicyEngine
)

from engine.behavior_engine import (
    BehaviorEngine
)

from engine.services.monitor_snapshot import (
    MonitorSnapshotBuilder
)

from engine.presentation.operator_read_model import (
    OperatorReadModel
)
from engine.presentation.operator_console import (
    OperatorConsoleRenderer
)
from engine.presentation.operator_console_controller import (
    OperatorConsoleController
)

def build_services(container):

    container.suppressor = (
        SuppressionEngine()
    )

    container.incident_manager = (
        IncidentManager()
    )

    container.soar = SOAREngine()

    container.threat_intel = (
        ThreatIntel()
    )

    container.risk_engine = (
        RiskEngine()
    )

    container.threat_memory = (
        ThreatMemory()
    )

    container.case_manager = (
        CaseManager()
    )

    container.response_engine = (
        ResponseEngine()
    )

    container.response_policy_engine = (
        ResponsePolicyEngine()
    )

    container.campaign_tracker = (
        CampaignTracker()
    )

    container.ai_analyst = AIAnalyst(
        threat_intel=
        container.threat_intel
    )

    container.hunter = ThreatHunter(
        container.event_cache
    )

    container.behavior_engine = (
        BehaviorEngine(
            threshold=5,
            window_seconds=60
        )
    )

    container.monitor_snapshot_builder = (
        MonitorSnapshotBuilder(
            incident_repository=(
                container.incident_repository
            ),
            campaign_repository=(
                container.campaign_repository
            )
        )
    )

    container.operator_read_model = (
        OperatorReadModel(
            incident_repository=(
                container.incident_repository
            ),
            campaign_repository=(
                container.campaign_repository
            ),
            case_manager=(
                container.case_manager
            ),
            event_cache=(
                container.event_cache
            ),
        )
    )

    container.operator_console_renderer = (
        OperatorConsoleRenderer()
    )

    container.operator_console_controller = (
        OperatorConsoleController(
            read_model=(
                container.operator_read_model
            ),
            renderer=(
                container.operator_console_renderer
            ),
        )
    )

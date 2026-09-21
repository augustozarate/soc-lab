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

from engine.services.response_block_lifecycle_service import (
    ResponseBlockLifecycleService
)

from engine.services.response_block_expiration_service import (
    ResponseBlockExpirationService
)

from engine.services.response_block_reconciliation_service import (
    ResponseBlockReconciliationService
)
from engine.services.windows_firewall_backend import (
    WindowsFirewallBackend
)
from engine.services.response_safety_policy import (
    ResponseSafetyPolicy
)
from engine.config import (
    RESPONSE_MODE,
    RESPONSE_PROTECTED_IPS,
    RESPONSE_BLOCK_TTL_SECONDS,
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

    firewall_backend = None

    if RESPONSE_MODE == "enforce":
        firewall_backend = (
            WindowsFirewallBackend()
        )

    response_safety_policy = (
        ResponseSafetyPolicy(
            protected_ips=(
                RESPONSE_PROTECTED_IPS
            )
        )
    )

    container.response_engine = (
        ResponseEngine(
            response_mode=RESPONSE_MODE,
            firewall_backend=firewall_backend,
            safety_policy=(
                response_safety_policy
            ),
        )
    )

    container.response_block_lifecycle = (
        ResponseBlockLifecycleService(
            repository=(
                container.response_block_repository
            ),
            ttl_seconds=(
                RESPONSE_BLOCK_TTL_SECONDS
            ),
        )
    )

    container.response_block_expiration = (
        ResponseBlockExpirationService(
            repository=(
                container.response_block_repository
            ),
            response_engine=(
                container.response_engine
            ),
        )
    )

    container.response_block_reconciliation = (
        ResponseBlockReconciliationService(
            repository=(
                container.response_block_repository
            ),
            response_engine=(
                container.response_engine
            ),
            firewall_backend=firewall_backend,
        )
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

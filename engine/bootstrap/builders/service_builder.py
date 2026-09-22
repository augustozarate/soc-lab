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
    RESPONSE_RECONCILIATION_RETRY_SECONDS,
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

from engine.services.notification_policy import (
    NotificationPolicy
)
from engine.services.notification_service import (
    NotificationService
)
from engine.services.local_notification_adapter import (
    LocalNotificationAdapter
)

from engine.services.webhook_notification_adapter import (
    WebhookNotificationAdapter
)

from engine.services.email_notification_adapter import (
    EmailNotificationAdapter
)

from engine.config import (
    NOTIFICATION_WEBHOOK_ENABLED,
    NOTIFICATION_WEBHOOK_URL,
    NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS,
    NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES,
    NOTIFICATION_WEBHOOK_AUTH_TOKEN,
    NOTIFICATION_WEBHOOK_CA_BUNDLE,
    NOTIFICATION_EMAIL_ENABLED,
    NOTIFICATION_EMAIL_HOST,
    NOTIFICATION_EMAIL_PORT,
    NOTIFICATION_EMAIL_SECURITY,
    NOTIFICATION_EMAIL_TIMEOUT_SECONDS,
    NOTIFICATION_EMAIL_USERNAME,
    NOTIFICATION_EMAIL_PASSWORD,
    NOTIFICATION_EMAIL_FROM,
    NOTIFICATION_EMAIL_TO,
    NOTIFICATION_EMAIL_CA_BUNDLE,
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

    firewall_backend = (
        WindowsFirewallBackend()
    )

    response_engine_firewall_backend = (
        firewall_backend
        if RESPONSE_MODE == "enforce"
        else None
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
            firewall_backend=(
                response_engine_firewall_backend
            ),
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
            safety_policy=(
                response_safety_policy
            ),
            retry_seconds=(
                RESPONSE_RECONCILIATION_RETRY_SECONDS
            ),
        )
    )

    container.response_policy_engine = (
        ResponsePolicyEngine()
    )

    # =====================================
    # NOTIFICATIONS
    # =====================================

    container.notification_policy = (
        NotificationPolicy()
    )

    container.local_notification_adapter = (
        LocalNotificationAdapter()
    )

    notification_adapters = {
        "local": (
            container
            .local_notification_adapter
        ),
    }

    container.email_notification_adapter = None

    if NOTIFICATION_EMAIL_ENABLED:

        required_email_config = {
            "NOTIFICATION_EMAIL_HOST": (
                NOTIFICATION_EMAIL_HOST
            ),
            "NOTIFICATION_EMAIL_USERNAME": (
                NOTIFICATION_EMAIL_USERNAME
            ),
            "NOTIFICATION_EMAIL_PASSWORD": (
                NOTIFICATION_EMAIL_PASSWORD
            ),
            "NOTIFICATION_EMAIL_FROM": (
                NOTIFICATION_EMAIL_FROM
            ),
            "NOTIFICATION_EMAIL_TO": (
                NOTIFICATION_EMAIL_TO
            ),
        }

        missing_email_config = [
            name
            for (
                name,
                value,
            ) in required_email_config.items()
            if not value
        ]

        if missing_email_config:

            raise ValueError(
                "Missing required email "
                "notification configuration: "
                + ", ".join(
                    missing_email_config
                )
            )

        container.email_notification_adapter = (
            EmailNotificationAdapter(
                host=(
                    NOTIFICATION_EMAIL_HOST
                ),
                port=(
                    NOTIFICATION_EMAIL_PORT
                ),
                security=(
                    NOTIFICATION_EMAIL_SECURITY
                ),
                timeout_seconds=(
                    NOTIFICATION_EMAIL_TIMEOUT_SECONDS
                ),
                username=(
                    NOTIFICATION_EMAIL_USERNAME
                ),
                password=(
                    NOTIFICATION_EMAIL_PASSWORD
                ),
                sender=(
                    NOTIFICATION_EMAIL_FROM
                ),
                recipient=(
                    NOTIFICATION_EMAIL_TO
                ),
                ca_bundle=(
                    NOTIFICATION_EMAIL_CA_BUNDLE
                    or None
                ),
            )
        )

        notification_adapters[
            "email"
        ] = (
            container
            .email_notification_adapter
        )

    container.webhook_notification_adapter = None

    if NOTIFICATION_WEBHOOK_ENABLED:

        if not NOTIFICATION_WEBHOOK_URL:

            raise ValueError(
                "NOTIFICATION_WEBHOOK_URL "
                "is required when webhook "
                "notifications are enabled"
            )

        container.webhook_notification_adapter = (
            WebhookNotificationAdapter(
                url=(
                    NOTIFICATION_WEBHOOK_URL
                ),
                timeout_seconds=(
                    NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS
                ),
                max_payload_bytes=(
                    NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES
                ),
                auth_token=(
                    NOTIFICATION_WEBHOOK_AUTH_TOKEN
                    or None
                ),
                ca_bundle=(
                    NOTIFICATION_WEBHOOK_CA_BUNDLE
                    or None
                ),
            )
        )

        notification_adapters[
            "webhook"
        ] = (
            container
            .webhook_notification_adapter
        )

    container.notification_service = (
        NotificationService(
            adapters=notification_adapters,
            delivery_repository=(
                container
                .notification_delivery_repository
            ),
            rate_limit_repository=(
                container
                .notification_rate_limit_repository
            ),
        )
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

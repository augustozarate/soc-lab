from pathlib import Path

from engine.storage.sqlite.database import Database
from engine.storage.sqlite.migrations import MigrationRunner

from engine.storage.repositories.incident_repository import (
    IncidentRepository
)

from engine.storage.repositories.campaign_repository import (
    CampaignRepository
)

from engine.storage.repositories.event_repository import (
    EventRepository
)

from engine.storage.repositories.processed_alert_repository import (
    ProcessedAlertRepository
)

from engine.storage.repositories.response_block_repository import (
    ResponseBlockRepository
)

from engine.storage.repositories.notification_delivery_repository import (
    NotificationDeliveryRepository
)


def build_repositories(
    container,
    db_file
):

    db_path = Path(db_file)

    # Garantiza que exista la carpeta padre
    db_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    container.database = Database(
        str(db_path)
    )

    MigrationRunner(
        container.database
    ).run()

    container.incident_repository = (
        IncidentRepository(
            container.database
        )
    )

    container.campaign_repository = (
        CampaignRepository(
            container.database
        )
    )

    container.event_repository = (
        EventRepository(
            container.database
        )
    )

    container.processed_alert_repository = (
        ProcessedAlertRepository(
            container.database
        )
    )

    container.response_block_repository = (
        ResponseBlockRepository(
            container.database
        )
    )

    container.notification_delivery_repository = (
        NotificationDeliveryRepository(
            container.database
        )
    )

    container.processed_alert_repository.reset_incomplete()

    container.notification_delivery_repository.reset_incomplete()

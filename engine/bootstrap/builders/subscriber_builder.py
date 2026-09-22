from engine.orchestration.subscribers.notification_subscriber import (
    NotificationSubscriber,
)


def build_subscribers(
    container,
):

    container.notification_subscriber = (
        NotificationSubscriber(
            policy=(
                container.notification_policy
            ),
            service=(
                container.notification_service
            ),
        )
    )

    container.event_bus.subscribe(
        "incident_persisted",
        (
            container
            .notification_subscriber
            .on_incident_persisted
        ),
    )

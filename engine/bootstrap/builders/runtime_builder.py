from engine.orchestration.runtime.event_scheduler import (
    EventScheduler
)

from engine.orchestration.runtime.retry_policy import (
    RetryPolicy
)

from engine.orchestration.runtime.worker_pool import (
    WorkerPool
)

from engine.orchestration.runtime.dlq.dead_letter_queue import (
    DeadLetterQueue
)

from engine.orchestration.runtime.dlq.failed_task_store import (
    FailedTaskStore
)

from engine.orchestration.runtime.dlq.replay_engine import (
    ReplayEngine
)

def build_runtime(
    container,
    dlq_file
):

    container.scheduler = EventScheduler(
        event_repository=
        container.event_repository
    )

    container.failed_store = (
        FailedTaskStore(dlq_file)
    )

    container.dead_letter_queue = (
        DeadLetterQueue(
            store=container.failed_store,
            auditor=container.audit,
            metrics=container.metrics
        )
    )

    container.replay_engine = (
        ReplayEngine(
            scheduler=
            container.scheduler
        )
    )

    container.retry_policy = (
        RetryPolicy(
            scheduler=
            container.scheduler,

            dead_letter_queue=
            container.dead_letter_queue,

            max_retries=3,
            backoff=2
        )
    )

    container.worker_pool = (
        WorkerPool(
            scheduler=
            container.scheduler,

            handler=
            container.process_task,

            retry_policy=
            container.retry_policy,

            workers=4
        )
    )
from engine.bootstrap.builders.core_builder import build_core
from engine.bootstrap.builders.repository_builder import build_repositories
from engine.bootstrap.builders.infrastructure_builder import build_infrastructure
from engine.bootstrap.builders.service_builder import build_services
from engine.bootstrap.builders.correlation_builder import build_correlation
from engine.bootstrap.builders.pipeline_builder import build_pipelines
from engine.bootstrap.builders.runtime_builder import build_runtime


class Container:

    def __init__(
        self,
        stream_file,
        detection_path,
        mitre_file,
        dlq_file,
        db_file,
        event_cache
    ):

        self.event_cache = event_cache

        build_core(self)

        build_repositories(
            self,
            db_file
        )

        build_infrastructure(
            self,
            stream_file,
            detection_path,
            mitre_file
        )

        build_services(self)

        build_correlation(self)

        build_pipelines(self)

        build_runtime(
            self,
            dlq_file
        )

    def reload_rules(self):

        self.rules = (
            self.loader.load()
        )

        self.detector.update_rules(
            self.rules
        )

    def process_task(self, task):

        task["state"] = "RUNNING"

        result = self.orchestrator.execute(
            task["payload"]
        )

        task["state"] = "COMPLETED"

        return result
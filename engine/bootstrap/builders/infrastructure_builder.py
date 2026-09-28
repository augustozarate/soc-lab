from engine.infrastructure.event_reader import EventReader
from engine.infrastructure.rule_loader import RuleLoader
from engine.infrastructure.rule_watcher import RuleWatcher

from engine.rule_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper



def build_infrastructure(
    container,
    stream_file,
    event_reader_checkpoint_file,
    detection_path,
    mitre_file
):

    # =====================================
    # EVENT READER
    # =====================================

    container.reader = EventReader(
        stream_file,
        event_reader_checkpoint_file
    )

    # =====================================
    # DETECTION RULES
    # =====================================

    container.loader = RuleLoader(
        detection_path
    )

    container.rules = (
        container.loader.load()
    )

    container.detector = DetectionEngine(
        container.rules
    )

    # =====================================
    # RULE WATCHER
    # =====================================

    container.rule_watcher = RuleWatcher(
        detection_path,
        container.reload_rules
    )

    # =====================================
    # MITRE MAPPER
    # =====================================

    container.mitre_mapper = MitreMapper(
        mitre_file
    )

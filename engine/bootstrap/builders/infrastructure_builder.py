from engine.infrastructure.event_reader import EventReader
from engine.infrastructure.rule_loader import RuleLoader
from engine.infrastructure.rule_watcher import RuleWatcher

from engine.rule_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper

from engine.adversary_simulator import AdversarySimulator


def build_infrastructure(
    container,
    stream_file,
    detection_path,
    mitre_file
):

    # =====================================
    # EVENT READER
    # =====================================

    container.reader = EventReader(
        stream_file
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

    # =====================================
    # ADVERSARY SIMULATOR
    # =====================================

    container.simulator = AdversarySimulator(
        stream_file
    )
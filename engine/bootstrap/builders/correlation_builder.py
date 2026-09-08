from engine.correlation.entity_resolver import (
    EntityResolver
)

from engine.correlation.threat_graph import (
    ThreatGraph
)

from engine.correlation.campaign_graph import (
    CampaignGraph
)

from engine.correlation.attack_graph import (
    AttackGraph
)

def build_correlation(container):

    container.entity_resolver = (
        EntityResolver()
    )

    container.threat_graph = (
        ThreatGraph()
    )

    container.campaign_graph = (
        CampaignGraph()
    )

    container.attack_graph = (
        AttackGraph()
    )
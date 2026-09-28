from engine.correlation.entity_resolver import (
    EntityResolver
)

from engine.correlation.threat_graph import (
    ThreatGraph
)

from engine.correlation.campaign_graph import (
    CampaignGraph
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

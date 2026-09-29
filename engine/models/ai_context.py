from dataclasses import dataclass, field

@dataclass
class AIContext:

    id: str
    ip: str

    risk: int
    severity: str

    campaign: dict | None = None

    mitre: set = field(default_factory=set)

    relations: list = field(default_factory=list)

    threat_intel: dict | None = None

    memory: dict | None = None

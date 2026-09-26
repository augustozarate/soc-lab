from engine.presentation.campaign_query_read_model import (
    CampaignQueryReadModel,
)


class CampaignRepositoryStub:

    def __init__(
        self,
        rows=None,
        by_id=None,
    ):
        self.rows = rows or []
        self.by_id = by_id or {}
        self.recent_calls = []
        self.get_calls = []
        self.list_all_calls = 0

    def list_recent(
        self,
        limit,
    ):
        self.recent_calls.append(
            limit
        )

        return self.rows[:limit]

    def get(
        self,
        campaign_id,
    ):
        self.get_calls.append(
            campaign_id
        )

        return self.by_id.get(
            campaign_id
        )

    def list_all(self):
        self.list_all_calls += 1

        raise AssertionError(
            "Unbounded campaign query used"
        )


def test_recent_uses_bounded_repository_query():
    repository = CampaignRepositoryStub(
        rows=[
            {
                "id": "CMP-1",
                "entities": {
                    "ip": [
                        "10.0.0.10"
                    ]
                },
                "stage": "INITIAL",
                "risk": 40,
                "incidents": [
                    "INC-1",
                    "INC-2",
                ],
                "updated": "t1",
            }
        ]
    )

    model = CampaignQueryReadModel(
        repository
    )

    result = model.recent(
        limit=7
    )

    assert repository.recent_calls == [
        7
    ]

    assert repository.list_all_calls == 0

    assert result == [
        {
            "id": "CMP-1",
            "ip": "10.0.0.10",
            "stage": "INITIAL",
            "risk": 40,
            "incidents": 2,
            "updated": "t1",
        }
    ]


def test_recent_limit_is_capped():
    repository = CampaignRepositoryStub()

    model = CampaignQueryReadModel(
        repository
    )

    model.recent(
        limit=9999
    )

    assert repository.recent_calls == [
        100
    ]


def test_recent_zero_returns_empty_query():
    repository = CampaignRepositoryStub()

    model = CampaignQueryReadModel(
        repository
    )

    result = model.recent(
        limit=0
    )

    assert result == []

    assert repository.recent_calls == [
        0
    ]


def test_recent_invalid_limit_uses_default():
    repository = CampaignRepositoryStub()

    model = CampaignQueryReadModel(
        repository
    )

    model.recent(
        limit="invalid"
    )

    assert repository.recent_calls == [
        20
    ]


def test_get_uses_repository_get():
    repository = CampaignRepositoryStub(
        by_id={
            "CMP-1": {
                "id": "CMP-1",
                "created": "c",
                "updated": "u",
                "stage": "SPREADING",
                "risk": 82,
                "incidents": [
                    "INC-1"
                ],
                "entities": {
                    "ip": [
                        "10.0.0.10"
                    ],
                    "user": [
                        "alice"
                    ],
                    "host": [
                        "host-1"
                    ],
                    "provider_debug": [
                        "PRIVATE"
                    ],
                },
                "tactics": [
                    "Lateral Movement"
                ],
                "timeline": [
                    {
                        "event": "safe"
                    }
                ],
                "internal_note": (
                    "DO-NOT-EXPOSE"
                ),
            }
        }
    )

    model = CampaignQueryReadModel(
        repository
    )

    result = model.get(
        "CMP-1"
    )

    assert repository.get_calls == [
        "CMP-1"
    ]

    assert result == {
        "id": "CMP-1",
        "created": "c",
        "updated": "u",
        "stage": "SPREADING",
        "risk": 82,
        "incidents": [
            "INC-1"
        ],
        "entities": {
            "ip": [
                "10.0.0.10"
            ],
            "user": [
                "alice"
            ],
            "host": [
                "host-1"
            ],
        },
        "tactics": [
            "Lateral Movement"
        ],
        "timeline": [
            {
                "event": "safe"
            }
        ],
    }

    assert (
        "internal_note"
        not in result
    )

    assert (
        "provider_debug"
        not in result[
            "entities"
        ]
    )


def test_get_returns_deepcopy_projection():
    original = {
        "id": "CMP-1",
        "entities": {
            "ip": [
                "10.0.0.10"
            ]
        },
        "incidents": [
            "INC-1"
        ],
        "tactics": [],
        "timeline": [],
    }

    repository = CampaignRepositoryStub(
        by_id={
            "CMP-1": original
        }
    )

    model = CampaignQueryReadModel(
        repository
    )

    result = model.get(
        "CMP-1"
    )

    result[
        "entities"
    ][
        "ip"
    ].append(
        "10.0.0.20"
    )

    result[
        "incidents"
    ].append(
        "INC-2"
    )

    assert original == {
        "id": "CMP-1",
        "entities": {
            "ip": [
                "10.0.0.10"
            ]
        },
        "incidents": [
            "INC-1"
        ],
        "tactics": [],
        "timeline": [],
    }


def test_get_missing_campaign_returns_none():
    repository = CampaignRepositoryStub()

    model = CampaignQueryReadModel(
        repository
    )

    assert (
        model.get(
            "CMP-missing"
        )
        is None
    )


def test_get_blank_id_does_not_query_repository():
    repository = CampaignRepositoryStub()

    model = CampaignQueryReadModel(
        repository
    )

    assert model.get(
        "   "
    ) is None

    assert repository.get_calls == []

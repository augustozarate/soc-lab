import pytest

from engine.presentation.campaign_console_controller import (
    CampaignConsoleController,
)


class CampaignQueryReadModelStub:
    def __init__(self):
        self.get_calls = []
        self.recent_calls = []

        self.detail = {
            "id": "CMP-1",
            "stage": "ACTIVE",
            "risk": 80,
            "entities": {
                "ip": [
                    "10.0.0.10",
                ],
            },
            "incidents": [
                "INC-1",
            ],
            "tactics": [
                "Lateral Movement",
            ],
            "timeline": [
                "INC-1 correlated",
            ],
        }

        self.recent_rows = [
            {
                "id": "CMP-1",
                "ip": "10.0.0.10",
                "stage": "ACTIVE",
                "risk": 80,
                "incidents": 1,
                "updated": "u",
            }
        ]

    def get(
        self,
        campaign_id,
    ):
        self.get_calls.append(
            campaign_id
        )

        if campaign_id != "CMP-1":
            return None

        return self.detail

    def recent(
        self,
        limit=20,
    ):
        self.recent_calls.append(
            limit
        )

        return self.recent_rows


def test_query_campaign_delegates_and_returns_deepcopy():
    model = CampaignQueryReadModelStub()

    controller = CampaignConsoleController(
        campaign_query_read_model=model,
    )

    result = controller.query_campaign(
        "CMP-1"
    )

    assert model.get_calls == [
        "CMP-1",
    ]

    assert result == model.detail
    assert result is not model.detail
    assert result["entities"] is not (
        model.detail["entities"]
    )
    assert result["incidents"] is not (
        model.detail["incidents"]
    )

    result["entities"]["ip"].append(
        "203.0.113.10"
    )

    assert model.detail["entities"]["ip"] == [
        "10.0.0.10",
    ]


def test_query_campaign_missing_returns_none():
    model = CampaignQueryReadModelStub()

    controller = CampaignConsoleController(
        campaign_query_read_model=model,
    )

    result = controller.query_campaign(
        "CMP-MISSING"
    )

    assert model.get_calls == [
        "CMP-MISSING",
    ]

    assert result is None


def test_query_campaign_fails_closed_without_read_model():
    controller = CampaignConsoleController(
        campaign_query_read_model=None,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Campaign query surface "
            "is unavailable"
        ),
    ):
        controller.query_campaign(
            "CMP-1"
        )


def test_query_campaigns_delegates_limit_and_returns_deepcopy():
    model = CampaignQueryReadModelStub()

    controller = CampaignConsoleController(
        campaign_query_read_model=model,
    )

    result = controller.query_campaigns(
        limit=7
    )

    assert model.recent_calls == [
        7,
    ]

    assert result == model.recent_rows
    assert result is not model.recent_rows
    assert result[0] is not (
        model.recent_rows[0]
    )

    result[0]["stage"] = "MUTATED"

    assert (
        model.recent_rows[0]["stage"]
        == "ACTIVE"
    )


def test_query_campaigns_fails_closed_without_read_model():
    controller = CampaignConsoleController(
        campaign_query_read_model=None,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Campaign query surface "
            "is unavailable"
        ),
    ):
        controller.query_campaigns(
            limit=20
        )

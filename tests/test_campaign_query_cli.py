from engine.cli.soc_cli import (
    SOCConsole,
)


class IncidentManagerStub:

    def __init__(
        self,
    ):
        self.rows = {
            "INC-1": {
                "id": "INC-1",
                "severity": "HIGH",
                "ip": "10.0.0.10",
                "mitre": {
                    "technique_id": "T1021",
                },
            }
        }

    def get(
        self,
        incident_id,
    ):
        return self.rows.get(
            incident_id
        )


class CaseManagerStub:
    pass


class TrackerTrap:

    @property
    def campaigns(
        self,
    ):
        raise AssertionError(
            "Raw campaign tracker accessed"
        )


class CampaignReadModelStub:

    def __init__(
        self,
    ):
        self.recent_calls = 0
        self.get_calls = []

        self.campaign = {
            "id": "CMP-1",
            "created": "c",
            "updated": "u",
            "stage": "SPREADING",
            "risk": 82,
            "incidents": [
                "INC-1",
            ],
            "entities": {
                "ip": [
                    "10.0.0.10",
                ],
                "user": [],
                "host": [],
            },
            "tactics": [
                "Lateral Movement",
            ],
            "timeline": [
                "INC-1 correlated",
            ],
        }

    def recent(
        self,
    ):
        self.recent_calls += 1

        return [
            {
                "id": "CMP-1",
                "ip": "10.0.0.10",
                "stage": "SPREADING",
                "risk": 82,
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

        if campaign_id == "CMP-1":
            return self.campaign

        return None


def make_console(
    model=None,
):
    return SOCConsole(
        incident_manager=(
            IncidentManagerStub()
        ),
        case_manager=(
            CaseManagerStub()
        ),
        campaign_tracker=(
            TrackerTrap()
        ),
        campaign_query_read_model=(
            model
        ),
    )


def test_campaign_list_delegates_to_read_model():
    model = CampaignReadModelStub()

    console = make_console(
        model
    )

    result = console.list_campaigns(
        args=[],
        flags={},
        data=None,
    )

    assert model.recent_calls == 1

    assert result == [
        {
            "id": "CMP-1",
            "ip": "10.0.0.10",
            "stage": "SPREADING",
            "risk": 82,
            "incidents": 1,
            "updated": "u",
        }
    ]


def test_campaign_list_requires_read_model():
    console = make_console()

    try:
        console.list_campaigns(
            args=[],
            flags={},
            data=None,
        )

    except RuntimeError as exc:
        assert str(
            exc
        ) == (
            "Campaign queries are unavailable"
        )

    else:
        raise AssertionError(
            "Missing campaign read model accepted"
        )


def test_campaign_list_rejects_pipeline_input():
    console = make_console(
        CampaignReadModelStub()
    )

    try:
        console.list_campaigns(
            args=[],
            flags={},
            data=[
                {
                    "id": "x",
                }
            ],
        )

    except ValueError as exc:
        assert (
            "cannot consume pipeline input"
            in str(
                exc
            )
        )

    else:
        raise AssertionError(
            "Campaign pipeline input accepted"
        )


def test_campaign_show_delegates_to_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console = make_console(
        model
    )

    console.show_campaign(
        args=[
            "CMP-1",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "CAMPAIGN DETAILS"
        in output
    )

    assert (
        "CMP-1"
        in output
    )

    assert (
        "SPREADING"
        in output
    )

    assert (
        "INC-1 (HIGH)"
        in output
    )

    assert (
        "Lateral Movement"
        in output
    )


def test_campaign_show_missing_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console = make_console(
        model
    )

    console.show_campaign(
        args=[
            "CMP-MISSING",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-MISSING"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "Campaign not found"
        in output
    )


def test_campaign_graph_delegates_to_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console = make_console(
        model
    )

    console.show_campaign_graph(
        args=[
            "CMP-1",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "CAMPAIGN GRAPH"
        in output
    )

    assert (
        "CAMPAIGN: CMP-1"
        in output
    )

    assert (
        "INCIDENT: INC-1"
        in output
    )

    assert (
        "USES_IP"
        in output
    )

    assert (
        "USES_TECHNIQUE"
        in output
    )


def test_campaign_graph_missing_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console = make_console(
        model
    )

    console.show_campaign_graph(
        args=[
            "CMP-MISSING",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-MISSING"
    ]

    assert (
        "Campaign not found"
        in (
            capsys
            .readouterr()
            .out
        )
    )


def test_campaign_routes_remain_registered():
    console = make_console(
        CampaignReadModelStub()
    )

    assert (
        console.routes[
            (
                "campaign",
                "list",
            )
        ]
        == console.list_campaigns
    )

    assert (
        console.routes[
            (
                "campaign",
                "show",
            )
        ]
        == console.show_campaign
    )

    assert (
        console.routes[
            (
                "campaign",
                "graph",
            )
        ]
        == console.show_campaign_graph
    )

    assert (
        console.routes[
            (
                "graph",
                "campaign",
            )
        ]
        == console.show_campaign_graph
    )


class AIAnalystStub:

    def __init__(
        self,
    ):
        self.calls = []

    def ask(
        self,
        incident,
        question,
        graph,
        campaign,
    ):
        self.calls.append(
            {
                "incident": incident,
                "question": question,
                "graph": graph,
                "campaign": campaign,
            }
        )

        return "AI-STUB-RESPONSE"


class ThreatGraphStub:

    def get_incident_context(
        self,
        incident_id,
    ):
        return {
            "ips": [],
            "campaigns": [],
            "mitre": [],
        }


def make_context_console(
    model,
):
    incident_manager = (
        IncidentManagerStub()
    )

    incident_manager.rows[
        "INC-AI"
    ] = {
        "id": "INC-AI",
        "severity": "HIGH",
        "risk_score": 80,
        "campaign_id": "CMP-1",
        "attack_story": {
            "progression": [],
        },
    }

    ai = AIAnalystStub()

    graph = ThreatGraphStub()

    console = SOCConsole(
        incident_manager=(
            incident_manager
        ),
        case_manager=(
            CaseManagerStub()
        ),
        campaign_tracker=(
            TrackerTrap()
        ),
        ai_analyst=ai,
        threat_graph=graph,
        campaign_query_read_model=(
            model
        ),
    )

    return (
        console,
        ai,
        graph,
    )


def test_show_graph_campaign_detection_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console, _, _ = (
        make_context_console(
            model
        )
    )

    console.show_graph(
        "CMP-1"
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "That is a CAMPAIGN ID"
        in output
    )


def test_explain_incident_campaign_detection_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console, _, _ = (
        make_context_console(
            model
        )
    )

    console.explain_incident(
        "CMP-1"
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "That is a CAMPAIGN ID"
        in output
    )


def test_ask_ai_uses_campaign_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console, ai, graph = (
        make_context_console(
            model
        )
    )

    console.ask_ai(
        args=[
            "INC-AI",
            "campaign",
            "status",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    assert len(
        ai.calls
    ) == 1

    call = ai.calls[0]

    assert (
        call[
            "campaign"
        ][
            "id"
        ]
        == "CMP-1"
    )

    assert (
        call[
            "graph"
        ]
        is graph
    )

    assert (
        call[
            "question"
        ]
        == "campaign status"
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "AI-STUB-RESPONSE"
        in output
    )


def test_ai_chat_campaign_detection_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console, ai, _ = (
        make_context_console(
            model
        )
    )

    console.ai_chat(
        "CMP-1"
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    assert ai.calls == []

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "That is a CAMPAIGN ID"
        in output
    )


def test_ai_chat_campaign_context_uses_read_model(
    monkeypatch,
):
    model = CampaignReadModelStub()

    console, ai, _ = (
        make_context_console(
            model
        )
    )

    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: "exit",
    )

    console.ai_chat(
        "INC-AI"
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    assert ai.calls == []


def test_story_campaign_detection_uses_read_model(
    capsys,
):
    model = CampaignReadModelStub()

    console, _, _ = (
        make_context_console(
            model
        )
    )

    console.cmd_story(
        args=[
            "CMP-1",
        ],
        flags={},
        data=None,
    )

    assert model.get_calls == [
        "CMP-1"
    ]

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "That is a CAMPAIGN ID"
        in output
    )

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


class HistoricalIncidentControllerStub:

    def __init__(
        self,
        incident_manager,
    ):
        self.incident_manager = (
            incident_manager
        )

    def query_incident(
        self,
        incident_id,
    ):
        return (
            self.incident_manager
            .get(
                incident_id
            )
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
    incident_manager = (
        IncidentManagerStub()
    )

    return SOCConsole(
        campaign_tracker=(
            TrackerTrap()
        ),
        monitor_console_controller=(
            HistoricalIncidentControllerStub(
                incident_manager
            )
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
        campaign_tracker=(
            TrackerTrap()
        ),
        ai_analyst=ai,
        threat_graph=graph,
        monitor_console_controller=(
            HistoricalIncidentControllerStub(
                incident_manager
            )
        ),
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


class MigrationCampaignQueryReadModelStub:

    def __init__(
        self,
    ):
        self.calls = []

    def get(
        self,
        campaign_id,
    ):
        self.calls.append(
            campaign_id
        )

        if campaign_id != "CAMP-1":
            return None

        return {
            "id": "CAMP-1",
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
            "tactics": [],
            "timeline": [],
        }


class SingleIncidentControllerStub:

    def __init__(
        self,
        rows,
    ):
        self.rows = rows
        self.calls = []

    def query_incident(
        self,
        incident_id,
    ):
        self.calls.append(
            incident_id
        )

        return self.rows.get(
            incident_id
        )


class NoGetIncidentManager:

    def get(
        self,
        incident_id,
    ):
        raise AssertionError(
            "IncidentManager.get reached"
        )


def test_ask_ai_uses_single_incident_controller():
    controller = (
        SingleIncidentControllerStub(
            {
                "INC-AI": {
                    "id": "INC-AI",
                    "campaign_id": None,
                    "severity": "HIGH",
                }
            }
        )
    )

    class AIStub:

        def __init__(
            self,
        ):
            self.calls = []

        def ask(
            self,
            incident,
            question,
            threat_graph,
            campaign,
        ):
            self.calls.append(
                (
                    incident,
                    question,
                    threat_graph,
                    campaign,
                )
            )

            return "AI-OK"

    ai = AIStub()

    console = SOCConsole(
        ai_analyst=ai,
        monitor_console_controller=(
            controller
        ),
        campaign_query_read_model=(
            MigrationCampaignQueryReadModelStub()
        ),
    )

    console.ask_ai(
        [
            "INC-AI",
            "what",
            "happened",
        ],
        {},
        None,
    )

    assert controller.calls == [
        "INC-AI"
    ]

    assert len(
        ai.calls
    ) == 1

    assert (
        ai.calls[0][0]["id"]
        == "INC-AI"
    )


def test_show_campaign_uses_single_incident_controller(
    capsys,
):
    controller = (
        SingleIncidentControllerStub(
            {
                "INC-1": {
                    "id": "INC-1",
                    "severity": "HIGH",
                }
            }
        )
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
        campaign_query_read_model=(
            MigrationCampaignQueryReadModelStub()
        ),
    )

    console.show_campaign(
        ["CAMP-1"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-1"
    ]

    assert (
        "INC-1 (HIGH)"
        in capsys.readouterr().out
    )


def test_campaign_graph_uses_controller_backed_incident_reader(
    capsys,
):
    controller = (
        SingleIncidentControllerStub(
            {
                "INC-1": {
                    "id": "INC-1",
                    "severity": "HIGH",
                    "ip": "10.0.0.10",
                    "mitre": {
                        "technique_id": "T1021",
                    },
                }
            }
        )
    )

    console = SOCConsole(
        monitor_console_controller=(
            controller
        ),
        campaign_query_read_model=(
            MigrationCampaignQueryReadModelStub()
        ),
    )

    console.show_campaign_graph(
        ["CAMP-1"],
        {},
        None,
    )

    assert controller.calls == [
        "INC-1"
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
        "INCIDENT: INC-1"
        in output
    )

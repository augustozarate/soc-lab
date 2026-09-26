from copy import deepcopy


REPORT_TYPE_EXECUTIVE = "executive"
REPORT_TYPE_TECHNICAL = "technical"
REPORT_TYPE_ADVANCED = "advanced"


EXECUTIVE_FIELDS = frozenset(
    {
        "report_type",
        "generated_at",
        "period",
        "summary",
        "risk",
        "critical_incidents",
        "campaigns",
        "response_overview",
        "recommendations",
    }
)


TECHNICAL_FIELDS = frozenset(
    {
        "report_type",
        "generated_at",
        "period",
        "summary",
        "incidents",
        "campaigns",
        "mitre",
        "timeline",
        "response_actions",
        "operational_status",
    }
)


ADVANCED_FIELDS = frozenset(
    {
        "report_type",
        "generated_at",
        "period",
        "summary",
        "incidents",
        "campaigns",
        "mitre",
        "timeline",
        "response_actions",
        "operational_status",
        "entities",
        "threat_intelligence",
        "hunting",
        "evidence",
    }
)


COMMON_INCIDENT_FIELDS = frozenset(
    {
        "id",
        "severity",
        "status",
        "risk_score",
        "campaign_id",
        "created",
        "updated",
        "last_seen",
    }
)


TECHNICAL_INCIDENT_FIELDS = (
    COMMON_INCIDENT_FIELDS
    | {
        "ip",
        "attack_phase",
        "timeline",
        "response_actions",
    }
)


ADVANCED_INCIDENT_FIELDS = (
    TECHNICAL_INCIDENT_FIELDS
    | {
        "alerts",
    }
)


CAMPAIGN_FIELDS = frozenset(
    {
        "id",
        "stage",
        "risk",
        "incidents",
        "tactics",
        "created",
        "updated",
    }
)


CASE_FIELDS = frozenset(
    {
        "id",
        "incident_id",
        "created",
        "status",
        "assignee",
        "severity",
        "timeline",
    }
)


ADVANCED_CASE_FIELDS = (
    CASE_FIELDS
    | {
        "notes",
        "evidence",
    }
)


FORBIDDEN_EXPORT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "authorization",
        "api_key",
        "private_key",
        "smtp_password",
        "webhook_url",
        "bot_token",
        "internal_note",
        "debug",
        "raw_event",
        "raw_payload",
        "dedup_key",
    }
)


REPORT_FIELDS_BY_TYPE = {
    REPORT_TYPE_EXECUTIVE: EXECUTIVE_FIELDS,
    REPORT_TYPE_TECHNICAL: TECHNICAL_FIELDS,
    REPORT_TYPE_ADVANCED: ADVANCED_FIELDS,
}


def normalize_report_type(
    report_type,
):
    normalized = str(
        report_type
        if report_type is not None
        else ""
    ).strip().lower()

    if normalized not in REPORT_FIELDS_BY_TYPE:
        raise ValueError(
            "Unsupported report type"
        )

    return normalized


def project_fields(
    source,
    allowed_fields,
):
    if not isinstance(
        source,
        dict,
    ):
        return {}

    return {
        key: deepcopy(
            source[key]
        )
        for key in allowed_fields
        if key in source
    }


def iter_nested_keys(
    value,
):
    if isinstance(
        value,
        dict,
    ):
        for key, nested in value.items():
            yield str(
                key
            ).strip().lower()

            yield from iter_nested_keys(
                nested
            )

    elif isinstance(
        value,
        (list, tuple),
    ):
        for nested in value:
            yield from iter_nested_keys(
                nested
            )


def forbidden_keys_present(
    value,
):
    return frozenset(
        key
        for key in iter_nested_keys(
            value
        )
        if key in FORBIDDEN_EXPORT_KEYS
    )


def assert_export_safe(
    value,
):
    forbidden = forbidden_keys_present(
        value
    )

    if forbidden:
        raise ValueError(
            "Report payload contains "
            "forbidden export fields"
        )

    return value

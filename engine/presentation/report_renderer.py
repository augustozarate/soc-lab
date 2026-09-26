import json
from copy import deepcopy

from engine.presentation.reporting_contract import (
    assert_export_safe,
)


class ReportRenderer:

    SUPPORTED_FORMATS = frozenset(
        {
            "json",
            "markdown",
        }
    )

    def render(
        self,
        document,
        output_format,
    ):
        normalized = self._normalize_format(
            output_format
        )

        safe_document = deepcopy(
            document
            if isinstance(
                document,
                dict,
            )
            else {}
        )

        assert_export_safe(
            safe_document
        )

        if normalized == "json":
            return self._render_json(
                safe_document
            )

        if normalized == "markdown":
            return self._render_markdown(
                safe_document
            )

        raise ValueError(
            "Unsupported report format"
        )

    @classmethod
    def _normalize_format(
        cls,
        value,
    ):
        normalized = str(
            value
            if value is not None
            else ""
        ).strip().lower()

        if (
            normalized
            not in cls.SUPPORTED_FORMATS
        ):
            raise ValueError(
                "Unsupported report format"
            )

        return normalized

    @staticmethod
    def _render_json(
        document,
    ):
        return json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"

    def _render_markdown(
        self,
        document,
    ):
        report_type = self._scalar(
            document.get(
                "report_type",
                "unknown",
            )
        ).upper()

        generated_at = self._scalar(
            document.get(
                "generated_at",
                "unknown",
            )
        )

        period = document.get(
            "period"
        )

        lines = [
            f"# SOC Report — {report_type}",
            "",
            f"- Generated: {generated_at}",
            (
                "- Period: "
                + self._period_text(
                    period
                )
            ),
            "",
        ]

        report_type_normalized = str(
            document.get(
                "report_type",
                ""
            )
        ).strip().lower()

        if report_type_normalized == "executive":
            lines.extend(
                self._executive_markdown(
                    document
                )
            )

        elif report_type_normalized == "technical":
            lines.extend(
                self._technical_markdown(
                    document
                )
            )

        elif report_type_normalized == "advanced":
            lines.extend(
                self._advanced_markdown(
                    document
                )
            )

        else:
            raise ValueError(
                "Unsupported report type"
            )

        return "\n".join(
            lines
        ).rstrip() + "\n"

    def _executive_markdown(
        self,
        document,
    ):
        summary = self._dict(
            document.get(
                "summary"
            )
        )

        risk = self._dict(
            document.get(
                "risk"
            )
        )

        lines = [
            "## Executive Summary",
            "",
            (
                "- Incidents: "
                + self._scalar(
                    summary.get(
                        "incidents",
                        0,
                    )
                )
            ),
            (
                "- High/Critical: "
                + self._scalar(
                    summary.get(
                        "high_critical",
                        0,
                    )
                )
            ),
            (
                "- Campaigns: "
                + self._scalar(
                    summary.get(
                        "campaigns",
                        0,
                    )
                )
            ),
            (
                "- Maximum Risk: "
                + self._scalar(
                    risk.get(
                        "maximum",
                        0,
                    )
                )
            ),
            "",
            "## Critical Incidents",
            "",
        ]

        critical = self._list(
            document.get(
                "critical_incidents"
            )
        )

        lines.extend(
            self._incident_bullets(
                critical
            )
        )

        lines.extend([
            "",
            "## Recommendations",
            "",
        ])

        recommendations = document.get(
            "recommendations",
            []
        )

        if not isinstance(
            recommendations,
            list,
        ):
            recommendations = []

        if recommendations:
            lines.extend(
                "- "
                + self._scalar(
                    recommendation
                )
                for recommendation
                in recommendations
            )
        else:
            lines.append(
                "- None"
            )

        return lines

    def _technical_markdown(
        self,
        document,
    ):
        lines = [
            "## Incidents",
            "",
        ]

        incidents = self._list(
            document.get(
                "incidents"
            )
        )

        lines.extend(
            self._incident_bullets(
                incidents
            )
        )

        lines.extend([
            "",
            "## MITRE ATT&CK",
            "",
        ])

        mitre = self._list(
            document.get(
                "mitre"
            )
        )

        if mitre:
            for item in mitre:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                item.get(
                                    "tactic",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "technique_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "technique",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        lines.extend([
            "",
            "## Timeline",
            "",
        ])

        timeline = self._list(
            document.get(
                "timeline"
            )
        )

        if timeline:
            for entry in timeline:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                entry.get(
                                    "time",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                entry.get(
                                    "incident_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                entry.get(
                                    "event",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        lines.extend([
            "",
            "## Response Actions",
            "",
        ])

        actions = self._list(
            document.get(
                "response_actions"
            )
        )

        if actions:
            for action in actions:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                action.get(
                                    "incident_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                action.get(
                                    "type",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                action.get(
                                    "status",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        return lines

    def _advanced_markdown(
        self,
        document,
    ):
        lines = self._technical_markdown(
            document
        )

        lines.extend([
            "",
            "## Entities",
            "",
        ])

        entities = self._list(
            document.get(
                "entities"
            )
        )

        if entities:
            for entity in entities:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                entity.get(
                                    "campaign_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                entity.get(
                                    "type",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                entity.get(
                                    "value",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        lines.extend([
            "",
            "## Threat Intelligence",
            "",
        ])

        intelligence = self._list(
            document.get(
                "threat_intelligence"
            )
        )

        if intelligence:
            for item in intelligence:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                item.get(
                                    "incident_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "reputation",
                                    "unknown",
                                )
                            ),
                            (
                                "confidence="
                                + self._scalar(
                                    item.get(
                                        "confidence",
                                        "unknown",
                                    )
                                )
                            ),
                            (
                                "country="
                                + self._scalar(
                                    item.get(
                                        "country",
                                        "UNKNOWN",
                                    )
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        lines.extend([
            "",
            "## Hunting",
            "",
        ])

        hunting = self._list(
            document.get(
                "hunting"
            )
        )

        if hunting:
            for finding in hunting:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                finding.get(
                                    "incident_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                finding.get(
                                    "type",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                finding.get(
                                    "description",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        lines.extend([
            "",
            "## Evidence",
            "",
        ])

        evidence = self._list(
            document.get(
                "evidence"
            )
        )

        if evidence:
            for item in evidence:
                lines.append(
                    "- "
                    + " | ".join(
                        (
                            self._scalar(
                                item.get(
                                    "case_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "incident_id",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "status",
                                    "UNKNOWN",
                                )
                            ),
                            self._scalar(
                                item.get(
                                    "severity",
                                    "UNKNOWN",
                                )
                            ),
                        )
                    )
                )
        else:
            lines.append(
                "- None"
            )

        return lines

    def _incident_bullets(
        self,
        incidents,
    ):
        if not incidents:
            return [
                "- None"
            ]

        values = []

        for incident in incidents:
            values.append(
                "- "
                + " | ".join(
                    (
                        self._scalar(
                            incident.get(
                                "id",
                                "UNKNOWN",
                            )
                        ),
                        self._scalar(
                            incident.get(
                                "severity",
                                "UNKNOWN",
                            )
                        ),
                        self._scalar(
                            incident.get(
                                "status",
                                "UNKNOWN",
                            )
                        ),
                    )
                )
            )

        return values

    def _period_text(
        self,
        value,
    ):
        if not isinstance(
            value,
            dict,
        ):
            return "unknown"

        label = value.get(
            "label"
        )

        if label:
            return self._scalar(
                label
            )

        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
        )

    @staticmethod
    def _dict(
        value,
    ):
        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _list(
        value,
    ):
        if not isinstance(
            value,
            list,
        ):
            return []

        return [
            item
            for item in value
            if isinstance(
                item,
                dict,
            )
        ]

    @staticmethod
    def _scalar(
        value,
    ):
        if value is None:
            return ""

        return (
            str(
                value
            )
            .replace(
                "\r",
                " ",
            )
            .replace(
                "\n",
                " ",
            )
            .strip()
        )

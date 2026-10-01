import json
from copy import deepcopy
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from engine.presentation.reporting_contract import (
    assert_export_safe,
)


class ReportRenderer:

    SUPPORTED_FORMATS = frozenset(
        {
            "json",
            "markdown",
            "pdf",
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

        if normalized == "pdf":
            return self._render_pdf(
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

    def _render_pdf(
        self,
        document,
    ):
        # Reuse the already-established textual
        # presentation contract so PDF cannot gain
        # access to additional report fields.
        markdown = self._render_markdown(
            document
        )

        buffer = BytesIO()

        pdf = canvas.Canvas(
            buffer,
            pagesize=A4,
            pageCompression=1,
            invariant=1,
        )

        width, height = A4

        left = 50
        right = 50
        top = 50
        bottom = 50

        body_size = 9
        heading_size = 12
        title_size = 15

        usable_width = (
            width
            - left
            - right
        )

        y = height - top

        def new_page():
            nonlocal y

            pdf.showPage()
            y = height - top

        def ensure_space(
            needed,
        ):
            nonlocal y

            if y - needed < bottom:
                new_page()

        def draw_line(
            value,
            font_name="Helvetica",
            font_size=body_size,
            leading=12,
        ):
            nonlocal y

            wrapped = self._pdf_wrap(
                value,
                font_name=font_name,
                font_size=font_size,
                max_width=usable_width,
            )

            if not wrapped:
                y -= leading
                return

            for line in wrapped:
                ensure_space(
                    leading
                )

                pdf.setFont(
                    font_name,
                    font_size,
                )

                pdf.drawString(
                    left,
                    y,
                    line,
                )

                y -= leading

        for raw_line in markdown.splitlines():
            line = raw_line.strip()

            if not line:
                ensure_space(8)
                y -= 8
                continue

            if line.startswith("# "):
                draw_line(
                    line[2:],
                    font_name="Helvetica-Bold",
                    font_size=title_size,
                    leading=19,
                )

            elif line.startswith("## "):
                ensure_space(18)
                y -= 4

                draw_line(
                    line[3:],
                    font_name="Helvetica-Bold",
                    font_size=heading_size,
                    leading=16,
                )

            elif line.startswith("- "):
                draw_line(
                    "• " + line[2:],
                    font_name="Helvetica",
                    font_size=body_size,
                    leading=12,
                )

            else:
                draw_line(
                    line,
                    font_name="Helvetica",
                    font_size=body_size,
                    leading=12,
                )

        pdf.save()

        payload = buffer.getvalue()

        if not payload.startswith(
            b"%PDF-"
        ):
            raise ValueError(
                "PDF rendering failed"
            )

        return payload

    @staticmethod
    def _pdf_wrap(
        value,
        font_name,
        font_size,
        max_width,
    ):
        text = (
            str(
                value
                if value is not None
                else ""
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

        if not text:
            return []

        # Built-in Helvetica cannot encode every
        # Unicode character. Replace unsupported
        # glyphs deterministically without loading
        # external font assets.
        safe = text.encode(
            "cp1252",
            errors="replace",
        ).decode(
            "cp1252"
        )

        words = safe.split()

        if not words:
            return []

        lines = []
        current = ""

        def split_token(
            token,
        ):
            chunks = []
            chunk = ""

            for character in token:
                candidate = (
                    chunk + character
                )

                width = stringWidth(
                    candidate,
                    font_name,
                    font_size,
                )

                if (
                    width <= max_width
                    or not chunk
                ):
                    chunk = candidate
                    continue

                chunks.append(
                    chunk
                )

                chunk = character

            if chunk:
                chunks.append(
                    chunk
                )

            return chunks

        for word in words:
            word_chunks = split_token(
                word
            )

            for chunk in word_chunks:
                candidate = (
                    chunk
                    if not current
                    else current + " " + chunk
                )

                width = stringWidth(
                    candidate,
                    font_name,
                    font_size,
                )

                if width <= max_width:
                    current = candidate
                    continue

                if current:
                    lines.append(
                        current
                    )

                current = chunk

        if current:
            lines.append(
                current
            )

        return lines

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

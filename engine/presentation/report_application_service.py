class ReportApplicationService:

    def __init__(
        self,
        document_builder,
        renderer,
        exporter,
    ):
        self.document_builder = (
            document_builder
        )

        self.renderer = renderer
        self.exporter = exporter

    def render(
        self,
        report_type,
        output_format,
        period=None,
        incident_limit=None,
        campaign_limit=None,
        case_limit=None,
    ):
        document = (
            self.document_builder
            .build(
                report_type=report_type,
                period=period,
                incident_limit=incident_limit,
                campaign_limit=campaign_limit,
                case_limit=case_limit,
            )
        )

        return self.renderer.render(
            document,
            output_format,
        )

    def export(
        self,
        report_type,
        output_format,
        basename,
        period=None,
        incident_limit=None,
        campaign_limit=None,
        case_limit=None,
    ):
        content = self.render(
            report_type=report_type,
            output_format=output_format,
            period=period,
            incident_limit=incident_limit,
            campaign_limit=campaign_limit,
            case_limit=case_limit,
        )

        return self.exporter.export(
            content,
            output_format,
            basename,
        )

from copy import deepcopy


class CampaignQueryReadModel:

    DEFAULT_LIMIT = 20
    MAX_LIMIT = 100

    SUMMARY_FIELDS = {
        "id",
        "stage",
        "risk",
        "updated",
    }

    DETAIL_FIELDS = {
        "id",
        "created",
        "updated",
        "stage",
        "risk",
        "incidents",
        "entities",
        "tactics",
        "timeline",
    }

    def __init__(
        self,
        campaign_repository,
    ):
        self.campaign_repository = (
            campaign_repository
        )

    def recent(
        self,
        limit=DEFAULT_LIMIT,
    ):
        bounded = self._limit(
            limit
        )

        campaigns = (
            self.campaign_repository
            .list_recent(
                limit=bounded
            )
        )

        return [
            self._summary_view(
                campaign
            )
            for campaign in campaigns
        ]

    def get(
        self,
        campaign_id,
    ):
        normalized = str(
            campaign_id
            if campaign_id is not None
            else ""
        ).strip()

        if not normalized:
            return None

        campaign = (
            self.campaign_repository
            .get(
                normalized
            )
        )

        if not campaign:
            return None

        return self._detail_view(
            campaign
        )

    @classmethod
    def _limit(
        cls,
        value,
    ):
        try:
            normalized = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            normalized = (
                cls.DEFAULT_LIMIT
            )

        if normalized <= 0:
            return 0

        return min(
            normalized,
            cls.MAX_LIMIT,
        )

    @classmethod
    def _summary_view(
        cls,
        campaign,
    ):
        campaign = (
            campaign
            if isinstance(
                campaign,
                dict,
            )
            else {}
        )

        entities = (
            campaign.get(
                "entities"
            )
            if isinstance(
                campaign.get(
                    "entities"
                ),
                dict,
            )
            else {}
        )

        ips = (
            entities.get(
                "ip"
            )
            if isinstance(
                entities.get(
                    "ip"
                ),
                list,
            )
            else []
        )

        return {
            "id": campaign.get(
                "id"
            ),
            "ip": (
                ips[0]
                if ips
                else "-"
            ),
            "stage": campaign.get(
                "stage"
            ),
            "risk": campaign.get(
                "risk",
                0,
            ),
            "incidents": len(
                campaign.get(
                    "incidents",
                    [],
                )
                if isinstance(
                    campaign.get(
                        "incidents"
                    ),
                    list,
                )
                else []
            ),
            "updated": campaign.get(
                "updated"
            ),
        }

    @classmethod
    def _detail_view(
        cls,
        campaign,
    ):
        campaign = (
            campaign
            if isinstance(
                campaign,
                dict,
            )
            else {}
        )

        projected = {
            key: deepcopy(
                campaign.get(
                    key
                )
            )
            for key
            in cls.DETAIL_FIELDS
        }

        entities = (
            projected.get(
                "entities"
            )
            if isinstance(
                projected.get(
                    "entities"
                ),
                dict,
            )
            else {}
        )

        projected[
            "entities"
        ] = {
            key: deepcopy(
                value
            )
            for key, value
            in entities.items()
            if key in {
                "ip",
                "user",
                "host",
            }
            and isinstance(
                value,
                list,
            )
        }

        for key in (
            "incidents",
            "tactics",
            "timeline",
        ):
            if not isinstance(
                projected.get(
                    key
                ),
                list,
            ):
                projected[key] = []

        return projected

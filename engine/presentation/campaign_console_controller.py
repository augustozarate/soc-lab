from copy import deepcopy


class CampaignConsoleController:

    def __init__(
        self,
        campaign_query_read_model=None,
    ):
        self.campaign_query_read_model = (
            campaign_query_read_model
        )

    def query_campaign(
        self,
        campaign_id,
    ):
        if (
            self.campaign_query_read_model
            is None
        ):
            raise RuntimeError(
                "Campaign query surface "
                "is unavailable"
            )

        return deepcopy(
            self.campaign_query_read_model.get(
                campaign_id
            )
        )

    def query_campaigns(
        self,
        limit=20,
    ):
        if (
            self.campaign_query_read_model
            is None
        ):
            raise RuntimeError(
                "Campaign query surface "
                "is unavailable"
            )

        return deepcopy(
            self.campaign_query_read_model.recent(
                limit=limit
            )
        )

import uuid
from datetime import datetime


class CampaignTracker:

    def __init__(self):

        self.campaigns = {}
        self.active_campaigns = {}

    # =========================================
    # INTERNAL HELPERS
    # =========================================

    def _generate_id(self):

        return str(
            uuid.uuid4()
        )[:8]

    def _now(self):

        return datetime.utcnow().isoformat()

    # =========================================
    # MAIN CORRELATION
    # =========================================

    def correlate(self, incident):

        ip = incident.get("ip")

        # =====================================
        # EXISTING CAMPAIGN
        # =====================================

        if ip in self.active_campaigns:

            campaign = (
                self.active_campaigns[ip]
            )

            self._update_campaign(
                campaign,
                incident
            )

            return campaign, False

        # =====================================
        # NEW CAMPAIGN
        # =====================================

        campaign = (
            self._create_campaign(
                incident
            )
        )

        self.active_campaigns[
            ip
        ] = campaign

        self.campaigns[
            campaign["id"]
        ] = campaign

        return campaign, True

    # =========================================
    # CREATE CAMPAIGN
    # =========================================

    def _create_campaign(
        self,
        incident
    ):

        cid = self._generate_id()
        now = self._now()

        ip = incident.get("ip")

        campaign = {

            "id": cid,

            "created": now,
            "updated": now,

            "incidents": [
                incident["id"]
            ],

            "entities": {

                "ip": (
                    [ip]
                    if ip
                    else []
                ),

                "user": [],
                "host": []
            },

            "timeline": [],

            "risk": incident.get(
                "risk_score",
                0
            ),

            "tactics": [],

            "stage": "INITIAL"
        }

        # =====================================
        # INITIAL TACTIC
        # =====================================

        phase = incident.get(
            "attack_phase",
            {}
        )

        tactic = phase.get(
            "tactic"
        )

        if tactic:

            campaign[
                "tactics"
            ].append(
                tactic
            )

        self._update_stage(
            campaign
        )

        return campaign

    # =========================================
    # UPDATE CAMPAIGN
    # =========================================

    def _update_campaign(
        self,
        campaign,
        incident
    ):

        # =====================================
        # INCIDENT
        # =====================================

        incident_id = incident.get(
            "id"
        )

        if (
            incident_id
            and incident_id
            not in campaign["incidents"]
        ):

            campaign[
                "incidents"
            ].append(
                incident_id
            )

        # =====================================
        # IP ENTITY
        # =====================================

        ip = incident.get("ip")

        if ip:

            ips = (
                campaign[
                    "entities"
                ].setdefault(
                    "ip",
                    []
                )
            )

            if ip not in ips:
                ips.append(ip)

        # =====================================
        # USER ENTITY
        # =====================================

        user = incident.get("user")

        if user:

            users = (
                campaign[
                    "entities"
                ].setdefault(
                    "user",
                    []
                )
            )

            if user not in users:
                users.append(user)

        # =====================================
        # TACTICS
        # =====================================

        phase = incident.get(
            "attack_phase",
            {}
        )

        tactic = phase.get(
            "tactic"
        )

        if (
            tactic
            and tactic
            not in campaign["tactics"]
        ):

            campaign[
                "tactics"
            ].append(
                tactic
            )

        # =====================================
        # CAMPAIGN RISK
        # =====================================

        base_risk = incident.get(
            "risk_score",
            0
        )

        incident_bonus = (
            len(
                campaign["incidents"]
            ) * 2
        )

        campaign["risk"] = min(
            100,
            max(
                campaign.get(
                    "risk",
                    0
                ),
                base_risk
                + incident_bonus
            )
        )

        # =====================================
        # CAMPAIGN STAGE
        # =====================================

        self._update_stage(
            campaign
        )

        campaign["updated"] = (
            self._now()
        )

    # =========================================
    # STAGE CALCULATION
    # =========================================

    def _update_stage(
        self,
        campaign
    ):

        tactics = campaign.get(
            "tactics",
            []
        )

        if "Exfiltration" in tactics:

            stage = "DATA THEFT"

        elif "Persistence" in tactics:

            stage = "ESTABLISHED"

        elif "Lateral Movement" in tactics:

            stage = "SPREADING"

        elif "Credential Access" in tactics:

            stage = "INITIAL ACCESS"

        else:

            stage = "INITIAL"

        campaign["stage"] = stage
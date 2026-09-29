from engine.storage.ai_memory import AIMemory
from engine.services.threat_intel import ThreatIntel
from engine.models.ai_context import AIContext


class AIAnalyst:

    def __init__(self, threat_intel=None):
        self.memory = AIMemory()
        self.ti = threat_intel or ThreatIntel()

    # =========================
    # MAIN ANALYSIS
    # =========================

    def analyze(self, incident, campaign=None, graph=None):

        ctx = self.build_context(
            incident,
            campaign,
            graph
        )

        summary = self.generate_summary(ctx)
        recommendations = self.generate_recommendations(ctx)

        analysis = {
            "severity": ctx.severity,
            "summary": summary,
            "recommendations": recommendations,
            "confidence": self.calculate_confidence(ctx),
            "risk": ctx.risk
        }

        if analysis["confidence"] >= 0.7:
            self.learn(
                ctx,
                analysis
            )

        return analysis

    # =========================

    def learn(self, ctx, analysis):

        tactic = (
            sorted(ctx.mitre)[0]
            if ctx.mitre
            else None
        )

        self.memory.store_incident(
            ctx.id,
            analysis["summary"]
        )

        self.memory.update_ip(
            ctx.ip,
            tactic=tactic,
            risk=ctx.risk
        )

        self.ti.learn_from_incident(
            ctx.ip,
            ctx.risk
        )

    # =========================
    # CONTEXT BUILDER
    # =========================

    def build_context(
        self,
        incident,
        campaign,
        graph
    ):

        risk = incident.get(
            "risk_score",
            0
        )

        ctx = AIContext(
            id=incident.get("id"),
            ip=incident.get("ip"),
            risk=risk,
            severity=self._get_severity(risk),
            campaign=campaign,
            threat_intel=incident.get(
                "threat_intel"
            )
        )

        # =========================
        # MITRE FROM INCIDENT
        # =========================

        attack_phase = incident.get(
            "attack_phase",
            {}
        )

        technique_id = (
            attack_phase.get("technique_id")
            or attack_phase.get("technique")
        )

        if technique_id:

            ctx.mitre.add(
                technique_id
            )

        if ctx.ip:
            ctx.memory = (
                self.memory.get_ip_context(
                    ctx.ip
                )
            )

        if graph:
            try:
                neighbors = graph.get_neighbors(
                    ctx.id
                )

                for edge in neighbors:

                    ctx.relations.append(
                        edge
                    )

                    if edge.get("relation") == "USES":
                        technique = edge.get("to")

                        if technique:
                            ctx.mitre.add(
                                technique
                            )

            except Exception:
                pass

        return ctx

    # =========================
    # NARRATIVE GENERATION
    # =========================

    def generate_summary(self, ctx):

        text = []

        text.append(
            f"Incident {ctx.id} "
            f"involves IP {ctx.ip}."
        )

        # MITRE
        if "T1110" in ctx.mitre:
            text.append(
                "Observed behavior is consistent "
                "with brute-force activity."
            )

        # Risk
        if ctx.severity == "CRITICAL":
            text.append(
                "Threat level is critical and "
                "requires immediate containment."
            )

        elif ctx.severity == "HIGH":
            text.append(
                "Threat level is high and should "
                "be investigated quickly."
            )

        # Campaign
        if ctx.campaign:

            cid = ctx.campaign.get(
                "id",
                "unknown"
            )

            text.append(
                f"Incident is correlated with "
                f"campaign {cid}."
            )

        # Memory
        ip_ctx = ctx.memory

        if ip_ctx:
            text.append(
                f"IP observed "
                f"{ip_ctx.get('seen', 0)} "
                f"previous times."
            )

        # Threat Intel
        ti = ctx.threat_intel or {}

        if ti:
            text.append(
                "Threat reputation classified as "
                f"{ti.get('reputation', 'unknown')}."
            )

        return " ".join(text)

    # =========================

    def generate_recommendations(
        self,
        ctx
    ):

        actions = []

        if "T1110" in ctx.mitre:

            actions.extend([
                "Block source IP",
                "Enable MFA",
                "Review authentication logs"
            ])

        if ctx.severity == "CRITICAL":

            actions.append(
                "Escalate incident to SOC immediately"
            )

        if not actions:
            actions.append(
                "Continue monitoring"
            )

        return list(
            dict.fromkeys(actions)
        )

    # =========================

    def calculate_confidence(
        self,
        ctx
    ):

        confidence = 0.3

        if ctx.threat_intel:
            confidence += 0.25

        if ctx.mitre:
            confidence += 0.25

        if ctx.risk >= 80:
            confidence += 0.15

        if ctx.memory:
            if ctx.memory.get("seen", 0) > 3:
                confidence += 0.05

        if ctx.campaign:
            confidence += 0.05

        return round(
            min(confidence, 0.99),
            2
        )

    # =========================
    # Q&A MODE (ChatGPT style)
    # =========================

    def ask(
        self,
        incident,
        question,
        graph=None,
        campaign=None
    ):

        ctx = self.build_context(
            incident,
            campaign,
            graph
        )

        q = question.lower()

        if "risk" in q:
            return (
                f"The current risk score is "
                f"{ctx.risk} ({ctx.severity})."
            )

        if "block" in q:
            return (
                "Yes, blocking the IP is "
                "strongly recommended."
            )

        if "campaign" in q:

            if ctx.campaign:
                return (
                    "This incident belongs to "
                    f"campaign {ctx.campaign['id']}."
                )

            return "No campaign associated."

        if "what" in q or "happening" in q:
            return self.generate_summary(ctx)

        return "I need more context to answer that."

    # =========================

    def _get_severity(self, risk):

        if risk >= 90:
            return "CRITICAL"

        elif risk >= 70:
            return "HIGH"

        return "MEDIUM"
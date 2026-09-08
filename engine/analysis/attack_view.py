from engine.cli.console_io import safe_print


def render_story(incident):

    safe_print("\n=== ATTACK STORY ===\n")

    safe_print(f"Incident: {incident['id']}")
    safe_print(f"Target IP: {incident['ip']}")
    safe_print(f"Risk: {incident['severity']}")

    story = incident.get("attack_story", {})
    progression = story.get("progression", [])

    safe_print("\nAttack Progression:")
    for stage in progression:
        safe_print(f"  → {stage}")

    # =========================
    # NEW: Predictions
    # =========================

    predictions = incident.get("predictions", [])

    if predictions:
        safe_print("\nLikely Next Attacker Moves:\n")

        for p in predictions:
            safe_print(
                f"  → {p['next_tactic']} "
                f"({p['probability']}%)"
            )

    safe_print("\nAssessment:")

    if incident["severity"] in ("HIGH", "CRITICAL"):
        safe_print("⚠ COMPROMISE LIKELY")
    else:
        safe_print("⚠ UNDER INVESTIGATION")

    safe_print("\nRecommended Actions:")
    safe_print("- Investigate authentication logs")
    safe_print("- Monitor lateral movement")
    safe_print("- Check privileged accounts")
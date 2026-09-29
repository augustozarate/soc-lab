MITRE_HUNT_RULES = {

    "Credential Access": [
        "login_failed",
        "multiple_auth_attempts"
    ],

    "Lateral Movement": [
        "remote_connection",
        "new_source_ip"
    ],

    "Privilege Escalation": [
        "admin_login",
        "privilege_change"
    ],

    "Persistence": [
        "new_service",
        "scheduled_task_created"
    ]
}

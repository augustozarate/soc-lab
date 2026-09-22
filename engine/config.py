import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print(
        "[CONFIG] dotenv not installed, "
        "using system environment variables"
    )

ABUSE_KEY = os.getenv("ABUSE_KEY")
VT_KEY = os.getenv("VT_KEY")


def _env_bool(
    name,
    default
):

    value = os.getenv(name)

    if value is None:
        return default

    return (
        value.strip().lower()
        in {
            "1",
            "true",
            "yes",
            "on"
        }
    )


def _env_choice(
    name,
    default,
    allowed,
):

    value = os.getenv(
        name,
        default
    )

    value = value.strip().lower()

    if value not in allowed:

        allowed_text = ", ".join(
            sorted(allowed)
        )

        raise ValueError(
            f"Invalid {name}: {value}. "
            f"Expected one of: {allowed_text}"
        )

    return value


RESPONSE_MODE = _env_choice(
    "RESPONSE_MODE",
    "simulate",
    {
        "simulate",
        "enforce",
    }
)


RESPONSE_PROTECTED_IPS = tuple(
    value.strip()
    for value in os.getenv(
        "RESPONSE_PROTECTED_IPS",
        ""
    ).split(",")
    if value.strip()
)


RESPONSE_BLOCK_TTL_SECONDS = int(
    os.getenv(
        "RESPONSE_BLOCK_TTL_SECONDS",
        "900"
    )
)

if RESPONSE_BLOCK_TTL_SECONDS <= 0:

    raise ValueError(
        "RESPONSE_BLOCK_TTL_SECONDS "
        "must be greater than 0"
    )


RESPONSE_RECONCILIATION_RETRY_SECONDS = int(
    os.getenv(
        "RESPONSE_RECONCILIATION_RETRY_SECONDS",
        "30"
    )
)

if (
    RESPONSE_RECONCILIATION_RETRY_SECONDS
    < 0
):

    raise ValueError(
        "RESPONSE_RECONCILIATION_RETRY_SECONDS "
        "must be greater than or equal to 0"
    )



NOTIFICATION_RETRY_BASE_SECONDS = int(
    os.getenv(
        "NOTIFICATION_RETRY_BASE_SECONDS",
        "30"
    )
)

if NOTIFICATION_RETRY_BASE_SECONDS < 0:

    raise ValueError(
        "NOTIFICATION_RETRY_BASE_SECONDS "
        "must be greater than or equal to 0"
    )


NOTIFICATION_RETRY_MAX_SECONDS = int(
    os.getenv(
        "NOTIFICATION_RETRY_MAX_SECONDS",
        "900"
    )
)

if (
    NOTIFICATION_RETRY_MAX_SECONDS
    < NOTIFICATION_RETRY_BASE_SECONDS
):

    raise ValueError(
        "NOTIFICATION_RETRY_MAX_SECONDS "
        "must be greater than or equal to "
        "NOTIFICATION_RETRY_BASE_SECONDS"
    )



NOTIFICATION_RATE_LIMIT_WINDOW_SECONDS = int(
    os.getenv(
        "NOTIFICATION_RATE_LIMIT_WINDOW_SECONDS",
        "60"
    )
)

if NOTIFICATION_RATE_LIMIT_WINDOW_SECONDS <= 0:

    raise ValueError(
        "NOTIFICATION_RATE_LIMIT_WINDOW_SECONDS "
        "must be greater than 0"
    )


NOTIFICATION_RATE_LIMIT_EMAIL = int(
    os.getenv(
        "NOTIFICATION_RATE_LIMIT_EMAIL",
        "20"
    )
)

NOTIFICATION_RATE_LIMIT_TELEGRAM = int(
    os.getenv(
        "NOTIFICATION_RATE_LIMIT_TELEGRAM",
        "30"
    )
)

NOTIFICATION_RATE_LIMIT_WEBHOOK = int(
    os.getenv(
        "NOTIFICATION_RATE_LIMIT_WEBHOOK",
        "60"
    )
)


for (
    _name,
    _value,
) in (
    (
        "NOTIFICATION_RATE_LIMIT_EMAIL",
        NOTIFICATION_RATE_LIMIT_EMAIL,
    ),
    (
        "NOTIFICATION_RATE_LIMIT_TELEGRAM",
        NOTIFICATION_RATE_LIMIT_TELEGRAM,
    ),
    (
        "NOTIFICATION_RATE_LIMIT_WEBHOOK",
        NOTIFICATION_RATE_LIMIT_WEBHOOK,
    ),
):

    if _value < 0:

        raise ValueError(
            f"{_name} must be greater "
            "than or equal to 0"
        )


NOTIFICATION_WEBHOOK_ENABLED = _env_bool(
    "NOTIFICATION_WEBHOOK_ENABLED",
    False,
)

NOTIFICATION_WEBHOOK_URL = (
    os.getenv(
        "NOTIFICATION_WEBHOOK_URL",
        "",
    )
    .strip()
)

NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS = float(
    os.getenv(
        "NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS",
        "5",
    )
)

if NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS <= 0:

    raise ValueError(
        "NOTIFICATION_WEBHOOK_TIMEOUT_SECONDS "
        "must be greater than 0"
    )


NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES = int(
    os.getenv(
        "NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES",
        "16384",
    )
)

if NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES <= 0:

    raise ValueError(
        "NOTIFICATION_WEBHOOK_MAX_PAYLOAD_BYTES "
        "must be greater than 0"
    )


NOTIFICATION_WEBHOOK_AUTH_TOKEN = (
    os.getenv(
        "NOTIFICATION_WEBHOOK_AUTH_TOKEN",
        "",
    )
    .strip()
)

NOTIFICATION_WEBHOOK_CA_BUNDLE = (
    os.getenv(
        "NOTIFICATION_WEBHOOK_CA_BUNDLE",
        "",
    )
    .strip()
)


NOTIFICATION_EMAIL_ENABLED = _env_bool(
    "NOTIFICATION_EMAIL_ENABLED",
    False,
)

NOTIFICATION_EMAIL_HOST = (
    os.getenv(
        "NOTIFICATION_EMAIL_HOST",
        "",
    )
    .strip()
)

NOTIFICATION_EMAIL_PORT = int(
    os.getenv(
        "NOTIFICATION_EMAIL_PORT",
        "465",
    )
)

if not (
    1
    <= NOTIFICATION_EMAIL_PORT
    <= 65535
):

    raise ValueError(
        "NOTIFICATION_EMAIL_PORT "
        "must be between 1 and 65535"
    )


NOTIFICATION_EMAIL_SECURITY = _env_choice(
    "NOTIFICATION_EMAIL_SECURITY",
    "ssl",
    {
        "ssl",
        "starttls",
    },
)


NOTIFICATION_EMAIL_TIMEOUT_SECONDS = float(
    os.getenv(
        "NOTIFICATION_EMAIL_TIMEOUT_SECONDS",
        "5",
    )
)

if NOTIFICATION_EMAIL_TIMEOUT_SECONDS <= 0:

    raise ValueError(
        "NOTIFICATION_EMAIL_TIMEOUT_SECONDS "
        "must be greater than 0"
    )


NOTIFICATION_EMAIL_USERNAME = (
    os.getenv(
        "NOTIFICATION_EMAIL_USERNAME",
        "",
    )
    .strip()
)

NOTIFICATION_EMAIL_PASSWORD = (
    os.getenv(
        "NOTIFICATION_EMAIL_PASSWORD",
        "",
    )
)

NOTIFICATION_EMAIL_FROM = (
    os.getenv(
        "NOTIFICATION_EMAIL_FROM",
        "",
    )
    .strip()
)

NOTIFICATION_EMAIL_TO = (
    os.getenv(
        "NOTIFICATION_EMAIL_TO",
        "",
    )
    .strip()
)

NOTIFICATION_EMAIL_CA_BUNDLE = (
    os.getenv(
        "NOTIFICATION_EMAIL_CA_BUNDLE",
        "",
    )
    .strip()
)


NOTIFICATION_TELEGRAM_ENABLED = _env_bool(
    "NOTIFICATION_TELEGRAM_ENABLED",
    False,
)

NOTIFICATION_TELEGRAM_BOT_TOKEN = (
    os.getenv(
        "NOTIFICATION_TELEGRAM_BOT_TOKEN",
        "",
    )
    .strip()
)

NOTIFICATION_TELEGRAM_CHAT_ID = (
    os.getenv(
        "NOTIFICATION_TELEGRAM_CHAT_ID",
        "",
    )
    .strip()
)

NOTIFICATION_TELEGRAM_TIMEOUT_SECONDS = float(
    os.getenv(
        "NOTIFICATION_TELEGRAM_TIMEOUT_SECONDS",
        "5",
    )
)

if NOTIFICATION_TELEGRAM_TIMEOUT_SECONDS <= 0:

    raise ValueError(
        "NOTIFICATION_TELEGRAM_TIMEOUT_SECONDS "
        "must be greater than 0"
    )


NOTIFICATION_TELEGRAM_MAX_MESSAGE_CHARS = int(
    os.getenv(
        "NOTIFICATION_TELEGRAM_MAX_MESSAGE_CHARS",
        "3500",
    )
)

if not (
    1
    <= NOTIFICATION_TELEGRAM_MAX_MESSAGE_CHARS
    <= 4096
):

    raise ValueError(
        "NOTIFICATION_TELEGRAM_MAX_MESSAGE_CHARS "
        "must be between 1 and 4096"
    )


NOTIFICATION_TELEGRAM_CA_BUNDLE = (
    os.getenv(
        "NOTIFICATION_TELEGRAM_CA_BUNDLE",
        "",
    )
    .strip()
)


THREAT_INTEL_PREFLIGHT_ENABLED = _env_bool(
    "THREAT_INTEL_PREFLIGHT_ENABLED",
    True
)

THREAT_INTEL_PREFLIGHT_HOST = os.getenv(
    "THREAT_INTEL_PREFLIGHT_HOST",
    "1.1.1.1"
)

THREAT_INTEL_PREFLIGHT_PORT = int(
    os.getenv(
        "THREAT_INTEL_PREFLIGHT_PORT",
        "443"
    )
)

THREAT_INTEL_PREFLIGHT_TIMEOUT = float(
    os.getenv(
        "THREAT_INTEL_PREFLIGHT_TIMEOUT",
        "0.10"
    )
)


if not ABUSE_KEY:
    print("[CONFIG] WARNING: ABUSE_KEY not set")

if not VT_KEY:
    print("[CONFIG] WARNING: VT_KEY not set")

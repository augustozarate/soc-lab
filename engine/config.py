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

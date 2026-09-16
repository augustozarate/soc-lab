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

import importlib
import sys

import dotenv


CONFIG_VARIABLES = (
    "ABUSE_KEY",
    "VT_KEY",
    "THREAT_INTEL_PREFLIGHT_ENABLED",
    "THREAT_INTEL_PREFLIGHT_HOST",
    "THREAT_INTEL_PREFLIGHT_PORT",
    "THREAT_INTEL_PREFLIGHT_TIMEOUT",
)


def load_config(
    monkeypatch,
    **overrides,
):
    # Prevent engine.config from loading the
    # developer's real project-level .env file.
    monkeypatch.setattr(
        dotenv,
        "load_dotenv",
        lambda *args, **kwargs: False,
    )

    for name in CONFIG_VARIABLES:
        monkeypatch.delenv(
            name,
            raising=False,
        )

    for name, value in overrides.items():
        monkeypatch.setenv(
            name,
            value,
        )

    sys.modules.pop(
        "engine.config",
        None,
    )

    return importlib.import_module(
        "engine.config"
    )


def test_default_configuration(
    monkeypatch,
):
    config = load_config(
        monkeypatch
    )

    assert config.ABUSE_KEY is None
    assert config.VT_KEY is None

    assert (
        config.THREAT_INTEL_PREFLIGHT_ENABLED
        is True
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_HOST
        == "1.1.1.1"
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_PORT
        == 443
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_TIMEOUT
        == 0.10
    )


def test_environment_overrides(
    monkeypatch,
):
    config = load_config(
        monkeypatch,
        ABUSE_KEY="test-abuse-key",
        VT_KEY="test-vt-key",
        THREAT_INTEL_PREFLIGHT_ENABLED="false",
        THREAT_INTEL_PREFLIGHT_HOST="127.0.0.1",
        THREAT_INTEL_PREFLIGHT_PORT="8443",
        THREAT_INTEL_PREFLIGHT_TIMEOUT="0.25",
    )

    assert (
        config.ABUSE_KEY
        == "test-abuse-key"
    )

    assert (
        config.VT_KEY
        == "test-vt-key"
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_ENABLED
        is False
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_HOST
        == "127.0.0.1"
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_PORT
        == 8443
    )

    assert (
        config.THREAT_INTEL_PREFLIGHT_TIMEOUT
        == 0.25
    )


def test_boolean_true_values(
    monkeypatch,
):
    for value in (
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
        "on",
        "ON",
    ):
        config = load_config(
            monkeypatch,
            THREAT_INTEL_PREFLIGHT_ENABLED=value,
        )

        assert (
            config.THREAT_INTEL_PREFLIGHT_ENABLED
            is True
        )


def test_boolean_false_values(
    monkeypatch,
):
    for value in (
        "0",
        "false",
        "FALSE",
        "no",
        "off",
        "anything-else",
    ):
        config = load_config(
            monkeypatch,
            THREAT_INTEL_PREFLIGHT_ENABLED=value,
        )

        assert (
            config.THREAT_INTEL_PREFLIGHT_ENABLED
            is False
        )

import pytest

from engine.services.response_safety_policy import (
    ResponseSafetyPolicy,
)


def test_protected_ipv4_is_detected():

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    assert (
        policy.is_protected(
            "192.168.20.128"
        )
        is True
    )


def test_unprotected_ipv4_is_allowed():

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    assert (
        policy.is_protected(
            "192.168.20.130"
        )
        is False
    )


def test_protected_ip_is_canonicalized():

    policy = ResponseSafetyPolicy(
        protected_ips=[
            " 192.168.20.128 ",
        ]
    )

    assert (
        policy.protected_ips
        == frozenset(
            {
                "192.168.20.128",
            }
        )
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-an-ip",
        "::1",
        "2001:db8::1",
    ],
)
def test_invalid_protected_configuration_fails(
    value,
):

    with pytest.raises(
        ValueError
    ):
        ResponseSafetyPolicy(
            protected_ips=[
                value,
            ]
        )


def test_invalid_action_target_is_not_misclassified():

    policy = ResponseSafetyPolicy(
        protected_ips=[
            "192.168.20.128",
        ]
    )

    assert (
        policy.is_protected(
            "invalid"
        )
        is False
    )

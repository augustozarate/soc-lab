import os

from threema.gateway.key import Key

from engine.services.threema_connection_factory import (
    ThreemaSecureConnectionFactory,
)


class ConnectionRecorder:

    calls = []

    def __init__(
        self,
        **kwargs,
    ):

        self.kwargs = kwargs

        self.__class__.calls.append(
            kwargs
        )


def private_key_text():

    private_key, _ = (
        Key.generate_pair()
    )

    return Key.encode(
        private_key
    )


def public_key_text():

    _, public_key = (
        Key.generate_pair()
    )

    return Key.encode(
        public_key
    )


def write_private_key(
    path,
):

    path.write_text(
        private_key_text()
        + "\n",
        encoding="utf-8",
    )

    os.chmod(
        path,
        0o600,
    )


def factory(
    path,
    **kwargs,
):

    return (
        ThreemaSecureConnectionFactory(
            gateway_id=kwargs.get(
                "gateway_id",
                "*ABC1234",
            ),
            api_secret=kwargs.get(
                "api_secret",
                "TEST-SECRET-DO-NOT-LOG",
            ),
            private_key_file=path,
            connection_class=(
                kwargs.get(
                    "connection_class",
                    ConnectionRecorder,
                )
            ),
        )
    )


def test_valid_private_key_builds_blocking_connection(
    tmp_path,
):

    ConnectionRecorder.calls.clear()

    key_file = (
        tmp_path
        / "sender.key"
    )

    write_private_key(
        key_file
    )

    result = factory(
        key_file
    ).build()

    assert isinstance(
        result,
        ConnectionRecorder,
    )

    assert len(
        ConnectionRecorder.calls
    ) == 1

    call = (
        ConnectionRecorder.calls[0]
    )

    assert (
        call["identity"]
        == "*ABC1234"
    )

    assert (
        call["secret"]
        == "TEST-SECRET-DO-NOT-LOG"
    )

    assert (
        call["blocking"]
        is True
    )

    assert "key_file" not in call

    encoded = Key.encode(
        call["key"]
    )

    assert encoded.startswith(
        "private:"
    )


def test_missing_private_key_is_rejected(
    tmp_path,
):

    missing = (
        tmp_path
        / "missing.key"
    )

    try:

        factory(
            missing
        ).build()

    except ValueError as error:

        assert str(
            error
        ) == (
            "Threema private key file "
            "does not exist"
        )

    else:

        raise AssertionError(
            "Missing private key accepted"
        )


def test_symlink_private_key_is_rejected(
    tmp_path,
):

    real = (
        tmp_path
        / "real.key"
    )

    link = (
        tmp_path
        / "link.key"
    )

    write_private_key(
        real
    )

    link.symlink_to(
        real
    )

    try:

        factory(
            link
        ).build()

    except ValueError as error:

        assert "symbolic link" in str(
            error
        )

    else:

        raise AssertionError(
            "Symlink key accepted"
        )


def test_permissive_private_key_mode_is_rejected(
    tmp_path,
):

    key_file = (
        tmp_path
        / "sender.key"
    )

    write_private_key(
        key_file
    )

    os.chmod(
        key_file,
        0o644,
    )

    try:

        factory(
            key_file
        ).build()

    except ValueError as error:

        assert (
            "permissions are too broad"
            in str(error)
        )

    else:

        raise AssertionError(
            "Permissive key accepted"
        )


def test_public_key_file_is_rejected(
    tmp_path,
):

    key_file = (
        tmp_path
        / "sender.key"
    )

    key_file.write_text(
        public_key_text()
        + "\n",
        encoding="utf-8",
    )

    os.chmod(
        key_file,
        0o600,
    )

    try:

        factory(
            key_file
        ).build()

    except ValueError as error:

        assert str(
            error
        ) == (
            "Invalid Threema private key"
        )

    else:

        raise AssertionError(
            "Public key accepted as private"
        )


def test_connection_error_is_sanitized(
    tmp_path,
):

    key_file = (
        tmp_path
        / "VERY-SECRET-KEY.key"
    )

    write_private_key(
        key_file
    )

    secret = (
        "ULTRA-SECRET-GATEWAY-VALUE"
    )

    class FailingConnection:

        def __init__(
            self,
            **kwargs,
        ):

            raise RuntimeError(
                "provider failed "
                + kwargs["secret"]
                + " "
                + str(key_file)
            )

    instance = factory(
        key_file,
        api_secret=secret,
        connection_class=(
            FailingConnection
        ),
    )

    try:

        instance.build()

    except RuntimeError as error:

        message = str(
            error
        )

        assert message == (
            "Unable to create secure "
            "Threema connection"
        )

        assert secret not in message
        assert str(
            key_file
        ) not in message

    else:

        raise AssertionError(
            "Connection failure not raised"
        )


def test_credentials_reject_empty_and_newlines(
    tmp_path,
):

    key_file = (
        tmp_path
        / "sender.key"
    )

    write_private_key(
        key_file
    )

    invalid = (
        {
            "gateway_id": "",
        },
        {
            "api_secret": "",
        },
        {
            "gateway_id": (
                "*ABC\n234"
            ),
        },
        {
            "api_secret": (
                "secret\nvalue"
            ),
        },
    )

    for values in invalid:

        try:

            factory(
                key_file,
                **values,
            )

        except ValueError:

            pass

        else:

            raise AssertionError(
                "Invalid credential accepted"
            )

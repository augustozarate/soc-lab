import asyncio

from threema.gateway import e2e
from threema.gateway.key import Key

from engine.services.threema_e2e_client import (
    ThreemaE2EClient,
)


class BlockingConnection:

    blocking = True


class NonBlockingConnection:

    blocking = False


class MessageRecorder:

    instances = []

    def __init__(
        self,
        connection,
        to_id,
        key,
        text,
    ):

        self.connection = connection
        self.to_id = to_id
        self.key = key
        self.text = text
        self.send_count = 0

        # The SDK sync boundary must establish
        # an explicit non-running event loop.
        self.loop = asyncio.get_event_loop()

        assert self.loop is not None
        assert not self.loop.is_running()

        self.__class__.instances.append(
            self
        )

    def send(
        self,
    ):

        self.send_count += 1

        return (
            "0123456789abcdef"
        )


def public_key():

    _, public = Key.generate_pair()

    return Key.encode(
        public
    )


def test_accepts_valid_pinned_public_key():

    client = ThreemaE2EClient(
        connection=BlockingConnection(),
        recipient_id="ABCD1234",
        recipient_public_key=(
            public_key()
        ),
        message_class=MessageRecorder,
    )

    assert (
        client.recipient_id
        == "ABCD1234"
    )

    assert (
        client.recipient_public_key
        is not None
    )


def test_private_key_is_rejected_as_recipient_key():

    private, _ = Key.generate_pair()

    encoded_private = Key.encode(
        private
    )

    try:

        ThreemaE2EClient(
            connection=BlockingConnection(),
            recipient_id="ABCD1234",
            recipient_public_key=(
                encoded_private
            ),
            message_class=MessageRecorder,
        )

    except ValueError as error:

        assert str(
            error
        ) == (
            "Invalid Threema recipient "
            "public key"
        )

    else:

        raise AssertionError(
            "Private key accepted as "
            "recipient public key"
        )


def test_invalid_recipient_ids_are_rejected():

    values = (
        "",
        "SHORT",
        "TOO-LONG-ID",
        "ABC\n1234",
    )

    for value in values:

        try:

            ThreemaE2EClient(
                connection=(
                    BlockingConnection()
                ),
                recipient_id=value,
                recipient_public_key=(
                    public_key()
                ),
                message_class=(
                    MessageRecorder
                ),
            )

        except ValueError:
            pass

        else:

            raise AssertionError(
                "Invalid recipient ID "
                "was accepted"
            )


def test_nonblocking_connection_is_rejected():

    try:

        ThreemaE2EClient(
            connection=(
                NonBlockingConnection()
            ),
            recipient_id="ABCD1234",
            recipient_public_key=(
                public_key()
            ),
            message_class=MessageRecorder,
        )

    except ValueError as error:

        assert (
            "blocking mode"
            in str(error)
        )

    else:

        raise AssertionError(
            "Non-blocking connection accepted"
        )


def test_send_uses_explicit_pinned_key_once():

    MessageRecorder.instances.clear()

    connection = BlockingConnection()

    client = ThreemaE2EClient(
        connection=connection,
        recipient_id="ABCD1234",
        recipient_public_key=(
            public_key()
        ),
        message_class=MessageRecorder,
    )

    result = client.send_text(
        "[SOC][HIGH]\nIncident: test"
    )

    assert result == (
        "0123456789abcdef"
    )

    assert len(
        MessageRecorder.instances
    ) == 1

    message = (
        MessageRecorder.instances[0]
    )

    assert message.connection is connection

    assert (
        message.to_id
        == "ABCD1234"
    )

    assert (
        message.key
        is client.recipient_public_key
    )

    assert (
        message.text
        == "[SOC][HIGH]\nIncident: test"
    )

    assert message.send_count == 1


def test_real_sdk_encrypts_locally_without_lookup_or_network():

    sender_private, _ = (
        Key.generate_pair()
    )

    _, recipient_public = (
        Key.generate_pair()
    )

    class LocalConnection:

        def __init__(
            self,
        ):

            self.blocking = True
            self.unwrap = self
            self.id = "*LABTEST"
            self.key = sender_private

            self.lookup_count = 0
            self.network_count = 0

        async def get_public_key(
            self,
            id_,
        ):

            self.lookup_count += 1

            raise AssertionError(
                "Dynamic public-key lookup "
                "must not occur"
            )

        async def send_e2e(
            self,
            **data,
        ):

            self.network_count += 1

            raise AssertionError(
                "Network send must not occur"
            )

    connection = LocalConnection()

    # threema.gateway 8.0.0 uses its synchronous
    # aio_run_proxy around asyncio.get_event_loop().
    # Python 3.12 requires an explicit current loop
    # to avoid the SDK deprecation boundary.
    loop = asyncio.new_event_loop()

    try:

        asyncio.set_event_loop(
            loop
        )

        message = e2e.TextMessage(
            connection,
            to_id="ABCD1234",
            key=recipient_public,
            text=(
                "[SOC][HIGH]\n"
                "Incident: local-crypto-test"
            ),
        )

        nonce, box = message.send(
            get_data_only=True
        )

    finally:

        asyncio.set_event_loop(
            None
        )

        loop.close()

    assert isinstance(
        nonce,
        bytes,
    )

    assert len(
        nonce
    ) == 24

    assert isinstance(
        box,
        bytes,
    )

    assert len(
        box
    ) > 0

    assert (
        connection.lookup_count
        == 0
    )

    assert (
        connection.network_count
        == 0
    )

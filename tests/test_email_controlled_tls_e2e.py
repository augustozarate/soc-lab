import base64
import socket
import ssl
import subprocess
import threading

from email import policy
from email.parser import (
    BytesParser,
)
from pathlib import Path
from tempfile import (
    TemporaryDirectory,
)

from engine.services.email_notification_adapter import (
    EmailNotificationAdapter,
)

from engine.services.notification_service import (
    NotificationService,
)


class ControlledSMTPSSLServer:

    def __init__(
        self,
        cert_file,
        key_file,
        username,
        password,
    ):

        self.cert_file = cert_file
        self.key_file = key_file
        self.username = username
        self.password = password

        self.authenticated = False
        self.auth_username = None

        self.mail_from = None
        self.rcpt_to = None
        self.raw_message = None

        self.error = None

        self.listener = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        self.listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        self.listener.bind(
            (
                "127.0.0.1",
                0,
            )
        )

        self.listener.listen(
            1
        )

        self.listener.settimeout(
            10
        )

        self.port = (
            self.listener
            .getsockname()[1]
        )

        self.thread = threading.Thread(
            target=self._serve,
            daemon=True,
        )

    def start(
        self,
    ):

        self.thread.start()

    def join(
        self,
    ):

        self.thread.join(
            timeout=10
        )

        if self.thread.is_alive():

            raise AssertionError(
                "Controlled SMTP server "
                "did not stop"
            )

        if self.error is not None:

            raise self.error

    def _write(
        self,
        writer,
        line,
    ):

        writer.write(
            line.encode(
                "ascii"
            )
            + b"\r\n"
        )

        writer.flush()

    def _address(
        self,
        line,
    ):

        value = line.split(
            ":",
            1,
        )[1].strip()

        value = value.split(
            " ",
            1,
        )[0]

        return value.strip(
            "<>"
        )

    def _authenticate_plain(
        self,
        reader,
        writer,
        line,
    ):

        parts = line.split(
            " ",
            2,
        )

        if len(parts) == 3:

            encoded = parts[2]

        else:

            self._write(
                writer,
                "334 ",
            )

            encoded = (
                reader
                .readline()
                .decode(
                    "ascii",
                    errors="replace",
                )
                .strip()
            )

        try:

            decoded = (
                base64
                .b64decode(
                    encoded,
                    validate=True,
                )
                .decode(
                    "utf-8"
                )
            )

        except Exception:

            self._write(
                writer,
                "535 Authentication failed",
            )

            return

        fields = decoded.split(
            "\x00"
        )

        if len(fields) < 3:

            self._write(
                writer,
                "535 Authentication failed",
            )

            return

        username = fields[-2]
        password = fields[-1]

        if (
            username != self.username
            or password != self.password
        ):

            self._write(
                writer,
                "535 Authentication failed",
            )

            return

        self.authenticated = True
        self.auth_username = username

        self._write(
            writer,
            "235 Authentication successful",
        )

    def _read_data(
        self,
        reader,
    ):

        chunks = []

        while True:

            line = reader.readline()

            if not line:

                break

            if line == b".\r\n":

                break

            if line.startswith(
                b".."
            ):

                line = line[1:]

            chunks.append(
                line
            )

        return b"".join(
            chunks
        )

    def _serve(
        self,
    ):

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )

        context.load_cert_chain(
            certfile=self.cert_file,
            keyfile=self.key_file,
        )

        try:

            connection, _ = (
                self.listener.accept()
            )

            with connection:

                with context.wrap_socket(
                    connection,
                    server_side=True,
                ) as tls_socket:

                    tls_socket.settimeout(
                        10
                    )

                    reader = (
                        tls_socket.makefile(
                            "rb"
                        )
                    )

                    writer = (
                        tls_socket.makefile(
                            "wb"
                        )
                    )

                    try:

                        self._write(
                            writer,
                            (
                                "220 localhost "
                                "ESMTP controlled-lab"
                            ),
                        )

                        while True:

                            raw = reader.readline()

                            if not raw:
                                break

                            line = (
                                raw.decode(
                                    "utf-8",
                                    errors="replace",
                                )
                                .rstrip(
                                    "\r\n"
                                )
                            )

                            upper = line.upper()

                            if upper.startswith(
                                "EHLO "
                            ):

                                writer.write(
                                    b"250-localhost\r\n"
                                    b"250-AUTH PLAIN\r\n"
                                    b"250 SIZE 1048576\r\n"
                                )

                                writer.flush()

                            elif upper.startswith(
                                "HELO "
                            ):

                                self._write(
                                    writer,
                                    "250 localhost",
                                )

                            elif upper.startswith(
                                "AUTH PLAIN"
                            ):

                                self._authenticate_plain(
                                    reader,
                                    writer,
                                    line,
                                )

                            elif upper.startswith(
                                "MAIL FROM:"
                            ):

                                if not self.authenticated:

                                    self._write(
                                        writer,
                                        (
                                            "530 Authentication "
                                            "required"
                                        ),
                                    )

                                    continue

                                self.mail_from = (
                                    self._address(
                                        line
                                    )
                                )

                                self._write(
                                    writer,
                                    "250 Sender OK",
                                )

                            elif upper.startswith(
                                "RCPT TO:"
                            ):

                                self.rcpt_to = (
                                    self._address(
                                        line
                                    )
                                )

                                self._write(
                                    writer,
                                    "250 Recipient OK",
                                )

                            elif upper == "DATA":

                                self._write(
                                    writer,
                                    (
                                        "354 End data with "
                                        "<CR><LF>.<CR><LF>"
                                    ),
                                )

                                self.raw_message = (
                                    self._read_data(
                                        reader
                                    )
                                )

                                self._write(
                                    writer,
                                    "250 Message accepted",
                                )

                            elif upper == "RSET":

                                self._write(
                                    writer,
                                    "250 Reset OK",
                                )

                            elif upper == "NOOP":

                                self._write(
                                    writer,
                                    "250 OK",
                                )

                            elif upper == "QUIT":

                                self._write(
                                    writer,
                                    "221 Bye",
                                )

                                break

                            else:

                                self._write(
                                    writer,
                                    (
                                        "500 Unsupported "
                                        "command"
                                    ),
                                )

                    finally:

                        writer.close()
                        reader.close()

        except Exception as error:

            self.error = error

        finally:

            self.listener.close()


class DeliveryRepository:

    def __init__(
        self,
    ):

        self.success = None
        self.failed = None

    def claim_delivery(
        self,
        **kwargs,
    ):

        return {
            "status": "CLAIMED",
            "attempt_count": 1,
        }

    def mark_success(
        self,
        **kwargs,
    ):

        self.success = kwargs

        return True

    def mark_failed(
        self,
        **kwargs,
    ):

        self.failed = kwargs

        return True


def create_certificate(
    directory,
):

    cert_file = (
        Path(directory)
        / "smtp-cert.pem"
    )

    key_file = (
        Path(directory)
        / "smtp-key.pem"
    )

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(
                key_file
            ),
            "-out",
            str(
                cert_file
            ),
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            (
                "subjectAltName="
                "IP:127.0.0.1,"
                "DNS:localhost"
            ),
            "-addext",
            (
                "basicConstraints="
                "critical,CA:TRUE"
            ),
            "-addext",
            (
                "keyUsage=critical,"
                "digitalSignature,"
                "keyEncipherment,"
                "keyCertSign"
            ),
            "-addext",
            (
                "extendedKeyUsage="
                "serverAuth"
            ),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return (
        cert_file,
        key_file,
    )


def test_controlled_smtp_ssl_end_to_end():

    username = (
        "soc-lab-user"
    )

    password = (
        "LAB-SMTP-SECRET"
    )

    with TemporaryDirectory(
        prefix=(
            "soc-email-e2e-"
        )
    ) as directory:

        (
            cert_file,
            key_file,
        ) = create_certificate(
            directory
        )

        server = (
            ControlledSMTPSSLServer(
                cert_file=str(
                    cert_file
                ),
                key_file=str(
                    key_file
                ),
                username=username,
                password=password,
            )
        )

        server.start()

        repository = (
            DeliveryRepository()
        )

        adapter = (
            EmailNotificationAdapter(
                host="127.0.0.1",
                port=server.port,
                security="ssl",
                timeout_seconds=5,
                sender=(
                    "soc@example.invalid"
                ),
                recipient=(
                    "analyst@example.invalid"
                ),
                username=username,
                password=password,
                ca_bundle=str(
                    cert_file
                ),
            )
        )

        service = (
            NotificationService(
                adapters={
                    "email": adapter,
                },
                delivery_repository=(
                    repository
                ),
            )
        )

        outcome = service.dispatch(
            {
                "incident_id": (
                    "controlled-email-e2e"
                ),
                "event_type": (
                    "incident_persisted"
                ),
                "severity": (
                    "CRITICAL"
                ),
                "risk_score": 99.0,
                "dedup_key": (
                    "notification:"
                    "controlled-email-e2e:"
                    "state"
                ),
                "channels": [
                    "email"
                ],
            },
            {
                "id": (
                    "controlled-email-e2e"
                ),
                "ip": (
                    "192.168.20.130"
                ),
                "alerts": [
                    {
                        "rule_id": (
                            "WIN_FAILED_LOGIN"
                        ),
                        "mitre": {
                            "technique_id": (
                                "T1110"
                            ),
                        },
                        "raw_event": (
                            "DO-NOT-EXPORT"
                        ),
                    }
                ],
                "response_actions": [
                    {
                        "type": (
                            "BLOCK_IP"
                        ),
                        "target": (
                            "192.168.20.130"
                        ),
                        "status": (
                            "SUCCESS"
                        ),
                        "execution_mode": (
                            "ENFORCED"
                        ),
                        "backend": (
                            "windows_firewall"
                        ),
                        "debug_secret": (
                            "DO-NOT-EXPORT"
                        ),
                    }
                ],
                "internal_secret": (
                    "DO-NOT-EXPORT"
                ),
            },
        )

        server.join()

        assert outcome == [
            {
                "channel": "email",
                "status": "SUCCESS",
                "backend": "smtp_ssl",
            }
        ]

        assert (
            server.authenticated
            is True
        )

        assert (
            server.auth_username
            == username
        )

        assert (
            server.mail_from
            == "soc@example.invalid"
        )

        assert (
            server.rcpt_to
            == "analyst@example.invalid"
        )

        assert (
            server.raw_message
            is not None
        )

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            server.raw_message
        )

        assert (
            message["From"]
            == "soc@example.invalid"
        )

        assert (
            message["To"]
            == "analyst@example.invalid"
        )

        assert (
            message["Subject"]
            == (
                "[SOC][CRITICAL] "
                "Incident controlled-email-e2e"
            )
        )

        body = (
            message.get_content()
        )

        assert (
            "Incident ID: "
            "controlled-email-e2e"
            in body
        )

        assert (
            "Severity: CRITICAL"
            in body
        )

        assert (
            "Risk Score: 99.0"
            in body
        )

        assert (
            "Source IP: 192.168.20.130"
            in body
        )

        assert (
            "MITRE: T1110"
            in body
        )

        assert (
            "- WIN_FAILED_LOGIN"
            in body
        )

        assert (
            "- BLOCK_IP | "
            "SUCCESS | ENFORCED"
            in body
        )

        serialized = (
            server.raw_message.decode(
                "utf-8",
                errors="replace",
            )
        )

        forbidden = (
            password,
            "DO-NOT-EXPORT",
            "windows_firewall",
            (
                "notification:"
                "controlled-email-e2e:"
                "state"
            ),
        )

        for value in forbidden:

            assert (
                value
                not in serialized
            )

        assert (
            repository.success
            is not None
        )

        assert (
            repository.failed
            is None
        )

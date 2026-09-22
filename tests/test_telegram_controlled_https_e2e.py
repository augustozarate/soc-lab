import json
import ssl
import subprocess
import threading

from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from tempfile import (
    TemporaryDirectory,
)

from engine.services.notification_service import (
    NotificationService,
)

from engine.services.telegram_notification_adapter import (
    TelegramNotificationAdapter,
)


FAKE_TOKEN = (
    "123456:"
    "CONTROLLED-TELEGRAM-LAB-TOKEN"
)

CHAT_ID = (
    "-1001234567890"
)


class ControlledTelegramHandler(
    BaseHTTPRequestHandler
):

    server_version = (
        "SOCControlledTelegram/1.0"
    )

    protocol_version = "HTTP/1.1"

    def log_message(
        self,
        format,
        *args,
    ):

        # Never emit the request path because it
        # contains the Telegram bot token.
        return

    def do_POST(
        self,
    ):

        state = self.server.state

        state[
            "request_count"
        ] += 1

        state[
            "method"
        ] = "POST"

        state[
            "path"
        ] = self.path

        state[
            "content_type"
        ] = self.headers.get(
            "Content-Type"
        )

        length = int(
            self.headers.get(
                "Content-Length",
                "0",
            )
        )

        raw = self.rfile.read(
            length
        )

        state[
            "raw_body"
        ] = raw

        try:

            payload = json.loads(
                raw.decode(
                    "utf-8"
                )
            )

        except Exception:

            payload = None

        state[
            "payload"
        ] = payload

        expected_path = (
            f"/bot{FAKE_TOKEN}"
            "/sendMessage"
        )

        if (
            self.path
            != expected_path
        ):

            response = {
                "ok": False,
            }

            encoded = json.dumps(
                response
            ).encode(
                "utf-8"
            )

            self.send_response(
                404
            )

            self.send_header(
                "Content-Type",
                "application/json",
            )

            self.send_header(
                "Content-Length",
                str(
                    len(encoded)
                ),
            )

            self.end_headers()

            self.wfile.write(
                encoded
            )

            return

        if not isinstance(
            payload,
            dict,
        ):

            response = {
                "ok": False,
            }

            encoded = json.dumps(
                response
            ).encode(
                "utf-8"
            )

            self.send_response(
                400
            )

            self.send_header(
                "Content-Type",
                "application/json",
            )

            self.send_header(
                "Content-Length",
                str(
                    len(encoded)
                ),
            )

            self.end_headers()

            self.wfile.write(
                encoded
            )

            return

        response = {
            "ok": True,
            "result": {
                "message_id": 1,
            },
        }

        encoded = json.dumps(
            response
        ).encode(
            "utf-8"
        )

        self.send_response(
            200
        )

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(
                len(encoded)
            ),
        )

        self.end_headers()

        self.wfile.write(
            encoded
        )


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
        / "telegram-cert.pem"
    )

    key_file = (
        Path(directory)
        / "telegram-key.pem"
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


def test_controlled_telegram_https_end_to_end():

    with TemporaryDirectory(
        prefix=(
            "soc-telegram-e2e-"
        )
    ) as directory:

        (
            cert_file,
            key_file,
        ) = create_certificate(
            directory
        )

        server = ThreadingHTTPServer(
            (
                "127.0.0.1",
                0,
            ),
            ControlledTelegramHandler,
        )

        server.state = {
            "request_count": 0,
            "method": None,
            "path": None,
            "content_type": None,
            "raw_body": None,
            "payload": None,
        }

        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )

        context.load_cert_chain(
            certfile=str(
                cert_file
            ),
            keyfile=str(
                key_file
            ),
        )

        server.socket = (
            context.wrap_socket(
                server.socket,
                server_side=True,
            )
        )

        port = (
            server.server_address[1]
        )

        thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
        )

        thread.start()

        repository = (
            DeliveryRepository()
        )

        try:

            adapter = (
                TelegramNotificationAdapter(
                    bot_token=FAKE_TOKEN,
                    chat_id=CHAT_ID,
                    timeout_seconds=5,
                    max_message_chars=3500,
                    ca_bundle=str(
                        cert_file
                    ),
                    api_base_url=(
                        "https://127.0.0.1:"
                        f"{port}"
                    ),
                )
            )

            service = (
                NotificationService(
                    adapters={
                        "telegram": adapter,
                    },
                    delivery_repository=(
                        repository
                    ),
                )
            )

            outcome = service.dispatch(
                {
                    "incident_id": (
                        "controlled-telegram-e2e"
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
                        "controlled-telegram-e2e:"
                        "state"
                    ),
                    "channels": [
                        "telegram"
                    ],
                },
                {
                    "id": (
                        "controlled-telegram-e2e"
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

        finally:

            server.shutdown()
            server.server_close()

            thread.join(
                timeout=10
            )

        if thread.is_alive():

            raise AssertionError(
                "Controlled HTTPS server "
                "did not stop"
            )

        state = server.state

        assert outcome == [
            {
                "channel": "telegram",
                "status": "SUCCESS",
                "backend": (
                    "telegram_bot_api"
                ),
                "http_status": 200,
            }
        ]

        assert (
            state[
                "request_count"
            ]
            == 1
        )

        assert (
            state[
                "method"
            ]
            == "POST"
        )

        assert (
            state[
                "path"
            ]
            == (
                f"/bot{FAKE_TOKEN}"
                "/sendMessage"
            )
        )

        assert (
            state[
                "content_type"
            ]
            == "application/json"
        )

        payload = state[
            "payload"
        ]

        assert isinstance(
            payload,
            dict,
        )

        assert payload[
            "chat_id"
        ] == CHAT_ID

        text = payload[
            "text"
        ]

        assert (
            "[SOC][CRITICAL]"
            in text
        )

        assert (
            "Incident: "
            "controlled-telegram-e2e"
            in text
        )

        assert (
            "Risk: 99.0"
            in text
        )

        assert (
            "Source IP: 192.168.20.130"
            in text
        )

        assert (
            "MITRE: T1110"
            in text
        )

        assert (
            "- WIN_FAILED_LOGIN"
            in text
        )

        assert (
            "- BLOCK_IP | "
            "SUCCESS | ENFORCED"
            in text
        )

        assert (
            FAKE_TOKEN
            not in text
        )

        assert (
            "DO-NOT-EXPORT"
            not in text
        )

        assert (
            "windows_firewall"
            not in text
        )

        assert (
            "notification:"
            "controlled-telegram-e2e:"
            "state"
            not in text
        )

        serialized_outcome = str(
            outcome
        )

        assert (
            FAKE_TOKEN
            not in serialized_outcome
        )

        assert (
            repository.success
            is not None
        )

        assert (
            repository.failed
            is None
        )

        assert (
            FAKE_TOKEN
            not in str(
                repository.success
            )
        )

        print(
            "result:",
            outcome
        )

        print(
            "receiver path:",
            "/bot<redacted>/sendMessage",
        )

        print(
            "chat_id:",
            payload[
                "chat_id"
            ],
        )

        print()
        print(
            "text:"
        )
        print(
            text
        )

        print()
        print(
            "Controlled Telegram HTTPS receiver: PASS"
        )

        print(
            "TLS certificate verification: PASS"
        )

        print(
            "Fake token path contract: PASS"
        )

        print(
            "Payload allowlist: PASS"
        )

        print(
            "Token exclusion from payload/outcome: PASS"
        )

        print(
            "Durable SUCCESS transition: PASS"
        )

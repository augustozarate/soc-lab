import json


class EventRepository:

    def __init__(self, db):
        self.db = db

    def save(self, event_type, payload):

        data = json.dumps(
            payload,
            default=str,
            ensure_ascii=False
        )

        with self.db.connect() as conn:

            conn.execute(
                """
                INSERT INTO events (
                    event_type,
                    payload,
                    created_at
                )
                VALUES (
                    ?,
                    ?,
                    datetime('now')
                )
                """,
                (
                    event_type,
                    data
                )
            )

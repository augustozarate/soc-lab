from pathlib import Path


class MigrationRunner:

    def __init__(self, db):
        self.db = db

    def run(self):

        schema = (
            Path(__file__)
            .with_name("schema.sql")
            .read_text(
                encoding="utf-8"
            )
        )

        with self.db.connect() as conn:

            conn.execute(
                "PRAGMA journal_mode = WAL"
            )

            conn.executescript(
                schema
            )
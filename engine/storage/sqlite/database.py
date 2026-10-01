from contextlib import contextmanager
import sqlite3


class Database:

    def __init__(self, db_path):
        self.db_path = db_path

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(
            self.db_path,
            timeout=10,
            check_same_thread=False
        )

        conn.row_factory = sqlite3.Row

        conn.execute(
            "PRAGMA foreign_keys = ON"
        )

        conn.execute(
            "PRAGMA busy_timeout = 10000"
        )

        try:
            with conn:
                yield conn
        finally:
            conn.close()

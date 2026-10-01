import sqlite3

import pytest

from engine.storage.sqlite.database import Database


def test_connect_context_closes_connection_on_exit(tmp_path):
    db = Database(tmp_path / "lifecycle.db")

    with db.connect() as conn:
        connection = conn
        result = conn.execute("SELECT 1").fetchone()

        assert result[0] == 1

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")

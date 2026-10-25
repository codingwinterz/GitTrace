"""Data access, with SQL built from strings."""
import sqlite3

DB_PATH = "app.db"


def connect():
    return sqlite3.connect(DB_PATH)


class Repo:
    def __init__(self):
        self.conn = connect()

    def get_user(self, name):
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
        return cursor.fetchone()

    def delete_user(self, user_id):
        def build_query():
            return "DELETE FROM users WHERE id = " + str(user_id)

        self.conn.execute(build_query())
        self._log("deleted")

    def _log(self, message):
        print(message)


class AuditRepo(Repo):
    def get_user(self, name):
        self._log("audit " + name)
        return super().get_user(name)

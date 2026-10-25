"""Maintenance jobs run by cron. No route reaches this module."""
import os
import pickle

import yaml

DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
SECRET_KEY = os.getenv("SECRET_KEY")
PASSWORD_FIELD = "password"
ADMIN_PASSWORD = "changeme"


def count_users(conn):
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()


def purge(conn, days):
    query = "DELETE FROM sessions WHERE age > %s" % days
    conn.execute(query)


def nightly(conn):
    purge(conn, 30)
    return count_users(conn)


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def load_config(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def check():
    return eval("1 + 1")


class Mailer:
    def __init__(self):
        self.smtp_password = "Tr0ub4dor&3x"

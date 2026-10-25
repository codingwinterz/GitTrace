"""Report routes: SQL built from the request, and safe neighbours."""
import yaml
from fastapi import APIRouter

from ..db import connect

router = APIRouter(prefix="/reports")
REPORT_API_KEY = "rk_live_51HxQ2vLs9Kd8Wm3Pq"


@router.get("/by-user")
def by_user(user_id: str, order: str = "name"):
    conn = connect()
    sql = "SELECT * FROM reports WHERE user_id = '" + user_id + "'"
    sql += " ORDER BY " + order
    return conn.execute(sql).fetchall()


@router.get("/count")
def count():
    conn = connect()
    return conn.execute("SELECT COUNT(*) FROM reports").fetchone()


@router.get("/safe/{user_id}")
def safe(user_id: str):
    conn = connect()
    return conn.execute("SELECT * FROM reports WHERE user_id = ?", (user_id,)).fetchall()


@router.post("/import")
def import_report(body: str):
    return yaml.load(body)


@router.get("/version")
def version():
    return {"version": eval("'1.0'")}

"""User views on a blueprint whose url_prefix app.py overrides."""
import pickle

from flask import Blueprint, request

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.route("/<int:uid>")
def show(uid):
    return str(uid)


@bp.post("/import")
def import_data():
    return pickle.loads(request.data)

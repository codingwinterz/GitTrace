"""Admin views behind flask_login."""
from flask import Blueprint
from flask_login import login_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/stats", methods=["GET"])
@login_required
def stats():
    return "stats"

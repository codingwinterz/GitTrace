"""A small Flask app with two blueprints. Never imported or run."""
from flask import Flask

from admin import admin_bp
from views import bp as users_bp

app = Flask(__name__)
app.register_blueprint(users_bp, url_prefix="/u")
app.register_blueprint(admin_bp)


@app.route("/")
def index():
    return "ok"


@app.route("/login", methods=["GET", "POST"])
def login():
    return "login"

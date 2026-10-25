"""Admin routes: the router requires the auth dependency on every route."""
from fastapi import APIRouter, Depends

from app.auth import get_current_user

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_user)])


@router.post("/eval")
def run_expression(expr: str):
    return {"result": eval(expr)}


@router.api_route("/report", methods=["GET", "POST"])
def report():
    def render(rows):
        return "\n".join(str(r) for r in rows)

    return render(load_rows())


def load_rows():
    return [1, 2, 3]

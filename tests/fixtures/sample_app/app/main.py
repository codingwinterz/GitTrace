"""Entry point: the FastAPI app and the routers it includes."""
from fastapi import Depends, FastAPI

from app import Repo
from app.auth import get_current_user
from app.routers import admin, users

app = FastAPI(title="sample")
app.include_router(users.router, prefix="/api")
app.include_router(admin.router, prefix="/api")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/me")
def me(user=Depends(get_current_user)):
    repo = Repo()
    return repo.get_user(user["name"])

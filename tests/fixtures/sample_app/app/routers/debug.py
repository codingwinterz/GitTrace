"""A debug router that main.py never includes."""
import os

from fastapi import APIRouter

router = APIRouter(prefix="/debug")


@router.get("/env")
def dump_env():
    return dict(os.environ)

"""User routes, on a router with its own prefix."""
import subprocess as sp

from fastapi import APIRouter

from ..db import Repo as Repository
from ..utils.shell import run_command

router = APIRouter(prefix="/users")


@router.get("/{name}")
def read_user(name: str):
    repo = Repository()
    return repo.get_user(name)


@router.post("/{user_id}/delete")
def remove_user(user_id: int):
    repo = Repository()
    repo.delete_user(user_id)
    return {"deleted": user_id}


@router.get("/{name}/ping")
async def ping_user(name: str):
    output = sp.check_output("ping -c 1 " + name, shell=True)
    return {"output": output.decode()}


@router.get("/{name}/files")
def list_files(name: str):
    return run_command("ls " + name)

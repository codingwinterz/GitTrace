"""The authentication dependency."""
from fastapi import Header, HTTPException

API_TOKEN = "s3cr3t-token-123"


def get_current_user(x_token: str = Header(...)):
    if x_token != API_TOKEN:
        raise HTTPException(status_code=401)
    return {"name": "admin"}

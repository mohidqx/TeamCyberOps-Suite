"""
TeamCyberOps Suite v3 — Authentication Module
JSON-based multi-user auth with SHA-256 hashing
"""
import json
import hashlib
import os
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "db" / "users.json"


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _load() -> dict:
    if not DB_PATH.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {"users": []}
        _save(data)
        return data
    with open(DB_PATH) as f:
        return json.load(f)


def _save(data: dict):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2)


def login(username: str, password: str) -> dict | None:
    """Returns user dict if credentials valid, else None."""
    data = _load()
    hashed = _hash(password)
    for user in data["users"]:
        if user["username"] == username and user["password"] == hashed and user.get("active", True):
            return user
    return None


def add_user(username: str, password: str, role: str = "member", email: str = "") -> bool:
    """Add a new user. Returns False if username already exists."""
    data = _load()
    if any(u["username"] == username for u in data["users"]):
        return False
    data["users"].append({
        "username": username,
        "password": _hash(password),
        "role": role,
        "email": email,
        "created": datetime.now().strftime("%Y-%m-%d"),
        "active": True
    })
    _save(data)
    return True


def delete_user(username: str) -> bool:
    data = _load()
    before = len(data["users"])
    data["users"] = [u for u in data["users"] if u["username"] != username]
    _save(data)
    return len(data["users"]) < before


def change_password(username: str, new_password: str) -> bool:
    data = _load()
    for user in data["users"]:
        if user["username"] == username:
            user["password"] = _hash(new_password)
            _save(data)
            return True
    return False


def list_users() -> list:
    data = _load()
    return [{"username": u["username"], "role": u["role"],
             "email": u.get("email", ""), "active": u.get("active", True),
             "created": u.get("created", "")} for u in data["users"]]


def toggle_user(username: str) -> bool:
    data = _load()
    for user in data["users"]:
        if user["username"] == username:
            user["active"] = not user.get("active", True)
            _save(data)
            return user["active"]
    return False

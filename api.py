# JSON API for the browser extension. Mounted by main.py under /api/v1.
# Versioned so old extensions keep working when the API changes later.
from contextlib import contextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from core import auth, match, sessions, sharing, storage, vault


router = APIRouter(prefix="/api/v1")
_db_path: Path | None = None


def setup(db_path: Path) -> None:
    # main.py (and tests) tell the API where the database is
    global _db_path
    _db_path = db_path


@contextmanager
def _db():
    # One connection per request, opened and closed in the same thread
    db_connection = storage.db_connect(_db_path)
    try:
        yield db_connection
    finally:
        db_connection.close()


def _token(authorization: str | None) -> str | None:
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip() or None
    return None


def current_session(authorization: str | None = Header(default=None)):
    # Every protected route needs a valid, unexpired token
    token = _token(authorization)
    session = sessions.get(token) if token else None
    if session is None:
        raise HTTPException(status_code=401, detail="Not signed in")
    return session


class LoginBody(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


@router.post("/login")
def login(body: LoginBody, request: Request):
    # Same checks as the web sign-in: lockout, vague errors, timing-safe
    ip_address = request.client.host if request.client else None
    with _db() as db_connection:
        try:
            session = auth.login(db_connection, body.email, body.password, ip_address)
        except auth.InvalidCredentialsError:
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        except auth.AccountLockedError:
            raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")
    return {"token": sessions.create(session), "expires_in": sessions.TIMEOUT_SECONDS}


@router.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    token = _token(authorization)
    if token:
        sessions.destroy(token)
    return {"ok": True}


@router.get("/logins")
def logins_for_page(url: str, session=Depends(current_session)):
    # Logins that match this page. Titles and usernames only, never passwords.
    with _db() as db_connection:
        names = {v.vault_id: v.name for v in sharing.list_vaults(db_connection, session)}
        entries = vault.list_entries(db_connection, session)
    found = [e for e in entries if match.url_matches(e.url, url)]
    found.sort(key=lambda e: e.title.lower())
    return [
        {"id": e.vault_entry_id, "title": e.title, "username": e.username or "",
         "vault": names.get(e.vault_id, "Shared with you")}
        for e in found
    ]


@router.get("/logins/{entry_id}/password")
def login_password(entry_id: str, response: Response, session=Depends(current_session)):
    # One password, only when the user clicks copy. Never cached.
    response.headers["Cache-Control"] = "no-store"
    with _db() as db_connection:
        entry = vault.get_entry(db_connection, session, entry_id)
    if entry is None:
        # Same answer for "doesn't exist" and "not yours"
        raise HTTPException(status_code=404, detail="Not found")
    return {"password": entry.password or ""}

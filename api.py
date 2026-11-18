# JSON API for the browser extension. Mounted by main.py under /api/v1.
# Versioned so old extensions keep working when the API changes later.
from contextlib import contextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from core import auth, generator, match, sessions, sharing, storage, vault


router = APIRouter(prefix="/api/v1")
_db_path: Path | None = None

# Word list for passphrases, loaded once (empty if the file is missing), same file as the app
_wordlist = generator.load_wordlist(Path(__file__).resolve().parent / "core" / "wordlists" / "eff_large_wordlist.txt")
# The separators the app offers: dash, space, period, underscore
PASSPHRASE_SEPARATORS = ("-", " ", ".", "_")


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
            raise HTTPException(
                status_code=429,
                detail="Too many sign-in attempts. Wait 15 minutes and try again.",
                headers={"Retry-After": "900"},
            )
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


class NewVaultBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class NewLoginBody(BaseModel):
    vault_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    url: str = Field(default="", max_length=2048)
    username: str = Field(default="", max_length=320)
    password: str = Field(default="", max_length=1024)
    notes: str = Field(default="", max_length=10000)


@router.get("/vaults")
def list_vaults(session=Depends(current_session)):
    # The user's vaults, and whether they can add to each
    with _db() as db_connection:
        vaults = sharing.list_vaults(db_connection, session)
    return [{"id": v.vault_id, "name": v.name, "can_edit": v.can_edit, "is_owner": v.is_owner}
            for v in vaults]


@router.post("/vaults", status_code=201)
def create_vault(body: NewVaultBody, session=Depends(current_session)):
    # Same rules as the app: name required, no duplicate names among your own vaults
    with _db() as db_connection:
        try:
            vault_id = sharing.create_vault(db_connection, session, body.name)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
    return {"id": vault_id, "name": body.name.strip()}


@router.post("/logins", status_code=201)
def create_login(body: NewLoginBody, session=Depends(current_session)):
    # Same rules as the app: title required, and you must be able to edit the vault
    with _db() as db_connection:
        try:
            entry_id = vault.add_entry(db_connection, session, body.vault_id, body.title.strip(),
                                       body.url.strip(), body.username.strip(), body.password,
                                       body.notes)
        except PermissionError as err:
            raise HTTPException(status_code=403, detail=str(err) or "You can't add logins to that vault.")
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
    return {"id": entry_id}


@router.get("/generate")
def generate(length: int = 20, upper: bool = True, lower: bool = True,
             digits: bool = True, symbols: bool = True, session=Depends(current_session)):
    # A strong password from the same generator the app uses, with the chosen character sets
    if not (upper or lower or digits or symbols):
        raise HTTPException(status_code=400, detail="Pick at least one type of character.")
    try:
        password = generator.generate_password(length, upper=upper, lower=lower,
                                               digits=digits, symbols=symbols)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    return {"password": password}


@router.get("/generate-passphrase")
def generate_passphrase(words: int = 5, separator: str = "-", capitalize: bool = True,
                        number: bool = True, session=Depends(current_session)):
    # Random words from the EFF list, with the same options as the app's generator page
    if not _wordlist:
        raise HTTPException(status_code=503, detail="Passphrases need the word list file on the server.")
    if separator not in PASSPHRASE_SEPARATORS:
        raise HTTPException(status_code=400, detail="Pick a dash, space, period, or underscore.")
    try:
        passphrase = generator.generate_passphrase(_wordlist, count=words, separator=separator,
                                                   capitalize=capitalize, include_number=number)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    return {"password": passphrase}

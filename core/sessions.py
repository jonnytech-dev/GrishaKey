import secrets
import threading
import time

from core.models import Session


TIMEOUT_SECONDS = 15 * 60

# token → (Session, last_active)
_sessions: dict[str, tuple[Session, float]] = {}
_lock = threading.Lock()     # login runs in a background thread, so guard the dict


def create(session: Session, now: float | None = None) -> str:
    with _lock:
        token = secrets.token_urlsafe(32)
        _sessions[token] = (session, now or time.time())
        return token

def get(token: str, now: float | None = None) -> Session | None:
    with _lock:
        # LOOK UP (get) → None if the key isn't there, no crash
        entry = _sessions.get(token)
        if entry is None:
            return None

        # Set now if not provided
        if now is None:
            now = time.time()

        # UNPACK the tuple you stored
        session, last_active = entry

        # Destroy the session in memory if idle time is longer than 15 minutes
        idle = now - last_active
        if idle > TIMEOUT_SECONDS:
            _sessions.pop(token, None)
            return None

        _sessions[token] = (session, now)

        return session


def destroy(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)
import secrets
import threading
import time

from core.models import Session


TIMEOUT_SECONDS = 15 * 60
# A session ends after this long even if it's used the whole time (a stolen token can't live forever)
MAX_LIFETIME_SECONDS = 12 * 60 * 60

# token → (Session, last_active, created_at)
_sessions: dict[str, tuple[Session, float, float]] = {}
_lock = threading.Lock()     # login runs in a background thread, so guard the dict


def create(session: Session, now: float | None = None) -> str:
    with _lock:
        token = secrets.token_urlsafe(32)
        created_at = now or time.time()
        _sessions[token] = (session, created_at, created_at)
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
        session, last_active, created_at = entry

        # Destroy the session in memory if idle time is longer than 15 minutes
        idle = now - last_active
        if idle > TIMEOUT_SECONDS:
            _sessions.pop(token, None)
            return None

        # Destroy it once it's older than the maximum lifetime, even if it was just used
        if now - created_at > MAX_LIFETIME_SECONDS:
            _sessions.pop(token, None)
            return None

        _sessions[token] = (session, now, created_at)

        return session


def destroy(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)


def destroy_user(user_id: str) -> int:
    # Ends every session of one user (web and extension), e.g. after a password change.
    # Returns how many were ended.
    with _lock:
        tokens = [token for token, (session, _, _) in _sessions.items() if session.user_id == user_id]
        for token in tokens:
            _sessions.pop(token, None)
        return len(tokens)

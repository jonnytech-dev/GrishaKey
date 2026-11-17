from core import sessions
from core.models import Session
import os


def fake_session(user_id="jon"):
    # A Session with fake keys, sessions.py never looks inside it
    return Session(
        user_id=user_id,
        role="user",
        private_key=os.urandom(32),
        private_key_nonce=os.urandom(12),
        public_key=os.urandom(32),
    )


class Test_Sessions:
    # A new token returns the same Session
    def test_create_and_get(self):
        session = fake_session()
        token = sessions.create(session, now=1000)
        assert sessions.get(token, now=1001) is session

    # Tokens are long and never repeat
    def test_tokens_are_unique(self):
        a = sessions.create(fake_session(), now=1000)
        b = sessions.create(fake_session(), now=1000)
        assert a != b
        assert len(a) >= 40

    # An unknown token gets nothing
    def test_unknown_token(self):
        assert sessions.get("not-a-real-token", now=1000) is None

    # Idle longer than the timeout → gone
    def test_expires_after_timeout(self):
        token = sessions.create(fake_session(), now=1000)
        assert sessions.get(token, now=1000 + sessions.TIMEOUT_SECONDS + 1) is None

    # Once expired, it stays gone (removed, not just hidden)
    def test_expired_is_removed(self):
        token = sessions.create(fake_session(), now=1000)
        sessions.get(token, now=1000 + sessions.TIMEOUT_SECONDS + 1)
        assert sessions.get(token, now=1001) is None

    # Activity resets the clock
    def test_activity_refreshes(self):
        token = sessions.create(fake_session(), now=1000)
        half = sessions.TIMEOUT_SECONDS // 2
        assert sessions.get(token, now=1000 + half) is not None
        assert sessions.get(token, now=1000 + half * 2 + 10) is not None   # still alive, clock was reset

    # Logout removes it
    def test_destroy(self):
        token = sessions.create(fake_session(), now=1000)
        sessions.destroy(token)
        assert sessions.get(token, now=1001) is None

    # Destroying a missing token doesn't crash
    def test_destroy_missing(self):
        sessions.destroy("not-a-real-token")
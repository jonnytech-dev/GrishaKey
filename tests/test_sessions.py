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

class Test_Session_Lifetime:
    # Even with steady activity, a session ends after the maximum lifetime
    def test_expires_after_max_lifetime(self):
        token = sessions.create(fake_session(), now=1000)
        step = sessions.TIMEOUT_SECONDS - 1
        now = 1000
        while now + step <= 1000 + sessions.MAX_LIFETIME_SECONDS:
            now += step
            assert sessions.get(token, now=now) is not None      # active the whole time
        assert sessions.get(token, now=1000 + sessions.MAX_LIFETIME_SECONDS + 1) is None

    # Once past the lifetime it's removed, not just hidden
    def test_lifetime_expired_is_removed(self):
        token = sessions.create(fake_session(), now=1000)
        sessions._sessions[token] = (sessions._sessions[token][0], 1000 + sessions.MAX_LIFETIME_SECONDS, 1000)
        assert sessions.get(token, now=1000 + sessions.MAX_LIFETIME_SECONDS + 1) is None
        assert token not in sessions._sessions


class Test_Destroy_User:
    # Ends every session of that user (several browsers, the extension), and only theirs
    def test_destroys_all_of_one_user(self):
        jon_web = sessions.create(fake_session("jon-destroy"), now=1000)
        jon_ext = sessions.create(fake_session("jon-destroy"), now=1000)
        amy = sessions.create(fake_session("amy-destroy"), now=1000)
        assert sessions.destroy_user("jon-destroy") == 2
        assert sessions.get(jon_web, now=1001) is None
        assert sessions.get(jon_ext, now=1001) is None
        assert sessions.get(amy, now=1001) is not None

    # No sessions → nothing happens
    def test_unknown_user(self):
        assert sessions.destroy_user("nobody-has-this-id") == 0

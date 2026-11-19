"""Checks on main.py that need the whole app imported: startup rules, security headers,
and ending sessions after a password change or recovery.

main.py reads its settings and creates the database when it's imported, so each check
imports it in a fresh Python process with its own data folder and settings.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOOD_SECRET = "x" * 48


def run_main(tmp_path, code: str, secret: str | None = GOOD_SECRET):
    env = {k: v for k, v in os.environ.items() if k != "STORAGE_SECRET"}
    env["GRISHAKEY_DATA"] = str(tmp_path / "data")
    env["NICEGUI_STORAGE_PATH"] = str(tmp_path / ".nicegui")
    if secret is not None:
        env["STORAGE_SECRET"] = secret
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


class Test_Storage_Secret:
    def test_short_secret_refuses_to_start(self, tmp_path):
        result = run_main(tmp_path, "import main", secret="too-short-secret")
        assert result.returncode != 0
        assert "STORAGE_SECRET is too short" in result.stderr

    def test_missing_secret_refuses_to_start(self, tmp_path):
        result = run_main(tmp_path, "import main", secret=None)
        assert result.returncode != 0
        assert "STORAGE_SECRET is not set" in result.stderr

    def test_long_secret_starts(self, tmp_path):
        result = run_main(tmp_path, "import main; print('loaded')")
        assert result.returncode == 0, result.stderr
        assert "loaded" in result.stdout


class Test_Security_Headers:
    def test_headers_on_every_response(self, tmp_path):
        result = run_main(tmp_path, """
            from fastapi.testclient import TestClient
            import main
            client = TestClient(main.app)
            for response in (client.post("/api/v1/logout"), client.get("/assets/favicon.png")):
                h = response.headers
                assert h["X-Frame-Options"] == "DENY", h
                assert h["X-Content-Type-Options"] == "nosniff", h
                assert h["Referrer-Policy"] == "no-referrer", h
                assert h["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()", h
            print("headers ok")
        """)
        assert result.returncode == 0, result.stderr
        assert "headers ok" in result.stdout


class Test_Sessions_End_On_Password_Change:
    def test_change_password_ends_all_sessions(self, tmp_path):
        result = run_main(tmp_path, """
            import main
            from core import auth, sessions, storage
            db = storage.db_connect(main.DB_PATH)
            auth.register(db, "jon", "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            auth.register(db, "amy", "amy@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            jon = auth.login(db, "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            amy = auth.login(db, "amy@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            db.close()
            web, extension = sessions.create(jon), sessions.create(jon)
            other = sessions.create(amy)

            main.do_change_password(jon, "c0rrect1horseb@ttery", "N3w-master-passw0rd!")
            assert sessions.get(web) is None and sessions.get(extension) is None
            assert sessions.get(other) is not None          # other users keep their sessions
            print("ended")
        """)
        assert result.returncode == 0, result.stderr
        assert "ended" in result.stdout

    def test_wrong_password_keeps_sessions(self, tmp_path):
        result = run_main(tmp_path, """
            import main
            from core import auth, sessions, storage
            db = storage.db_connect(main.DB_PATH)
            auth.register(db, "jon", "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            jon = auth.login(db, "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            db.close()
            token = sessions.create(jon)
            try:
                main.do_change_password(jon, "not-the-password!", "N3w-master-passw0rd!")
            except auth.InvalidCredentialsError:
                pass
            assert sessions.get(token) is not None
            print("kept")
        """)
        assert result.returncode == 0, result.stderr
        assert "kept" in result.stdout

    def test_recovery_ends_all_sessions(self, tmp_path):
        result = run_main(tmp_path, """
            import main
            from core import auth, sessions, storage
            db = storage.db_connect(main.DB_PATH)
            user_id = auth.register(db, "jon", "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            code = auth.create_recovery_code(db, user_id, "c0rrect1horseb@ttery")
            jon = auth.login(db, "jon@gmail.com", "c0rrect1horseb@ttery", "127.0.0.1")
            db.close()
            token = sessions.create(jon)       # e.g. a stolen session

            main.do_recover_account("jon@gmail.com", code, "N3w-master-passw0rd!", "127.0.0.1")
            assert sessions.get(token) is None
            print("ended")
        """)
        assert result.returncode == 0, result.stderr
        assert "ended" in result.stdout

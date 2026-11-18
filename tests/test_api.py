from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

import api
from core import auth, sharing, storage, vault


PASSWORD = "c0rrect1horseb@ttery"


@pytest.fixture
def setup(tmp_path):
    # A fresh database, a test app with only the API, and two users with entries
    db_path = tmp_path / "test.db"
    db_connection = storage.db_connect(db_path)
    storage.create_tables(db_connection)

    auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
    auth.register(db_connection, "eve", "eve@gmail.com", PASSWORD)
    jon = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    personal = sharing.list_vaults(db_connection, jon)[0].vault_id
    github = vault.add_entry(db_connection, jon, personal, "GitHub", "https://github.com", "jonnytech", "Gh!pw-123456", "")
    vault.add_entry(db_connection, jon, personal, "Google", "https://accounts.google.com", "jon@gmail.com", "Go!pw-123456", "")
    db_connection.close()

    api.setup(db_path)
    test_app = FastAPI()
    test_app.include_router(api.router)
    return TestClient(test_app), github


def sign_in(client, email="jon@gmail.com", password=PASSWORD):
    return client.post("/api/v1/login", json={"email": email, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class Test_Login:
    def test_login_returns_token(self, setup):
        client, _ = setup
        response = sign_in(client)
        assert response.status_code == 200
        assert len(response.json()["token"]) >= 40

    def test_wrong_password_and_unknown_email_look_the_same(self, setup):
        client, _ = setup
        wrong = sign_in(client, password="wr0ng!password")
        unknown = sign_in(client, email="nobody@gmail.com")
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json() == unknown.json()

    def test_logout_ends_token(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        client.post("/api/v1/logout", headers=bearer(token))
        assert client.get("/api/v1/logins", params={"url": "https://github.com"}, headers=bearer(token)).status_code == 401

    def test_lockout_says_so(self, setup):
        client, _ = setup
        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            sign_in(client, password="wr0ng!password")
        response = sign_in(client)       # correct password, but locked out
        assert response.status_code == 429
        assert "Too many" in response.json()["detail"]
        assert response.headers["retry-after"] == "900"


class Test_Auth_Required:
    def test_no_token(self, setup):
        client, _ = setup
        assert client.get("/api/v1/logins", params={"url": "https://github.com"}).status_code == 401

    def test_bad_token(self, setup):
        client, _ = setup
        assert client.get("/api/v1/logins", params={"url": "https://github.com"},
                          headers=bearer("not-a-real-token")).status_code == 401


class Test_Logins:
    def test_matches_page_only(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        found = client.get("/api/v1/logins", params={"url": "https://github.com/login"}, headers=bearer(token)).json()
        assert [f["title"] for f in found] == ["GitHub"]

    def test_lookalike_gets_nothing(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        found = client.get("/api/v1/logins", params={"url": "https://github.com.evil.io/"}, headers=bearer(token)).json()
        assert found == []

    def test_list_never_includes_passwords(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        found = client.get("/api/v1/logins", params={"url": "https://github.com"}, headers=bearer(token)).json()
        assert "password" not in found[0]
        assert "Gh!pw-123456" not in str(found)


class Test_Password:
    def test_get_password(self, setup):
        client, github = setup
        token = sign_in(client).json()["token"]
        response = client.get(f"/api/v1/logins/{github}/password", headers=bearer(token))
        assert response.json() == {"password": "Gh!pw-123456"}
        assert response.headers["cache-control"] == "no-store"

    def test_other_users_entry_is_not_found(self, setup):
        client, github = setup
        token = sign_in(client, email="eve@gmail.com").json()["token"]
        assert client.get(f"/api/v1/logins/{github}/password", headers=bearer(token)).status_code == 404

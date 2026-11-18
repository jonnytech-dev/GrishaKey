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


class Test_Vaults:
    def test_list_vaults(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        vaults = client.get("/api/v1/vaults", headers=bearer(token)).json()
        assert [v["name"] for v in vaults] == ["Personal"]
        assert vaults[0]["can_edit"] is True

    def test_create_vault(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        response = client.post("/api/v1/vaults", json={"name": "Work"}, headers=bearer(token))
        assert response.status_code == 201
        names = [v["name"] for v in client.get("/api/v1/vaults", headers=bearer(token)).json()]
        assert "Work" in names

    def test_duplicate_vault_name(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        client.post("/api/v1/vaults", json={"name": "Work"}, headers=bearer(token))
        assert client.post("/api/v1/vaults", json={"name": "work"}, headers=bearer(token)).status_code == 400

    def test_empty_vault_name(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        assert client.post("/api/v1/vaults", json={"name": ""}, headers=bearer(token)).status_code == 422


class Test_Create_Login:
    def _personal(self, client, token):
        return client.get("/api/v1/vaults", headers=bearer(token)).json()[0]["id"]

    def test_create_and_find(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        vault_id = self._personal(client, token)
        response = client.post("/api/v1/logins", headers=bearer(token), json={
            "vault_id": vault_id, "title": "Netflix", "url": "https://netflix.com",
            "username": "jon", "password": " spaced pw ", "notes": ""})
        assert response.status_code == 201
        found = client.get("/api/v1/logins", params={"url": "https://www.netflix.com/login"},
                           headers=bearer(token)).json()
        assert [f["title"] for f in found] == ["Netflix"]
        entry_id = response.json()["id"]
        pw = client.get(f"/api/v1/logins/{entry_id}/password", headers=bearer(token)).json()
        assert pw["password"] == " spaced pw "      # spaces kept

    def test_title_required(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        vault_id = self._personal(client, token)
        response = client.post("/api/v1/logins", headers=bearer(token),
                               json={"vault_id": vault_id, "title": ""})
        assert response.status_code == 422

    def test_cannot_add_to_someone_elses_vault(self, setup):
        client, _ = setup
        jon_token = sign_in(client).json()["token"]
        jon_vault = self._personal(client, jon_token)
        eve_token = sign_in(client, email="eve@gmail.com").json()["token"]
        response = client.post("/api/v1/logins", headers=bearer(eve_token),
                               json={"vault_id": jon_vault, "title": "Sneaky"})
        assert response.status_code in (400, 403)

    def test_requires_sign_in(self, setup):
        client, _ = setup
        assert client.post("/api/v1/logins", json={"vault_id": "x", "title": "y"}).status_code == 401


class Test_Generate:
    def test_generate(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        password = client.get("/api/v1/generate", params={"length": 24}, headers=bearer(token)).json()["password"]
        assert len(password) == 24

    def test_bad_length(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        assert client.get("/api/v1/generate", params={"length": 3}, headers=bearer(token)).status_code == 400

    def test_digits_only(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        password = client.get("/api/v1/generate", headers=bearer(token), params={
            "length": 16, "upper": False, "lower": False, "digits": True, "symbols": False}).json()["password"]
        assert len(password) == 16 and password.isdigit()

    def test_no_sets_rejected(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        response = client.get("/api/v1/generate", headers=bearer(token), params={
            "upper": False, "lower": False, "digits": False, "symbols": False})
        assert response.status_code == 400


class Test_Passphrase:
    def test_default_passphrase(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        response = client.get("/api/v1/generate-passphrase", headers=bearer(token))
        assert response.status_code == 200
        passphrase = response.json()["password"]
        assert any(ch.isdigit() for ch in passphrase)          # "Add a number" is on by default
        assert passphrase[0].isupper()                         # "Capitalize" is on by default

    def test_word_count_and_separator(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        # Period, because a few EFF words contain a dash (t-shirt, yo-yo)
        passphrase = client.get("/api/v1/generate-passphrase", headers=bearer(token), params={
            "words": 7, "separator": ".", "capitalize": False, "number": False}).json()["password"]
        parts = passphrase.split(".")
        assert len(parts) == 7
        assert all(part == part.lower() and not any(ch.isdigit() for ch in part) for part in parts)

    def test_space_separator(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        passphrase = client.get("/api/v1/generate-passphrase", headers=bearer(token), params={
            "words": 4, "separator": " "}).json()["password"]
        assert len(passphrase.split(" ")) == 4

    def test_bad_word_count(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        for words in (2, 13):
            response = client.get("/api/v1/generate-passphrase", headers=bearer(token), params={"words": words})
            assert response.status_code == 400

    def test_bad_separator(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        response = client.get("/api/v1/generate-passphrase", headers=bearer(token), params={"separator": "x"})
        assert response.status_code == 400

    def test_requires_sign_in(self, setup):
        client, _ = setup
        assert client.get("/api/v1/generate-passphrase").status_code == 401


class Test_Edit_Login:
    def test_details_and_edit(self, setup):
        client, github = setup
        token = sign_in(client).json()["token"]
        details = client.get(f"/api/v1/logins/{github}", headers=bearer(token)).json()
        assert details["title"] == "GitHub" and details["can_edit"] is True
        assert "password" not in details

        response = client.put(f"/api/v1/logins/{github}", headers=bearer(token), json={
            "title": "GitHub (work)", "url": "https://github.com", "username": "jon-work",
            "password": "New!pw-987654", "notes": "2FA on"})
        assert response.status_code == 200
        found = client.get("/api/v1/logins", params={"url": "https://github.com"}, headers=bearer(token)).json()
        assert found[0]["title"] == "GitHub (work)" and found[0]["username"] == "jon-work"
        assert found[0]["can_edit"] is True
        pw = client.get(f"/api/v1/logins/{github}/password", headers=bearer(token)).json()
        assert pw["password"] == "New!pw-987654"

    def test_empty_title_rejected(self, setup):
        client, github = setup
        token = sign_in(client).json()["token"]
        response = client.put(f"/api/v1/logins/{github}", headers=bearer(token), json={"title": ""})
        assert response.status_code == 422

    def test_other_user_cannot_edit(self, setup):
        client, github = setup
        token = sign_in(client, email="eve@gmail.com").json()["token"]
        response = client.put(f"/api/v1/logins/{github}", headers=bearer(token), json={"title": "Hacked"})
        assert response.status_code in (403, 404)
        assert client.get(f"/api/v1/logins/{github}", headers=bearer(token)).status_code == 404


class Test_Rename_Vault:
    def _personal(self, client, token):
        return client.get("/api/v1/vaults", headers=bearer(token)).json()[0]["id"]

    def test_rename(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        vault_id = self._personal(client, token)
        response = client.patch(f"/api/v1/vaults/{vault_id}", headers=bearer(token), json={"name": "Home"})
        assert response.status_code == 200
        names = [v["name"] for v in client.get("/api/v1/vaults", headers=bearer(token)).json()]
        assert names == ["Home"]

    def test_duplicate_name(self, setup):
        client, _ = setup
        token = sign_in(client).json()["token"]
        vault_id = self._personal(client, token)
        client.post("/api/v1/vaults", json={"name": "Work"}, headers=bearer(token))
        response = client.patch(f"/api/v1/vaults/{vault_id}", headers=bearer(token), json={"name": "Work"})
        assert response.status_code == 400

    def test_not_owner(self, setup):
        client, _ = setup
        jon_token = sign_in(client).json()["token"]
        vault_id = self._personal(client, jon_token)
        eve_token = sign_in(client, email="eve@gmail.com").json()["token"]
        response = client.patch(f"/api/v1/vaults/{vault_id}", headers=bearer(eve_token), json={"name": "Mine"})
        assert response.status_code in (403, 404)

from core import transfer
from types import SimpleNamespace
import pytest


def entry(title, url, username, password, notes, vault_id):
    return SimpleNamespace(title=title, url=url, username=username, password=password,
                           notes=notes, vault_id=vault_id)


class Test_Export:
    # Header plus one row per entry, with the vault name
    def test_export(self):
        csv_text = transfer.entries_to_csv(
            [entry("Gmail", "https://mail.google.com", "jon", "Sneaky!22", "note", "v1")],
            {"v1": "Personal"},
        )
        lines = csv_text.strip().splitlines()
        assert lines[0] == "name,url,username,password,notes,vault"
        assert lines[1] == "Gmail,https://mail.google.com,jon,Sneaky!22,note,Personal"

    # Values that start with = are kept exactly (no formula escaping)
    def test_exact_values(self):
        csv_text = transfer.entries_to_csv([entry("X", "", "", "=1+1", "", "v1")], {"v1": "V"})
        assert "=1+1" in csv_text

    # Export, then import, gives back the same logins
    def test_round_trip(self):
        original = [entry("Bank", "https://bank.com", "jon", ' sp@ce, "quoted" ', "line1\nline2", "v1")]
        rows, skipped = transfer.parse_csv(transfer.entries_to_csv(original, {"v1": "V"}).encode())
        assert skipped == 0
        assert rows[0]["title"] == "Bank"
        assert rows[0]["password"] == ' sp@ce, "quoted" '
        assert rows[0]["notes"] == "line1\nline2"


class Test_Import:
    # Bitwarden-style headers
    def test_bitwarden_headers(self):
        data = b"folder,name,login_uri,login_username,login_password,notes\n,Gmail,https://g.com,jon,pw123,n\n"
        rows, _ = transfer.parse_csv(data)
        assert rows == [{"title": "Gmail", "url": "https://g.com", "username": "jon", "password": "pw123", "notes": "n"}]

    # Chrome-style headers
    def test_chrome_headers(self):
        data = b"name,url,username,password,note\nGitHub,https://github.com,jon,pw,\n"
        rows, _ = transfer.parse_csv(data)
        assert rows[0]["title"] == "GitHub" and rows[0]["password"] == "pw"

    # Missing title → taken from the URL's domain
    def test_title_from_url(self):
        data = b"url,username,password\nhttps://www.netflix.com/login,jon,pw\n"
        rows, _ = transfer.parse_csv(data)
        assert rows[0]["title"] == "netflix.com"

    # Fully empty rows are skipped and counted
    def test_skips_empty(self):
        data = b"name,username,password\n,,\nReal,jon,pw\n"
        rows, skipped = transfer.parse_csv(data)
        assert len(rows) == 1 and skipped == 1

    # Excel's hidden BOM doesn't break the header
    def test_bom(self):
        rows, _ = transfer.parse_csv("﻿name,password\nX,pw\n".encode("utf-8"))
        assert rows[0]["title"] == "X"

    # Unusable files → ValueError with a clear message
    def test_no_useful_columns(self):
        with pytest.raises(ValueError):
            transfer.parse_csv(b"color,size\nred,big\n")

    def test_too_large(self):
        with pytest.raises(ValueError):
            transfer.parse_csv(b"name,password\n" + b"x" * (transfer.MAX_IMPORT_BYTES + 1))

    def test_not_utf8(self):
        with pytest.raises(ValueError):
            transfer.parse_csv("name,password\nCafé,pw\n".encode("utf-16"))

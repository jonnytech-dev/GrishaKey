from core import auth, crypto, sharing, storage, vault
import pytest
import uuid
from cryptography.exceptions import InvalidTag


PASSWORD = "c0rrect1horseb@ttery"


def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def make_session(db_connection, username):
    # Registers a user and logs them in, returning their Session
    auth.register(db_connection, username, f"{username}@gmail.com", PASSWORD)
    return auth.login(db_connection, f"{username}@gmail.com", PASSWORD)


def personal_vault_id(db_connection, session):
    # Finds the user's Personal vault by its decrypted name
    for v in sharing.list_vaults(db_connection, session):
        if v.is_owner and v.name == "Personal":
            return v.vault_id


def add_member(db_connection, owner, vault_id, member, role=None):
    # Adds a member to a vault by hand: owner unwraps the vault key, wraps it for the member
    owner_row = storage.get_vault_membership(db_connection, owner.user_id, vault_id)
    vault_key = crypto.unwrap_with_private_key(
        owner.private_key,
        owner_row["wrapped_vault_key"],
        crypto.wrapped_vault_key_aad(vault_id, owner.user_id),
    )
    member_public = storage.get_public_key(db_connection, member.user_id)
    wrapped = crypto.wrap_for_public_key(
        member_public,
        vault_key,
        crypto.wrapped_vault_key_aad(vault_id, member.user_id),
    )
    storage.create_vault_share(db_connection, vault_id, member.user_id, wrapped, role)

def share_entry_by_hand(db_connection, owner, entry_id, member, role="view"):
    # Shares one entry directly: owner gets the entry key, wraps it for the member
    row = storage.get_vault_entry(db_connection, owner.user_id, entry_id)
    entry_key = vault.get_entry_key_from_vault_row(owner, row)
    member_public = storage.get_public_key(db_connection, member.user_id)
    wrapped = crypto.wrap_for_public_key(
        member_public,
        entry_key,
        crypto.direct_share_wrapped_entry_key_aad(entry_id, member.user_id),
    )
    storage.create_entry_share(db_connection, entry_id, member.user_id, wrapped, role)


def add_gmail(db_connection, session, vault_id):
    # Adds a standard test entry, returns its id
    return vault.add_entry(db_connection, session, vault_id, "Gmail", "https://mail.google.com",
                           "jon@gmail.com", "SneakyPanda!22", "recovery code 1234")


# ========== Add and Get (owner) ==========

class Test_Add_And_Get:
    # Every field comes back exactly the same
    def test_add_then_get(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        vault_id = personal_vault_id(db_connection, jon)

        entry_id = add_gmail(db_connection, jon, vault_id)
        entry = vault.get_entry(db_connection, jon, entry_id)

        assert entry.vault_entry_id == entry_id
        assert entry.vault_id == vault_id
        assert entry.title == "Gmail"
        assert entry.password == "SneakyPanda!22"
        assert entry.notes == "recovery code 1234"
        assert entry.can_edit is True
        db_connection.close()

    # Title is required
    def test_empty_title_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        with pytest.raises(ValueError):
            vault.add_entry(db_connection, jon, personal_vault_id(db_connection, jon), "", "", "", "pw", "")
        db_connection.close()

    # A missing entry id returns None
    def test_get_missing_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        assert vault.get_entry(db_connection, jon, str(uuid.uuid4())) is None
        db_connection.close()

    # Each entry gets its own entry key, so two entries never share a wrapped key
    def test_each_entry_has_own_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        vault_id = personal_vault_id(db_connection, jon)
        add_gmail(db_connection, jon, vault_id)
        add_gmail(db_connection, jon, vault_id)

        rows = db_connection.execute("SELECT wrapped_entry_key FROM vault_entries").fetchall()
        assert rows[0]["wrapped_entry_key"] != rows[1]["wrapped_entry_key"]
        db_connection.close()


# ========== Encryption at Rest ==========

class Test_Encryption_At_Rest:
    # Nothing readable in the stored row
    def test_no_plaintext_in_db(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        row = db_connection.execute("SELECT ciphertext FROM vault_entries").fetchone()
        assert b"SneakyPanda!22" not in row["ciphertext"]
        assert b"Gmail" not in row["ciphertext"]
        db_connection.close()

    # Swapping two entries' data is caught by the labels
    def test_swapped_entries_fail(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        vault_id = personal_vault_id(db_connection, jon)
        a = add_gmail(db_connection, jon, vault_id)
        b = vault.add_entry(db_connection, jon, vault_id, "Bank", "", "jon", "BankPw!99", "")

        row_b = db_connection.execute("SELECT * FROM vault_entries WHERE vault_entry_id = ?", (b,)).fetchone()
        db_connection.execute(
            "UPDATE vault_entries SET wrapped_entry_key = ?, entry_key_nonce = ?, nonce = ?, ciphertext = ? WHERE vault_entry_id = ?",
            (row_b["wrapped_entry_key"], row_b["entry_key_nonce"], row_b["nonce"], row_b["ciphertext"], a),
        )
        db_connection.commit()

        with pytest.raises(InvalidTag):
            vault.get_entry(db_connection, jon, a)
        db_connection.close()


# ========== Vault Members ==========

class Test_Vault_Members:
    # A member can read entries in a vault they were added to
    def test_member_can_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)

        assert vault.get_entry(db_connection, brock, entry_id).password == "SneakyPanda!22"
        db_connection.close()

    # A view-only member sees can_edit = False
    def test_view_member_cannot_edit(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)

        assert vault.get_entry(db_connection, brock, entry_id).can_edit is False
        db_connection.close()

    # A view-only member can't add entries
    def test_view_member_cannot_add(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)

        with pytest.raises(PermissionError):
            add_gmail(db_connection, brock, vault_id)
        db_connection.close()

    # A member with an edit override can add, and others can read it
    def test_edit_member_can_add(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, kim, role="edit")

        entry_id = add_gmail(db_connection, kim, vault_id)

        assert vault.get_entry(db_connection, jon, entry_id).title == "Gmail"
        assert vault.get_entry(db_connection, kim, entry_id).can_edit is True
        db_connection.close()


# ========== Outsiders ==========

class Test_Outsiders:
    # Someone not in the vault can't read it, even with the entry id
    def test_outsider_cannot_get(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.get_entry(db_connection, eve, entry_id) is None
        db_connection.close()

    # Someone not in the vault can't add to it, even with the vault id
    def test_outsider_cannot_add(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")

        with pytest.raises(PermissionError):
            add_gmail(db_connection, eve, personal_vault_id(db_connection, jon))
        db_connection.close()

# ========== Direct Shares ==========

class Test_Direct_Shares:
    # A direct share can read the entry
    def test_direct_share_can_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy)

        entry = vault.get_entry(db_connection, amy, entry_id)
        assert entry.password == "SneakyPanda!22"
        assert entry.can_edit is False
        db_connection.close()

    # An edit share sees can_edit = True
    def test_direct_edit_share_can_edit(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy, role="edit")

        assert vault.get_entry(db_connection, amy, entry_id).can_edit is True
        db_connection.close()

    # A direct share only opens that one entry, not the rest of the vault
    def test_direct_share_only_one_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        vault_id = personal_vault_id(db_connection, jon)
        shared = add_gmail(db_connection, jon, vault_id)
        not_shared = vault.add_entry(db_connection, jon, vault_id, "Bank", "", "jon", "BankPw!99", "")
        share_entry_by_hand(db_connection, jon, shared, amy)

        assert vault.get_entry(db_connection, amy, shared) is not None
        assert vault.get_entry(db_connection, amy, not_shared) is None
        db_connection.close()


# ========== List ==========

class Test_List:
    # A new user's vault is empty
    def test_list_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        assert vault.list_entries(db_connection, jon) == []
        db_connection.close()

    # The owner sees every entry in their vault
    def test_list_owner_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        vault_id = personal_vault_id(db_connection, jon)
        add_gmail(db_connection, jon, vault_id)
        vault.add_entry(db_connection, jon, vault_id, "Bank", "", "jon", "BankPw!99", "")

        titles = [entry.title for entry in vault.list_entries(db_connection, jon)]
        assert len(titles) == 2
        assert "Gmail" in titles
        assert "Bank" in titles
        db_connection.close()

    # A member sees entries other members added
    def test_list_member_sees_others_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, kim, role="edit")
        add_gmail(db_connection, jon, vault_id)
        vault.add_entry(db_connection, kim, vault_id, "GitHub", "", "kim", "GhPw!11", "")

        titles = [entry.title for entry in vault.list_entries(db_connection, kim)]
        assert "Gmail" in titles
        assert "GitHub" in titles
        db_connection.close()

    # Direct shares show up in the list
    def test_list_includes_direct_shares(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy)

        titles = [entry.title for entry in vault.list_entries(db_connection, amy)]
        assert "Gmail" in titles
        db_connection.close()

    # An entry reachable both ways shows up once, not twice
    def test_list_no_duplicates(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)
        share_entry_by_hand(db_connection, jon, entry_id, brock)

        ids = [entry.vault_entry_id for entry in vault.list_entries(db_connection, brock)]
        assert ids.count(entry_id) == 1
        db_connection.close()

    # An outsider sees none of Jon's entries
    def test_list_outsider_sees_nothing(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.list_entries(db_connection, eve) == []
        db_connection.close()


# ========== Update ==========

class Test_Update:
    # The owner can update, and the new value comes back
    def test_owner_can_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.update_entry(db_connection, jon, entry_id, "Gmail", "", "jon@gmail.com", "NewPass!33", "") is True
        assert vault.get_entry(db_connection, jon, entry_id).password == "NewPass!33"
        db_connection.close()

    # After an update, other members can still read it (same entry key)
    def test_update_still_readable_by_members(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)

        vault.update_entry(db_connection, jon, entry_id, "Gmail", "", "jon@gmail.com", "NewPass!33", "")

        assert vault.get_entry(db_connection, brock, entry_id).password == "NewPass!33"
        db_connection.close()

    # Every update uses a new nonce
    def test_update_uses_new_nonce(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        before = db_connection.execute("SELECT nonce FROM vault_entries").fetchone()["nonce"]

        vault.update_entry(db_connection, jon, entry_id, "Gmail", "", "jon@gmail.com", "SneakyPanda!22", "")

        after = db_connection.execute("SELECT nonce FROM vault_entries").fetchone()["nonce"]
        assert before != after
        db_connection.close()

    # Title is still required on update
    def test_update_empty_title_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        with pytest.raises(ValueError):
            vault.update_entry(db_connection, jon, entry_id, "", "", "", "pw", "")
        db_connection.close()

    # A view-only member can't update, and the data stays the same
    def test_view_member_cannot_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)

        with pytest.raises(PermissionError):
            vault.update_entry(db_connection, brock, entry_id, "Hacked", "", "", "", "")

        assert vault.get_entry(db_connection, jon, entry_id).title == "Gmail"
        db_connection.close()

    # An edit member can update
    def test_edit_member_can_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, kim, role="edit")
        entry_id = add_gmail(db_connection, jon, vault_id)

        assert vault.update_entry(db_connection, kim, entry_id, "Gmail", "", "", "KimPw!44", "") is True
        assert vault.get_entry(db_connection, jon, entry_id).password == "KimPw!44"
        db_connection.close()

    # A direct-share editor can update
    def test_direct_edit_share_can_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy, role="edit")

        assert vault.update_entry(db_connection, amy, entry_id, "Gmail", "", "", "AmyPw!55", "") is True
        assert vault.get_entry(db_connection, jon, entry_id).password == "AmyPw!55"
        db_connection.close()

    # A direct-share viewer can't update
    def test_direct_view_share_cannot_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy)

        with pytest.raises(PermissionError):
            vault.update_entry(db_connection, amy, entry_id, "Hacked", "", "", "", "")
        db_connection.close()

    # Someone with no access gets False, and the data stays the same
    def test_outsider_cannot_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.update_entry(db_connection, eve, entry_id, "Hacked", "", "", "", "") is False
        assert vault.get_entry(db_connection, jon, entry_id).title == "Gmail"
        db_connection.close()


# ========== Delete ==========

class Test_Delete:
    # The owner can delete
    def test_owner_can_delete(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.delete_entry(db_connection, jon, entry_id) is True
        assert vault.get_entry(db_connection, jon, entry_id) is None
        db_connection.close()

    # An edit member can delete
    # def test_edit_member_can_delete(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
    #     jon = make_session(db_connection, "jon")
    #     kim = make_session(db_connection, "kim")
    #     vault_id = personal_vault_id(db_connection, jon)
    #     add_member(db_connection, jon, vault_id, kim, role="edit")
    #     entry_id = add_gmail(db_connection, jon, vault_id)

    #     assert vault.delete_entry(db_connection, kim, entry_id) is True
    #     assert vault.get_entry(db_connection, jon, entry_id) is None
    #     db_connection.close()

    # A view-only member can't delete, and the entry stays
    def test_view_member_cannot_delete(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)

        with pytest.raises(PermissionError):
            vault.delete_entry(db_connection, brock, entry_id)
        assert vault.get_entry(db_connection, jon, entry_id) is not None
        db_connection.close()

    # A direct-share editor can edit, but can't delete
    def test_direct_edit_share_cannot_delete(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        share_entry_by_hand(db_connection, jon, entry_id, amy, role="edit")

        with pytest.raises(PermissionError):
            vault.delete_entry(db_connection, amy, entry_id)
        assert vault.get_entry(db_connection, jon, entry_id) is not None
        db_connection.close()

    # Someone with no access gets False, and the entry stays
    def test_outsider_cannot_delete(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.delete_entry(db_connection, eve, entry_id) is False
        assert vault.get_entry(db_connection, jon, entry_id) is not None
        db_connection.close()

    # A missing entry id returns False
    def test_delete_missing_returns_false(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        assert vault.delete_entry(db_connection, jon, str(uuid.uuid4())) is False
        db_connection.close()


# ========== Trash ==========

class Test_Trash:
    # A trashed entry disappears from get and list
    def test_trash_hides_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.trash_entry(db_connection, jon, entry_id) is True

        assert vault.get_entry(db_connection, jon, entry_id) is None
        assert vault.list_entries(db_connection, jon) == []
        db_connection.close()

    # Members and direct shares lose access while it's in the Trash
    def test_trash_hides_from_others(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        amy = make_session(db_connection, "amy")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)
        share_entry_by_hand(db_connection, jon, entry_id, amy)

        vault.trash_entry(db_connection, jon, entry_id)

        assert vault.get_entry(db_connection, brock, entry_id) is None
        assert vault.get_entry(db_connection, amy, entry_id) is None
        db_connection.close()

    # Only the vault owner can trash
    def test_non_owner_cannot_trash(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, kim, role="edit")
        entry_id = add_gmail(db_connection, jon, vault_id)

        with pytest.raises(PermissionError):
            vault.trash_entry(db_connection, kim, entry_id)
        assert vault.get_entry(db_connection, jon, entry_id) is not None
        db_connection.close()

    # The Trash lists it, decrypted, and restore brings it back for everyone
    def test_list_and_restore(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, brock)
        entry_id = add_gmail(db_connection, jon, vault_id)
        vault.trash_entry(db_connection, jon, entry_id)

        trash = vault.list_trash(db_connection, jon)
        assert [item.entry.title for item in trash] == ["Gmail"]
        assert trash[0].deleted_at

        assert vault.restore_entry(db_connection, jon, entry_id) is True
        assert vault.get_entry(db_connection, jon, entry_id).password == "SneakyPanda!22"
        assert vault.get_entry(db_connection, brock, entry_id) is not None
        assert vault.list_trash(db_connection, jon) == []
        db_connection.close()

    # Members don't see the owner's Trash and can't restore from it
    def test_member_cannot_restore(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        vault_id = personal_vault_id(db_connection, jon)
        add_member(db_connection, jon, vault_id, kim, role="edit")
        entry_id = add_gmail(db_connection, jon, vault_id)
        vault.trash_entry(db_connection, jon, entry_id)

        assert vault.list_trash(db_connection, kim) == []
        assert vault.restore_entry(db_connection, kim, entry_id) is False
        db_connection.close()

    # A trashed entry can't be edited
    def test_trashed_entry_cannot_be_updated(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))
        vault.trash_entry(db_connection, jon, entry_id)

        assert vault.update_entry(db_connection, jon, entry_id, "Gmail", "", "", "New!pw", "") is False
        db_connection.close()

    # Delete forever only works on entries already in the Trash
    def test_delete_forever(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        entry_id = add_gmail(db_connection, jon, personal_vault_id(db_connection, jon))

        assert vault.delete_entry_forever(db_connection, jon, entry_id) is False   # not trashed yet

        vault.trash_entry(db_connection, jon, entry_id)
        assert vault.delete_entry_forever(db_connection, jon, entry_id) is True
        assert vault.restore_entry(db_connection, jon, entry_id) is False         # gone for good
        db_connection.close()

    # Empty trash removes everything trashed, and leaves the rest alone
    def test_empty_trash(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        vault_id = personal_vault_id(db_connection, jon)
        a = add_gmail(db_connection, jon, vault_id)
        b = add_gmail(db_connection, jon, vault_id)
        keep = add_gmail(db_connection, jon, vault_id)
        vault.trash_entry(db_connection, jon, a)
        vault.trash_entry(db_connection, jon, b)

        assert vault.empty_trash(db_connection, jon) == 2
        assert vault.list_trash(db_connection, jon) == []
        assert vault.get_entry(db_connection, jon, keep) is not None
        db_connection.close()
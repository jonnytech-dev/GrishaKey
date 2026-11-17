from core import auth, sharing, storage, vault
import pytest
import uuid
from core import crypto
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


def add_gmail(db_connection, session, vault_id):
    # Adds a standard test entry, returns its id
    return vault.add_entry(db_connection, session, vault_id, "Gmail", "https://mail.google.com",
                           "jon@gmail.com", "SneakyPanda!22", "recovery code 1234")


# ========== Create Vault ==========

class Test_Create_Vault:
    # The creator owns the new vault and can add entries to it
    def test_creator_can_use_new_vault(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        entry = vault.get_entry(db_connection, jon, entry_id)
        assert entry.vault_id == work
        assert entry.can_edit is True
        db_connection.close()

    # A new vault is private until someone is added
    def test_new_vault_is_private(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")

        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        assert vault.get_entry(db_connection, brock, entry_id) is None
        db_connection.close()

    # A vault needs a name
    def test_vault_name_required(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        with pytest.raises(ValueError):
            sharing.create_vault(db_connection, jon, "")
        db_connection.close()

    # The name comes back decrypted, and the database only holds ciphertext
    def test_vault_name_encrypted(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")

        work = sharing.create_vault(db_connection, jon, "Work")

        names = [v.name for v in sharing.list_vaults(db_connection, jon)]
        assert "Work" in names
        stored = db_connection.execute("SELECT encrypted_vault_name FROM vaults WHERE vault_id = ?", (work,)).fetchone()
        assert b"Work" not in stored["encrypted_vault_name"]
        db_connection.close()

    # Two vaults with the same name for the same owner are rejected
    def test_duplicate_name_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        sharing.create_vault(db_connection, jon, "Work")

        with pytest.raises(ValueError):
            sharing.create_vault(db_connection, jon, "work")
        db_connection.close()

    # Members see the vault's name too
    def test_member_sees_vault_name(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        names = [v.name for v in sharing.list_vaults(db_connection, brock)]
        assert "Work" in names
        db_connection.close()

    # Saved rows survive closing and reopening the database
    def test_vault_survives_reconnect(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")
        db_connection.close()

        reopened = storage.db_connect(tmp_path / "test.db")
        assert storage.get_vault_membership(reopened, jon.user_id, work) is not None
        reopened.close()


# ========== Add Vault Member ==========

class Test_share_vault:
    # A new member can read every entry in the vault
    def test_member_can_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        assert vault.get_entry(db_connection, brock, entry_id).password == "SneakyPanda!22"
        db_connection.close()

    # A member also sees entries added AFTER they joined
    def test_member_sees_future_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        entry_id = add_gmail(db_connection, jon, work)

        assert vault.get_entry(db_connection, brock, entry_id) is not None
        db_connection.close()

    # Members get the vault's default role unless one is given
    def test_member_gets_vault_default_role(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work", member_role="view")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        with pytest.raises(PermissionError):
            add_gmail(db_connection, brock, work)
        db_connection.close()

    # A role override lets one member edit in a view-only vault
    def test_member_role_override(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work", member_role="view")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")

        entry_id = add_gmail(db_connection, kim, work)
        assert vault.get_entry(db_connection, jon, entry_id).title == "Gmail"
        db_connection.close()

    # Only the owner can add members
    def test_non_owner_cannot_add(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        make_session(db_connection, "eve")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")

        with pytest.raises(PermissionError):
            sharing.share_vault(db_connection, kim, work, "eve@gmail.com")
        db_connection.close()

    # Someone outside the vault can't add themselves
    def test_outsider_cannot_add_self(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        work = sharing.create_vault(db_connection, jon, "Work")

        with pytest.raises(PermissionError):
            sharing.share_vault(db_connection, eve, work, "eve@gmail.com")
        db_connection.close()

    # Unknown email → LookupError
    def test_unknown_email(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")

        with pytest.raises(LookupError):
            sharing.share_vault(db_connection, jon, work, "nobody@gmail.com")
        db_connection.close()

    # Adding the same person twice → ValueError
    def test_already_member(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        with pytest.raises(ValueError):
            sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        db_connection.close()


# ========== Share Entry ==========

class Test_Share_Entry:
    # The recipient can read the shared entry
    def test_recipient_can_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        entry = vault.get_entry(db_connection, amy, entry_id)
        assert entry.password == "SneakyPanda!22"
        assert entry.can_edit is False
        db_connection.close()

    # Sharing one entry doesn't open the rest of the vault
    def test_only_that_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        shared = add_gmail(db_connection, jon, work)
        not_shared = add_gmail(db_connection, jon, work)

        sharing.share_entry(db_connection, jon, shared, "amy@gmail.com")

        assert vault.get_entry(db_connection, amy, not_shared) is None
        db_connection.close()

    # An edit share can update, and the owner sees the change
    def test_edit_share_can_update(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com", role="edit")

        vault.update_entry(db_connection, amy, entry_id, "Gmail", "", "", "AmyPw!55", "")

        assert vault.get_entry(db_connection, jon, entry_id).password == "AmyPw!55"
        db_connection.close()

    # Only the vault owner can share an entry
    def test_non_owner_cannot_share(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")
        entry_id = add_gmail(db_connection, jon, work)

        with pytest.raises(PermissionError):
            sharing.share_entry(db_connection, kim, entry_id, "amy@gmail.com")
        db_connection.close()

    # Someone with no access can't share it
    def test_outsider_cannot_share(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        with pytest.raises(PermissionError):
            sharing.share_entry(db_connection, eve, entry_id, "eve@gmail.com")
        db_connection.close()

    # Unknown email → LookupError
    def test_unknown_email(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        with pytest.raises(LookupError):
            sharing.share_entry(db_connection, jon, entry_id, "nobody@gmail.com")
        db_connection.close()

    # Sharing the same entry with the same person twice → ValueError
    def test_already_shared(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        with pytest.raises(ValueError):
            sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")
        db_connection.close()

# ========== Remove Vault Member ==========

class Test_Remove_Vault_Member:
    # A removed member can't read the vault anymore
    def test_removed_member_cannot_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        assert vault.get_entry(db_connection, brock, entry_id) is None
        db_connection.close()

    # Everyone else still reads it after the rotation
    def test_remaining_members_still_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com")

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        assert vault.get_entry(db_connection, jon, entry_id).password == "SneakyPanda!22"
        assert vault.get_entry(db_connection, kim, entry_id).password == "SneakyPanda!22"
        db_connection.close()

    # The removed member's OLD vault key no longer opens anything
    def test_old_vault_key_is_useless(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        # Brock "saves" his vault key while he's still a member
        brock_membership = storage.get_vault_membership(db_connection, brock.user_id, work)
        brocks_old_vault_key = vault.get_vault_key_from_row(brock, brock_membership)

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        # Later, Brock gets a copy of the database and tries his old key
        row = db_connection.execute(
            "SELECT * FROM vault_entries WHERE vault_entry_id = ?", (entry_id,)
        ).fetchone()
        with pytest.raises(InvalidTag):
            vault.get_entry_key_from_vault_key(brocks_old_vault_key, row)
        db_connection.close()

    # New entries after a removal are also readable by remaining members
    def test_new_entries_after_rotation(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com")
        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        entry_id = add_gmail(db_connection, jon, work)

        assert vault.get_entry(db_connection, kim, entry_id) is not None
        assert vault.get_entry(db_connection, brock, entry_id) is None
        db_connection.close()

    # Only the owner can remove members
    def test_non_owner_cannot_remove(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        with pytest.raises(PermissionError):
            sharing.remove_vault_member(db_connection, kim, work, "brock@gmail.com")
        db_connection.close()

    # The owner can't remove themselves (the vault would have no owner)
    def test_owner_cannot_remove_self(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")

        with pytest.raises(ValueError):
            sharing.remove_vault_member(db_connection, jon, work, "jon@gmail.com")
        db_connection.close()

    # Removing someone who isn't a member → LookupError
    def test_remove_non_member(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")

        with pytest.raises(LookupError):
            sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")
        db_connection.close()

    # The vault name is still readable after a rotation
    def test_name_survives_rotation(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com")

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        assert "Work" in [v.name for v in sharing.list_vaults(db_connection, jon)]
        assert "Work" in [v.name for v in sharing.list_vaults(db_connection, kim)]
        db_connection.close()


# ========== Unshare Entry ==========

class Test_Unshare_Entry:
    # An unshared user can't read the entry anymore
    def test_unshared_user_cannot_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        sharing.unshare_entry(db_connection, jon, entry_id, "amy@gmail.com")

        assert vault.get_entry(db_connection, amy, entry_id) is None
        db_connection.close()

    # The owner, vault members, and other direct shares still read it
    def test_others_still_read(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        amy = make_session(db_connection, "amy")
        sam = make_session(db_connection, "sam")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")
        sharing.share_entry(db_connection, jon, entry_id, "sam@gmail.com")

        sharing.unshare_entry(db_connection, jon, entry_id, "amy@gmail.com")

        assert vault.get_entry(db_connection, jon, entry_id).password == "SneakyPanda!22"
        assert vault.get_entry(db_connection, brock, entry_id).password == "SneakyPanda!22"
        assert vault.get_entry(db_connection, sam, entry_id).password == "SneakyPanda!22"
        db_connection.close()

    # The unshared user's OLD entry key no longer opens the data
    def test_old_entry_key_is_useless(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        # Amy "saves" her entry key while she still has access
        amy_row = storage.get_shared_entry(db_connection, amy.user_id, entry_id)
        amys_old_entry_key = vault.get_entry_key_from_shared_row(amy, amy_row)

        sharing.unshare_entry(db_connection, jon, entry_id, "amy@gmail.com")

        row = db_connection.execute(
            "SELECT * FROM vault_entries WHERE vault_entry_id = ?", (entry_id,)
        ).fetchone()
        with pytest.raises(InvalidTag):
            crypto.decrypt(amys_old_entry_key, row["nonce"], row["ciphertext"], crypto.ciphertext_aad(entry_id))
        db_connection.close()

    # Only the vault owner can unshare
    def test_non_owner_cannot_unshare(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        with pytest.raises(PermissionError):
            sharing.unshare_entry(db_connection, kim, entry_id, "amy@gmail.com")
        db_connection.close()

    # Unsharing someone it was never shared with → LookupError
    def test_unshare_not_shared(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)

        with pytest.raises(LookupError):
            sharing.unshare_entry(db_connection, jon, entry_id, "amy@gmail.com")
        db_connection.close()


# ========== Rename Vault ==========

class Test_Rename_Vault:
    # The owner can rename, and members see the new name
    def test_owner_can_rename(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        brock = make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        sharing.rename_vault(db_connection, jon, work, "Office")

        assert "Office" in [v.name for v in sharing.list_vaults(db_connection, jon)]
        assert "Office" in [v.name for v in sharing.list_vaults(db_connection, brock)]
        db_connection.close()

    # A member can't rename
    def test_member_cannot_rename(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")

        with pytest.raises(PermissionError):
            sharing.rename_vault(db_connection, kim, work, "Hacked")
        db_connection.close()

    # Can't rename to the name of another of your vaults
    def test_rename_to_existing_name_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.create_vault(db_connection, jon, "Home")

        with pytest.raises(ValueError):
            sharing.rename_vault(db_connection, jon, work, "home")
        db_connection.close()

    # Renaming to the same name with different capitals is allowed
    def test_rename_same_vault_new_capitals(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        work = sharing.create_vault(db_connection, jon, "Work")

        sharing.rename_vault(db_connection, jon, work, "WORK")

        assert "WORK" in [v.name for v in sharing.list_vaults(db_connection, jon)]
        db_connection.close()


# ========== List Vault Members ==========

class Test_List_Vault_Members:
    # The owner sees themselves first, then members with their roles
    def test_owner_sees_members(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")

        members = sharing.list_vault_members(db_connection, jon, work)

        assert members[0].username == "jon"
        assert members[0].is_owner is True
        assert members[1].email == "kim@gmail.com"
        assert members[1].role == "edit"
        assert members[1].is_owner is False
        db_connection.close()

    # A member who isn't the owner can't see the list
    def test_non_owner_cannot_list(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com", role="edit")

        with pytest.raises(PermissionError):
            sharing.list_vault_members(db_connection, kim, work)
        db_connection.close()

    # A removed member disappears from the list
    def test_removed_member_gone(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        emails = [m.email for m in sharing.list_vault_members(db_connection, jon, work)]
        assert "brock@gmail.com" not in emails
        db_connection.close()


# ========== List Entry Shares ==========

class Test_List_Entry_Shares:
    # The owner sees who an entry is shared with
    def test_owner_sees_shares(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com", role="edit")

        shares = sharing.list_entry_shares(db_connection, jon, entry_id)

        assert [s.email for s in shares] == ["amy@gmail.com"]
        assert shares[0].role == "edit"
        db_connection.close()

    # Someone the entry is shared with can't see the list
    def test_sharee_cannot_list(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        with pytest.raises(PermissionError):
            sharing.list_entry_shares(db_connection, amy, entry_id)
        db_connection.close()

    # An unshared person disappears from the list
    def test_unshared_gone(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        sharing.unshare_entry(db_connection, jon, entry_id, "amy@gmail.com")

        assert sharing.list_entry_shares(db_connection, jon, entry_id) == []
        db_connection.close()


# ========== Counts and Owner Names ==========

class Test_Counts_And_Owner_Names:
    # Counts match the number of entries in each vault, including shared vaults
    def test_entry_counts(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        add_gmail(db_connection, jon, work)
        add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com")

        assert sharing.entry_counts(db_connection, jon)[work] == 2
        assert sharing.entry_counts(db_connection, kim)[work] == 2
        db_connection.close()

    # Vaults the user isn't in never show up in their counts
    def test_entry_counts_only_own_vaults(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        eve = make_session(db_connection, "eve")
        work = sharing.create_vault(db_connection, jon, "Work")
        add_gmail(db_connection, jon, work)

        assert work not in sharing.entry_counts(db_connection, eve)
        db_connection.close()

    # Shared vaults carry the owner's username
    def test_list_vaults_owner_name(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        kim = make_session(db_connection, "kim")
        work = sharing.create_vault(db_connection, jon, "Work")
        sharing.share_vault(db_connection, jon, work, "kim@gmail.com")

        shared = next(v for v in sharing.list_vaults(db_connection, kim) if v.vault_id == work)
        assert shared.owner_name == "jon"
        assert shared.is_owner is False
        db_connection.close()

    # Direct shares map to the username of whoever shared them
    def test_direct_share_owner_names(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        amy = make_session(db_connection, "amy")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_entry(db_connection, jon, entry_id, "amy@gmail.com")

        assert sharing.direct_share_owner_names(db_connection, amy) == {entry_id: "jon"}
        db_connection.close()


# ========== Trash and Rotation ==========

class Test_Trash_Rotation:
    # An entry trashed BEFORE a member is removed still restores and opens after rotation
    def test_restore_after_rotation(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "brock")
        work = sharing.create_vault(db_connection, jon, "Work")
        entry_id = add_gmail(db_connection, jon, work)
        sharing.share_vault(db_connection, jon, work, "brock@gmail.com")
        vault.trash_entry(db_connection, jon, entry_id)

        sharing.remove_vault_member(db_connection, jon, work, "brock@gmail.com")

        assert vault.restore_entry(db_connection, jon, entry_id) is True
        assert vault.get_entry(db_connection, jon, entry_id).password == "SneakyPanda!22"
        db_connection.close()


# ========== User Directory ==========

class Test_User_Directory:
    # Everyone else shows up, sorted by name, and you don't
    def test_directory(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        make_session(db_connection, "kim")
        make_session(db_connection, "amy")

        directory = sharing.user_directory(db_connection, jon)

        assert directory == [("amy", "amy@gmail.com"), ("kim", "kim@gmail.com")]
        db_connection.close()

    # Someone who registers later appears the next time it's loaded
    def test_new_user_appears(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = make_session(db_connection, "jon")
        assert sharing.user_directory(db_connection, jon) == []

        make_session(db_connection, "brock")
        assert ("brock", "brock@gmail.com") in sharing.user_directory(db_connection, jon)
        db_connection.close()
from core import storage
import os
import pytest
import uuid


# ========== Setup helpers ==========

def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def add_user(db_connection, username):
    # Inserts a test user with fake keys and returns their user_id
    user_id = str(uuid.uuid4())
    db_connection.execute(
        """INSERT INTO users (user_id, username, email, password_hash, encrypted_dek, encrypted_dek_nonce,
                              kek_salt, public_key, encrypted_private_key, private_key_nonce)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, username, f"{username}@example.com", "$argon2id$fake", os.urandom(48), os.urandom(12),
         os.urandom(16), os.urandom(32), os.urandom(48), os.urandom(12)),
    )
    return user_id


def add_vault(db_connection, vault_name, owner_id, member_role="view"):
    # Inserts a vault (with a fake encrypted name) and gives the owner a share row
    vault_id = str(uuid.uuid4())
    db_connection.execute(
        "INSERT INTO vaults (vault_id, encrypted_vault_name, vault_name_nonce, owner_id, member_role) VALUES (?, ?, ?, ?, ?)",
        (vault_id, os.urandom(40), os.urandom(12), owner_id, member_role),
    )
    share_vault(db_connection, vault_id, owner_id)
    return vault_id


def share_vault(db_connection, vault_id, user_id, role=None, wrapped_vault_key=None):
    # Adds a user to a vault, role None means "use the vault's member_role"
    db_connection.execute(
        "INSERT INTO vault_shares (vault_id, user_id, wrapped_vault_key, role) VALUES (?, ?, ?, ?)",
        (vault_id, user_id, wrapped_vault_key or os.urandom(92), role),
    )


def add_entry(db_connection, vault_id, created_by, wrapped_entry_key=None):
    # Inserts an entry into a vault, returns the vault_entry_id
    vault_entry_id = str(uuid.uuid4())
    db_connection.execute(
        """INSERT INTO vault_entries (vault_entry_id, vault_id, created_by, wrapped_entry_key,
                                      entry_key_nonce, nonce, ciphertext)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (vault_entry_id, vault_id, created_by, wrapped_entry_key or os.urandom(48),
         os.urandom(12), os.urandom(12), os.urandom(60)),
    )
    return vault_entry_id


def add_direct_share(db_connection, vault_entry_id, user_id, role="view", wrapped_entry_key=None):
    # Shares one entry directly with a user
    db_connection.execute(
        "INSERT INTO entry_shares (vault_entry_id, user_id, wrapped_entry_key, role) VALUES (?, ?, ?, ?)",
        (vault_entry_id, user_id, wrapped_entry_key or os.urandom(92), role),
    )


# ========== Vault path: get_vault_entries ==========

class Test_Get_Vault_Entries:
    # A member sees every entry in the vault, including ones other members created
    def test_member_sees_entries_others_created(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)

        aws = add_entry(db_connection, work, created_by=jon)
        github = add_entry(db_connection, work, created_by=brock)

        ids = [row["vault_entry_id"] for row in storage.get_vault_entries(db_connection, brock)]
        assert len(ids) == 2
        assert aws in ids
        assert github in ids
        db_connection.close()

    # Entries in vaults the user isn't in never come back
    def test_only_entries_from_own_vaults(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        personal = add_vault(db_connection, "Personal", jon)
        share_vault(db_connection, work, brock)

        work_entry = add_entry(db_connection, work, created_by=jon)
        personal_entry = add_entry(db_connection, personal, created_by=jon)

        ids = [row["vault_entry_id"] for row in storage.get_vault_entries(db_connection, brock)]
        assert work_entry in ids
        assert personal_entry not in ids
        db_connection.close()

    # Each entry comes back once, not once per vault member
    def test_no_duplicate_rows(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        share_vault(db_connection, work, amy)
        add_entry(db_connection, work, created_by=jon)

        assert len(storage.get_vault_entries(db_connection, brock)) == 1
        db_connection.close()

    # A user in no vaults gets an empty list
    def test_no_vaults_returns_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, "Work", jon)
        add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entries(db_connection, eve) == []
        db_connection.close()


# ========== Vault path: get_vault_entry ==========

class Test_Get_Vault_Entry:
    # A member gets the entry, with THEIR OWN wrapped vault key
    def test_returns_members_own_wrapped_vault_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        brocks_copy = os.urandom(92)
        share_vault(db_connection, work, brock, wrapped_vault_key=brocks_copy)
        entry = add_entry(db_connection, work, created_by=jon)

        row = storage.get_vault_entry(db_connection, brock, entry)
        assert row["wrapped_vault_key"] == brocks_copy
        db_connection.close()

    # A non-member gets None, even with the entry id
    def test_non_member_gets_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, eve, entry) is None
        db_connection.close()

    # A missing entry id returns None
    def test_missing_entry_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        add_vault(db_connection, "Work", jon)

        assert storage.get_vault_entry(db_connection, jon, str(uuid.uuid4())) is None
        db_connection.close()

    # No override → the vault's member_role is used
    def test_role_falls_back_to_vault_default(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon, member_role="view")
        share_vault(db_connection, work, brock, role=None)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, brock, entry)["role"] == "view"
        db_connection.close()

    # A member's own role overrides the vault's default
    def test_member_role_overrides_vault_default(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        kim = add_user(db_connection, "kim")
        work = add_vault(db_connection, "Work", jon, member_role="view")
        share_vault(db_connection, work, kim, role="edit")
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_vault_entry(db_connection, kim, entry)["role"] == "edit"
        db_connection.close()

    # owner_id comes back so vault.py can give the owner full rights
    def test_returns_owner_id(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=brock)

        assert storage.get_vault_entry(db_connection, brock, entry)["owner_id"] == jon
        db_connection.close()


# ========== Direct path: get_shared_entry ==========

class Test_Get_Shared_Entry:
    # A direct share returns the user's own wrapped entry key, not the vault's
    def test_returns_users_own_wrapped_entry_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        vaults_copy = os.urandom(48)
        amys_copy = os.urandom(92)
        entry = add_entry(db_connection, work, created_by=jon, wrapped_entry_key=vaults_copy)
        add_direct_share(db_connection, entry, amy, wrapped_entry_key=amys_copy)

        row = storage.get_shared_entry(db_connection, amy, entry)
        assert row["wrapped_entry_key"] == amys_copy
        assert row["wrapped_entry_key"] != vaults_copy
        db_connection.close()

    # The direct share's role comes back
    def test_returns_share_role(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, entry, amy, role="edit")

        assert storage.get_shared_entry(db_connection, amy, entry)["role"] == "edit"
        db_connection.close()

    # No direct share → None
    def test_not_shared_returns_none(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_shared_entry(db_connection, eve, entry) is None
        db_connection.close()

    # A vault member with no direct share gets None from the DIRECT path
    def test_vault_member_not_on_direct_path(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.get_shared_entry(db_connection, brock, entry) is None
        db_connection.close()


# ========== Direct path: get_shared_entries ==========

class Test_Get_Shared_Entries:
    # Only the entries shared directly come back, not the rest of the vault
    def test_only_shared_entries(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        wifi = add_entry(db_connection, work, created_by=jon)
        aws = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, wifi, amy)

        ids = [row["vault_entry_id"] for row in storage.get_shared_entries(db_connection, amy)]
        assert ids == [wifi]
        assert aws not in ids
        db_connection.close()

    # Multiple direct shares all come back
    def test_multiple_shares(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        wifi = add_entry(db_connection, work, created_by=jon)
        aws = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, wifi, amy)
        add_direct_share(db_connection, aws, amy)

        ids = [row["vault_entry_id"] for row in storage.get_shared_entries(db_connection, amy)]
        assert len(ids) == 2
        assert wifi in ids
        assert aws in ids
        db_connection.close()

    # Nothing shared → empty list
    def test_nothing_shared_returns_empty(self, tmp_path):
        db_connection = setup_db(tmp_path)
        amy = add_user(db_connection, "amy")

        assert storage.get_shared_entries(db_connection, amy) == []
        db_connection.close()

# ========== Delete vault share (remove a vault member) ==========

class Test_Delete_Vault_Share:
    # Removing a member returns True, and they can't reach the vault's entries anymore
    def test_delete_member(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.delete_vault_share(db_connection, brock, work) is True
        assert storage.get_vault_entry(db_connection, brock, entry) is None
        db_connection.close()

    # Other members are untouched
    def test_other_members_stay(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        kim = add_user(db_connection, "kim")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        share_vault(db_connection, work, kim)
        entry = add_entry(db_connection, work, created_by=jon)

        storage.delete_vault_share(db_connection, brock, work)

        assert storage.get_vault_entry(db_connection, jon, entry) is not None
        assert storage.get_vault_entry(db_connection, kim, entry) is not None
        db_connection.close()

    # Only removes them from THIS vault, not their other vaults
    def test_only_that_vault(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        home = add_vault(db_connection, "Home", jon)
        share_vault(db_connection, work, brock)
        share_vault(db_connection, home, brock)
        home_entry = add_entry(db_connection, home, created_by=jon)

        storage.delete_vault_share(db_connection, brock, work)

        assert storage.get_vault_entry(db_connection, brock, home_entry) is not None
        db_connection.close()

    # Removing someone who isn't a member returns False
    def test_not_a_member(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, "Work", jon)

        assert storage.delete_vault_share(db_connection, eve, work) is False
        db_connection.close()

    # The function must NOT commit, so a crash during rotation can undo it
    def test_delete_can_roll_back(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        brock = add_user(db_connection, "brock")
        work = add_vault(db_connection, "Work", jon)
        share_vault(db_connection, work, brock)
        entry = add_entry(db_connection, work, created_by=jon)
        db_connection.commit()      # save the setup, so only the delete can be rolled back

        with pytest.raises(RuntimeError):
            with db_connection:
                storage.delete_vault_share(db_connection, brock, work)
                raise RuntimeError("simulated crash in the middle of rotation")

        # The crash rolled everything back, so Brock is still a member
        assert storage.get_vault_entry(db_connection, brock, entry) is not None
        db_connection.close()


# ========== Delete entry share (remove a direct share) ==========

class Test_Delete_Entry_Share:
    # Removing a direct share returns True, and they can't reach the entry anymore
    def test_delete_share(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, entry, amy)

        assert storage.delete_entry_share(db_connection, amy, entry) is True
        assert storage.get_shared_entry(db_connection, amy, entry) is None
        db_connection.close()

    # Other direct shares on the same entry are untouched
    def test_other_shares_stay(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        sam = add_user(db_connection, "sam")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, entry, amy)
        add_direct_share(db_connection, entry, sam)

        storage.delete_entry_share(db_connection, amy, entry)

        assert storage.get_shared_entry(db_connection, sam, entry) is not None
        db_connection.close()

    # Only removes that ONE entry's share, not other entries shared with them
    def test_only_that_entry(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        wifi = add_entry(db_connection, work, created_by=jon)
        aws = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, wifi, amy)
        add_direct_share(db_connection, aws, amy)

        storage.delete_entry_share(db_connection, amy, wifi)

        assert storage.get_shared_entry(db_connection, amy, aws) is not None
        db_connection.close()

    # The entry itself stays for the vault owner
    def test_entry_itself_stays(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        amy = add_user(db_connection, "amy")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)
        add_direct_share(db_connection, entry, amy)

        storage.delete_entry_share(db_connection, amy, entry)

        assert storage.get_vault_entry(db_connection, jon, entry) is not None
        db_connection.close()

    # Removing a share that doesn't exist returns False
    def test_not_shared(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = add_user(db_connection, "jon")
        eve = add_user(db_connection, "eve")
        work = add_vault(db_connection, "Work", jon)
        entry = add_entry(db_connection, work, created_by=jon)

        assert storage.delete_entry_share(db_connection, eve, entry) is False
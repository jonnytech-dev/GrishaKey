from core import auth, crypto, sharing, storage, vault
import pytest


PASSWORD = "c0rrect1horseb@ttery"
NEW_PASSWORD = "brand-new-p@ssw0rd"


def setup_db(tmp_path):
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


def register_with_code(db_connection, username="jon"):
    # Registers a user and creates their first recovery code, returns (user_id, code)
    user_id = auth.register(db_connection, username, f"{username}@gmail.com", PASSWORD)
    code = auth.create_recovery_code(db_connection, user_id, PASSWORD)
    return user_id, code


class Test_Recovery_Code_Format:
    # Six groups of four, only allowed characters
    def test_format(self):
        code = crypto.new_recovery_code()
        groups = code.split("-")
        assert len(groups) == 6
        assert all(len(g) == 4 for g in groups)
        assert all(c in crypto.RECOVERY_ALPHABET for c in code.replace("-", ""))

    # Never the same twice
    def test_random(self):
        assert crypto.new_recovery_code() != crypto.new_recovery_code()

    # Lowercase, spaces, dashes, and look-alikes all normalize the same
    def test_normalize(self):
        assert crypto.normalize_recovery_code("abcd-efgh") == "ABCDEFGH"
        assert crypto.normalize_recovery_code("ab cd") == "ABCD"
        assert crypto.normalize_recovery_code("O1IL") == "0111"


class Test_Create_Recovery_Code:
    # A new user has no code until one is created
    def test_has_recovery_code(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        assert auth.has_recovery_code(db_connection, user_id) is False

        auth.create_recovery_code(db_connection, user_id, PASSWORD)
        assert auth.has_recovery_code(db_connection, user_id) is True
        db_connection.close()

    # Creating a code needs the right master password
    def test_wrong_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        with pytest.raises(auth.InvalidCredentialsError):
            auth.create_recovery_code(db_connection, user_id, "wr0ng!password")
        db_connection.close()

    # A new code from Settings makes the old one stop working
    def test_new_code_replaces_old(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id, old_code = register_with_code(db_connection)
        new_code = auth.create_recovery_code(db_connection, user_id, PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.recover_account(db_connection, "jon@gmail.com", old_code, NEW_PASSWORD)
        assert auth.recover_account(db_connection, "jon@gmail.com", new_code, NEW_PASSWORD)
        db_connection.close()


class Test_Recover_Account:
    # Recovery sets a new password, and everything still opens
    def test_recover_and_data_survives(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id, code = register_with_code(db_connection)
        before = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        personal = sharing.list_vaults(db_connection, before)[0].vault_id
        entry_id = vault.add_entry(db_connection, before, personal, "Gmail", "", "jon", "SneakyPanda!22", "")

        auth.recover_account(db_connection, "jon@gmail.com", code, NEW_PASSWORD)

        after = auth.login(db_connection, "jon@gmail.com", NEW_PASSWORD)
        assert after.private_key == before.private_key
        assert vault.get_entry(db_connection, after, entry_id).password == "SneakyPanda!22"
        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()

    # A code works once; recovery hands back a new one that works
    def test_code_is_one_time(self, tmp_path):
        db_connection = setup_db(tmp_path)
        _user_id, code = register_with_code(db_connection)

        next_code = auth.recover_account(db_connection, "jon@gmail.com", code, NEW_PASSWORD)
        assert next_code != code

        with pytest.raises(auth.InvalidCredentialsError):
            auth.recover_account(db_connection, "jon@gmail.com", code, "another-p@ssw0rd!")
        assert auth.recover_account(db_connection, "jon@gmail.com", next_code, "another-p@ssw0rd!")
        db_connection.close()

    # Typing the code in lowercase without dashes still works
    def test_code_typed_loosely(self, tmp_path):
        db_connection = setup_db(tmp_path)
        _user_id, code = register_with_code(db_connection)
        loose = code.replace("-", " ").lower()
        assert auth.recover_account(db_connection, "jon@gmail.com", loose, NEW_PASSWORD)
        db_connection.close()

    # Wrong code: vague error, password unchanged
    def test_wrong_code(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id, _code = register_with_code(db_connection)
        with pytest.raises(auth.InvalidCredentialsError):
            auth.recover_account(db_connection, "jon@gmail.com", crypto.new_recovery_code(), NEW_PASSWORD)
        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # Unknown email and wrong code give the exact same message
    def test_errors_look_identical(self, tmp_path):
        db_connection = setup_db(tmp_path)
        register_with_code(db_connection)

        with pytest.raises(auth.InvalidCredentialsError) as wrong_code:
            auth.recover_account(db_connection, "jon@gmail.com", crypto.new_recovery_code(), NEW_PASSWORD)
        with pytest.raises(auth.InvalidCredentialsError) as unknown_email:
            auth.recover_account(db_connection, "nobody@gmail.com", crypto.new_recovery_code(), NEW_PASSWORD)
        assert str(wrong_code.value) == str(unknown_email.value)
        db_connection.close()

    # A user who never created a code can't recover
    def test_no_code_created(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        with pytest.raises(auth.InvalidCredentialsError):
            auth.recover_account(db_connection, "jon@gmail.com", crypto.new_recovery_code(), NEW_PASSWORD)
        db_connection.close()

    # The new password follows the same rules as register
    def test_new_password_rules(self, tmp_path):
        db_connection = setup_db(tmp_path)
        _user_id, code = register_with_code(db_connection)
        with pytest.raises(auth.PasswordComplexityError):
            auth.recover_account(db_connection, "jon@gmail.com", code, "short")
        db_connection.close()

    # Too many wrong codes → locked out, like login
    def test_lockout(self, tmp_path):
        db_connection = setup_db(tmp_path)
        _user_id, code = register_with_code(db_connection)
        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.recover_account(db_connection, "jon@gmail.com", crypto.new_recovery_code(), NEW_PASSWORD)
        with pytest.raises(auth.AccountLockedError):
            auth.recover_account(db_connection, "jon@gmail.com", code, NEW_PASSWORD)
        db_connection.close()

    # Changing the master password keeps the recovery code working
    def test_password_change_keeps_code(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id, code = register_with_code(db_connection)
        auth.change_password(db_connection, user_id, PASSWORD, "changed-p@ssw0rd!")
        assert auth.recover_account(db_connection, "jon@gmail.com", code, NEW_PASSWORD)
        db_connection.close()

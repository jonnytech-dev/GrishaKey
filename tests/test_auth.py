from core import auth, crypto, sharing, storage, vault
import pytest
from cryptography.exceptions import InvalidTag
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def setup_db(tmp_path):
    # Fresh DB with tables for each test
    db_connection = storage.db_connect(tmp_path / "test.db")
    storage.create_tables(db_connection)
    return db_connection


# ========== Register ==========

class Test_Register:
    # register returns user_id if creation is successful
    def test_register_returns_user_id(self, tmp_path):
        db_connection = setup_db(tmp_path)
        register_user = auth.register(db_connection, "jon", "jon@gmail.com", "correct111-horse-battery")
        assert isinstance(register_user, str)

        db_connection.close()

    # Password must be atleast 12 characters, this test 11 only
    def test_register_with_too_short_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "johnnymailman@gmail.com", "12345678911")

        db_connection.close()

    # Password must be atleast 12 characters, this test 12 exactly
    def test_register_with_minimal_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        
        assert isinstance(auth.register(db_connection, "jon", "johnnymailman@gmail.com", "123456789112"), str)

        db_connection.close()

    # Password must be at most 256 characters, this test 256 exactly
    def test_register_with_maximum_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        password = "a" * 250 + "123!@#" 
        
        
        assert isinstance(auth.register(db_connection, "jon", "johnnymailman@gmail.com", password), str)

        db_connection.close()

    # Password must be at most 256 characters, this test 257
    def test_register_with_too_long_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        password = "a" * 250 + "123!@#7" 
        
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "johnnymailman@gmail.com", password)

        db_connection.close()

    # # Password must have atleast 3 numbers or 3 special characters
    # def test_register_password_not_strong(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
        
    #     with pytest.raises(ValueError):
    #         auth.register(db_connection, "jonnnnnn", "johnnygfdgdfg@gmail.com", "Panda-Turtle-Dove")

    #     db_connection.close()

    # The stored hash must verify with the real password, and must not be the password
    def test_register_stores_real_password_hash(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")

        user = storage.get_user_by_email(db_connection, "jon@gmail.com")
        assert user["password_hash"] != "c0rrect1horseb@ttery"
        assert crypto.verify_password(user["password_hash"], "c0rrect1horseb@ttery")
        db_connection.close()

    # The full chain: password + stored salt rebuilds the KEK, which unwraps the stored DEK
    # def test_register_dek_unwraps_with_password(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
    #     user_id = auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")

    #     user = storage.get_user_by_email(db_connection, "jon@gmail.com")
    #     kek = crypto.derive_kek("c0rrect1horseb@ttery", user["kek_salt"])
    #     aad = f"user:{user_id}:dek".encode()
    #     dek = crypto.decrypt(kek, user["encrypted_dek_nonce"], user["encrypted_dek"], aad)
    #     assert len(dek) == 32
    #     db_connection.close()

    # New accounts are never admins
    def test_register_role_is_user(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        assert storage.get_user_by_email(db_connection, "jon@gmail.com")["role"] == "user"
        db_connection.close()

    # A short password is rejected before anything is saved
    def test_register_short_password_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        with pytest.raises(ValueError):
            auth.register(db_connection, "jon", "jon@gmail.com", "short")
        assert storage.get_user_by_email(db_connection, "jon@gmail.com") is None
        db_connection.close()

    # A duplicate email raises the app's own error, not a database error
    def test_register_duplicate_email_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        with pytest.raises(auth.UserExistsError):
            auth.register(db_connection, "gavin", "jon@gmail.com", "correct111-horse-battery")
        db_connection.close()

    # A duplicate username raises the same error
    def test_register_duplicate_username_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", "c0rrect1horseb@ttery")
        with pytest.raises(auth.UserExistsError):
            auth.register(db_connection, "jon", "gavin@gmail.com", "correct111-horse-battery")
        db_connection.close()

# ========== Login ==========

PASSWORD = "c0rrect1horseb@ttery"

class Test_Login:
    # Correct email and password returns a Session for that user
    def test_login_success(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        assert session.user_id == user_id
        assert session.role == "user"
        db_connection.close()

    # Two logins must give back the SAME DEK, or old entries could never be read
    # def test_login_returns_same_dek_each_time(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
    #     auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

    #     first = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    #     second = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    #     assert first.dek == second.dek
    #     db_connection.close()

    # Data locked with the DEK from one login opens with the DEK from the next login
    # def test_dek_from_login_decrypts_saved_data(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
    #     auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

    #     session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    #     nonce, ciphertext = crypto.encrypt(session.dek, b"gmail-password", b"test")

    #     session_again = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    #     assert crypto.decrypt(session_again.dek, nonce, ciphertext, b"test") == b"gmail-password"
    #     db_connection.close()

    # Login works no matter how the email is capitalized
    def test_login_email_any_case(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "JON@Gmail.COM", PASSWORD)
        assert session.user_id == user_id
        db_connection.close()

    # Wrong password fails
    def test_login_wrong_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "jon@gmail.com", "wr0ng!password")
        db_connection.close()

    # Unknown email fails with the same error
    def test_login_unknown_email(self, tmp_path):
        db_connection = setup_db(tmp_path)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)
        db_connection.close()

    # Wrong email and wrong password must give the exact same message
    def test_login_errors_look_identical(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError) as wrong_password:
            auth.login(db_connection, "jon@gmail.com", "wr0ng!password")
        with pytest.raises(auth.InvalidCredentialsError) as unknown_email:
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)

        assert str(wrong_password.value) == str(unknown_email.value)
        db_connection.close()

    # A tampered encrypted DEK must fail loudly, not look like a wrong password
    def test_login_tampered_dek_fails_loudly(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        db_connection.execute("UPDATE users SET encrypted_dek = ?", (os.urandom(48),))
        db_connection.commit()

        with pytest.raises(InvalidTag):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()


# ========== Login Lockout ==========

class Test_Login_Lockout:
    # Too many wrong passwords lock the email, even if the next one is correct
    def test_email_locks_after_max_failures(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "jon@gmail.com", "wr0ng!password")

        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()

    # One under the limit still lets the correct password in
    def test_login_works_under_limit(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS - 1):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "jon@gmail.com", "wr0ng!password")

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # Successful logins must never count toward the lockout
    def test_successful_logins_never_lock(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS + 1):
            assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # Unknown emails lock the same way, so lockout can't reveal who has an account
    def test_unknown_email_also_locks(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, "nobody@gmail.com", PASSWORD)

        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "nobody@gmail.com", PASSWORD)
        db_connection.close()

    # Failures older than the window no longer lock the account
    def test_lockout_expires(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for _ in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            db_connection.execute(
                "INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, 0, datetime('now', '-20 minutes'))",
                (None, "jon@gmail.com"),
            )
        db_connection.commit()

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # One IP trying many different emails gets locked out (password spraying)
    def test_ip_locks_after_max_failures(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for number in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, f"victim{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        # Even a real user with the correct password is blocked from that IP
        with pytest.raises(auth.AccountLockedError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # A locked IP does not affect other IPs
    def test_ip_lock_does_not_affect_other_ips(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        for number in range(auth.MAX_FAILED_LOGIN_ATTEMPTS):
            with pytest.raises(auth.InvalidCredentialsError):
                auth.login(db_connection, f"victim{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD, ip_address="1.1.1.1").user_id == user_id
        db_connection.close()


# ========== Register Limit ==========

class Test_Register_Limit:
    # Too many registers from one IP are blocked
    def test_register_limit_by_ip(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for number in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            auth.register(db_connection, f"user{number}", f"user{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        with pytest.raises(auth.AccountLockedError):
            auth.register(db_connection, "one_more", "one_more@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # Duplicate-account attempts still count toward the limit
    def test_duplicate_registers_count(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")

        for _ in range(auth.MAX_FAILED_REGISTER_ATTEMPTS - 1):
            with pytest.raises(auth.UserExistsError):
                auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6")

        with pytest.raises(auth.AccountLockedError):
            auth.register(db_connection, "new", "new@gmail.com", PASSWORD, ip_address="6.6.6.6")
        db_connection.close()

    # Weak passwords are not logged as register attempts
    def test_weak_password_not_counted(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for _ in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            with pytest.raises(ValueError):
                auth.register(db_connection, "jon", "jon@gmail.com", "short", ip_address="6.6.6.6")

        assert isinstance(auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="6.6.6.6"), str)
        db_connection.close()

    # A blocked IP does not affect other IPs
    def test_register_limit_does_not_affect_other_ips(self, tmp_path):
        db_connection = setup_db(tmp_path)

        for number in range(auth.MAX_FAILED_REGISTER_ATTEMPTS):
            auth.register(db_connection, f"user{number}", f"user{number}@gmail.com", PASSWORD, ip_address="6.6.6.6")

        assert isinstance(auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD, ip_address="1.1.1.1"), str)
        db_connection.close()

# ========== Keys and Personal Vault ==========

class Test_Register_Keys:
    # The stored private key unlocks with the DEK and matches the stored public key
    def test_private_key_matches_public_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        public_key = storage.get_public_key(db_connection, user_id)
        rebuilt = X25519PrivateKey.from_private_bytes(session.private_key).public_key().public_bytes_raw()
        assert rebuilt == public_key
        db_connection.close()

    # Every user gets their own key pair
    def test_users_get_different_key_pairs(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        brock = auth.register(db_connection, "brock", "brock@gmail.com", PASSWORD)

        assert storage.get_public_key(db_connection, jon) != storage.get_public_key(db_connection, brock)
        db_connection.close()

    # The private key is never stored plain
    def test_private_key_not_stored_plain(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        stored = storage.get_user_by_email(db_connection, "jon@gmail.com")["encrypted_private_key"]
        assert session.private_key not in stored
        db_connection.close()

    # Login returns the same private key every time
    def test_login_returns_same_private_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        first = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        second = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        assert first.private_key == second.private_key
        assert len(first.private_key) == 32
        db_connection.close()

    # The private key unlocks with the DEK and the private key label
    # def test_private_key_unlocks_with_dek(self, tmp_path):
    #     db_connection = setup_db(tmp_path)
    #     user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

    #     session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
    #     user = storage.get_user_by_email(db_connection, "jon@gmail.com")
    #     private_key = crypto.decrypt(
    #         session.dek,
    #         user["private_key_nonce"],
    #         user["encrypted_private_key"],
    #         f"user:{user_id}:private_key".encode(),
    #     )
    #     assert private_key == session.private_key
    #     db_connection.close()


class Test_Personal_Vault:
    # Register creates exactly one vault, named Personal, owned by the new user
    def test_register_creates_personal_vault(self, tmp_path):
        db_connection = setup_db(tmp_path)
        auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)

        vaults = sharing.list_vaults(db_connection, session)
        assert len(vaults) == 1
        assert vaults[0].name == "Personal"
        assert vaults[0].is_owner is True
        db_connection.close()

    # The owner is also a member, so they hold a copy of the vault key
    def test_owner_has_vault_share(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        shares = db_connection.execute("SELECT * FROM vault_shares WHERE user_id = ?", (user_id,)).fetchall()
        assert len(shares) == 1
        db_connection.close()

    # The full chain: login private key unwraps the Personal vault key
    def test_private_key_unwraps_personal_vault_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        share = db_connection.execute("SELECT * FROM vault_shares WHERE user_id = ?", (user_id,)).fetchone()

        session = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        vault_key = crypto.unwrap_with_private_key(
            session.private_key,
            share["wrapped_vault_key"],
            f"vault:{share['vault_id']}:user:{user_id}".encode(),
        )
        assert len(vault_key) == 32
        db_connection.close()

    # Another user's private key can't unwrap Jon's vault key
    def test_other_user_cannot_unwrap_vault_key(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        auth.register(db_connection, "brock", "brock@gmail.com", PASSWORD)
        share = db_connection.execute("SELECT * FROM vault_shares WHERE user_id = ?", (jon,)).fetchone()

        brock = auth.login(db_connection, "brock@gmail.com", PASSWORD)
        with pytest.raises(InvalidTag):
            crypto.unwrap_with_private_key(
                brock.private_key,
                share["wrapped_vault_key"],
                f"vault:{share['vault_id']}:user:{jon}".encode(),
            )
        db_connection.close()


# ========== Change Password ==========

class Test_Change_Password:
    # The new password works for login
    def test_new_password_works(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        auth.change_password(db_connection, user_id, PASSWORD, "brand-new-p@ssw0rd")

        assert auth.login(db_connection, "jon@gmail.com", "brand-new-p@ssw0rd").user_id == user_id
        db_connection.close()

    # The old password stops working
    def test_old_password_stops_working(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        auth.change_password(db_connection, user_id, PASSWORD, "brand-new-p@ssw0rd")

        with pytest.raises(auth.InvalidCredentialsError):
            auth.login(db_connection, "jon@gmail.com", PASSWORD)
        db_connection.close()

    # A wrong current password changes nothing
    def test_wrong_current_password(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.change_password(db_connection, user_id, "wr0ng!password", "brand-new-p@ssw0rd")

        assert auth.login(db_connection, "jon@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # The new password follows the same length rules as register
    def test_new_password_rules(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.PasswordComplexityError):
            auth.change_password(db_connection, user_id, PASSWORD, "short")
        db_connection.close()

    # Same private key, and saved entries still open, after the change
    def test_data_survives(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        before = auth.login(db_connection, "jon@gmail.com", PASSWORD)
        personal = sharing.list_vaults(db_connection, before)[0].vault_id
        entry_id = vault.add_entry(db_connection, before, personal, "Gmail", "", "jon", "SneakyPanda!22", "")

        auth.change_password(db_connection, user_id, PASSWORD, "brand-new-p@ssw0rd")

        after = auth.login(db_connection, "jon@gmail.com", "brand-new-p@ssw0rd")
        assert after.private_key == before.private_key
        assert vault.get_entry(db_connection, after, entry_id).password == "SneakyPanda!22"
        db_connection.close()


# ========== Update Profile ==========

class Test_Update_Profile:
    # Username and email change with the right password, and login uses the new email
    def test_change_username_and_email(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        auth.update_profile(db_connection, user_id, PASSWORD, "jonny", "Jonny@Gmail.com")

        assert auth.get_profile(db_connection, user_id) == {"username": "jonny", "email": "jonny@gmail.com"}
        assert auth.login(db_connection, "jonny@gmail.com", PASSWORD).user_id == user_id
        db_connection.close()

    # A wrong password changes nothing
    def test_wrong_password_changes_nothing(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(auth.InvalidCredentialsError):
            auth.update_profile(db_connection, user_id, "wr0ng!password", "hacker", "hacker@gmail.com")

        assert auth.get_profile(db_connection, user_id) == {"username": "jon", "email": "jon@gmail.com"}
        db_connection.close()

    # Can't take someone else's email
    def test_duplicate_email_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        jon = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)
        auth.register(db_connection, "brock", "brock@gmail.com", PASSWORD)

        with pytest.raises(auth.UserExistsError):
            auth.update_profile(db_connection, jon, PASSWORD, "jon", "brock@gmail.com")
        db_connection.close()

    # Username can't be blank
    def test_empty_username_fails(self, tmp_path):
        db_connection = setup_db(tmp_path)
        user_id = auth.register(db_connection, "jon", "jon@gmail.com", PASSWORD)

        with pytest.raises(ValueError):
            auth.update_profile(db_connection, user_id, PASSWORD, "   ", "jon@gmail.com")
        db_connection.close()
import sqlite3
from core import crypto, storage
import uuid
import string
from dataclasses import dataclass, field
from core.models import Session
import os
from cryptography.exceptions import InvalidTag

MAX_FAILED_LOGIN_ATTEMPTS=10
MAX_FAILED_REGISTER_ATTEMPTS=5

# ---------- Custom error exceptions ----------
# Username or email is already taken
class UserExistsError(Exception):
    pass

# Password is less than 12 or more than 256 characters long
class PasswordComplexityError(ValueError):
    pass

# Wrong email or password when attempting to login
class InvalidCredentialsError(Exception):
    pass

# Too many login attempts error
class AccountLockedError(Exception):
    pass

# ---------- Register & Login ----------

# Password requirement characters
strong_characters = string.digits + string.punctuation

# Register a new user
# Registration attempts do not get logged for password failures
def register(db_connection: sqlite3.Connection, username: str, email: str, password: str,
             ip_address: str | None = None) -> str:
    # Check if user is blocked from making too many requests
    if storage.count_recent_registers_by_ip_address(db_connection, ip_address, 15) >= MAX_FAILED_REGISTER_ATTEMPTS:
        raise AccountLockedError("Too many register attempts")

    # Verify password is strong/secure
    if len(password) < 12:
        raise PasswordComplexityError("Password must be at least 12 characters")
    elif len(password) > 256:
        raise PasswordComplexityError("Password must not be more than 256 characters")

    # Record the attempt BEFORE the transaction, so it counts even if registering fails
    # (record_register_attempt commits on its own, so it can't go inside the with block)
    storage.record_register_attempt(db_connection, ip_address)

    # Login: password hash
    user_id = str(uuid.uuid4())
    password_hash = crypto.hash_password(password)

    # Password → KEK → locks the DEK
    kek_salt = crypto.new_salt()
    kek = crypto.derive_kek(password, kek_salt)
    dek = crypto.new_dek()
    encrypted_dek_nonce, encrypted_dek = crypto.encrypt(kek, dek, crypto.user_dek_aad(user_id))

    # Key pair: DEK locks the private key, public key is stored plain
    private_key, public_key = crypto.new_key_pair()
    private_key_nonce, encrypted_private_key = crypto.encrypt(dek, private_key, crypto.user_private_key_aad(user_id))

    # Personal vault: new vault key, encrypted name, wrapped for the new user
    vault_id = str(uuid.uuid4())
    vault_key = crypto.new_vault_key()
    vault_name_nonce, encrypted_vault_name = crypto.encrypt(vault_key, "Personal".encode(), crypto.vault_name_aad(vault_id))
    wrapped_vault_key = crypto.wrap_for_public_key(public_key, vault_key, crypto.wrapped_vault_key_aad(vault_id, user_id))

    # Save the user, their vault, and their vault share together, or none of them
    try:
        with db_connection:
            storage.create_user(
                db_connection,
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                encrypted_dek=encrypted_dek,
                encrypted_dek_nonce=encrypted_dek_nonce,
                kek_salt=kek_salt,
                public_key=public_key,
                encrypted_private_key=encrypted_private_key,
                private_key_nonce=private_key_nonce,
            )
            storage.create_vault(
                db_connection,
                vault_id=vault_id,
                encrypted_vault_name=encrypted_vault_name,
                vault_name_nonce=vault_name_nonce,
                owner_id=user_id,
            )
            storage.create_vault_share(
                db_connection,
                vault_id=vault_id,
                user_id=user_id,
                wrapped_vault_key=wrapped_vault_key,
            )
    except sqlite3.IntegrityError as e:
        raise UserExistsError("Username or Email already exists") from e

    return user_id

# A real Argon2 hash of a throwaway value, used to keep timing the same for unknown emails
_DUMMY_HASH = crypto.hash_password("dummy-password-for-timing")

def login(db_connection: sqlite3.Connection, email: str, password: str, ip_address: str | None = None, ) -> Session:
    # Check if user is blocked from making too many request
    if storage.count_recent_logins_by_ip_address(db_connection, ip_address, 15) >= MAX_FAILED_LOGIN_ATTEMPTS or storage.count_recent_logins_by_email(db_connection, email, 15) >= MAX_FAILED_LOGIN_ATTEMPTS:
        raise AccountLockedError("Too many login attempts")

    # Find user by email
    user = storage.get_user_by_email(db_connection, email)

    # If user does not exist, hash the dummy password to prevent attackers from using time measuring
    if user is None:
        # Check if password provided matches the password hash stored
        crypto.verify_password(_DUMMY_HASH, password)
        # Record register attempt
        storage.record_login_attempt(db_connection, ip_address, email, 0)
        raise InvalidCredentialsError("Incorrect email or password")
        
    if crypto.verify_password(user["password_hash"], password) == False:
        storage.record_login_attempt(db_connection, ip_address, email, 0)
        raise InvalidCredentialsError("Incorrect email or password")

    # Derive the KEK by the provided password and the stored salt
    kek = crypto.derive_kek(password, user['kek_salt'])

    # AAD / Labels
    dek_aad = crypto.user_dek_aad(user['user_id'])
    private_key_aad = crypto.user_private_key_aad(user['user_id'])

    # Decrypt the encrypted DEK to get the plain DEK
    dek = crypto.decrypt(kek, user["encrypted_dek_nonce"], user["encrypted_dek"], dek_aad)
    private_key = crypto.decrypt(dek, user["private_key_nonce"], user["encrypted_private_key"], private_key_aad)

    # Record login attempt as successful
    storage.record_login_attempt(db_connection, ip_address, email, 1)

    # Return the session data to the caller (server code)
    # DEK stays in server memory, never stored in the DB or remembered after logout
    return Session(user["user_id"], user["role"], private_key, user["private_key_nonce"], user["public_key"])


def get_profile(db_connection: sqlite3.Connection, user_id: str) -> dict | None:
    # The user's username and email, for the settings page
    user = storage.get_user_by_id(db_connection, user_id)
    if user is None:
        return None
    return {"username": user["username"], "email": user["email"]}


def update_profile(db_connection: sqlite3.Connection, user_id: str, current_password: str,
                   username: str, email: str) -> None:
    # Change username and/or email. Requires the current master password.
    # Wrong password → InvalidCredentialsError. Taken name or email → UserExistsError.
    username = username.strip()
    email = email.strip().lower()

    if not username:
        raise ValueError("Username can't be empty.")
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise ValueError("Enter a valid email address.")

    # Prove it's really them before changing how they sign in
    user = storage.get_user_by_id(db_connection, user_id)
    if user is None or not crypto.verify_password(user["password_hash"], current_password):
        raise InvalidCredentialsError("Current password is incorrect")

    try:
        with db_connection:
            storage.update_user_profile(db_connection, user_id, username, email)
    except sqlite3.IntegrityError as e:
        raise UserExistsError("Username or email already exists") from e


def change_password(db_connection: sqlite3.Connection, user_id: str,
                    old_password: str, new_password: str) -> None:
    # Re-locks the SAME DEK with a key from the new password.
    # Nothing else changes, so vaults, entries, and the private key all keep working.
    if len(new_password) < 12 or len(new_password) > 256:
        raise PasswordComplexityError("Password must be at least 12 and no more than 256 characters long.")

    user = storage.get_user_by_id(db_connection, user_id)
    if user is None:
        raise InvalidCredentialsError("Current password is incorrect")

    # Prove they know the current password
    if not crypto.verify_password(user["password_hash"], old_password):
        raise InvalidCredentialsError("Current password is incorrect")

    # Old password → old KEK → unlock the DEK
    old_kek = crypto.derive_kek(old_password, user["kek_salt"])
    dek = crypto.decrypt(old_kek, user["encrypted_dek_nonce"], user["encrypted_dek"], crypto.user_dek_aad(user_id))

    # New password → new salt → new KEK → lock the same DEK again
    new_salt = crypto.new_salt()
    new_kek = crypto.derive_kek(new_password, new_salt)
    new_dek_nonce, new_encrypted_dek = crypto.encrypt(new_kek, dek, crypto.user_dek_aad(user_id))

    with db_connection:
        storage.update_user_password(
            db_connection,
            user_id=user_id,
            password_hash=crypto.hash_password(new_password),
            kek_salt=new_salt,
            encrypted_dek=new_encrypted_dek,
            encrypted_dek_nonce=new_dek_nonce,
        )


def _lock_dek_with_new_recovery_code(user_id: str, dek: bytes) -> tuple[str, bytes, bytes, bytes]:
    # Makes a new code and locks a copy of the DEK with it.
    # Returns (code, salt, locked DEK, nonce). The code is shown to the user once and never stored.
    code = crypto.new_recovery_code()
    salt = crypto.new_salt()
    recovery_key = crypto.derive_kek(crypto.normalize_recovery_code(code), salt)
    nonce, locked_dek = crypto.encrypt(recovery_key, dek, crypto.user_dek_recovery_aad(user_id))
    return code, salt, locked_dek, nonce


def has_recovery_code(db_connection: sqlite3.Connection, user_id: str) -> bool:
    # True if this user has created a recovery code
    user = storage.get_user_by_id(db_connection, user_id)
    return user is not None and user["recovery_salt"] is not None


def create_recovery_code(db_connection: sqlite3.Connection, user_id: str, password: str) -> str:
    # New recovery code for a signed-in user. Needs the master password to reach the DEK.
    # Any previous code stops working.
    user = storage.get_user_by_id(db_connection, user_id)
    if user is None or not crypto.verify_password(user["password_hash"], password):
        raise InvalidCredentialsError("Current password is incorrect")

    kek = crypto.derive_kek(password, user["kek_salt"])
    dek = crypto.decrypt(kek, user["encrypted_dek_nonce"], user["encrypted_dek"], crypto.user_dek_aad(user_id))

    code, salt, locked_dek, nonce = _lock_dek_with_new_recovery_code(user_id, dek)
    with db_connection:
        storage.update_user_recovery(db_connection, user_id, salt, locked_dek, nonce)
    return code


def recover_account(db_connection: sqlite3.Connection, email: str, code: str, new_password: str,
                    ip_address: str | None = None) -> str:
    # Forgot password: the recovery code unlocks the DEK, the DEK gets locked with the new password,
    # and a NEW recovery code is issued (the used one stops working). Returns the new code.

    # Same lockout as login
    if (storage.count_recent_logins_by_ip_address(db_connection, ip_address, 15) >= MAX_FAILED_LOGIN_ATTEMPTS
            or storage.count_recent_logins_by_email(db_connection, email, 15) >= MAX_FAILED_LOGIN_ATTEMPTS):
        raise AccountLockedError("Too many attempts")

    # Same rules as register
    if len(new_password) < 12 or len(new_password) > 256:
        raise PasswordComplexityError("Password must be at least 12 and no more than 256 characters long.")

    row = storage.get_user_recovery_by_email(db_connection, email)

    # Unknown email, or no code ever created: same error, same slow work, so neither can be detected
    if row is None or row["recovery_salt"] is None:
        crypto.derive_kek(crypto.normalize_recovery_code(code) or "dummy", crypto.new_salt())
        storage.record_login_attempt(db_connection, ip_address, email, False)
        raise InvalidCredentialsError("Incorrect email or recovery code")

    user_id = row["user_id"]
    recovery_key = crypto.derive_kek(crypto.normalize_recovery_code(code), row["recovery_salt"])
    try:
        dek = crypto.decrypt(recovery_key, row["encrypted_dek_recovery_nonce"],
                             row["encrypted_dek_recovery"], crypto.user_dek_recovery_aad(user_id))
    except InvalidTag:
        # Wrong code: the lock won't open
        storage.record_login_attempt(db_connection, ip_address, email, False)
        raise InvalidCredentialsError("Incorrect email or recovery code")

    # Lock the same DEK with the new password
    new_salt = crypto.new_salt()
    new_kek = crypto.derive_kek(new_password, new_salt)
    dek_nonce, encrypted_dek = crypto.encrypt(new_kek, dek, crypto.user_dek_aad(user_id))

    # And with a brand-new recovery code (the old one is used up)
    new_code, recovery_salt, locked_dek, recovery_nonce = _lock_dek_with_new_recovery_code(user_id, dek)

    with db_connection:
        storage.update_user_password(
            db_connection,
            user_id=user_id,
            password_hash=crypto.hash_password(new_password),
            kek_salt=new_salt,
            encrypted_dek=encrypted_dek,
            encrypted_dek_nonce=dek_nonce,
        )
        storage.update_user_recovery(db_connection, user_id, recovery_salt, locked_dek, recovery_nonce)

    storage.record_login_attempt(db_connection, ip_address, email, True)
    return new_code
import sqlite3
from pathlib import Path
import uuid


# ======================================
# ========== CONNECTION / TABLES =======
# ======================================

# Create a sqlite3 connection
def db_connect(db_path: Path) -> sqlite3.Connection:
    db_connection = sqlite3.connect(db_path)
    # Enable foreign keys / references
    db_connection.execute("PRAGMA foreign_keys = ON")
    # Enable reading rows by name rather than by position [ex. 0]
    db_connection.row_factory = sqlite3.Row

    return db_connection 

# Creates every table the app uses
def create_tables(db_connection: sqlite3.Connection) -> None:
    # recovery_* hold a second copy of the DEK, locked with a key made from the user's recovery code (NULL = no code yet)
    # Creates the users table
    # kek_salt is used to create KEK that decrypts the encrypted DEK
    # public_key lets others wrap vault keys and entry keys FOR this user (safe to store plain)
    # encrypted_private_key is the user's private key, locked with their DEK
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS users(
            user_id TEXT NOT NULL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
            encrypted_dek BLOB NOT NULL,
            encrypted_dek_nonce BLOB NOT NULL,
            kek_salt BLOB NOT NULL,
            public_key BLOB NOT NULL,
            encrypted_private_key BLOB NOT NULL,
            private_key_nonce BLOB NOT NULL,
            recovery_salt BLOB,
            encrypted_dek_recovery BLOB,
            encrypted_dek_recovery_nonce BLOB,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Migration: older databases have users without the recovery columns. Add any that are missing.
    # (The column names below are fixed in code, never user input, so building the SQL here is safe.)
    user_columns = [row["name"] for row in db_connection.execute("PRAGMA table_info(users)")]
    for column in ("recovery_salt", "encrypted_dek_recovery", "encrypted_dek_recovery_nonce"):
        if column not in user_columns:
            db_connection.execute(f"ALTER TABLE users ADD COLUMN {column} BLOB")

    # Creates the vaults table (a vault is also a group)
    # owner_id has full control of the vault
    # member_role is what every other member of the vault can do
    # The vault name is encrypted with the vault key, so the DB never sees it
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS vaults(
            vault_id TEXT NOT NULL PRIMARY KEY,
            encrypted_vault_name BLOB NOT NULL,
            vault_name_nonce BLOB NOT NULL,
            owner_id TEXT NOT NULL REFERENCES users(user_id),
            member_role TEXT NOT NULL DEFAULT 'view' CHECK (member_role IN ('edit', 'view')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Creates the vault shares table (who is in each vault)
    # wrapped_vault_key is the vault key locked with that member's public key
    # role is empty to use the vault's member_role, or set to override it for this member
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS vault_shares(
            vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            wrapped_vault_key BLOB NOT NULL,
            role TEXT CHECK (role IN ('edit', 'view')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (vault_id, user_id)
        )"""
    )

    # deleted_at is set when the entry is in the Trash (NULL = not trashed)
    # Creates the entries table
    # Data is locked with the entry's own key
    # wrapped_entry_key is the entry key locked with the vault key
    # created_by is who added it, kept even if that user is later deleted
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries(
            vault_entry_id TEXT NOT NULL PRIMARY KEY,
            vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
            created_by TEXT REFERENCES users(user_id) ON DELETE SET NULL,
            wrapped_entry_key BLOB NOT NULL,
            entry_key_nonce BLOB NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            deleted_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Migration: older databases have vault_entries without deleted_at.
    # CREATE TABLE IF NOT EXISTS skips existing tables, so add the column if it's missing.
    columns = [row["name"] for row in db_connection.execute("PRAGMA table_info(vault_entries)")]
    if "deleted_at" not in columns:
        db_connection.execute("ALTER TABLE vault_entries ADD COLUMN deleted_at TEXT")

    # Creates the entry permissions table (single entries shared directly)
    # wrapped_entry_key is the entry key locked with that user's public key
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS entry_shares(
            vault_entry_id TEXT NOT NULL REFERENCES vault_entries(vault_entry_id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            wrapped_entry_key BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'view' CHECK (role IN ('edit', 'view')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (vault_entry_id, user_id)
        )"""
    )

    # Indexes for looking up everything a user can open
    db_connection.execute("CREATE INDEX IF NOT EXISTS idx_vault_shares_user ON vault_shares (user_id)")
    db_connection.execute("CREATE INDEX IF NOT EXISTS idx_entry_shares_user ON entry_shares (user_id)")
    db_connection.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_vault ON vault_entries (vault_id)")

    # Creates the login attempts table 
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts(
            login_attempt_id INTEGER NOT NULL PRIMARY KEY,
            ip_address TEXT,
            email TEXT NOT NULL,
            success INTEGER NOT NULL CHECK (success in (0, 1)),
            attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Creates the register attempts table 
    db_connection.execute("""
        CREATE TABLE IF NOT EXISTS register_attempts(
            register_attempt_id INTEGER NOT NULL PRIMARY KEY,
            ip_address TEXT,
            attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Commit the table creations
    db_connection.commit()


# ======================================
# ========== CREATE (saves itself) =====
# ======================================
# These commit on their own. Safe to call by themselves.

# Create a new vault entry inside a vault
def create_vault_entry(
    db_connection: sqlite3.Connection,
    vault_entry_id: str, # must be passed in since the encryption uses the vault_entry_id as the AAD(label)
    vault_id: str,
    created_by: str,
    wrapped_entry_key: bytes,
    entry_key_nonce: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> None:

    db_connection.execute('''
        INSERT INTO vault_entries (vault_entry_id, vault_id, created_by, wrapped_entry_key, entry_key_nonce, nonce, ciphertext) 
            VALUES (?, ?, ?, ?, ?, ?, ?)''', (vault_entry_id, vault_id, created_by, wrapped_entry_key, entry_key_nonce, nonce, ciphertext))
    db_connection.commit()


# ======================================
# ========== CREATE (no commit) ========
# ======================================
# These do NOT commit. The caller must wrap them in "with db_connection:",
# so a vault and its owner's share are saved together, or not at all.

# Create a new user
def create_user(
        db_connection: sqlite3.Connection,
        user_id: str,
        username: str,
        email: str,
        password_hash: str,
        encrypted_dek: bytes,
        encrypted_dek_nonce: bytes,
        kek_salt: bytes,
        public_key: bytes,
        encrypted_private_key: bytes,
        private_key_nonce: bytes,
        role: str = "user"
    ) -> None:

        user_data = (
            user_id,
            username,
            email.lower(),
            password_hash,
            role,
            encrypted_dek,
            encrypted_dek_nonce,
            kek_salt,
            public_key,
            encrypted_private_key,
            private_key_nonce
        )

        db_connection.execute("""
            INSERT INTO users 
                (user_id, username, email, password_hash, role, encrypted_dek, encrypted_dek_nonce, kek_salt, public_key, encrypted_private_key, private_key_nonce) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", user_data)

# Create a new vault with an encrypted name (no commit, caller uses "with db_connection:")
def create_vault(db_connection: sqlite3.Connection, vault_id: str, encrypted_vault_name: bytes,
                 vault_name_nonce: bytes, owner_id: str, member_role: str = 'view') -> None:
    db_connection.execute("""
        INSERT INTO vaults (vault_id, encrypted_vault_name, vault_name_nonce, owner_id, member_role)
        VALUES (?, ?, ?, ?, ?)""",
        (vault_id, encrypted_vault_name, vault_name_nonce, owner_id, member_role))

# Add someone to a vault, with their own wrapped copy of the vault key
def create_vault_share(db_connection: sqlite3.Connection, vault_id: str, user_id: str, wrapped_vault_key: bytes, role: str | None = None) -> None:
    db_connection.execute("""
        INSERT INTO vault_shares (vault_id, user_id, wrapped_vault_key, role) VALUES (?, ?, ?, ?)""",
        (vault_id, user_id, wrapped_vault_key, role)    
    )

# Share one entry directly with someone, with their own wrapped copy of the entry key
def create_entry_share(db_connection: sqlite3.Connection, vault_entry_id: str, user_id: str, wrapped_entry_key: bytes, role: str = 'view') -> None:
    db_connection.execute("""
        INSERT INTO entry_shares (vault_entry_id, user_id, wrapped_entry_key, role) VALUES (?, ?, ?, ?)""",
        (vault_entry_id, user_id, wrapped_entry_key, role)    
    )


# ======================================
# ========== GET USER DATA =============
# ======================================

# Someone's public key, so others can wrap keys for them
def get_public_key(db_connection: sqlite3.Connection, user_id: str) -> bytes | None:
    row = db_connection.execute("""
        SELECT public_key FROM users WHERE user_id = ?""", (user_id, )
    ).fetchone()
    if row is None:
        return None
    return row[0]

# GET a user by email
def get_user_by_email(db_connection: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    user = db_connection.execute("""
        SELECT user_id, role, password_hash, kek_salt, encrypted_dek, encrypted_dek_nonce, public_key, encrypted_private_key, private_key_nonce 
        FROM users 
        WHERE email = ?""", (email.lower(), )).fetchone()
    return user

# A user by id: profile fields plus what's needed to change the password
def get_user_by_id(db_connection: sqlite3.Connection, user_id: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT user_id, username, email, role, password_hash,
               kek_salt, encrypted_dek, encrypted_dek_nonce, recovery_salt
        FROM users
        WHERE user_id = ?""", (user_id,)).fetchone()


# What's needed to reset a password with a recovery code, found by email
def get_user_recovery_by_email(db_connection: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT user_id, recovery_salt, encrypted_dek_recovery, encrypted_dek_recovery_nonce
        FROM users
        WHERE email = ?""", (email.lower(),)).fetchone()


# Every registered user's username and email, for the share dialog's picker
def list_user_directory(db_connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT user_id, username, email
        FROM users
        ORDER BY username COLLATE NOCASE
        LIMIT 1000""").fetchall()

# Every vault the user is a member of, with the encrypted name and their copy of the vault key
def get_user_vaults(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT vaults.vault_id,
               vaults.encrypted_vault_name,
               vaults.vault_name_nonce,
               vaults.owner_id,
               vault_shares.wrapped_vault_key,
               COALESCE(vault_shares.role, vaults.member_role) AS role,
               owner_users.username AS owner_name
        FROM vault_shares
        JOIN vaults ON vaults.vault_id = vault_shares.vault_id
        JOIN users AS owner_users ON owner_users.user_id = vaults.owner_id
        WHERE vault_shares.user_id = ?""", (user_id,)).fetchall()


# How many entries each of the user's vaults has. Counts rows only, no decryption.
# Vaults with zero entries don't appear; callers treat a missing vault as 0.
def count_entries_by_vault(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT vault_entries.vault_id,
               COUNT(*) AS entry_count
        FROM vault_entries
        JOIN vault_shares ON vault_shares.vault_id = vault_entries.vault_id
        WHERE vault_shares.user_id = ? AND vault_entries.deleted_at IS NULL
        GROUP BY vault_entries.vault_id""", (user_id,)).fetchall()


# For entries shared DIRECTLY with the user: who owns the vault each one lives in
def get_direct_share_owners(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT entry_shares.vault_entry_id,
               users.username AS owner_name
        FROM entry_shares
        JOIN vault_entries ON vault_entries.vault_entry_id = entry_shares.vault_entry_id
        JOIN vaults ON vaults.vault_id = vault_entries.vault_id
        JOIN users ON users.user_id = vaults.owner_id
        WHERE entry_shares.user_id = ? AND vault_entries.deleted_at IS NULL""", (user_id,)).fetchall()


# Trashed entries in vaults the user OWNS, newest first, with what's needed to decrypt them
def get_trashed_entries(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT vault_entries.vault_entry_id,
            vault_entries.vault_id,
            vault_entries.wrapped_entry_key,
            vault_entries.entry_key_nonce,
            vault_entries.nonce,
            vault_entries.ciphertext,
            vault_entries.deleted_at,
            vault_shares.wrapped_vault_key
        FROM vault_entries
        JOIN vault_shares ON vault_shares.vault_id = vault_entries.vault_id
        JOIN vaults ON vaults.vault_id = vault_entries.vault_id
        WHERE vault_shares.user_id = ?
          AND vaults.owner_id = ?
          AND vault_entries.deleted_at IS NOT NULL
        ORDER BY vault_entries.deleted_at DESC""", (user_id, user_id)).fetchall()


# One trashed entry, only if it's in a vault the user OWNS
def get_trashed_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT vault_entries.vault_entry_id, vault_entries.vault_id
        FROM vault_entries
        JOIN vaults ON vaults.vault_id = vault_entries.vault_id
        WHERE vault_entries.vault_entry_id = ?
          AND vaults.owner_id = ?
          AND vault_entries.deleted_at IS NOT NULL""", (vault_entry_id, user_id)).fetchone()


# A vault's encrypted name, used when re-locking it with a new vault key
def get_vault_name(db_connection: sqlite3.Connection, vault_id: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT encrypted_vault_name, vault_name_nonce
        FROM vaults
        WHERE vault_id = ?""", (vault_id,)).fetchone()


# ======================================
# ========== GET ENTRIES ===============
# ======================================

# Vault path: every entry in every vault the user is a member of
def get_vault_entries(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute('''
        SELECT vault_entries.vault_entry_id,
            vault_entries.vault_id,
            vault_entries.wrapped_entry_key,
            vault_entries.entry_key_nonce,
            vault_entries.nonce,
            vault_entries.ciphertext,
            vault_shares.wrapped_vault_key,
            COALESCE(vault_shares.role, vaults.member_role) AS role,
            vaults.owner_id
        FROM vault_entries
        JOIN vault_shares ON vault_shares.vault_id = vault_entries.vault_id
        JOIN vaults ON vaults.vault_id = vault_entries.vault_id
        WHERE vault_shares.user_id = ? AND vault_entries.deleted_at IS NULL''', (user_id, )).fetchall()

# Vault path: one entry, only if the user is a member of its vault
def get_vault_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> sqlite3.Row | None:
    return db_connection.execute('''
        SELECT vault_entries.vault_entry_id,
            vault_entries.vault_id,
            vault_entries.wrapped_entry_key,
            vault_entries.entry_key_nonce,
            vault_entries.nonce,
            vault_entries.ciphertext,
            vault_shares.wrapped_vault_key,
            COALESCE(vault_shares.role, vaults.member_role) AS role,
            vaults.owner_id
        FROM vault_entries
        JOIN vault_shares ON vault_shares.vault_id = vault_entries.vault_id
        JOIN vaults ON vaults.vault_id = vault_entries.vault_id
        WHERE vault_shares.user_id = ? AND vault_entries.vault_entry_id = ?
            AND vault_entries.deleted_at IS NULL''', (user_id, vault_entry_id)).fetchone()

# Direct path: one entry, only if it was shared directly with the user
def get_shared_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> sqlite3.Row | None:
    return db_connection.execute('''
        SELECT vault_entries.vault_entry_id,
            vault_entries.vault_id,
            vault_entries.nonce,
            vault_entries.ciphertext,
            entry_shares.wrapped_entry_key,
            entry_shares.role
        FROM vault_entries
        JOIN entry_shares
        ON entry_shares.vault_entry_id = vault_entries.vault_entry_id
        WHERE entry_shares.user_id = ? AND entry_shares.vault_entry_id = ?
            AND vault_entries.deleted_at IS NULL''', (user_id, vault_entry_id)).fetchone()

# Direct path: every entry shared directly with the user
def get_shared_entries(db_connection: sqlite3.Connection, user_id: str) -> list[sqlite3.Row]:
    return db_connection.execute('''
        SELECT vault_entries.vault_entry_id,
            vault_entries.vault_id,
            vault_entries.nonce,
            vault_entries.ciphertext,
            entry_shares.wrapped_entry_key,
            entry_shares.role
        FROM vault_entries
        JOIN entry_shares
        ON entry_shares.vault_entry_id = vault_entries.vault_entry_id
        WHERE entry_shares.user_id = ? AND vault_entries.deleted_at IS NULL''', (user_id, )).fetchall()


# ======================================
# ========== GET MEMBERSHIP ============
# ======================================

# The user's place in a vault: their wrapped vault key, their role, and who owns the vault
# None if the user isn't in that vault
def get_vault_membership(db_connection: sqlite3.Connection, user_id: str, vault_id: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT 
            vault_shares.vault_id,
            vault_shares.wrapped_vault_key, 
            COALESCE(vault_shares.role, vaults.member_role) AS role,
            vaults.owner_id
        FROM vault_shares
        JOIN vaults ON vaults.vault_id = vault_shares.vault_id
        WHERE vault_shares.user_id = ? AND vault_shares.vault_id = ?
    """, (user_id, vault_id, )).fetchone()

# Everyone in a vault, with their name, email, and effective role. The owner comes first.
def get_vault_member_details(db_connection: sqlite3.Connection, vault_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT users.user_id,
               users.username,
               users.email,
               COALESCE(vault_shares.role, vaults.member_role) AS role,
               vaults.owner_id
        FROM vault_shares
        JOIN users ON users.user_id = vault_shares.user_id
        JOIN vaults ON vaults.vault_id = vault_shares.vault_id
        WHERE vault_shares.vault_id = ?
        ORDER BY (users.user_id = vaults.owner_id) DESC, users.username""", (vault_id,)).fetchall()


# Everyone one entry is shared with directly, with their name, email, and role
def get_entry_share_details(db_connection: sqlite3.Connection, vault_entry_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT users.user_id,
               users.username,
               users.email,
               entry_shares.role
        FROM entry_shares
        JOIN users ON users.user_id = entry_shares.user_id
        WHERE entry_shares.vault_entry_id = ?
        ORDER BY users.username""", (vault_entry_id,)).fetchall()

# The user's direct share on one entry
# None if the entry isn't shared with them
def get_entry_membership(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> sqlite3.Row | None:
    return db_connection.execute("""
        SELECT entry_shares.role
        FROM entry_shares
        WHERE entry_shares.user_id = ? AND entry_shares.vault_entry_id = ?
    """, (user_id, vault_entry_id, )).fetchone()


# ======================================
# ========== ROTATION: READS ===========
# ======================================

# Every member of a vault, with their public key
# Used during rotation to give each remaining member a copy of the NEW vault key
def get_vault_members(db_connection: sqlite3.Connection, vault_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT vault_shares.user_id,
               users.public_key
        FROM vault_shares
        JOIN users ON users.user_id = vault_shares.user_id
        WHERE vault_shares.vault_id = ?""", (vault_id,)).fetchall()

# Every entry in a vault, with its entry key locked by the vault key
# Used during rotation to re-lock each entry key with the NEW vault key
def get_vault_entry_keys(db_connection: sqlite3.Connection, vault_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT vault_entry_id,
               vault_id,
               wrapped_entry_key,
               entry_key_nonce
        FROM vault_entries
        WHERE vault_id = ?""", (vault_id,)).fetchall()

# Everyone an entry is shared with directly, with their public key
# Used during rotation to give each remaining sharee a copy of the NEW entry key
def get_entry_shares(db_connection: sqlite3.Connection, vault_entry_id: str) -> list[sqlite3.Row]:
    return db_connection.execute("""
        SELECT entry_shares.user_id,
               users.public_key
        FROM entry_shares
        JOIN users ON users.user_id = entry_shares.user_id
        WHERE entry_shares.vault_entry_id = ?""", (vault_entry_id,)).fetchall()


# ======================================
# ========== UPDATE (saves itself) =====
# ======================================

# Save new encrypted data for an entry
# Coarse check: the user must be connected to the entry (vault member OR direct share)
# vault.py does the detailed role check before calling this
def update_vault_entry(
    db_connection: sqlite3.Connection,
    user_id: str,
    vault_entry_id: str,
    nonce: bytes,
    ciphertext: bytes,
) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_entries 
        SET nonce = ?, ciphertext = ?, updated_at = CURRENT_TIMESTAMP
        WHERE vault_entry_id = ? AND vault_entries.deleted_at IS NULL
            AND (
                EXISTS (SELECT 1 FROM vault_shares
                            WHERE vault_shares.vault_id = vault_entries.vault_id
                            AND vault_shares.user_id = ?)
                OR EXISTS (SELECT 1 FROM entry_shares
                            WHERE entry_shares.vault_entry_id = vault_entries.vault_entry_id
                            AND entry_shares.user_id = ?)
        )""", (nonce, ciphertext, vault_entry_id, user_id, user_id, ))
    db_connection.commit()
    return cursor.rowcount == 1


# ======================================
# ========== UPDATE (no commit) ========
# ======================================
# Used during key rotation. The caller wraps them in "with db_connection:"
# so every key changes together, or none do.

# Replaces one member's copy of the vault key
def update_vault_share_key(db_connection: sqlite3.Connection, user_id: str,
                           vault_id: str, wrapped_vault_key: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_shares
        SET wrapped_vault_key = ?
        WHERE user_id = ? AND vault_id = ?""", (wrapped_vault_key, user_id, vault_id))
    return cursor.rowcount == 1

# Replaces an entry's key that's locked with the vault key
def update_wrapped_entry_key(db_connection: sqlite3.Connection, vault_entry_id: str,
                            entry_key_nonce: bytes, wrapped_entry_key: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_entries
        SET wrapped_entry_key = ?, entry_key_nonce = ?
        WHERE vault_entry_id = ?""", (wrapped_entry_key, entry_key_nonce, vault_entry_id))
    return cursor.rowcount == 1

# Replaces one direct sharee's copy of the entry key
def update_entry_share_key(db_connection: sqlite3.Connection, user_id: str,
                           vault_entry_id: str, wrapped_entry_key: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE entry_shares
        SET wrapped_entry_key = ?
        WHERE user_id = ? AND vault_entry_id = ?""", (wrapped_entry_key, user_id, vault_entry_id))
    return cursor.rowcount == 1

# Replaces an entry's encrypted data (used when the entry key changes)
def update_entry_data(db_connection: sqlite3.Connection, vault_entry_id: str,
                      nonce: bytes, ciphertext: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_entries
        SET nonce = ?, ciphertext = ?, updated_at = CURRENT_TIMESTAMP
        WHERE vault_entry_id = ?""", (nonce, ciphertext, vault_entry_id))
    return cursor.rowcount == 1

# Replaces a vault's encrypted name (rotation re-locks it, rename changes it)
def update_vault_name(db_connection: sqlite3.Connection, vault_id: str,
                      encrypted_vault_name: bytes, vault_name_nonce: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE vaults
        SET encrypted_vault_name = ?, vault_name_nonce = ?, updated_at = CURRENT_TIMESTAMP
        WHERE vault_id = ?""", (encrypted_vault_name, vault_name_nonce, vault_id))
    return cursor.rowcount == 1

# Change a user's username and email (caller uses "with db_connection:")
def update_user_profile(db_connection: sqlite3.Connection, user_id: str,
                        username: str, email: str) -> bool:
    cursor = db_connection.execute("""
        UPDATE users
        SET username = ?, email = ?, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?""", (username, email.lower(), user_id))
    return cursor.rowcount == 1


# Save a new password hash, and the DEK locked with the NEW password's KEK
def update_user_password(db_connection: sqlite3.Connection, user_id: str, password_hash: str,
                         kek_salt: bytes, encrypted_dek: bytes, encrypted_dek_nonce: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE users
        SET password_hash = ?, kek_salt = ?, encrypted_dek = ?, encrypted_dek_nonce = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?""", (password_hash, kek_salt, encrypted_dek, encrypted_dek_nonce, user_id))
    return cursor.rowcount == 1


# Save a new recovery copy of the DEK (caller uses "with db_connection:")
def update_user_recovery(db_connection: sqlite3.Connection, user_id: str, recovery_salt: bytes,
                         encrypted_dek_recovery: bytes, encrypted_dek_recovery_nonce: bytes) -> bool:
    cursor = db_connection.execute("""
        UPDATE users
        SET recovery_salt = ?, encrypted_dek_recovery = ?, encrypted_dek_recovery_nonce = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?""", (recovery_salt, encrypted_dek_recovery, encrypted_dek_recovery_nonce, user_id))
    return cursor.rowcount == 1


# Move one entry to the Trash (no commit)
def trash_vault_entry(db_connection: sqlite3.Connection, vault_entry_id: str) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_entries
        SET deleted_at = CURRENT_TIMESTAMP
        WHERE vault_entry_id = ? AND deleted_at IS NULL""", (vault_entry_id,))
    return cursor.rowcount == 1


# Take one entry back out of the Trash (no commit)
def restore_vault_entry(db_connection: sqlite3.Connection, vault_entry_id: str) -> bool:
    cursor = db_connection.execute("""
        UPDATE vault_entries
        SET deleted_at = NULL
        WHERE vault_entry_id = ? AND deleted_at IS NOT NULL""", (vault_entry_id,))
    return cursor.rowcount == 1


# ======================================
# ========== DELETE (saves itself) =====
# ======================================

# Delete an entry for everyone
# Coarse check: the user must be a member of the entry's vault
# vault.py checks that they're the OWNER before calling this
def delete_vault_entry(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> bool:
    cursor = db_connection.execute("""
        DELETE FROM vault_entries
        WHERE vault_entry_id = ?
            AND EXISTS (SELECT 1 FROM vault_shares
                        WHERE vault_shares.vault_id = vault_entries.vault_id
                        AND vault_shares.user_id = ?)
        """, (vault_entry_id, user_id, ))
    db_connection.commit()
    return cursor.rowcount == 1


# ======================================
# ========== DELETE (no commit) ========
# ======================================
# Used when removing access. The caller wraps them in "with db_connection:"
# together with the key rotation.

# Remove someone's direct share on one entry
def delete_entry_share(db_connection: sqlite3.Connection, user_id: str, vault_entry_id: str) -> bool:
    cursor = db_connection.execute("""
        DELETE FROM entry_shares
        WHERE user_id = ? AND vault_entry_id = ?""", (user_id, vault_entry_id, ))
    return cursor.rowcount == 1

# Remove someone from a vault
def delete_vault_share(db_connection: sqlite3.Connection, user_id: str, vault_id: str) -> bool:
    cursor = db_connection.execute("""
        DELETE FROM vault_shares
        WHERE user_id = ? AND vault_id = ?""", (user_id, vault_id, ))
    return cursor.rowcount == 1


# Permanently delete every trashed entry in vaults the user owns (no commit). Returns how many.
def delete_trashed_entries(db_connection: sqlite3.Connection, user_id: str) -> int:
    cursor = db_connection.execute("""
        DELETE FROM vault_entries
        WHERE deleted_at IS NOT NULL
          AND vault_id IN (SELECT vault_id FROM vaults WHERE owner_id = ?)""", (user_id,))
    return cursor.rowcount


# ======================================
# ========== LOGIN / REGISTER ATTEMPTS =
# ======================================

def record_login_attempt(db_connection: sqlite3.Connection, ip_address: str, email: str, success: bool) -> None:
    email = email.lower()
    db_connection.execute("INSERT INTO login_attempts (ip_address, email, success, attempted_at) VALUES (?, ?, ?, datetime('now'))", (ip_address, email, success))
    db_connection.commit()

def record_register_attempt(db_connection: sqlite3.Connection, ip_address: str) -> None:
    db_connection.execute("INSERT INTO register_attempts (ip_address, attempted_at) VALUES (?, datetime('now'))", (ip_address, ))
    db_connection.commit()

def count_recent_logins_by_email(db_connection: sqlite3.Connection, email: str, minutes: int) -> int:
    email = email.lower()
    email_count = db_connection.execute("SELECT COUNT(*) AS failures FROM login_attempts WHERE email = ? AND success = 0 AND attempted_at > datetime('now', ?)", (email, f"-{minutes} minutes")).fetchone()[0]
    return email_count

def count_recent_logins_by_ip_address(db_connection: sqlite3.Connection, ip_address: str, minutes: int) -> int:
    ip_count = db_connection.execute("SELECT COUNT(*) AS failures FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > datetime('now', ?)", (ip_address, f"-{minutes} minutes")).fetchone()[0]
    return ip_count

def count_recent_registers_by_ip_address(db_connection: sqlite3.Connection, ip_address: str, minutes: int) -> int:
    ip_count = db_connection.execute("SELECT COUNT(*) AS attempts FROM register_attempts WHERE ip_address = ? AND attempted_at > datetime('now', ?)", (ip_address, f"-{minutes} minutes")).fetchone()[0]
    return ip_count
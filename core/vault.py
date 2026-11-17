import json
import sqlite3
import uuid
from dataclasses import dataclass
import os

from core import crypto, storage
from core.models import VaultEntry, Access, Session, TrashItem


# ========== Packing ==========

def _pack(title: str, url: str, username: str, password: str, notes: str) -> bytes:
    # Puts the fields in a dict, turns it into JSON text, then into bytes for encryption
    data = {
        "title": title,
        "url": url,
        "username": username,
        "password": password,
        "notes": notes
    }

    data = json.dumps(data).encode()
    return data

def _unpack(vault_entry_id: str, vault_id:str, can_edit: bool, packed: bytes) -> VaultEntry:
    # Turns the decrypted bytes back into text, then into a dict, then into a VaultEntry
    data = json.loads(packed.decode())
    return VaultEntry(
        vault_entry_id=vault_entry_id,
        vault_id=vault_id,
        can_edit=can_edit,
        title=data["title"],
        url=data["url"],
        username=data["username"],
        password=data["password"],
        notes=data["notes"]
    )


# ========== Key helpers ==========

def get_vault_key_from_row(session: Session, row) -> bytes:
    # Unwraps this user's copy of the vault key (public-key unwrap)
    vault_key_aad = crypto.wrapped_vault_key_aad(row["vault_id"], session.user_id)
    return crypto.unwrap_with_private_key(session.private_key, row["wrapped_vault_key"], vault_key_aad)

def get_entry_key_from_vault_key(vault_key: bytes, row) -> bytes:
    # Opens the entry key with the vault key (AES-GCM)
    entry_key_aad = crypto.wrapped_entry_key_aad(row["vault_id"], row["vault_entry_id"])
    return crypto.decrypt(vault_key, row["entry_key_nonce"], row["wrapped_entry_key"], entry_key_aad)

def get_entry_key_from_vault_row(session: Session, row) -> bytes:
    # Both steps together, for when you only need one entry
    # private key → vault key → entry key
    vault_key = get_vault_key_from_row(session, row)
    return get_entry_key_from_vault_key(vault_key, row)

def get_entry_key_from_shared_row(session: Session, row) -> bytes:
    # Unwraps the user's own copy of the entry key from a direct share
    # Only this user's private key can open it, since it was wrapped with their public key
    # private key → entry key (no vault key needed)
    entry_key_aad = crypto.direct_share_wrapped_entry_key_aad(row["vault_entry_id"], session.user_id)
    return crypto.unwrap_with_private_key(session.private_key, row["wrapped_entry_key"], entry_key_aad)


# ========== Access ==========

def _find_access(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> Access | None:
    # Works out how this user can reach the entry, and what they're allowed to do
    # Returns None if the user has no access at all
    # The rules for edit and delete live here, so every function uses the same ones

    # Vault path first: is the user a member of the entry's vault?
    row = storage.get_vault_entry(db_connection, session.user_id, vault_entry_id)
    if row is not None:
        is_owner = row["owner_id"] == session.user_id
        return Access(
            row=row,
            entry_key=get_entry_key_from_vault_row(session, row),
            can_edit=is_owner or row["role"] == "edit",
            is_owner=is_owner,
        )

    # Direct path: was this one entry shared with the user?
    row = storage.get_shared_entry(db_connection, session.user_id, vault_entry_id)
    if row is not None:
        return Access(
            row=row,
            entry_key=get_entry_key_from_shared_row(session, row),
            can_edit=row["role"] == "edit",
            is_owner=False,     # a direct share is never the vault owner
        )

    # Neither path found the user
    return None


# ========== Entries ==========

def add_entry(db_connection: sqlite3.Connection, session: Session, vault_id: str,
              title: str, url: str, username: str, password: str, notes: str) -> str:
    # Title must be filled to record the new vault entry
    if not title:
        raise ValueError("You must provide a title")

    # Is user allowed to add entries to the requested vault?
    # Must be a member, and either the owner or have the edit role
    membership = storage.get_vault_membership(db_connection, session.user_id, vault_id)
    if membership is None or membership["role"] != 'edit' and membership["owner_id"] != session.user_id:
        raise PermissionError("You are not allowed to add entries to this vault.")
    
    # Create vault entry ID & entry_key
    # The ID is made first so it can go into the labels
    vault_entry_id = str(uuid.uuid4())
    entry_key = crypto.new_dek()

    # Pack the fields together into JSON bytes
    packed = _pack(title, url, username, password, notes)

    # Labels
    vault_key_aad = crypto.wrapped_vault_key_aad(vault_id, session.user_id)
    entry_key_aad = crypto.wrapped_entry_key_aad(vault_id, vault_entry_id)
    ciphertext_aad = crypto.ciphertext_aad(vault_entry_id)

    # Encrypt the packed fields with the entry_key and this entry's AAD
    nonce, ciphertext = crypto.encrypt(entry_key, packed, ciphertext_aad)
   
    # Unwrap this user's copy of the vault key
    vault_key = crypto.unwrap_with_private_key(session.private_key, membership["wrapped_vault_key"], vault_key_aad)
    
    # Lock the entry key with the vault key, so every vault member can open it
    entry_key_nonce, wrapped_entry_key = crypto.encrypt(vault_key, entry_key, entry_key_aad)

    # Record the encrypted entry into the db
    storage.create_vault_entry(db_connection, vault_entry_id, vault_id, session.user_id, wrapped_entry_key, entry_key_nonce, nonce, ciphertext)

    return vault_entry_id


def get_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> VaultEntry | None:
    # Get the entry only if this user can reach it (vault member or direct share)
    # None if not found or no access
    access = _find_access(db_connection, session, vault_entry_id)
    if access is None:
        return None

    # Decrypt the entry's data with its entry key
    ciphertext_aad = crypto.ciphertext_aad(vault_entry_id)
    packed = crypto.decrypt(access.entry_key, access.row["nonce"], access.row["ciphertext"], ciphertext_aad)
    
    return _unpack(vault_entry_id, access.row["vault_id"], access.can_edit, packed)


def list_entries(db_connection: sqlite3.Connection, session: Session) -> list[VaultEntry]:
    # Every entry the user can reach: from their vaults, plus direct shares
    # Doesn't use _find_access, since that looks up one entry at a time
    seen = set()            # entry ids already added, so nothing shows up twice
    entries = []
    vault_keys = {}         # vault_id → vault key, so each vault is unwrapped only once

    vault_entry_rows = storage.get_vault_entries(db_connection, session.user_id)
    
    share_entry_rows = storage.get_shared_entries(db_connection, session.user_id)

    # Entries from vaults the user is a member of
    for row in vault_entry_rows:
        seen.add(row["vault_entry_id"])
        ciphertext_aad = crypto.ciphertext_aad(row["vault_entry_id"])

        # Unwrap this vault's key the first time we see the vault, reuse it after
        if row["vault_id"] not in vault_keys:
            vault_keys[row["vault_id"]] = get_vault_key_from_row(session, row)
        vault_key = vault_keys[row["vault_id"]]

        # Get entry key from each entry in the vault_entries table
        entry_key = get_entry_key_from_vault_key(vault_key, row)

        can_edit = row["owner_id"] == session.user_id or row["role"] == "edit"
        packed = crypto.decrypt(entry_key, row["nonce"], row["ciphertext"], ciphertext_aad)
        unpacked = _unpack(row["vault_entry_id"], row["vault_id"], can_edit, packed)
        entries.append(unpacked)

    # Entries shared directly with the user
    for row in share_entry_rows:
        # If the row already exists in vault_entries, do not duplicate (skip over it if its in entry_shares)
        if row["vault_entry_id"] in seen:
            continue

        # AAD / Label
        ciphertext_aad = crypto.ciphertext_aad(row["vault_entry_id"])

        # Get entry key from each entry in the entry_shares table
        entry_key = get_entry_key_from_shared_row(session, row)

        packed = crypto.decrypt(entry_key, row["nonce"], row["ciphertext"], ciphertext_aad)
        can_edit = row["role"] == "edit"

        unpacked = _unpack(row["vault_entry_id"], row["vault_id"], can_edit, packed)
        entries.append(unpacked)

    return entries


def update_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str,
                 title: str, url: str, username: str, password: str, notes: str) -> bool:
    # Title is still required on update
    if not title:
        raise ValueError("You must provide a title")

    # No access at all → False (same as get_entry returning None)
    access = _find_access(db_connection, session, vault_entry_id)
    if access is None:
        return False

    # Has access, but only to view → not allowed to change it
    if not access.can_edit:
        raise PermissionError("You are not allowed to update this entry.")
        
    # Re-encrypt with the SAME entry key, so everyone who could read it still can
    # encrypt() makes a new nonce automatically
    ciphertext_aad = crypto.ciphertext_aad(vault_entry_id)
    packed = _pack(title, url, username, password, notes)
    nonce, ciphertext = crypto.encrypt(access.entry_key, packed, ciphertext_aad)

    return storage.update_vault_entry(db_connection, session.user_id, vault_entry_id, nonce, ciphertext)


def delete_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> bool:
    # No access at all → False
    access = _find_access(db_connection, session, vault_entry_id)
    if access is None:
        return False
    
    # Only the vault owner can delete
    # Edit members and direct shares can change an entry, but not remove it for everyone
    if not access.is_owner:
        raise PermissionError("You are not allowed to delete this entry.")

    return storage.delete_vault_entry(db_connection, session.user_id, vault_entry_id)


def trash_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> bool:
    # Move to Trash. No access → False. Not the vault owner → PermissionError.
    access = _find_access(db_connection, session, vault_entry_id)
    if access is None:
        return False
    if not access.is_owner:
        raise PermissionError("Only the vault owner can move entries to the Trash.")
    with db_connection:
        return storage.trash_vault_entry(db_connection, vault_entry_id)


def list_trash(db_connection: sqlite3.Connection, session: Session) -> list[TrashItem]:
    # Every trashed entry in vaults the user owns, decrypted, newest first
    items = []
    vault_keys = {}         # vault_id → vault key, so each vault is unwrapped only once
    for row in storage.get_trashed_entries(db_connection, session.user_id):
        if row["vault_id"] not in vault_keys:
            vault_keys[row["vault_id"]] = get_vault_key_from_row(session, row)
        entry_key = get_entry_key_from_vault_key(vault_keys[row["vault_id"]], row)
        packed = crypto.decrypt(entry_key, row["nonce"], row["ciphertext"],
                                crypto.ciphertext_aad(row["vault_entry_id"]))
        entry = _unpack(row["vault_entry_id"], row["vault_id"], True, packed)
        items.append(TrashItem(entry=entry, deleted_at=row["deleted_at"]))
    return items


def restore_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> bool:
    # Take it out of the Trash. Not found, not trashed, or not the owner → False.
    if storage.get_trashed_entry(db_connection, session.user_id, vault_entry_id) is None:
        return False
    with db_connection:
        return storage.restore_vault_entry(db_connection, vault_entry_id)


def delete_entry_forever(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> bool:
    # Permanent delete, only for entries already in the Trash. Not found or not the owner → False.
    if storage.get_trashed_entry(db_connection, session.user_id, vault_entry_id) is None:
        return False
    return storage.delete_vault_entry(db_connection, session.user_id, vault_entry_id)


def empty_trash(db_connection: sqlite3.Connection, session: Session) -> int:
    # Permanently delete everything in this user's Trash. Returns how many were deleted.
    with db_connection:
        return storage.delete_trashed_entries(db_connection, session.user_id)
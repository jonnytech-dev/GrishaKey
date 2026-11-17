from dataclasses import dataclass, field
import sqlite3

# ---------- Data Formats ----------
# Data format that login should return
@dataclass
class Session:
    user_id: str
    role: str
    # dek: bytes
    private_key: bytes = field(repr=False)
    private_key_nonce: bytes = field(repr=False)
    public_key: bytes = field(repr=False)

# One decrypted vault entry, ready for the UI
@dataclass
class VaultEntry:
    vault_entry_id: str
    vault_id: str
    title: str
    url: str
    username: str
    password: str
    notes: str
    can_edit: bool          # tells the UI whether to show the Edit button


# One entry in the Trash, with when it was trashed
@dataclass
class TrashItem:
    entry: VaultEntry
    deleted_at: str        # SQLite UTC timestamp, e.g. "2026-11-16 14:03:22"


# What a user is allowed to do with one entry, and the key to open it
@dataclass
class Access:
    row: sqlite3.Row        # the entry's row (from the vault path or the direct path)
    entry_key: bytes        # the plain entry key, already unwrapped
    can_edit: bool          # owner, vault edit role, or direct edit share
    is_owner: bool          # only the vault owner can delete


# One vault the user can see, with its name decrypted
@dataclass
class VaultInfo:
    vault_id: str
    name: str
    is_owner: bool
    can_edit: bool
    owner_name: str = ""   # the vault owner's username, for "from kim" labels


# One person with access to a vault or an entry, for the "people with access" list
@dataclass
class MemberInfo:
    user_id: str
    username: str
    email: str
    role: str          # "edit" or "view"
    is_owner: bool     # the vault owner (shown, but can't be removed)
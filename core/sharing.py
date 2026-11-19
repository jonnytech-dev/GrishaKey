import sqlite3
import uuid

from core import crypto, storage, vault
from core.models import VaultInfo, Session, MemberInfo


# Every vault the user can see, with the name decrypted
def list_vaults(db_connection: sqlite3.Connection, session: Session) -> list[VaultInfo]:
    vaults = []
    for row in storage.get_user_vaults(db_connection, session.user_id):
        vault_key = vault.get_vault_key_from_row(session, row)
        name = crypto.decrypt(vault_key, row["vault_name_nonce"], row["encrypted_vault_name"],
                              crypto.vault_name_aad(row["vault_id"])).decode()
        is_owner = row["owner_id"] == session.user_id
        vaults.append(VaultInfo(
            vault_id=row["vault_id"],
            name=name,
            is_owner=is_owner,
            can_edit=is_owner or row["role"] == "edit",
            owner_name=row["owner_name"],
        ))
    return vaults


def create_vault(db_connection: sqlite3.Connection, session: Session,
                 vault_name: str, member_role: str = "view") -> str:
    # Name is required, and can't be just spaces
    vault_name = vault_name.strip()
    if not vault_name:
        raise ValueError("You must provide a name for the vault.")

    # The DB can't compare encrypted names, so check your own vaults here
    for existing in list_vaults(db_connection, session):
        if existing.is_owner and existing.name.lower() == vault_name.lower():
            raise ValueError("This vault already exists")

    # New vault key, encrypted name, and your own wrapped copy of the key
    vault_id = str(uuid.uuid4())
    vault_key = crypto.new_vault_key()
    vault_name_nonce, encrypted_vault_name = crypto.encrypt(vault_key, vault_name.encode(), crypto.vault_name_aad(vault_id))
    public_key = storage.get_public_key(db_connection, session.user_id)
    wrapped_vault_key = crypto.wrap_for_public_key(public_key, vault_key, crypto.wrapped_vault_key_aad(vault_id, session.user_id))

    # Save the vault and the owner's share together
    with db_connection:
        storage.create_vault(
            db_connection,
            vault_id=vault_id,
            encrypted_vault_name=encrypted_vault_name,
            vault_name_nonce=vault_name_nonce,
            owner_id=session.user_id,
            member_role=member_role,
        )
        storage.create_vault_share(
            db_connection,
            vault_id=vault_id,
            user_id=session.user_id,
            wrapped_vault_key=wrapped_vault_key,     # role left empty: the owner's power comes from owner_id
        )

    return vault_id

def can_user_edit(session: Session, row: sqlite3.Row, type: str):
    types = ['vault', 'vault_share', 'entry']
    if type not in types: return False

    if type == "vault":
        can_edit = row["owner_id"] == session.user_id 
    elif type == "vault_share" or type == "entry": can_edit = row["owner_id"] or row["role"] == "edit" 
    else: return False

    return can_edit

def share_vault(db_connection: sqlite3.Connection, session: Session, vault_id: str,
                     member_email: str, role: str | None = None) -> None:
    # Is user allowed to add entries to the requested vault?
    # Must be a member, and either the owner or have the edit role
    membership = storage.get_vault_membership(db_connection, session.user_id, vault_id)
    if membership is None or membership["owner_id"] != session.user_id:
        raise PermissionError("You are not allowed to add members to this vault.")

    member = storage.get_user_by_email(db_connection, member_email)
    if member is None:
        raise LookupError("User does not exist.")
    member_id = member["user_id"]
    
    vault_key_aad = crypto.wrapped_vault_key_aad(vault_id, session.user_id)
    vault_key = crypto.unwrap_with_private_key(session.private_key, membership["wrapped_vault_key"], vault_key_aad)
    member_vault_key_aad = crypto.wrapped_vault_key_aad(vault_id, member_id)
    members_wrapped_vault_key = crypto.wrap_for_public_key(member["public_key"], vault_key, member_vault_key_aad)
    
    try:
        with db_connection:
            storage.create_vault_share(
                db_connection,
                vault_id=vault_id,
                user_id=member_id,
                wrapped_vault_key=members_wrapped_vault_key,
                role=role,
            )
    except sqlite3.IntegrityError as e:
        raise ValueError("Already a member of this vault.") from e

def share_entry(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str,
                member_email: str, role: str = "view") -> None:
    access = vault._find_access(db_connection, session, vault_entry_id)
    if access is None or not access.is_owner:
        raise PermissionError("You cannot share this entry.")

    member = storage.get_user_by_email(db_connection, member_email)
    if member is None:
        raise LookupError("User does not exist")
    elif member["user_id"] == session.user_id:
        raise ValueError("You already have access")
    member_id = member["user_id"]
    member_public_key = member["public_key"]

    # Original entry key
    entry_key = access.entry_key

    # Wrap the entry_key with the new shared user's public key
    entry_key_aad = crypto.direct_share_wrapped_entry_key_aad(vault_entry_id, member_id)
    wrapped_entry_key = crypto.wrap_for_public_key(member_public_key, entry_key, entry_key_aad)

    try:
        with db_connection:
            storage.create_entry_share(
                db_connection,
                vault_entry_id=vault_entry_id,
                user_id=member_id,
                wrapped_entry_key=wrapped_entry_key,
                role=role,
            )
    except sqlite3.IntegrityError as e:
        raise ValueError("This entry is already shared with the user.") from e

def remove_vault_member(db_connection: sqlite3.Connection, session: Session,
                        vault_id: str, member_email: str) -> None:
    member = storage.get_user_by_email(db_connection, member_email)
    if member is None:
        raise LookupError("User does not exist")
    
    access = storage.get_vault_membership(db_connection, session.user_id, vault_id)
    if access is None or access["owner_id"] != session.user_id:
        raise PermissionError("You do not have permission to remove vault member.")
    elif access["owner_id"] == member["user_id"]:
        raise ValueError("Cannot remove the vault owner.")

    with db_connection:
        delete_vault_share = storage.delete_vault_share(db_connection, member["user_id"], vault_id)
        if not delete_vault_share:
            raise LookupError("User is not a member of the vault.")

        old_vault_key = vault.get_vault_key_from_row(session, access)
        new_vault_key = crypto.new_vault_key()

        # The name was locked with the OLD vault key, so re-lock it with the new one
        name_row = storage.get_vault_name(db_connection, vault_id)
        name = crypto.decrypt(old_vault_key, name_row["vault_name_nonce"],
                              name_row["encrypted_vault_name"], crypto.vault_name_aad(vault_id))
        new_name_nonce, new_encrypted_name = crypto.encrypt(new_vault_key, name, crypto.vault_name_aad(vault_id))
        storage.update_vault_name(
            db_connection,
            vault_id=vault_id,
            encrypted_vault_name=new_encrypted_name,
            vault_name_nonce=new_name_nonce,
        )

        vault_member_rows = storage.get_vault_members(db_connection, vault_id)
        for row in vault_member_rows: 
            new_vault_key_aad = crypto.wrapped_vault_key_aad(vault_id, row["user_id"])
            wrapped_vault_key = crypto.wrap_for_public_key(row["public_key"], new_vault_key, new_vault_key_aad)
            storage.update_vault_share_key(db_connection, row["user_id"], vault_id, wrapped_vault_key)

        vault_entry_keys = storage.get_vault_entry_keys(db_connection, vault_id)
        for row in vault_entry_keys:
            entry_key = vault.get_entry_key_from_vault_key(old_vault_key, row)
            entry_key_aad = crypto.wrapped_entry_key_aad(vault_id, row["vault_entry_id"])
            new_entry_key_nonce, new_wrapped_entry_key = crypto.encrypt(new_vault_key, entry_key, entry_key_aad)

            storage.update_wrapped_entry_key(db_connection, row["vault_entry_id"], new_entry_key_nonce, new_wrapped_entry_key)
    # TODO: owner only → PermissionError
    # TODO: look up member → LookupError
    # TODO: member is the owner → ValueError
    # TODO: old_vault_key = unwrap YOUR copy (before anything changes)

    # with db_connection:
    #     TODO: delete_vault_share → False means they weren't a member → LookupError
    #     TODO: new_vault_key = crypto.new_vault_key()
    #     TODO: for each remaining member: wrap new key for them → update_vault_share_key
    #     TODO: for each entry: unwrap with old key, wrap with new key → update_wrapped_entry_key
    ...


def unshare_entry(db_connection: sqlite3.Connection, session: Session,
                  vault_entry_id: str, member_email: str) -> None:
        member = storage.get_user_by_email(db_connection, member_email)
        if member is None:
            raise LookupError("User does not exist")
        
        access = vault._find_access(db_connection, session, vault_entry_id)
        if access is None or not access.is_owner:
            raise PermissionError("You do not have permission to remove vault member.")
        elif access.is_owner and session.user_id == member["user_id"]:
            raise ValueError("Cannot remove the share owner.")

        vault_key = vault.get_vault_key_from_row(session, access.row)
        vault_data = vault.get_entry(db_connection, session, vault_entry_id)
        packed = vault._pack(vault_data.title, vault_data.url, vault_data.username, vault_data.password, vault_data.notes)

        with db_connection:
            delete_entry_share = storage.delete_entry_share(db_connection, member["user_id"], vault_entry_id)
            if not delete_entry_share:
                raise LookupError("Entry does not exist for this member.")

            new_entry_key = crypto.new_dek()
            packed_aad = crypto.ciphertext_aad(vault_entry_id)
            new_entry_key_aad = crypto.wrapped_entry_key_aad(vault_data.vault_id, vault_entry_id)
            
            nonce, ciphertext = crypto.encrypt(new_entry_key, packed, packed_aad)
            new_entry_key_nonce, new_wrapped_entry_key = crypto.encrypt(vault_key, new_entry_key, new_entry_key_aad)

            storage.update_entry_data(db_connection, vault_entry_id, nonce, ciphertext)
            storage.update_wrapped_entry_key(db_connection, vault_entry_id, new_entry_key_nonce, new_wrapped_entry_key)

            shared_entry_members = storage.get_entry_shares(db_connection, vault_entry_id)
            for row in shared_entry_members:
                direct_shared_entry_key_aad = crypto.direct_share_wrapped_entry_key_aad(vault_entry_id, row["user_id"])
                direct_share_wrapped_entry_key = crypto.wrap_for_public_key(row["public_key"], new_entry_key, direct_shared_entry_key_aad)
                storage.update_entry_share_key(db_connection, row["user_id"], vault_entry_id, direct_share_wrapped_entry_key)


def rename_vault(db_connection: sqlite3.Connection, session: Session,
                 vault_id: str, new_name: str) -> None:
    # Only the owner can rename
    membership = storage.get_vault_membership(db_connection, session.user_id, vault_id)
    if membership is None or membership["owner_id"] != session.user_id:
        raise PermissionError("You are not allowed to rename this vault.")

    # Name is required, and can't be just spaces
    new_name = new_name.strip()
    if not new_name:
        raise ValueError("You must provide a name for the vault.")

    # No two of your own vaults can share a name
    for existing in list_vaults(db_connection, session):
        if existing.is_owner and existing.vault_id != vault_id and existing.name.lower() == new_name.lower():
            raise ValueError("This vault already exists")

    # Lock the new name with the CURRENT vault key
    vault_key = vault.get_vault_key_from_row(session, membership)
    name_nonce, encrypted_name = crypto.encrypt(vault_key, new_name.encode(), crypto.vault_name_aad(vault_id))

    with db_connection:
        storage.update_vault_name(
            db_connection,
            vault_id=vault_id,
            encrypted_vault_name=encrypted_name,
            vault_name_nonce=name_nonce,
        )


def list_vault_members(db_connection: sqlite3.Connection, session: Session, vault_id: str) -> list[MemberInfo]:
    # Who's in a vault. Only the owner can see this list.
    membership = storage.get_vault_membership(db_connection, session.user_id, vault_id)
    if membership is None or membership["owner_id"] != session.user_id:
        raise PermissionError("Only the vault owner can see who has access.")

    return [
        MemberInfo(
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            role=row["role"],
            is_owner=row["user_id"] == row["owner_id"],
        )
        for row in storage.get_vault_member_details(db_connection, vault_id)
    ]


def list_entry_shares(db_connection: sqlite3.Connection, session: Session, vault_entry_id: str) -> list[MemberInfo]:
    # Who one entry is shared with directly. Only the vault owner can see this list.
    access = vault._find_access(db_connection, session, vault_entry_id)
    if access is None or not access.is_owner:
        raise PermissionError("Only the vault owner can see who has access.")

    return [
        MemberInfo(
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            role=row["role"],
            is_owner=False,
        )
        for row in storage.get_entry_share_details(db_connection, vault_entry_id)
    ]


def entry_counts(db_connection: sqlite3.Connection, session: Session) -> dict[str, int]:
    # vault_id → number of entries, for every vault the user is a member of.
    # Counted in SQL, so nothing is decrypted.
    return {row["vault_id"]: row["entry_count"]
            for row in storage.count_entries_by_vault(db_connection, session.user_id)}


def direct_share_owner_names(db_connection: sqlite3.Connection, session: Session) -> dict[str, str]:
    # vault_entry_id → username of whoever shared it, for entries shared directly with the user
    return {row["vault_entry_id"]: row["owner_name"]
            for row in storage.get_direct_share_owners(db_connection, session.user_id)}


def user_directory(db_connection: sqlite3.Connection, session: Session) -> list[tuple[str, str]]:
    # (username, email) for every registered user except yourself, sorted by name
    return [(row["username"], row["email"])
            for row in storage.list_user_directory(db_connection)
            if row["user_id"] != session.user_id]
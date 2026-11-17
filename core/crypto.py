from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import secrets
from core.models import Session
import uuid

# ========== Links / References / Documentation ==========
# PasswordHasher = https://argon2-cffi.readthedocs.io/en/stable/api.html
# AESGCM = https://cryptography.io/en/latest/hazmat/primitives/aead/


_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    encoding='utf-8',
    type=Type.ID
)


def hash_password(password: str) -> str:
    # Creates a hash of a plaintext password entered by the user
    hash = _ph.hash(password)
    return hash


def verify_password(stored_hash: str, password: str) -> bool:
    # Verifies a password entered to the hash stored in the database for that user
    # If successful, it returns True, otherwise False
    # Uses the .verify function rather than the .hash because it reads the salt from the stored hash string.
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception as e:
        print(f'verify_password error: {e}')
        return False

def new_salt() -> bytes:
    # Creates a 16 byte salt 
    return os.urandom(16)

def derive_kek(password: str, salt: bytes) -> bytes:
    # Creates a Key Encryption Key (KEK) derived from the master password. 
    # The KEK is used to encrypt the Data Encryption Key (DEK is randomly generated at account creation)
    # The KEK decrypts the DEK when the user logs in.
    # The KEK is rebuilt from the master password every login.
    # -----
    # The encrypted DEK version (encrypted by the KEK) is stored in the DB.
    # The encrypted DEK gets decrypted at every login by the KEK.
    # The decrypted DEK is dropped from memory when the user logs out.
    # The decrypted DEK is the key that encrypts each password in the vault
    # -----
    # The DEK prevents hundreds of vault password encryption rewrites when a master password is reset.
    # If there was no DEK, each vault password would need to be re-encrypted by master password.
    # If the master password is reset, there is only one encryption key (the KEK) changed, instead of many.
    return hash_secret_raw(
        secret=password.encode('utf-8'), 
        salt=salt, 
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32, # AES-256 standard
        type=Type.ID
    )

def new_dek() -> bytes:
    # Create a random 256 bit (32 byte) key
    dek = AESGCM.generate_key(256)
    return dek

# Builds the AAD label for one vault entry, as bytes
def ciphertext_aad(vault_entry_id: str) -> bytes:
    return f"entry:{vault_entry_id}:ciphertext".encode()

# Does not include user in order for each user in the vault to read the vault entry's ciphertext
# EX. Jon shares the Company vault with Brock that stores all the passwords related to
# the company. Brock can read the passwords since the label isnt tied to a specific user.
# If the label was tied to a specific user, then that one user can only view the passwords due to the encryption label.
def wrapped_entry_key_aad(vault_id: str, vault_entry_id: str) -> bytes:
    return f"vault:{vault_id}:entry:{vault_entry_id}".encode()

# Each user that has access to a vault will get their own aad tied to their user id
def wrapped_vault_key_aad(vault_id: str, user_id: str) -> bytes:
    return f"vault:{vault_id}:user:{user_id}".encode()

# Needs user in the label because its per entry (ex: Jon shares Amazon password with Brock)
def direct_share_wrapped_entry_key_aad(vault_entry_id: str, user_id: str) -> bytes:
    return f"entry:{vault_entry_id}:user:{user_id}".encode()

# The vault's name is locked with the vault key, shared by every member, so no user_id
def vault_name_aad(vault_id: str) -> bytes:
    return f"vault:{vault_id}:name".encode()

def user_dek_aad(user_id: str) -> bytes:
    return f"user:{user_id}:dek".encode()

def user_private_key_aad(user_id: str) -> bytes:
    return f"user:{user_id}:private_key".encode()

# The DEK's second copy, locked with the recovery key. Separate label from the normal DEK copy.
def user_dek_recovery_aad(user_id: str) -> bytes:
    return f"user:{user_id}:dek:recovery".encode()

def encrypt(key: bytes, unencrypted_data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    # Encrypts data with AES-GCM using the key passed in.
    # This function is generic. It is used to encrypt the DEK with the KEK, and to encrypt vault passwords with the DEK.
    # aad = adittional authenticated data (AAD). It is unencrypted data you pass in as label (ex. user's uuid)
    # The aad is not hidden, but it is checked. If the aad is changed, decryption fails.
    # -----
    # A new 12 byte nonce is created every time encrypt runs.
    # A nonce must never be reused with the same key.
    # The nonce is not secret. It is stored in the DB next to the encrypted data.
    # Returns the nonce and the encrypted data, since both are needed to decrypt later.

    cipher = AESGCM(key) # Creates the cipher object with the key. Same pattern as PasswordHasher.
    nonce = os.urandom(12)
    
    encrypted_data = cipher.encrypt(nonce, unencrypted_data, aad) # the encrypted DEK derived from the KEK + data (un-encrypted DEK)
    return (nonce, encrypted_data)

def decrypt(key: bytes, nonce: bytes, encrypted_data: bytes, aad: bytes) -> bytes:
    # Decrypts data with AES-GCM using the same key, nonce, and aad used to encrypt it.
    # If the key, nonce, or aad is wrong, or the encrypted data was changed, it raises InvalidTag.
    # InvalidTag is not caught here on purpose. Tampered or wrong data should fail loudly, not return something.
    # The error does not say which part was wrong. This prevents an attacker from learning what they got right.

    cipher = AESGCM(key)
    unencrypted_data = cipher.decrypt(nonce, encrypted_data, aad)
    return unencrypted_data


def new_key_pair() -> tuple[bytes, bytes]:
    # TODO: generate a private key
    # TODO: get its public key
    # TODO: return (private_key_bytes, public_key_bytes), 32 bytes each
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    private_key_bytes = private_key.private_bytes_raw()

    return private_key_bytes, public_key_bytes

def wrap_key_from_shared(shared: bytes) -> bytes:
    # TODO: turn the shared secret into a 32-byte AES key with HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"grisha-wrap").derive(shared)

def wrap_for_public_key(public_key: bytes, data: bytes, aad: bytes) -> bytes:
    temp_private_key_bytes, temp_public_key_bytes = new_key_pair()
    temp_private = X25519PrivateKey.from_private_bytes(temp_private_key_bytes)
    users_public_key = X25519PublicKey.from_public_bytes(public_key)

    shared = temp_private.exchange(users_public_key)
    wrap_key = wrap_key_from_shared(shared)
    nonce, ciphertext = encrypt(wrap_key, data, aad)

    blob = temp_public_key_bytes + nonce + ciphertext
    return blob


def unwrap_with_private_key(private_key: bytes, wrapped: bytes, aad: bytes) -> bytes:
    temp_public_key_bytes = wrapped[:32]
    nonce = wrapped[32:44]
    ciphertext = wrapped[44:]
    private_key_obj = X25519PrivateKey.from_private_bytes(private_key)
    public_key_obj = X25519PublicKey.from_public_bytes(temp_public_key_bytes)

    shared = private_key_obj.exchange(public_key_obj)
    wrap_key = wrap_key_from_shared(shared)

    return decrypt(wrap_key, nonce, ciphertext, aad)

def new_vault_key() -> bytes:
    # A random 32-byte AES key for locking entry keys and the vault name
    return AESGCM.generate_key(bit_length=256)


# Recovery codes: 24 characters from an alphabet with no look-alikes (no I, L, O, U).
# 24 × log2(32) = 120 bits of randomness. Shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX.
RECOVERY_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_recovery_code() -> str:
    # A fresh random recovery code, grouped in fours for easy reading
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(24))
    return "-".join(raw[i:i + 4] for i in range(0, 24, 4))


def normalize_recovery_code(code: str) -> str:
    # Accepts lowercase, spaces, and dashes, and fixes common look-alike typos (O→0, I/L→1)
    cleaned = code.upper().replace("-", "").replace(" ", "")
    return cleaned.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
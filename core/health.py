# Password health: weak, reused, and not-strong-enough passwords.
# Works on decrypted entries in memory. Nothing here is stored.
import math
import string
from dataclasses import dataclass


STRONG_BITS = 60        # 60+ bits and not reused → strong
FAIR_BITS = 40          # 40–59 bits → "Not strong enough"; under 40 → weak

# A short list of very common passwords and base words. Matching one makes a password weak,
# even with numbers or symbols added ("Sunshine2024!").
COMMON = {
    "password", "passw0rd", "123456", "12345678", "123456789", "1234567890", "qwerty", "qwertyuiop",
    "abc123", "111111", "000000", "letmein", "welcome", "admin", "login", "iloveyou", "monkey",
    "dragon", "football", "baseball", "sunshine", "princess", "master", "shadow", "superman",
    "trustno1", "starwars", "whatever", "freedom", "hello", "secret", "changeme", "default",
}


@dataclass
class HealthIssue:
    entry: object      # a VaultEntry
    issue: str         # "reused", "weak", or "fair"


def _pool_size(password: str) -> int:
    # How many kinds of characters the password uses
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size


def strength_bits(password: str) -> float:
    # length × log2(kinds of characters used)
    pool = _pool_size(password)
    if not password or pool <= 1:
        return 0.0
    return len(password) * math.log2(pool)


def _is_common(password: str) -> bool:
    lowered = password.lower()
    base = "".join(c for c in lowered if c.isalpha())   # "Sunshine2024!" → "sunshine"
    return lowered in COMMON or base in COMMON


def password_strength(password: str) -> str:
    # "weak", "fair", or "strong" (reuse is checked separately)
    if len(password) < 8 or _is_common(password) or len(set(password)) <= 2:
        return "weak"
    bits = strength_bits(password)
    if bits < FAIR_BITS:
        return "weak"
    if bits < STRONG_BITS:
        return "fair"
    return "strong"


def find_reused(entries) -> set[str]:
    # vault_entry_ids whose password is used by at least one OTHER entry
    by_password: dict[str, list[str]] = {}
    for e in entries:
        if e.password:
            by_password.setdefault(e.password, []).append(e.vault_entry_id)
    return {eid for ids in by_password.values() if len(ids) > 1 for eid in ids}


def analyze(entries) -> dict:
    # Health report for a list of entries. Entries with no password are skipped.
    # Each entry gets its single most serious issue: reused, then weak, then fair.
    checked = [e for e in entries if e.password]
    reused = find_reused(checked)
    issues = []
    for e in checked:
        if e.vault_entry_id in reused:
            issues.append(HealthIssue(e, "reused"))
        else:
            level = password_strength(e.password)
            if level != "strong":
                issues.append(HealthIssue(e, level))

    order = {"reused": 0, "weak": 1, "fair": 2}
    issues.sort(key=lambda i: (order[i.issue], i.entry.title.lower()))
    return {
        "total": len(checked),
        "insecure": len(issues),
        "strong": len(checked) - len(issues),
        "issues": issues,
    }

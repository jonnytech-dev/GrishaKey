# Password and passphrase generator.
# All randomness comes from the secrets module (cryptographically secure). Never use random here.
#
# Passphrases use the EFF Large Wordlist by the Electronic Frontier Foundation,
# licensed under CC BY 3.0 US: https://www.eff.org/dice
import math
import secrets
import string
from pathlib import Path
from core.config import env_int
import os

# Password and passphrase limits (from .env, kept in safe ranges)
MIN_LENGTH = env_int("MIN_LENGTH", 8, minimum=8, maximum=64)
MAX_LENGTH = env_int("MAX_LENGTH", 100, minimum=16, maximum=256)
MIN_WORDS = env_int("MIN_WORDS", 3, minimum=3, maximum=12)
MAX_WORDS = env_int("MAX_WORDS", 12, minimum=4, maximum=20)

# If someone sets a minimum above the maximum, fall back to the defaults
if MIN_LENGTH > MAX_LENGTH:
    MIN_LENGTH, MAX_LENGTH = 8, 100
if MIN_WORDS > MAX_WORDS:
    MIN_WORDS, MAX_WORDS = 3, 12

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*-_=+?"


def generate_password(length: int = 20, upper: bool = True, lower: bool = True,
                      digits: bool = True, symbols: bool = True) -> str:
    # A random password with at least one character from every selected set
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    sets = [chars for chars, on in ((UPPERCASE, upper), (LOWERCASE, lower),
                                    (DIGITS, digits), (SYMBOLS, symbols)) if on]
    if not sets:
        raise ValueError("Pick at least one kind of character.")

    # One from each selected set first, so none is left out by chance...
    chars = [secrets.choice(s) for s in sets]
    # ...then fill the rest from all selected sets together
    pool = "".join(sets)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]

    # Shuffle, so the guaranteed characters aren't always at the front
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_pool_size(upper: bool, lower: bool, digits: bool, symbols: bool) -> int:
    # How many different characters the password can use
    return (len(UPPERCASE) if upper else 0) + (len(LOWERCASE) if lower else 0) \
        + (len(DIGITS) if digits else 0) + (len(SYMBOLS) if symbols else 0)


def load_wordlist(path: Path) -> list[str]:
    # Reads the EFF wordlist ("11111<tab>abacus" per line). Missing file → empty list.
    if not path.exists():
        return []
    words = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            words.append(parts[1])
    return words


def generate_passphrase(words: list[str], count: int = 5, separator: str = "-",
                        capitalize: bool = True, include_number: bool = True) -> str:
    # Random words joined together, e.g. "Correct-Horse-Battery7-Staple-Cloud"
    if not words:
        raise ValueError("No word list is available.")
    if count < MIN_WORDS or count > MAX_WORDS:
        raise ValueError(f"Word count must be between {MIN_WORDS} and {MAX_WORDS}.")

    chosen = [secrets.choice(words) for _ in range(count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    if include_number:
        # Add one digit to the end of one randomly chosen word
        i = secrets.randbelow(count)
        chosen[i] = chosen[i] + str(secrets.randbelow(10))
    return separator.join(chosen)


def entropy_bits(choices: int, picks: int) -> float:
    # Bits of strength: picks × log2(choices). Each bit doubles the guesses needed.
    if choices <= 1 or picks <= 0:
        return 0.0
    return picks * math.log2(choices)


def strength_label(bits: float) -> str:
    # Plain-English strength for a number of bits
    if bits < 40:
        return "Weak"
    if bits < 60:
        return "Fair"
    if bits < 80:
        return "Strong"
    return "Very strong"

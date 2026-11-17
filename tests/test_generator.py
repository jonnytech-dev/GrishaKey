from core import generator
from pathlib import Path
import pytest


WORDS = ["apple", "brick", "cloud", "delta", "ember", "frost", "grove", "harbor"]


class Test_Password:
    # Exact length every time, at the ends of the allowed range too
    def test_length(self):
        for length in (8, 20, 100):
            assert len(generator.generate_password(length)) == length

    # Outside 8–100 → ValueError
    def test_length_limits(self):
        with pytest.raises(ValueError):
            generator.generate_password(7)
        with pytest.raises(ValueError):
            generator.generate_password(101)

    # All character types off → ValueError
    def test_needs_a_character_set(self):
        with pytest.raises(ValueError):
            generator.generate_password(20, upper=False, lower=False, digits=False, symbols=False)

    # Only numbers on → only digits come out
    def test_only_digits(self):
        result = generator.generate_password(30, upper=False, lower=False, digits=True, symbols=False)
        assert result.isdigit()

    # Every selected type shows up, even in the shortest password
    def test_every_selected_set_present(self):
        for _ in range(200):
            result = generator.generate_password(8)
            assert any(c in generator.UPPERCASE for c in result)
            assert any(c in generator.LOWERCASE for c in result)
            assert any(c in generator.DIGITS for c in result)
            assert any(c in generator.SYMBOLS for c in result)

    # Symbols off → no symbols
    def test_symbols_off(self):
        for _ in range(50):
            result = generator.generate_password(40, symbols=False)
            assert not any(c in generator.SYMBOLS for c in result)

    # Two passwords in a row are different
    def test_random(self):
        assert generator.generate_password(20) != generator.generate_password(20)


class Test_Passphrase:
    # Right number of words, joined by the separator
    def test_word_count_and_separator(self):
        result = generator.generate_passphrase(WORDS, count=4, separator=".", capitalize=False, include_number=False)
        parts = result.split(".")
        assert len(parts) == 4
        assert all(p in WORDS for p in parts)

    # Capitalize → every word starts with a capital letter
    def test_capitalize(self):
        result = generator.generate_passphrase(WORDS, count=5, separator="-", capitalize=True, include_number=False)
        assert all(p[0].isupper() for p in result.split("-"))

    # Add a number → exactly one digit somewhere
    def test_include_number(self):
        result = generator.generate_passphrase(WORDS, count=5, separator="-", capitalize=False, include_number=True)
        assert sum(c.isdigit() for c in result) == 1

    # Word count limits and empty list → ValueError
    def test_limits(self):
        with pytest.raises(ValueError):
            generator.generate_passphrase(WORDS, count=2)
        with pytest.raises(ValueError):
            generator.generate_passphrase(WORDS, count=13)
        with pytest.raises(ValueError):
            generator.generate_passphrase([], count=5)

    # Missing word list file → empty list, not a crash
    def test_missing_wordlist(self, tmp_path):
        assert generator.load_wordlist(tmp_path / "missing.txt") == []

    # EFF format: "11111<tab>word" per line
    def test_load_wordlist_format(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("11111\tabacus\n11112\tabdomen\n", encoding="utf-8")
        assert generator.load_wordlist(path) == ["abacus", "abdomen"]


class Test_Strength:
    # 20 characters from 76 possible ≈ 125 bits
    def test_entropy_math(self):
        bits = generator.entropy_bits(76, 20)
        assert 124 < bits < 126

    # Labels change at 40, 60, 80 bits
    def test_labels(self):
        assert generator.strength_label(30) == "Weak"
        assert generator.strength_label(50) == "Fair"
        assert generator.strength_label(70) == "Strong"
        assert generator.strength_label(100) == "Very strong"

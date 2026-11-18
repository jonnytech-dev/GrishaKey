from core import health
from types import SimpleNamespace


def entry(eid, password, title="Site"):
    # A stand-in for VaultEntry with just what health.py uses
    return SimpleNamespace(vault_entry_id=eid, password=password, title=title)


class Test_Strength:
    def test_short_is_weak(self):
        assert health.password_strength("aB3$xyz") == "weak"

    def test_common_is_weak(self):
        assert health.password_strength("password") == "weak"
        assert health.password_strength("Sunshine2024!") == "weak"     # common base word

    def test_repeated_is_weak(self):
        assert health.password_strength("aaaaaaaaaaaa") == "weak"

    def test_fair(self):
        assert health.password_strength("purplelamp") == "fair"        # 10 × log2(26) ≈ 47

    def test_strong(self):
        assert health.password_strength("kT9#mQ2!vX7@pL4$") == "strong"

    def test_bits(self):
        assert round(health.strength_bits("abcdefgh")) == 38            # 8 × log2(26)


class Test_Reuse:
    def test_finds_both_entries(self):
        entries = [entry("a", "kT9#mQ2!vX7@pL4$"), entry("b", "kT9#mQ2!vX7@pL4$"), entry("c", "Other#Pass99xyZ")]
        assert health.find_reused(entries) == {"a", "b"}

    def test_empty_passwords_ignored(self):
        assert health.find_reused([entry("a", ""), entry("b", "")]) == set()


class Test_Analyze:
    def test_report(self):
        entries = [
            entry("a", "kT9#mQ2!vX7@pL4$", "AWS"),
            entry("b", "kT9#mQ2!vX7@pL4$", "Bank"),       # reused with AWS
            entry("c", "password", "Gmail"),              # weak
            entry("d", "purplelamp", "Netflix"),          # fair
            entry("e", "Zq8!rT2#wL6$nP4&", "GitHub"),     # strong
            entry("f", "", "Notes only"),                 # skipped
        ]
        report = health.analyze(entries)
        assert report["total"] == 5
        assert report["insecure"] == 4
        assert report["strong"] == 1
        assert [i.issue for i in report["issues"]] == ["reused", "reused", "weak", "fair"]

    def test_all_strong(self):
        report = health.analyze([entry("a", "kT9#mQ2!vX7@pL4$")])
        assert report["insecure"] == 0 and report["issues"] == []

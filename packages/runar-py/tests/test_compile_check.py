"""Tests for runar.compile_check — verifies real frontend invocation."""

import os
import pytest

from runar import compile_check


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def test_compile_check_accepts_valid_p2pkh():
    """A real, well-formed .runar.py contract passes compile_check."""
    path = os.path.join(REPO_ROOT, "examples", "python", "p2pkh", "P2PKH.runar.py")
    if not os.path.isfile(path):
        pytest.skip(f"{path} not found")
    compile_check(path)


def test_compile_check_rejects_non_class():
    """A source file with no class declaration fails parse/validate."""
    with pytest.raises(RuntimeError):
        compile_check("x = 1\ny = 2\n", file_name="bad.runar.py")


def test_compile_check_rejects_unknown_builtin():
    """A contract that calls an unknown builtin fails typecheck."""
    source = """\
from runar import SmartContract, assert_

class Bad(SmartContract):
    pub_key_hash: bytes

    def __init__(self, pub_key_hash):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    def unlock(self, sig: bytes, pub: bytes) -> None:
        _ = totally_not_a_builtin(sig)
        assert_(check_sig(sig, pub))
"""
    with pytest.raises(RuntimeError, match="(?i)unknown|not allowed|builtin"):
        compile_check(source, file_name="Bad.runar.py")


def test_compile_check_rejects_bad_syntax():
    """Source with parse-level syntax errors fails compile_check."""
    with pytest.raises(RuntimeError):
        compile_check("class Broken(\n", file_name="Broken.runar.py")


def test_compile_check_accepts_kb_and_bn254_after_typecheck_fix():
    """Regression: kbFieldAdd + bn254FieldMul must be recognised builtins.

    Covers CC-1 (typecheck FuncSig registration). Before that fix the typecheck
    would reject this source with 'unknown function'.
    """
    source = """\
from runar import SmartContract, assert_

class KbBn(SmartContract):
    hash: int

    def __init__(self, hash: int):
        super().__init__(hash)
        self.hash = hash

    def unlock(self, a: int, b: int) -> None:
        s = kb_field_add(a, b)
        p = bn254_field_mul(a, b)
        assert_(s != 0)
        assert_(p != 0)
"""
    compile_check(source, file_name="KbBn.runar.py")

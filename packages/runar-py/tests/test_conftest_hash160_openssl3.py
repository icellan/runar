"""
Test conftest._hash160 on OpenSSL-3 (where ripemd160 is unavailable).

This test loads integration/python/conftest.py's _hash160 function for real,
simulates an OpenSSL-3 host where hashlib.new('ripemd160') raises ValueError,
and verifies that the function handles it gracefully via the pure-Python fallback.
"""

import hashlib
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


def test_conftest_hash160_on_openssl3_with_fix():
    """Test that conftest._hash160 works on OpenSSL-3 with the fix applied.

    This test:
    1. Loads conftest._hash160 from integration/python/conftest.py
    2. Simulates OpenSSL-3 by patching hashlib.new to raise ValueError
    3. Forces runar._ripemd160 to use pure-Python fallback
    4. Verifies conftest._hash160 still produces the correct result

    This test MUST FAIL before the fix and PASS after the fix.
    """
    # Find and load conftest.py from integration/python
    # Path structure: packages/runar-py/tests/test_conftest_hash160_openssl3.py
    # We need to go up to the worktree root (4 levels up from test file)
    worktree_root = Path(__file__).parent.parent.parent.parent
    conftest_path = worktree_root / "integration" / "python" / "conftest.py"

    if not conftest_path.exists():
        raise FileNotFoundError(f"conftest.py not found at {conftest_path}")

    # Set up sys.path so conftest's imports work (it needs the compiler)
    compilers_python = str(worktree_root / "compilers" / "python")
    runar_py = str(worktree_root / "packages" / "runar-py")

    if compilers_python not in sys.path:
        sys.path.insert(0, compilers_python)
    if runar_py not in sys.path:
        sys.path.insert(0, runar_py)

    # Load conftest module from its path
    spec = importlib.util.spec_from_file_location("conftest_module", conftest_path)
    conftest = importlib.util.module_from_spec(spec)

    # Execute the module (this will import everything conftest needs)
    try:
        spec.loader.exec_module(conftest)
    except Exception as e:
        raise RuntimeError(f"Failed to load conftest: {e}") from e

    # Get the _hash160 function
    hash160_func = conftest._hash160

    # Test data
    test_data = b"hello"
    expected_hex = "b6a9c8c230722b7c748331a8b450f05566dc7d0f"  # known hash160("hello")

    # Verify it works normally first (sanity check)
    normal_result = hash160_func(test_data)
    assert normal_result == expected_hex, \
        f"Normal case failed: {normal_result} != {expected_hex}"

    # Now simulate OpenSSL-3: patch hashlib.new AND force _ripemd160 fallback
    import runar._ripemd160 as ripemd160_module

    original_hashlib_new = hashlib.new

    def mock_hashlib_new(name, data=None):
        if name == "ripemd160":
            raise ValueError(f"unsupported hash type {name}")
        return original_hashlib_new(name, data)

    # Patch both hashlib.new (to simulate OpenSSL-3) AND the _HAS_HASHLIB_RIPEMD160
    # flag to force the pure-Python path
    with patch("hashlib.new", side_effect=mock_hashlib_new):
        with patch.object(ripemd160_module, "_HAS_HASHLIB_RIPEMD160", False):
            result_with_fallback = hash160_func(test_data)

    # Should still get the correct result (via pure-Python fallback)
    assert result_with_fallback == expected_hex, \
        f"OpenSSL-3 fallback failed: {result_with_fallback} != {expected_hex}"

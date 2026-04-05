import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "CrossCovenantRef.runar.py"))
CrossCovenantRef = contract_mod.CrossCovenantRef

from runar import hash256, num2bin


# ---------------------------------------------------------------------------
# Test fixtures -- simulated referenced output
# ---------------------------------------------------------------------------

# Layout: 16 bytes prefix + 32 bytes state root + 8 bytes suffix
PREFIX = bytes([
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
])
STATE_ROOT = bytes([
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
])
SUFFIX = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
REFERENCED_OUTPUT = PREFIX + STATE_ROOT + SUFFIX
OUTPUT_HASH = hash256(REFERENCED_OUTPUT)


# ---------------------------------------------------------------------------
# verify_and_extract
# ---------------------------------------------------------------------------

def test_verify_and_extract():
    c = CrossCovenantRef(source_script_hash=OUTPUT_HASH)
    c.verify_and_extract(REFERENCED_OUTPUT, STATE_ROOT, 16)


def test_verify_and_extract_tampered():
    c = CrossCovenantRef(source_script_hash=OUTPUT_HASH)
    tampered = b"\xff" + REFERENCED_OUTPUT[1:]
    with pytest.raises(AssertionError):
        c.verify_and_extract(tampered, STATE_ROOT, 16)


def test_verify_and_extract_wrong_root():
    c = CrossCovenantRef(source_script_hash=OUTPUT_HASH)
    wrong_root = b"\x00" * 32
    with pytest.raises(AssertionError):
        c.verify_and_extract(REFERENCED_OUTPUT, wrong_root, 16)


# ---------------------------------------------------------------------------
# verify_and_extract_numeric
# ---------------------------------------------------------------------------

def test_verify_and_extract_numeric():
    # Build an output with a numeric value embedded at offset 16
    num_prefix = b"\x00" * 16
    num_value = num2bin(42, 4)
    num_suffix = b"\x00" * 8
    num_output = num_prefix + num_value + num_suffix
    num_hash = hash256(num_output)

    c = CrossCovenantRef(source_script_hash=num_hash)
    c.verify_and_extract_numeric(num_output, 42, 16, 4)


# ---------------------------------------------------------------------------
# Compile check
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source_path = str(Path(__file__).parent / "CrossCovenantRef.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "CrossCovenantRef.runar.py")

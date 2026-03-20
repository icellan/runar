"""Runar - TypeScript-to-Bitcoin Script Compiler (Python runtime).

Provides types, real crypto, real hashes, EC operations, and base classes
for writing and testing Runar smart contracts in Python.
"""

from runar.types import (
    Bigint, Int, ByteString, PubKey, Sig, Addr, Sha256, Ripemd160,
    SigHashPreimage, RabinSig, RabinPubKey, Point, Readonly,
)
from runar.builtins import (
    assert_,
    check_sig, check_multi_sig, check_preimage,
    hash160, hash256, sha256, ripemd160,
    extract_locktime, extract_output_hash, extract_amount,
    extract_version, extract_sequence,
    extract_hash_prevouts, extract_outpoint,
    num2bin, bin2num, cat, substr, reverse_bytes, len_,
    verify_rabin_sig,
    safediv, safemod, clamp, sign, pow_, mul_div, percent_of,
    sqrt, gcd, divmod_, log2, bool_cast,
    mock_sig, mock_pub_key, mock_preimage,
    verify_wots,
    verify_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128f,
    verify_slh_dsa_sha2_192s, verify_slh_dsa_sha2_192f,
    verify_slh_dsa_sha2_256s, verify_slh_dsa_sha2_256f,
    blake3_compress, blake3_hash,
    sha256_compress, sha256_finalize,
)
from runar.ecdsa import (
    sign_test_message, pub_key_from_priv_key,
    ecdsa_verify, ecdsa_sign,
    TEST_MESSAGE, TEST_MESSAGE_DIGEST,
)
from runar.test_keys import (
    TestKeyPair, TEST_KEYS,
    ALICE, BOB, CHARLIE, DAVE, EVE,
    FRANK, GRACE, HEIDI, IVAN, JUDY,
)
from runar.wots import wots_keygen, wots_sign, WOTSKeyPair
from runar.slhdsa_impl import slh_keygen, slh_verify, SLHKeyPair
from runar.ec import (
    ec_add, ec_mul, ec_mul_gen, ec_negate, ec_on_curve,
    ec_mod_reduce, ec_encode_compressed, ec_make_point,
    ec_point_x, ec_point_y,
    EC_P, EC_N, EC_G,
)
from runar.base import SmartContract, StatefulSmartContract
from runar.decorators import public
from runar.compile_check import compile_check

import builtins as _builtins

# Re-export Python builtins that Runar contracts use directly
abs = _builtins.abs
min = _builtins.min
max = _builtins.max

def within(x: int, lo: int, hi: int) -> bool:
    return lo <= x < hi

__all__ = [
    # Types
    'Bigint', 'Int', 'ByteString', 'PubKey', 'Sig', 'Addr', 'Sha256',
    'Ripemd160', 'SigHashPreimage', 'RabinSig', 'RabinPubKey', 'Point',
    'Readonly',
    # Decorators
    'public',
    # Base classes
    'SmartContract', 'StatefulSmartContract',
    # Assertions
    'assert_',
    # Crypto
    'check_sig', 'check_multi_sig', 'check_preimage',
    'hash160', 'hash256', 'sha256', 'ripemd160',
    'verify_rabin_sig',
    'verify_wots',
    'verify_slh_dsa_sha2_128s', 'verify_slh_dsa_sha2_128f',
    'verify_slh_dsa_sha2_192s', 'verify_slh_dsa_sha2_192f',
    'verify_slh_dsa_sha2_256s', 'verify_slh_dsa_sha2_256f',
    # ECDSA
    'ecdsa_verify', 'ecdsa_sign', 'sign_test_message', 'pub_key_from_priv_key',
    'TEST_MESSAGE', 'TEST_MESSAGE_DIGEST',
    # Test keys
    'TestKeyPair', 'TEST_KEYS',
    'ALICE', 'BOB', 'CHARLIE', 'DAVE', 'EVE',
    'FRANK', 'GRACE', 'HEIDI', 'IVAN', 'JUDY',
    # Preimage extraction
    'extract_locktime', 'extract_output_hash', 'extract_amount',
    'extract_version', 'extract_sequence',
    'extract_hash_prevouts', 'extract_outpoint',
    # Binary utilities
    'num2bin', 'bin2num', 'cat', 'substr', 'reverse_bytes', 'len_',
    # Math
    'within', 'safediv', 'safemod', 'clamp', 'sign', 'pow_',
    'mul_div', 'percent_of', 'sqrt', 'gcd', 'divmod_', 'log2', 'bool_cast',
    # EC
    'ec_add', 'ec_mul', 'ec_mul_gen', 'ec_negate', 'ec_on_curve',
    'ec_mod_reduce', 'ec_encode_compressed', 'ec_make_point',
    'ec_point_x', 'ec_point_y', 'EC_P', 'EC_N', 'EC_G',
    # BLAKE3
    'blake3_compress', 'blake3_hash',
    # SHA-256 compression
    'sha256_compress', 'sha256_finalize',
    # Test helpers
    'mock_sig', 'mock_pub_key', 'mock_preimage',
    # WOTS+ keygen/sign
    'wots_keygen', 'wots_sign', 'WOTSKeyPair',
    # SLH-DSA keygen/verify
    'slh_keygen', 'slh_verify', 'SLHKeyPair',
    # Compile check
    'compile_check',
]

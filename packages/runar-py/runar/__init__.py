"""Runar - TypeScript-to-Bitcoin Script Compiler (Python runtime).

Provides types, real crypto, real hashes, EC operations, and base classes
for writing and testing Runar smart contracts in Python.
"""

from runar.types import (
    Bigint, Int, ByteString, PubKey, Sig, Addr, Sha256, Ripemd160,
    SigHashPreimage, RabinSig, RabinPubKey, Point, Readonly, FixedArray,
)
from runar.builtins import (
    assert_,
    check_sig, check_multi_sig, check_preimage,
    hash160, hash256, sha256, ripemd160,
    extract_locktime, extract_output_hash, extract_amount,
    extract_version, extract_sequence,
    extract_hash_prevouts, extract_outpoint,
    num2bin, bin2num, int_to_str, cat, substr, reverse_bytes, len_,
    verify_rabin_sig,
    safediv, safemod, clamp, sign, pow_, mul_div, percent_of,
    sqrt, gcd, divmod_, log2, bool_cast,
    mock_sig, mock_pub_key, mock_preimage,
    verify_wots,
    verify_ecdsa_p256,
    verify_ecdsa_p384,
    verify_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128f,
    verify_slh_dsa_sha2_192s, verify_slh_dsa_sha2_192f,
    verify_slh_dsa_sha2_256s, verify_slh_dsa_sha2_256f,
    blake3_compress, blake3_hash,
    sha256_compress, sha256_finalize,
    bb_field_add, bb_field_sub, bb_field_mul, bb_field_inv,
    bb_ext4_mul0, bb_ext4_mul1, bb_ext4_mul2, bb_ext4_mul3,
    bb_ext4_inv0, bb_ext4_inv1, bb_ext4_inv2, bb_ext4_inv3,
    kb_field_add, kb_field_sub, kb_field_mul, kb_field_inv,
    kb_ext4_mul0, kb_ext4_mul1, kb_ext4_mul2, kb_ext4_mul3,
    kb_ext4_inv0, kb_ext4_inv1, kb_ext4_inv2, kb_ext4_inv3,
    bn254_field_add, bn254_field_sub, bn254_field_mul, bn254_field_inv, bn254_field_neg,
    merkle_root_sha256, merkle_root_hash256,
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
from runar.p256 import p256_keygen, p256_sign, P256KeyPair
from runar.p384 import p384_keygen, p384_sign, P384KeyPair
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
    'Readonly', 'FixedArray',
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
    'num2bin', 'bin2num', 'int_to_str', 'cat', 'substr', 'reverse_bytes', 'len_',
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
    # Baby Bear field arithmetic
    'bb_field_add', 'bb_field_sub', 'bb_field_mul', 'bb_field_inv',
    # Baby Bear quartic extension field (x^4 - 11)
    'bb_ext4_mul0', 'bb_ext4_mul1', 'bb_ext4_mul2', 'bb_ext4_mul3',
    'bb_ext4_inv0', 'bb_ext4_inv1', 'bb_ext4_inv2', 'bb_ext4_inv3',
    # KoalaBear field arithmetic
    'kb_field_add', 'kb_field_sub', 'kb_field_mul', 'kb_field_inv',
    # KoalaBear quartic extension field (x^4 - 3)
    'kb_ext4_mul0', 'kb_ext4_mul1', 'kb_ext4_mul2', 'kb_ext4_mul3',
    'kb_ext4_inv0', 'kb_ext4_inv1', 'kb_ext4_inv2', 'kb_ext4_inv3',
    # BN254 field arithmetic
    'bn254_field_add', 'bn254_field_sub', 'bn254_field_mul',
    'bn254_field_inv', 'bn254_field_neg',
    # Merkle proof verification
    'merkle_root_sha256', 'merkle_root_hash256',
    # Test helpers
    'mock_sig', 'mock_pub_key', 'mock_preimage',
    # WOTS+ keygen/sign
    'wots_keygen', 'wots_sign', 'WOTSKeyPair',
    # P-256 keygen/sign
    'p256_keygen', 'p256_sign', 'P256KeyPair',
    # P-256 ECDSA verification
    'verify_ecdsa_p256',
    # P-384 keygen/sign
    'p384_keygen', 'p384_sign', 'P384KeyPair',
    # P-384 ECDSA verification
    'verify_ecdsa_p384',
    # SLH-DSA keygen/verify
    'slh_keygen', 'slh_verify', 'SLHKeyPair',
    # Compile check
    'compile_check',
]

"""Poseidon2 permutation over KoalaBear field -- codegen for Bitcoin Script.

Implements the Poseidon2 hash function used by SP1 v6 for Merkle commitments
and Fiat-Shamir challenges. All operations use the KoalaBear prime field
(p = 2^31 - 2^24 + 1 = 2,130,706,433).

Parameters (SP1 v6.0.2):
  - State width: 16 KoalaBear field elements
  - Sbox: x^3 (cube)
  - External rounds: 8 (4 before internal, 4 after)
  - Internal rounds: 20
  - Total rounds: 28
  - Digest: first 8 elements of the output state

The permutation is structured as:
  Phase 1 -- 4 external rounds (rounds 0-3)
  Phase 2 -- 20 internal rounds (rounds 4-23)
  Phase 3 -- 4 external rounds (rounds 24-27)

External rounds apply the full S-box and MDS matrix to all 16 elements.
Internal rounds apply S-box only to element 0 and use a diagonal diffusion matrix.

This module provides internal codegen functions called by Merkle verification
and sponge codegen modules. It is NOT registered as a contract-level builtin.

Direct port of ``compilers/go/codegen/poseidon2_koalabear.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from runar_compiler.codegen.koalabear import (
    KBTracker,
    _kb_field_add,
    _kb_field_add_unreduced,
    _kb_field_mul,
    _kb_field_mul_const,
    _kb_field_sqr,
)

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp

# ===========================================================================
# Constants
# ===========================================================================

POSEIDON2_KB_WIDTH = 16
POSEIDON2_KB_EXTERNAL_ROUNDS = 8
POSEIDON2_KB_INTERNAL_ROUNDS = 20
POSEIDON2_KB_TOTAL_ROUNDS = POSEIDON2_KB_EXTERNAL_ROUNDS + POSEIDON2_KB_INTERNAL_ROUNDS

# Internal diagonal M-1 (16 values).
# From Plonky3 p3-koala-bear DiffusionMatrixKoalaBear.
# V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
# Values are computed mod p (fractions via modular inverse).
POSEIDON2_KB_INTERNAL_DIAG_M1 = [
    2130706431,  # V[0]  = -2 mod p
    1,           # V[1]  = 1
    2,           # V[2]  = 2
    1065353217,  # V[3]  = 1/2 mod p
    3,           # V[4]  = 3
    4,           # V[5]  = 4
    1065353216,  # V[6]  = -1/2 mod p
    2130706430,  # V[7]  = -3 mod p
    2130706429,  # V[8]  = -4 mod p
    2122383361,  # V[9]  = 1/2^8 mod p
    1864368129,  # V[10] = 1/8 mod p
    2130706306,  # V[11] = 1/2^24 mod p
    8323072,     # V[12] = -1/2^8 mod p
    266338304,   # V[13] = -1/8 mod p
    133169152,   # V[14] = -1/16 mod p
    127,         # V[15] = -1/2^24 mod p
]

# Round constants (28 rounds x 16 elements).
# For external rounds, all 16 are used.
# For internal rounds (4-23), only element [0] is used (rest are zero).
#
# Extracted from Plonky3 p3-koala-bear (SP1 v6.0.2):
#   koala-bear/src/poseidon2.rs
POSEIDON2_KB_ROUND_CONSTANTS = [
    # External initial rounds (0-3)
    [2128964168, 288780357, 316938561, 2126233899, 426817493, 1714118888, 1045008582, 1738510837, 889721787, 8866516, 681576474, 419059826, 1596305521, 1583176088, 1584387047, 1529751136],
    [1863858111, 1072044075, 517831365, 1464274176, 1138001621, 428001039, 245709561, 1641420379, 1365482496, 770454828, 693167409, 757905735, 136670447, 436275702, 525466355, 1559174242],
    [1030087950, 869864998, 322787870, 267688717, 948964561, 740478015, 679816114, 113662466, 2066544572, 1744924186, 367094720, 1380455578, 1842483872, 416711434, 1342291586, 1692058446],
    [1493348999, 1113949088, 210900530, 1071655077, 610242121, 1136339326, 2020858841, 1019840479, 678147278, 1678413261, 1361743414, 61132629, 1209546658, 64412292, 1936878279, 1980661727],
    # Internal rounds (4-23) -- only element [0] is used
    [1423960925, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [2101391318, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1915532054, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [275400051, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1168624859, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1141248885, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [356546469, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1165250474, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1320543726, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [932505663, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1204226364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1452576828, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1774936729, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [926808140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1184948056, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1186493834, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [843181003, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [185193011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [452207447, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [510054082, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    # External final rounds (24-27)
    [1139268644, 630873441, 669538875, 462500858, 876500520, 1214043330, 383937013, 375087302, 636912601, 307200505, 390279673, 1999916485, 1518476730, 1606686591, 1410677749, 1581191572],
    [1004269969, 143426723, 1747283099, 1016118214, 1749423722, 66331533, 1177761275, 1581069649, 1851371119, 852520128, 1499632627, 1820847538, 150757557, 884787840, 619710451, 1651711087],
    [505263814, 212076987, 1482432120, 1458130652, 382871348, 417404007, 2066495280, 1996518884, 902934924, 582892981, 1337064375, 1199354861, 2102596038, 1533193853, 1436311464, 2012303432],
    [839997195, 1225781098, 2011967775, 575084315, 1309329169, 786393545, 995788880, 1702925345, 1444525226, 908073383, 1811535085, 1531002367, 1635653662, 1585100155, 867006515, 879151050],
]

assert len(POSEIDON2_KB_ROUND_CONSTANTS) == POSEIDON2_KB_TOTAL_ROUNDS


# ===========================================================================
# State naming helpers
# ===========================================================================

def p2kb_state_name(i: int) -> str:
    """Return the canonical name for state element i."""
    return f"_p2s{i}"


def _p2kb_state_names() -> list[str]:
    """Return a list of canonical state element names."""
    return [p2kb_state_name(i) for i in range(POSEIDON2_KB_WIDTH)]


# ===========================================================================
# Sbox: x^3 (cube) over KoalaBear field
# ===========================================================================

def p2kb_sbox(t: KBTracker, name: str, round_: int, idx: int) -> None:
    """Compute state[idx] = state[idx]^3 mod p.

    Uses: x^3 = x * x^2. Two multiplications, one squaring copy.
    """
    tmp = f"_p2sbox_r{round_}_{idx}"

    # x^2
    t.copy_to_top(name, tmp + "_sq_copy")
    _kb_field_sqr(t, tmp + "_sq_copy", tmp + "_sq")
    # x^3 = x * x^2
    _kb_field_mul(t, name, tmp + "_sq", tmp + "_cube")
    t.rename(name)


# ===========================================================================
# External MDS: circ(2, 3, 1, 1) applied blockwise to 4 groups of 4
# ===========================================================================

def p2kb_external_mds4(t: KBTracker, names: list[str], round_: int, group: int) -> None:
    """Apply the circulant matrix circ(2,3,1,1) to a 4-element block [a, b, c, d].

    sum = a + b + c + d
    out0 = sum + a + 2*b  (= 2a + 3b + c + d)
    out1 = sum + b + 2*c  (= a + 2b + 3c + d)
    out2 = sum + c + 2*d  (= a + b + 2c + 3d)
    out3 = sum + d + 2*a  (= 3a + b + c + 2d)
    """
    assert len(names) == 4
    prefix = f"_p2mds_r{round_}_g{group}"

    # Compute sum = a + b + c + d (unreduced -- intermediate)
    # Max value: 4p ≈ 8.5e9 (fits in 34 bits, safe for BSV script numbers)
    t.copy_to_top(names[0], prefix + "_ca")
    t.copy_to_top(names[1], prefix + "_cb")
    _kb_field_add_unreduced(t, prefix + "_ca", prefix + "_cb", prefix + "_ab")
    t.copy_to_top(names[2], prefix + "_cc")
    _kb_field_add_unreduced(t, prefix + "_ab", prefix + "_cc", prefix + "_abc")
    t.copy_to_top(names[3], prefix + "_cd")
    _kb_field_add_unreduced(t, prefix + "_abc", prefix + "_cd", prefix + "_sum")

    # out0 = sum + a + 2*b (unreduced adds -- kbFieldMulConst does final mod)
    t.copy_to_top(prefix + "_sum", prefix + "_s0")
    t.copy_to_top(names[0], prefix + "_a0")
    _kb_field_add_unreduced(t, prefix + "_s0", prefix + "_a0", prefix + "_sa0")
    t.copy_to_top(names[1], prefix + "_b0")
    _kb_field_mul_const(t, prefix + "_b0", 2, prefix + "_2b0")
    _kb_field_add(t, prefix + "_sa0", prefix + "_2b0", prefix + "_out0")

    # out1 = sum + b + 2*c
    t.copy_to_top(prefix + "_sum", prefix + "_s1")
    t.copy_to_top(names[1], prefix + "_b1")
    _kb_field_add_unreduced(t, prefix + "_s1", prefix + "_b1", prefix + "_sb1")
    t.copy_to_top(names[2], prefix + "_c1")
    _kb_field_mul_const(t, prefix + "_c1", 2, prefix + "_2c1")
    _kb_field_add(t, prefix + "_sb1", prefix + "_2c1", prefix + "_out1")

    # out2 = sum + c + 2*d
    t.copy_to_top(prefix + "_sum", prefix + "_s2")
    t.copy_to_top(names[2], prefix + "_c2")
    _kb_field_add_unreduced(t, prefix + "_s2", prefix + "_c2", prefix + "_sc2")
    t.copy_to_top(names[3], prefix + "_d2")
    _kb_field_mul_const(t, prefix + "_d2", 2, prefix + "_2d2")
    _kb_field_add(t, prefix + "_sc2", prefix + "_2d2", prefix + "_out2")

    # out3 = sum + d + 2*a
    t.copy_to_top(prefix + "_sum", prefix + "_s3")
    t.copy_to_top(names[3], prefix + "_d3")
    _kb_field_add_unreduced(t, prefix + "_s3", prefix + "_d3", prefix + "_sd3")
    t.copy_to_top(names[0], prefix + "_a3")
    _kb_field_mul_const(t, prefix + "_a3", 2, prefix + "_2a3")
    _kb_field_add(t, prefix + "_sd3", prefix + "_2a3", prefix + "_out3")

    # Drop old state elements and sum
    t.to_top(names[0]); t.drop()
    t.to_top(names[1]); t.drop()
    t.to_top(names[2]); t.drop()
    t.to_top(names[3]); t.drop()
    t.to_top(prefix + "_sum"); t.drop()

    # Rename outputs to the original state names
    t.to_top(prefix + "_out0"); t.rename(names[0])
    t.to_top(prefix + "_out1"); t.rename(names[1])
    t.to_top(prefix + "_out2"); t.rename(names[2])
    t.to_top(prefix + "_out3"); t.rename(names[3])


def p2kb_external_mds_full(t: KBTracker, names: list[str], round_: int) -> None:
    """Apply the external MDS to all 16 state elements.

    1. Apply circ(2,3,1,1) to each group of 4 (via p2kb_external_mds4)
    2. Cross-group mixing: add sum of position-equivalent elements to each element
    """
    assert len(names) == POSEIDON2_KB_WIDTH

    # Step 1: Apply 4x4 MDS blockwise (names are modified in-place by MDS4)
    for g in range(4):
        group = [names[g * 4], names[g * 4 + 1], names[g * 4 + 2], names[g * 4 + 3]]
        p2kb_external_mds4(t, group, round_, g)

    # Step 2: Cross-group mixing
    # For each position k (0..3), compute sums[k] = state[k] + state[k+4] + state[k+8] + state[k+12]
    # Then add sums[k] to each state[i] where i % 4 == k
    prefix = f"_p2xg_r{round_}"
    for k in range(4):
        sum_name = f"{prefix}_s{k}"
        t.copy_to_top(names[k], sum_name)
        for j in range(1, 4):
            idx = k + j * 4
            add_name = f"{prefix}_a{k}_{j}"
            t.copy_to_top(names[idx], add_name)
            _kb_field_add(t, sum_name, add_name, sum_name + "_n")
            t.rename(sum_name)

    # Add sums[i%4] to each element
    for i in range(POSEIDON2_KB_WIDTH):
        k = i % 4
        sum_name = f"{prefix}_s{k}"
        copy_name = f"{prefix}_sc{i}"
        t.copy_to_top(sum_name, copy_name)
        _kb_field_add(t, names[i], copy_name, names[i])

    # Clean up: drop the 4 sum accumulators
    for k in range(4):
        t.to_top(f"{prefix}_s{k}")
        t.drop()


# ===========================================================================
# Internal diffusion: diagonal matrix + sum
# ===========================================================================

def p2kb_internal_diffusion(t: KBTracker, names: list[str], round_: int) -> None:
    """Apply the internal linear layer.

    sum = sum(state[i])
    state[i] = state[i] * diag_m_1[i] + sum   for each i

    For diag_m_1[0] = p-2 (== -2 mod p): state[0] = -2*state[0] + sum
    Other entries include modular inverses (1/2, 1/8, etc.); uses kbFieldMulConst.
    """
    assert len(names) == POSEIDON2_KB_WIDTH
    prefix = f"_p2id_r{round_}"

    # Step 1: Compute sum of all state elements.
    # Accumulate pairwise: sum = s0 + s1 + ... + s15
    t.copy_to_top(names[0], prefix + "_acc")
    for i in range(1, POSEIDON2_KB_WIDTH):
        t.copy_to_top(names[i], f"{prefix}_add{i}")
        _kb_field_add(t, prefix + "_acc", f"{prefix}_add{i}", prefix + "_acc_new")
        t.rename(prefix + "_acc")
    # prefix+"_acc" now holds the sum
    t.rename(prefix + "_sum")

    # Step 2: For each element, compute state[i] = state[i] * diag_m_1[i] + sum.
    for i in range(POSEIDON2_KB_WIDTH):
        diag = POSEIDON2_KB_INTERNAL_DIAG_M1[i]
        prod_name = f"{prefix}_prod{i}"

        # Multiply state[i] by diag_m_1[i]
        if diag == 1:
            # Multiplication by 1 is identity -- just copy
            t.copy_to_top(names[i], prod_name)
        else:
            t.copy_to_top(names[i], f"{prefix}_si{i}")
            _kb_field_mul_const(t, f"{prefix}_si{i}", diag, prod_name)

        # Add sum
        t.copy_to_top(prefix + "_sum", f"{prefix}_sc{i}")
        result_name = f"{prefix}_out{i}"
        _kb_field_add(t, prod_name, f"{prefix}_sc{i}", result_name)

    # Step 3: Drop old state elements and sum, rename outputs.
    for i in range(POSEIDON2_KB_WIDTH):
        t.to_top(names[i])
        t.drop()
    t.to_top(prefix + "_sum")
    t.drop()

    for i in range(POSEIDON2_KB_WIDTH):
        t.to_top(f"{prefix}_out{i}")
        t.rename(names[i])


# ===========================================================================
# Add round constants
# ===========================================================================

def p2kb_add_round_constants(t: KBTracker, names: list[str], round_: int) -> None:
    """Add round constants to all 16 state elements. Used in external rounds."""
    assert len(names) == POSEIDON2_KB_WIDTH
    for i in range(POSEIDON2_KB_WIDTH):
        rc = POSEIDON2_KB_ROUND_CONSTANTS[round_][i]
        if rc == 0:
            continue  # Skip zero round constants (no-op addition)
        prefix = f"_p2rc_r{round_}_{i}"
        t.push_int(prefix + "_c", rc)
        _kb_field_add(t, names[i], prefix + "_c", prefix + "_sum")
        t.rename(names[i])


def p2kb_add_round_constant_elem0(t: KBTracker, names: list[str], round_: int) -> None:
    """Add the round constant to element 0 only. Used in internal rounds."""
    assert len(names) == POSEIDON2_KB_WIDTH
    rc = POSEIDON2_KB_ROUND_CONSTANTS[round_][0]
    if rc == 0:
        return  # Skip zero round constants
    prefix = f"_p2rc_r{round_}_0"
    t.push_int(prefix + "_c", rc)
    _kb_field_add(t, names[0], prefix + "_c", prefix + "_sum")
    t.rename(names[0])


# ===========================================================================
# Full Poseidon2 permutation
# ===========================================================================

def p2kb_permute(t: KBTracker, names: list[str]) -> None:
    """Apply the full Poseidon2 permutation to 16 state elements.

    The state names list is mutated in place as elements are renamed through
    intermediate results.

    Algorithm:
      Initial -- external MDS (Plonky3's external_initial_permute_state)
      Phase 1 -- 4 external rounds (rounds 0-3):
        add round constants, full sbox, external MDS (blockwise + cross-group)
      Phase 2 -- 20 internal rounds (rounds 4-23):
        add round constant to elem 0, sbox on elem 0, internal diffusion
      Phase 3 -- 4 external rounds (rounds 24-27):
        add round constants, full sbox, external MDS (blockwise + cross-group)
    """
    assert len(names) == POSEIDON2_KB_WIDTH

    # Initial MDS before external rounds (Plonky3's external_initial_permute_state)
    p2kb_external_mds_full(t, names, -1)

    # Phase 1: 4 external rounds (rounds 0-3)
    for r in range(4):
        p2kb_add_round_constants(t, names, r)
        for i in range(POSEIDON2_KB_WIDTH):
            p2kb_sbox(t, names[i], r, i)
        p2kb_external_mds_full(t, names, r)

    # Phase 2: 20 internal rounds (rounds 4-23)
    for r in range(4, 4 + POSEIDON2_KB_INTERNAL_ROUNDS):
        p2kb_add_round_constant_elem0(t, names, r)
        p2kb_sbox(t, names[0], r, 0)
        p2kb_internal_diffusion(t, names, r)

    # Phase 3: 4 external rounds (rounds 24-27)
    for r in range(4 + POSEIDON2_KB_INTERNAL_ROUNDS, POSEIDON2_KB_TOTAL_ROUNDS):
        p2kb_add_round_constants(t, names, r)
        for i in range(POSEIDON2_KB_WIDTH):
            p2kb_sbox(t, names[i], r, i)
        p2kb_external_mds_full(t, names, r)


# ===========================================================================
# Public emit functions
# ===========================================================================

def emit_poseidon2_kb_permute(emit: Callable[["StackOp"], None]) -> None:
    """Emit the full Poseidon2 permutation over KoalaBear.

    Stack in:  [..., s0, s1, ..., s15] (s15 on top)
    Stack out: [..., s0', s1', ..., s15'] (s15' on top)

    All 16 state elements are permuted in place. The caller is responsible for
    extracting the elements it needs from the resulting stack.
    """
    init_names = [p2kb_state_name(i) for i in range(POSEIDON2_KB_WIDTH)]
    t = KBTracker(init_names, emit)
    t.push_prime_cache()  # Cache the KoalaBear prime on alt-stack

    names = _p2kb_state_names()
    p2kb_permute(t, names)

    t.pop_prime_cache()  # Clean up cached prime

    # Reorder so that _p2s0 is deepest and _p2s15 is on top (original order).
    for i in range(POSEIDON2_KB_WIDTH):
        t.to_top(p2kb_state_name(i))
    # Now stack is: [_p2s0, _p2s1, ..., _p2s15] with _p2s15 on top.


def emit_poseidon2_kb_compress(emit: Callable[["StackOp"], None]) -> None:
    """Emit Poseidon2 compression (permute + truncate to 8 elements).

    Stack in:  [..., s0, s1, ..., s15] (s15 on top)
    Stack out: [..., h0, h1, ..., h7] (h7 on top)

    The digest is the first 8 elements of the permuted state.
    Elements s8'..s15' are dropped after permutation.
    """
    init_names = [p2kb_state_name(i) for i in range(POSEIDON2_KB_WIDTH)]
    t = KBTracker(init_names, emit)
    t.push_prime_cache()  # Cache the KoalaBear prime on alt-stack

    names = _p2kb_state_names()
    p2kb_permute(t, names)

    t.pop_prime_cache()  # Clean up cached prime

    # Drop elements 8-15 (the non-digest portion)
    for i in range(8, POSEIDON2_KB_WIDTH):
        t.to_top(p2kb_state_name(i))
        t.drop()

    # Reorder digest elements so _p2s0 is deepest, _p2s7 on top
    for i in range(8):
        t.to_top(p2kb_state_name(i))

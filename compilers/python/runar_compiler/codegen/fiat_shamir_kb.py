"""Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear -- codegen for Bitcoin Script.

Implements the Fiat-Shamir challenge derivation used by SP1's StackedBasefold
verifier. The sponge uses Poseidon2 as the permutation primitive.

Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
  - State width: 16 KoalaBear field elements
  - Rate: 8 elements (positions 0-7)
  - Capacity: 8 elements (positions 8-15)

Key design property: the sponge position is tracked at codegen time (in Python),
not at runtime (in Bitcoin Script). Because the verifier's transcript structure
is fully deterministic, we always know exactly when to permute without runtime
conditionals.

Matches Plonky3 DuplexChallenger behavior:
  - Observations write directly into the sponge state and invalidate cached
    squeeze outputs. When the rate is filled, the state is permuted.
  - Squeezing reads consecutive elements from the permuted state. A single
    permutation provides up to RATE (8) squeeze outputs. Only when all cached
    outputs are consumed does the next squeeze trigger a fresh permutation.
  - Any observation after squeezing invalidates the cached outputs.

This module provides codegen-time helpers used by the Basefold verifier's
codegen. It is NOT registered as a contract-level builtin.

Direct port of ``compilers/go/codegen/fiat_shamir_kb.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

from runar_compiler.codegen.koalabear import KBTracker, _big_int_push, _make_stack_op
from runar_compiler.codegen.poseidon2_koalabear import (
    p2kb_state_name,
    p2kb_permute,
    _p2kb_state_names,
    POSEIDON2_KB_WIDTH,
)

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp

# ===========================================================================
# Constants
# ===========================================================================

FS_SPONGE_WIDTH = 16   # full Poseidon2 state width (rate + capacity)
FS_SPONGE_RATE = 8     # number of rate elements in the duplex sponge


# ===========================================================================
# State naming helpers
# ===========================================================================

def _fs_sponge_state_name(i: int) -> str:
    """Return the canonical name for sponge state element i."""
    return f"fs{i}"


# ===========================================================================
# FiatShamirState -- codegen-time duplex sponge state machine
# ===========================================================================

class FiatShamirState:
    """Tracks the duplex sponge position at codegen time.

    Matches Plonky3's DuplexChallenger semantics. The 16-element KoalaBear
    state lives on the Bitcoin Script stack as fs0 (deepest) through fs15 (top).

    Two independent positions are tracked:
      - absorb_pos: where the next observation will be written (0..RATE-1)
      - squeeze_pos: where the next squeeze will read from (0..RATE-1)
      - output_valid: whether the current state has been permuted and is safe
        to squeeze from (invalidated by any observation)
    """

    def __init__(self) -> None:
        self.absorb_pos: int = 0
        self.squeeze_pos: int = 0
        self.output_valid: bool = False

    # -----------------------------------------------------------------------
    # emit_init -- push the initial all-zero sponge state
    # -----------------------------------------------------------------------

    def emit_init(self, t: KBTracker) -> None:
        """Push 16 zero-valued KoalaBear field elements onto the stack as the
        initial sponge state. After this call the stack contains:

        [..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
        """
        for i in range(FS_SPONGE_WIDTH):
            t.push_int(_fs_sponge_state_name(i), 0)
        self.absorb_pos = 0
        self.squeeze_pos = 0
        self.output_valid = False

    # -----------------------------------------------------------------------
    # _emit_permute -- rename sponge state, run Poseidon2, rename back
    # -----------------------------------------------------------------------

    def _emit_permute(self, t: KBTracker) -> None:
        """Emit a full Poseidon2 permutation on the 16-element sponge state.

        The sponge elements fs0..fs15 are renamed to the Poseidon2 canonical
        names _p2s0.._p2s15, the permutation is applied, and the results are
        renamed back to fs0..fs15.
        """
        # Rename fs0..fs15 -> _p2s0.._p2s15 and reorder for Poseidon2.
        # Poseidon2 expects _p2s0 deepest, _p2s15 on top.
        for i in range(FS_SPONGE_WIDTH):
            t.to_top(_fs_sponge_state_name(i))
            t.rename(p2kb_state_name(i))

        # Cache the KoalaBear prime on the alt-stack for the duration of the
        # permutation. Without this, every field operation pushes a fresh 5-byte
        # prime literal, adding ~50 KB of unnecessary script per permutation.
        t.push_prime_cache()

        # Run the permutation.
        names = _p2kb_state_names()
        p2kb_permute(t, names)

        t.pop_prime_cache()

        # Reorder post-permutation elements and rename back to fs0..fs15.
        for i in range(FS_SPONGE_WIDTH):
            t.to_top(p2kb_state_name(i))
            t.rename(_fs_sponge_state_name(i))

    # -----------------------------------------------------------------------
    # emit_observe -- absorb one field element into the sponge
    # -----------------------------------------------------------------------

    def emit_observe(self, t: KBTracker) -> None:
        """Absorb one KoalaBear field element from the top of the stack.

        The element replaces the current rate slot and the absorption position
        advances. When the rate is filled (absorb_pos reaches FS_SPONGE_RATE),
        a Poseidon2 permutation is emitted, the position resets, and the
        squeeze output becomes valid.

        Any observation invalidates cached squeeze outputs, matching
        DuplexChallenger behavior where observation clears the output buffer.

        Stack in:  [..., fs0, ..., fs15, element]
        Stack out: [..., fs0', ..., fs15']   (element consumed)
        """
        target_name = _fs_sponge_state_name(self.absorb_pos)

        # The element to absorb is on top of the stack. Rename it to a temp name
        # to avoid collision with the target sponge slot.
        t.rename("_fs_absorb_elem")

        # Bring the target sponge slot to the top and drop it.
        t.to_top(target_name)
        t.drop()

        # Move the absorbed element to the top and rename it to the sponge slot.
        t.to_top("_fs_absorb_elem")
        t.rename(target_name)

        # Invalidate cached squeeze outputs.
        self.output_valid = False

        self.absorb_pos += 1
        if self.absorb_pos == FS_SPONGE_RATE:
            # Rate full -- permute. After permutation, squeeze output is valid.
            self._emit_permute(t)
            self.absorb_pos = 0
            self.squeeze_pos = 0
            self.output_valid = True

    # -----------------------------------------------------------------------
    # emit_squeeze -- sample one field element from the sponge
    # -----------------------------------------------------------------------

    def emit_squeeze(self, t: KBTracker) -> None:
        """Sample one KoalaBear field element from the sponge.

        Matches Plonky3's DuplexChallenger behavior:
        1. If the output is not valid (observations have been made since last
           permutation) or all rate elements have been consumed
           (squeeze_pos >= RATE), a permutation is emitted to produce fresh output.
        2. The element at the current squeeze position is copied to the top
           of the stack as "_fs_squeezed".
        3. The squeeze position advances. Up to RATE (8) consecutive squeezes
           can be served from a single permutation.

        Stack in:  [..., fs0, ..., fs15]
        Stack out: [..., fs0', ..., fs15', sampled]
        """
        if not self.output_valid or self.squeeze_pos >= FS_SPONGE_RATE:
            # No valid output available -- permute to produce fresh output.
            self._emit_permute(t)
            self.absorb_pos = 0
            self.squeeze_pos = 0
            self.output_valid = True

        # Copy the current rate element to the top.
        source_name = _fs_sponge_state_name(self.squeeze_pos)
        t.copy_to_top(source_name, "_fs_squeezed")

        self.squeeze_pos += 1

    # -----------------------------------------------------------------------
    # emit_squeeze_ext4 -- sample a quartic extension element (4 field elements)
    # -----------------------------------------------------------------------

    def emit_squeeze_ext4(self, t: KBTracker) -> None:
        """Sample 4 consecutive KoalaBear field elements from the sponge.

        Forms a quartic extension field element. This is equivalent to 4
        sequential squeezes. With DuplexChallenger semantics, at most one
        permutation is needed (since 4 < RATE = 8).

        Stack in:  [..., fs0, ..., fs15]
        Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
        """
        for i in range(4):
            self.emit_squeeze(t)
            # Rename from _fs_squeezed to a numbered output name.
            t.rename(f"_fs_ext4_{i}")

    # -----------------------------------------------------------------------
    # emit_sample_bits -- squeeze and extract low n bits
    # -----------------------------------------------------------------------

    def emit_sample_bits(self, t: KBTracker, n: int) -> None:
        """Squeeze one field element and extract its low n bits.

        The result is an integer in [0, 2^n).

        Stack in:  [..., fs0, ..., fs15]
        Stack out: [..., fs0', ..., fs15', bits]
        """
        if n < 1 or n > 20:
            raise RuntimeError(
                f"emit_sample_bits: n must be in [1, 20], got {n} "
                f"(n>20 has non-negligible bias for KoalaBear field)"
            )
        self.emit_squeeze(t)
        # _fs_squeezed is on top. Mask to low n bits: val % (2^n).
        mask = 1 << n
        t.raw_block(["_fs_squeezed"], "_fs_bits", lambda e: (
            e(_make_stack_op(op="push", value=_big_int_push(mask))),
            e(_make_stack_op(op="opcode", code="OP_MOD")),
        ))

    # -----------------------------------------------------------------------
    # emit_check_witness -- verify proof-of-work on sponge state
    # -----------------------------------------------------------------------

    def emit_check_witness(self, t: KBTracker, bits: int) -> None:
        """Absorb a witness element from the top of the stack, squeeze a
        challenge, and verify that the low `bits` bits of the challenge are
        all zero (proof-of-work check).

        Stack in:  [..., fs0, ..., fs15, witness]
        Stack out: [..., fs0', ..., fs15']   (witness consumed, assert on failure)
        """
        if bits < 1 or bits > 30:
            raise RuntimeError(
                f"emit_check_witness: bits must be in [1, 30] "
                f"(KoalaBear field is 31-bit), got {bits}"
            )

        # Absorb the witness.
        self.emit_observe(t)

        # Squeeze a challenge element.
        self.emit_squeeze(t)

        # Extract low `bits` bits and assert they are zero.
        mask = 1 << bits
        t.raw_block(["_fs_squeezed"], "_fs_pow_check", lambda e: (
            e(_make_stack_op(op="push", value=_big_int_push(mask))),
            e(_make_stack_op(op="opcode", code="OP_MOD")),
        ))
        # Assert _fs_pow_check == 0: push 0, check equal, assert.
        t.push_int("_fs_pow_zero", 0)
        t.raw_block(["_fs_pow_check", "_fs_pow_zero"], "", lambda e: (
            e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")),
            e(_make_stack_op(op="opcode", code="OP_VERIFY")),
        ))

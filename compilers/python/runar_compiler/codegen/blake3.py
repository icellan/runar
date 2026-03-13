"""BLAKE3 compression codegen for Bitcoin Script.

emit_blake3_compress: [chainingValue(32 BE), block(64 BE)] -> [hash(32 BE)]
emit_blake3_hash:     [message(<=64 BE)]                   -> [hash(32 BE)]

Architecture (same as sha256.py):
  - All 32-bit words stored as 4-byte little-endian during computation.
  - LE additions via BIN2NUM/NUM2BIN (13 ops per add32).
  - Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).
  - Non-byte-aligned rotations (12, 7) via LE->BE->rotrBE->BE->LE (31 ops).
  - BE<->LE conversion only at input unpack and output pack.

Stack layout during rounds:
  [m0..m15, v0..v15]  (all LE 4-byte values)
  v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.

Direct port of ``packages/runar-compiler/src/passes/blake3-codegen.ts``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    return StackOp(op=op, **kwargs)


def _make_push_value(*, kind: str, **kwargs) -> "PushValue":
    from runar_compiler.codegen.stack import PushValue
    return PushValue(kind=kind, **kwargs)


# ---------------------------------------------------------------------------
# BLAKE3 constants
# ---------------------------------------------------------------------------

BLAKE3_IV: list[int] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

MSG_PERMUTATION: list[int] = [
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
]

# Flags
CHUNK_START = 1
CHUNK_END = 2
ROOT = 8


def _u32_to_le(n: int) -> bytes:
    """Encode a uint32 as 4-byte little-endian."""
    return bytes([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff])


def _u32_to_be(n: int) -> bytes:
    """Encode a uint32 as 4-byte big-endian."""
    return bytes([(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])


# ---------------------------------------------------------------------------
# Precompute message schedule for all 7 rounds
# ---------------------------------------------------------------------------

def _compute_msg_schedule() -> list[list[int]]:
    """For each round, compute which original message word index is used at each
    position. Returns msg_schedule[round][position] = original msg word index."""
    schedule: list[list[int]] = []
    current = list(range(16))
    for _ in range(7):
        schedule.append(list(current))
        nxt = [0] * 16
        for i in range(16):
            nxt[i] = current[MSG_PERMUTATION[i]]
        current = nxt
    return schedule


MSG_SCHEDULE = _compute_msg_schedule()


# ---------------------------------------------------------------------------
# State word position tracker
# ---------------------------------------------------------------------------

class _StateTracker:
    """Tracks the stack depth of each of the 16 state words.
    Depth 0 = TOS. Message words sit below the state area at fixed positions."""

    def __init__(self) -> None:
        # Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
        self.positions: list[int] = [15 - i for i in range(16)]

    def depth(self, word_idx: int) -> int:
        return self.positions[word_idx]

    def on_roll_to_top(self, word_idx: int) -> None:
        """Update after rolling a state word from its current depth to TOS."""
        d = self.positions[word_idx]
        for j in range(16):
            if j != word_idx and self.positions[j] >= 0 and self.positions[j] < d:
                self.positions[j] += 1
        self.positions[word_idx] = 0


# ---------------------------------------------------------------------------
# Emitter with depth tracking
# ---------------------------------------------------------------------------

class _Emitter:
    """Emitter with depth tracking for BLAKE3 codegen."""

    def __init__(self, initial_depth: int) -> None:
        self.ops: list["StackOp"] = []
        self.depth = initial_depth
        self.alt_depth = 0

    def _e(self, sop: "StackOp") -> None:
        self.ops.append(sop)

    def e_raw(self, sop: "StackOp") -> None:
        """Push a raw op without depth tracking (for splicing pre-generated ops)."""
        self.ops.append(sop)

    def oc(self, code: str) -> None:
        self._e(_make_stack_op(op="opcode", code=code))

    def push_i(self, v: int) -> None:
        self._e(_make_stack_op(op="push", value=_make_push_value(kind="bigint", big_int=v)))
        self.depth += 1

    def push_b(self, v: bytes) -> None:
        self._e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_val=v)))
        self.depth += 1

    def dup(self) -> None:
        self._e(_make_stack_op(op="dup"))
        self.depth += 1

    def drop(self) -> None:
        self._e(_make_stack_op(op="drop"))
        self.depth -= 1

    def swap(self) -> None:
        self._e(_make_stack_op(op="swap"))

    def over(self) -> None:
        self._e(_make_stack_op(op="over"))
        self.depth += 1

    def nip(self) -> None:
        self._e(_make_stack_op(op="nip"))
        self.depth -= 1

    def rot(self) -> None:
        self._e(_make_stack_op(op="rot"))

    def pick(self, d: int) -> None:
        if d == 0:
            self.dup()
            return
        if d == 1:
            self.over()
            return
        self.push_i(d)
        self._e(_make_stack_op(op="pick", depth=d))

    def roll(self, d: int) -> None:
        if d == 0:
            return
        if d == 1:
            self.swap()
            return
        if d == 2:
            self.rot()
            return
        self.push_i(d)
        self._e(_make_stack_op(op="roll", depth=d))
        self.depth -= 1

    def to_alt(self) -> None:
        self.oc("OP_TOALTSTACK")
        self.depth -= 1
        self.alt_depth += 1

    def from_alt(self) -> None:
        self.oc("OP_FROMALTSTACK")
        self.depth += 1
        self.alt_depth -= 1

    def bin_op(self, code: str) -> None:
        self.oc(code)
        self.depth -= 1

    def uni_op(self, code: str) -> None:
        self.oc(code)

    def dup2(self) -> None:
        self.oc("OP_2DUP")
        self.depth += 2

    def split(self) -> None:
        self.oc("OP_SPLIT")

    def split4(self) -> None:
        self.push_i(4)
        self.split()

    def assert_depth(self, expected: int, msg: str) -> None:
        if self.depth != expected:
            raise RuntimeError(
                f"BLAKE3 codegen: {msg}. Expected depth {expected}, got {self.depth}"
            )

    # --- Byte reversal (only for BE<->LE conversion at boundaries) ---

    def reverse_bytes4(self) -> None:
        """Reverse 4 bytes on TOS: [abcd] -> [dcba]. Net: 0. 12 ops."""
        self.push_i(1); self.split()
        self.push_i(1); self.split()
        self.push_i(1); self.split()
        self.swap(); self.bin_op("OP_CAT")
        self.swap(); self.bin_op("OP_CAT")
        self.swap(); self.bin_op("OP_CAT")

    # --- LE <-> Numeric conversions (cheap -- no byte reversal) ---

    def le2num(self) -> None:
        """Convert 4-byte LE to unsigned script number. [le4] -> [num]. Net: 0. 3 ops."""
        self.push_b(bytes([0x00]))  # unsigned padding
        self.bin_op("OP_CAT")
        self.uni_op("OP_BIN2NUM")

    def num2le(self) -> None:
        """Convert script number to 4-byte LE (truncates to 32 bits). [num] -> [le4]. Net: 0. 5 ops."""
        self.push_i(5)
        self.bin_op("OP_NUM2BIN")   # 5-byte LE
        self.push_i(4)
        self.split()                # [4-byte LE, overflow+sign]
        self.drop()                 # discard overflow byte

    # --- LE arithmetic ---

    def add32(self) -> None:
        """[a(LE), b(LE)] -> [(a+b mod 2^32)(LE)]. Net: -1. 13 ops."""
        self.le2num()
        self.swap()
        self.le2num()
        self.bin_op("OP_ADD")
        self.num2le()

    def add_n(self, n: int) -> None:
        """Add N LE values. [v0..vN-1] (vN-1=TOS) -> [sum(LE)]. Net: -(N-1)."""
        if n < 2:
            return
        self.le2num()
        for _ in range(1, n):
            self.swap()
            self.le2num()
            self.bin_op("OP_ADD")
        self.num2le()

    # --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT (native BE byte-array shifts) ---

    def rotr_be(self, n: int) -> None:
        """ROTR(x, n) on BE 4-byte value. [x_BE] -> [rotated_BE]. Net: 0. 7 ops."""
        self.dup()                             # [x, x]
        self.push_i(n)
        self.bin_op("OP_RSHIFT")               # [x, x>>n]
        self.swap()                            # [x>>n, x]
        self.push_i(32 - n)
        self.bin_op("OP_LSHIFT")               # [x>>n, x<<(32-n)]
        self.bin_op("OP_OR")                   # [ROTR result]

    # --- ROTR on LE values ---

    def rotr16_le(self) -> None:
        """ROTR(x, 16) on LE 4-byte value. Net: 0. 4 ops.
        Swaps the two 16-bit halves: [b0,b1,b2,b3] -> [b2,b3,b0,b1]."""
        self.push_i(2)
        self.split()         # [lo2, hi2]
        self.swap()          # [hi2, lo2]
        self.bin_op("OP_CAT")  # [hi2||lo2]

    def rotr8_le(self) -> None:
        """ROTR(x, 8) on LE 4-byte value. Net: 0. 4 ops.
        [b0,b1,b2,b3] -> [b1,b2,b3,b0]."""
        self.push_i(1)
        self.split()         # [b0, b1b2b3]
        self.swap()          # [b1b2b3, b0]
        self.bin_op("OP_CAT")  # [b1b2b3||b0]

    def rotr_le_general(self, n: int) -> None:
        """ROTR(x, n) on LE 4-byte value (general, non-byte-aligned). Net: 0. 31 ops.
        Converts LE->BE, applies rotr_be, converts back."""
        self.reverse_bytes4()  # LE -> BE (12 ops)
        self.rotr_be(n)        # rotate on BE (7 ops)
        self.reverse_bytes4()  # BE -> LE (12 ops)

    def be_words_to_le(self, n: int) -> None:
        """Convert N x BE words on TOS to LE, preserving stack order."""
        for _ in range(n):
            self.reverse_bytes4()
            self.to_alt()
        for _ in range(n):
            self.from_alt()


# ---------------------------------------------------------------------------
# G function (quarter-round)
# ---------------------------------------------------------------------------

def _emit_half_g(em: _Emitter, rot_d: int, rot_b: int) -> None:
    """Emit one half of the G function.
    Stack entry: [a, b, c, d, m] (m on TOS) -- 5 items
    Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items
    Net depth: -1

    Operations:
      a' = a + b + m
      d' = (d ^ a') >>> rotD
      c' = c + d'
      b' = (original_b ^ c') >>> rotB
    """
    d0 = em.depth

    # Save original b for step 4 (b is at depth 3)
    em.pick(3)
    em.to_alt()

    # Step 1: a' = a + b + m
    # Stack: [a, b, c, d, m] -- a=4, b=3, c=2, d=1, m=0
    em.roll(3)    # [a, c, d, m, b]
    em.roll(4)    # [c, d, m, b, a]
    em.add_n(3)   # [c, d, a']
    em.assert_depth(d0 - 2, "halfG step1")

    # Step 2: d' = (d ^ a') >>> rotD
    # Stack: [c, d, a'] -- c=2, d=1, a'=0
    em.dup()           # [c, d, a', a']
    em.rot()           # [c, a', a', d]
    em.bin_op("OP_XOR")  # [c, a', (d^a')]
    if rot_d == 16:
        em.rotr16_le()
    elif rot_d == 8:
        em.rotr8_le()
    else:
        em.rotr_le_general(rot_d)
    em.assert_depth(d0 - 2, "halfG step2")

    # Step 3: c' = c + d'
    # Stack: [c, a', d']
    em.dup()           # [c, a', d', d']
    em.roll(3)         # [a', d', d', c]
    em.add32()         # [a', d', c']
    em.assert_depth(d0 - 2, "halfG step3")

    # Step 4: b' = (original_b ^ c') >>> rotB
    # Stack: [a', d', c']
    em.from_alt()       # [a', d', c', b]
    em.over()           # [a', d', c', b, c']
    em.bin_op("OP_XOR")  # [a', d', c', (b^c')]
    em.rotr_le_general(rot_b)
    # Stack: [a', d', c', b']
    em.assert_depth(d0 - 1, "halfG step4")

    # Rearrange: [a', d', c', b'] -> [a', b', c', d']
    em.swap()          # [a', d', b', c']
    em.rot()           # [a', b', c', d']
    em.assert_depth(d0 - 1, "halfG done")


def _emit_g(em: _Emitter) -> None:
    """Emit the full G function (quarter-round).
    Stack entry: [a, b, c, d, mx, my] (my on TOS) -- 6 items
    Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items
    Net depth: -2
    """
    d0 = em.depth

    # Save my to alt for phase 2
    em.to_alt()       # [a, b, c, d, mx]

    # Phase 1: first half with mx, ROTR(16) and ROTR(12)
    _emit_half_g(em, 16, 12)
    em.assert_depth(d0 - 2, "G phase1")

    # Restore my for phase 2
    em.from_alt()     # [a', b', c', d', my]
    em.assert_depth(d0 - 1, "G before phase2")

    # Phase 2: second half with my, ROTR(8) and ROTR(7)
    _emit_half_g(em, 8, 7)
    em.assert_depth(d0 - 2, "G done")


# ---------------------------------------------------------------------------
# G call with state management
# ---------------------------------------------------------------------------

def _emit_g_call(
    em: _Emitter,
    tracker: _StateTracker,
    ai: int, bi: int, ci: int, di: int,
    mx_orig_idx: int, my_orig_idx: int,
) -> None:
    """Emit a single G call with state word roll management.

    Rolls 4 state words (ai, bi, ci, di) to top, picks 2 message words,
    runs G, then updates tracker.
    """
    d0 = em.depth

    # Roll 4 state words to top: a, b, c, d (d ends up as TOS)
    for idx in [ai, bi, ci, di]:
        em.roll(tracker.depth(idx))
        tracker.on_roll_to_top(idx)

    # Pick message words from below the 16 state word area
    # m[i] is at depth: 16 (state words) + (15 - i)
    em.pick(16 + (15 - mx_orig_idx))
    em.pick(16 + (15 - my_orig_idx) + 1)  # +1 for mx just pushed
    em.assert_depth(d0 + 2, "before G")

    # Run G: consumes 6 (a, b, c, d, mx, my), produces 4 (a', b', c', d')
    _emit_g(em)
    em.assert_depth(d0, "after G")

    # Update tracker: result words at depths 0-3
    tracker.positions[ai] = 3
    tracker.positions[bi] = 2
    tracker.positions[ci] = 1
    tracker.positions[di] = 0


# ---------------------------------------------------------------------------
# Full compression ops generator
# ---------------------------------------------------------------------------

def _generate_compress_ops() -> "list[StackOp]":
    """Generate BLAKE3 compression ops.
    Stack entry: [..., chainingValue(32 BE), block(64 BE)] -- 2 items
    Stack exit:  [..., hash(32 BE)] -- 1 item
    Net depth: -1
    """
    em = _Emitter(2)

    # ================================================================
    # Phase 1: Unpack block into 16 LE message words
    # ================================================================
    # Stack: [chainingValue(32 BE), block(64 BE)]
    # Split block into 16 x 4-byte BE words, convert to LE
    for _ in range(15):
        em.split4()
    em.assert_depth(17, "after block unpack")  # 16 block words + 1 chainingValue
    em.be_words_to_le(16)
    em.assert_depth(17, "after block LE convert")
    # Stack: [CV, m0(LE), m1(LE), ..., m15(LE)] -- m0 deepest of msg words, m15 TOS

    # ================================================================
    # Phase 2: Initialize 16-word state on top of message words
    # ================================================================
    # Move CV to alt (it's below the 16 msg words, at depth 16)
    em.roll(16)
    em.to_alt()
    em.assert_depth(16, "after CV to alt")
    # Stack: [m0, m1, ..., m15]  Alt: [CV]

    # Get CV back, split into 8 LE words, place on top of msg
    em.from_alt()
    em.assert_depth(17, "after CV from alt")
    for _ in range(7):
        em.split4()
    em.assert_depth(24, "after cv unpack")
    em.be_words_to_le(8)
    em.assert_depth(24, "after cv LE convert")
    # Stack: [m0..m15, cv0(LE)..cv7(LE)]

    # v[0..7] = chaining value (already on stack)
    # v[8..11] = IV[0..3]
    for i in range(4):
        em.push_b(_u32_to_le(BLAKE3_IV[i]))
    em.assert_depth(28, "after IV push")

    # v[12] = counter_low = 0, v[13] = counter_high = 0
    em.push_b(_u32_to_le(0))
    em.push_b(_u32_to_le(0))
    # v[14] = block_len = 64
    em.push_b(_u32_to_le(64))
    # v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
    em.push_b(_u32_to_le(CHUNK_START | CHUNK_END | ROOT))
    em.assert_depth(32, "after state init")

    # Stack: [m0..m15(bottom), v0..v15(top)] -- v15=TOS, m0=deepest

    # ================================================================
    # Phase 3: 7 rounds of G function calls
    # ================================================================
    tracker = _StateTracker()

    for round_idx in range(7):
        s = MSG_SCHEDULE[round_idx]

        # Column mixing
        _emit_g_call(em, tracker, 0, 4, 8, 12, s[0], s[1])
        _emit_g_call(em, tracker, 1, 5, 9, 13, s[2], s[3])
        _emit_g_call(em, tracker, 2, 6, 10, 14, s[4], s[5])
        _emit_g_call(em, tracker, 3, 7, 11, 15, s[6], s[7])

        # Diagonal mixing
        _emit_g_call(em, tracker, 0, 5, 10, 15, s[8], s[9])
        _emit_g_call(em, tracker, 1, 6, 11, 12, s[10], s[11])
        _emit_g_call(em, tracker, 2, 7, 8, 13, s[12], s[13])
        _emit_g_call(em, tracker, 3, 4, 9, 14, s[14], s[15])

    em.assert_depth(32, "after all rounds")

    # ================================================================
    # Phase 4: Output -- hash[i] = state[i] XOR state[i+8], for i=0..7
    # ================================================================

    # Reorder state words to canonical positions using alt stack
    for i in range(15, -1, -1):
        d = tracker.depth(i)
        em.roll(d)
        tracker.on_roll_to_top(i)
        em.to_alt()
        # Remaining words shift up because one was removed from main
        for j in range(16):
            if j != i and tracker.positions[j] >= 0:
                tracker.positions[j] -= 1
        tracker.positions[i] = -1

    # Pop to get canonical order: [v0(bottom)..v15(TOS)]
    for _ in range(16):
        em.from_alt()
    em.assert_depth(32, "after canonical reorder")

    # State: [m0..m15, v0(bottom)..v15(TOS)], canonical order.
    # XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
    # Process top-down: v15^v7, v14^v6, ..., v8^v0. Send each result to alt.
    for k in range(8):
        em.roll(8 - k)       # bring v[7-k] to TOS (past v[15-k] and remaining)
        em.bin_op("OP_XOR")  # h[7-k] = v[7-k] ^ v[15-k]
        em.to_alt()          # result to alt; main shrinks by 2
    em.assert_depth(16, "after XOR pairs")
    # Alt (bottom->top): h7, h6, h5, h4, h3, h2, h1, h0. Main: [m0..m15].

    # Pop results to main: h0 first (LIFO), then h1, ..., h7
    for _ in range(8):
        em.from_alt()
    em.assert_depth(24, "after XOR results restored")
    # Main: [m0..m15, h0, h1, ..., h7] h7=TOS

    # Pack into 32-byte BE result: h0_BE || h1_BE || ... || h7_BE
    em.reverse_bytes4()  # h7 -> h7_BE
    for _ in range(1, 8):
        em.swap()           # bring h[7-i] (LE) to TOS
        em.reverse_bytes4()  # -> BE
        em.swap()           # [new_BE, accumulated]
        em.bin_op("OP_CAT")  # new_BE || accumulated
    em.assert_depth(17, "after hash pack")

    # Drop 16 message words
    for _ in range(16):
        em.swap()
        em.drop()
    em.assert_depth(1, "compress final")

    return em.ops


# Cache the ops since they're identical every time
_blake3_compress_ops_cache: "list[StackOp] | None" = None


def _get_compress_ops() -> "list[StackOp]":
    global _blake3_compress_ops_cache
    if _blake3_compress_ops_cache is None:
        _blake3_compress_ops_cache = _generate_compress_ops()
    return _blake3_compress_ops_cache


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def emit_blake3_compress(emit: Callable[["StackOp"], None]) -> None:
    """Emit BLAKE3 single-block compression in Bitcoin Script.
    Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
    Stack on exit:  [..., hash(32 BE)]
    Net depth: -1
    """
    for op in _get_compress_ops():
        emit(op)


def emit_blake3_hash(emit: Callable[["StackOp"], None]) -> None:
    """Emit BLAKE3 hash for a message up to 64 bytes.
    Stack on entry: [..., message(<=64 BE)]
    Stack on exit:  [..., hash(32 BE)]
    Net depth: 0

    Applies zero-padding and uses IV as chaining value.
    """
    em = _Emitter(1)

    # Pad message to 64 bytes (BLAKE3 zero-pads, no length suffix)
    em.oc("OP_SIZE"); em.depth += 1  # [message, len]
    em.push_i(64)
    em.swap()
    em.bin_op("OP_SUB")    # [message, 64-len]
    em.push_i(0)
    em.swap()
    em.bin_op("OP_NUM2BIN")  # [message, zeros]
    em.bin_op("OP_CAT")    # [paddedMessage(64)]

    # Push IV as 32-byte BE chaining value
    iv_bytes = bytearray(32)
    for i in range(8):
        be = _u32_to_be(BLAKE3_IV[i])
        iv_bytes[i * 4: i * 4 + 4] = be
    em.push_b(bytes(iv_bytes))
    em.swap()  # [IV(32 BE), paddedMessage(64 BE)]

    # Splice compression ops
    compress_ops = _get_compress_ops()
    for op in compress_ops:
        em.e_raw(op)
    em.depth = 1

    em.assert_depth(1, "blake3Hash final")
    for op in em.ops:
        emit(op)

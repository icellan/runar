"""Stack IR to Bitcoin Script emission.

Converts Stack IR (list of ``StackOp``) to hex-encoded Bitcoin Script and
human-readable ASM.

Port of ``compilers/go/codegen/emit.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runar_compiler.codegen.stack import StackOp, StackMethod, PushValue


# ---------------------------------------------------------------------------
# Opcode table -- complete BSV opcode set
# ---------------------------------------------------------------------------

OPCODES: dict[str, int] = {
    "OP_0":                   0x00,
    "OP_FALSE":               0x00,
    "OP_PUSHDATA1":           0x4c,
    "OP_PUSHDATA2":           0x4d,
    "OP_PUSHDATA4":           0x4e,
    "OP_1NEGATE":             0x4f,
    "OP_1":                   0x51,
    "OP_TRUE":                0x51,
    "OP_2":                   0x52,
    "OP_3":                   0x53,
    "OP_4":                   0x54,
    "OP_5":                   0x55,
    "OP_6":                   0x56,
    "OP_7":                   0x57,
    "OP_8":                   0x58,
    "OP_9":                   0x59,
    "OP_10":                  0x5a,
    "OP_11":                  0x5b,
    "OP_12":                  0x5c,
    "OP_13":                  0x5d,
    "OP_14":                  0x5e,
    "OP_15":                  0x5f,
    "OP_16":                  0x60,
    "OP_NOP":                 0x61,
    "OP_IF":                  0x63,
    "OP_NOTIF":               0x64,
    "OP_ELSE":                0x67,
    "OP_ENDIF":               0x68,
    "OP_VERIFY":              0x69,
    "OP_RETURN":              0x6a,
    "OP_TOALTSTACK":          0x6b,
    "OP_FROMALTSTACK":        0x6c,
    "OP_2DROP":               0x6d,
    "OP_2DUP":                0x6e,
    "OP_3DUP":                0x6f,
    "OP_2OVER":               0x70,
    "OP_2ROT":                0x71,
    "OP_2SWAP":               0x72,
    "OP_IFDUP":               0x73,
    "OP_DEPTH":               0x74,
    "OP_DROP":                0x75,
    "OP_DUP":                 0x76,
    "OP_NIP":                 0x77,
    "OP_OVER":                0x78,
    "OP_PICK":                0x79,
    "OP_ROLL":                0x7a,
    "OP_ROT":                 0x7b,
    "OP_SWAP":                0x7c,
    "OP_TUCK":                0x7d,
    "OP_CAT":                 0x7e,
    "OP_SPLIT":               0x7f,
    "OP_NUM2BIN":             0x80,
    "OP_BIN2NUM":             0x81,
    "OP_SIZE":                0x82,
    "OP_INVERT":              0x83,
    "OP_AND":                 0x84,
    "OP_OR":                  0x85,
    "OP_XOR":                 0x86,
    "OP_EQUAL":               0x87,
    "OP_EQUALVERIFY":         0x88,
    "OP_1ADD":                0x8b,
    "OP_1SUB":                0x8c,
    "OP_NEGATE":              0x8f,
    "OP_ABS":                 0x90,
    "OP_NOT":                 0x91,
    "OP_0NOTEQUAL":           0x92,
    "OP_ADD":                 0x93,
    "OP_SUB":                 0x94,
    "OP_MUL":                 0x95,
    "OP_DIV":                 0x96,
    "OP_MOD":                 0x97,
    "OP_LSHIFT":              0x98,
    "OP_RSHIFT":              0x99,
    "OP_BOOLAND":             0x9a,
    "OP_BOOLOR":              0x9b,
    "OP_NUMEQUAL":            0x9c,
    "OP_NUMEQUALVERIFY":      0x9d,
    "OP_NUMNOTEQUAL":         0x9e,
    "OP_LESSTHAN":            0x9f,
    "OP_GREATERTHAN":         0xa0,
    "OP_LESSTHANOREQUAL":     0xa1,
    "OP_GREATERTHANOREQUAL":  0xa2,
    "OP_MIN":                 0xa3,
    "OP_MAX":                 0xa4,
    "OP_WITHIN":              0xa5,
    "OP_RIPEMD160":           0xa6,
    "OP_SHA1":                0xa7,
    "OP_SHA256":              0xa8,
    "OP_HASH160":             0xa9,
    "OP_HASH256":             0xaa,
    "OP_CODESEPARATOR":       0xab,
    "OP_CHECKSIG":            0xac,
    "OP_CHECKSIGVERIFY":      0xad,
    "OP_CHECKMULTISIG":       0xae,
    "OP_CHECKMULTISIGVERIFY": 0xaf,
}


# ---------------------------------------------------------------------------
# ConstructorSlot
# ---------------------------------------------------------------------------

@dataclass
class ConstructorSlot:
    """Records the byte offset of a constructor parameter placeholder."""
    param_index: int = 0
    byte_offset: int = 0


# ---------------------------------------------------------------------------
# EmitResult
# ---------------------------------------------------------------------------

@dataclass
class EmitResult:
    """Holds the outputs of the emission pass."""
    script_hex: str = ""
    script_asm: str = ""
    constructor_slots: list[ConstructorSlot] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Emit context
# ---------------------------------------------------------------------------

class _EmitContext:
    def __init__(self) -> None:
        self.hex_parts: list[str] = []
        self.asm_parts: list[str] = []
        self.byte_length: int = 0
        self.constructor_slots: list[ConstructorSlot] = []

    def append_hex(self, h: str) -> None:
        self.hex_parts.append(h)
        self.byte_length += len(h) // 2

    def append_asm(self, a: str) -> None:
        self.asm_parts.append(a)

    def emit_opcode(self, name: str) -> None:
        b = OPCODES.get(name)
        if b is None:
            raise ValueError(f"unknown opcode: {name}")
        self.append_hex(f"{b:02x}")
        self.append_asm(name)

    def emit_push(self, value: PushValue) -> None:
        h, a = encode_push_value(value)
        self.append_hex(h)
        self.append_asm(a)

    def emit_placeholder(self, param_index: int) -> None:
        byte_offset = self.byte_length
        self.append_hex("00")  # OP_0 placeholder byte
        self.append_asm("OP_0")
        self.constructor_slots.append(ConstructorSlot(
            param_index=param_index,
            byte_offset=byte_offset,
        ))

    def get_hex(self) -> str:
        return "".join(self.hex_parts)

    def get_asm(self) -> str:
        return " ".join(self.asm_parts)


# ---------------------------------------------------------------------------
# Script number encoding
# ---------------------------------------------------------------------------

def encode_script_number(n: int) -> bytes:
    """Encode an integer as a Bitcoin Script number.

    Little-endian, sign-magnitude with sign bit in MSB.
    """
    if n == 0:
        return b""

    negative = n < 0
    abs_n = abs(n)

    result = bytearray()
    while abs_n > 0:
        result.append(abs_n & 0xFF)
        abs_n >>= 8

    last_byte = result[-1]
    if last_byte & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0x00)
    elif negative:
        result[-1] = last_byte | 0x80

    return bytes(result)


# ---------------------------------------------------------------------------
# Push data encoding
# ---------------------------------------------------------------------------

def encode_push_data(data: bytes) -> bytes:
    """Encode raw bytes as a Bitcoin Script push-data operation."""
    length = len(data)

    if length == 0:
        return bytes([0x00])  # OP_0

    # MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16, 0x81 must use OP_1NEGATE.
    # Note: 0x00 is NOT converted to OP_0 because OP_0 pushes empty [] not [0x00].
    if length == 1:
        b = data[0]
        if 1 <= b <= 16:
            return bytes([0x50 + b])  # OP_1 through OP_16
        if b == 0x81:
            return bytes([0x4F])  # OP_1NEGATE

    if 1 <= length <= 75:
        return bytes([length]) + data

    if 76 <= length <= 255:
        return bytes([0x4C, length]) + data  # OP_PUSHDATA1

    if 256 <= length <= 65535:
        return bytes([0x4D, length & 0xFF, (length >> 8) & 0xFF]) + data  # OP_PUSHDATA2

    # OP_PUSHDATA4
    return bytes([
        0x4E,
        length & 0xFF,
        (length >> 8) & 0xFF,
        (length >> 16) & 0xFF,
        (length >> 24) & 0xFF,
    ]) + data


# ---------------------------------------------------------------------------
# Push value encoding
# ---------------------------------------------------------------------------

def encode_push_value(value: PushValue) -> tuple[str, str]:
    """Convert a PushValue to (hex_str, asm_str)."""
    if value.kind == "bool":
        if value.bool_val:
            return "51", "OP_TRUE"
        return "00", "OP_FALSE"

    if value.kind == "bigint":
        return encode_push_big_int(value.big_int if value.big_int is not None else 0)

    if value.kind == "bytes":
        data = value.bytes_val if value.bytes_val is not None else b""
        encoded = encode_push_data(data)
        h = encoded.hex()
        if len(data) == 0:
            return h, "OP_0"
        return h, f"<{data.hex()}>"

    # default
    return "00", "OP_0"


def encode_push_big_int(n: int) -> tuple[str, str]:
    """Encode an int as a push operation, using small-integer opcodes where possible."""
    if n == 0:
        return "00", "OP_0"

    if n == -1:
        return "4f", "OP_1NEGATE"

    if 0 < n <= 16:
        opcode = 0x50 + n
        return f"{opcode:02x}", f"OP_{n}"

    num_bytes = encode_script_number(n)
    encoded = encode_push_data(num_bytes)
    return encoded.hex(), f"<{num_bytes.hex()}>"


# ---------------------------------------------------------------------------
# Emit a single StackOp
# ---------------------------------------------------------------------------

def _emit_stack_op(op: StackOp, ctx: _EmitContext) -> None:
    if op.op == "push":
        ctx.emit_push(op.value)
    elif op.op == "dup":
        ctx.emit_opcode("OP_DUP")
    elif op.op == "swap":
        ctx.emit_opcode("OP_SWAP")
    elif op.op == "roll":
        ctx.emit_opcode("OP_ROLL")
    elif op.op == "pick":
        ctx.emit_opcode("OP_PICK")
    elif op.op == "drop":
        ctx.emit_opcode("OP_DROP")
    elif op.op == "nip":
        ctx.emit_opcode("OP_NIP")
    elif op.op == "over":
        ctx.emit_opcode("OP_OVER")
    elif op.op == "rot":
        ctx.emit_opcode("OP_ROT")
    elif op.op == "tuck":
        ctx.emit_opcode("OP_TUCK")
    elif op.op == "opcode":
        ctx.emit_opcode(op.code)
    elif op.op == "if":
        _emit_if(op.then, op.else_ops, ctx)
    elif op.op == "placeholder":
        ctx.emit_placeholder(op.param_index)
    else:
        raise ValueError(f"unknown stack op: {op.op}")


def _emit_if(then_ops: list[StackOp], else_ops: list[StackOp], ctx: _EmitContext) -> None:
    """Emit an OP_IF / OP_ELSE / OP_ENDIF structure."""
    ctx.emit_opcode("OP_IF")

    for op in then_ops:
        _emit_stack_op(op, ctx)

    if else_ops:
        ctx.emit_opcode("OP_ELSE")
        for op in else_ops:
            _emit_stack_op(op, ctx)

    ctx.emit_opcode("OP_ENDIF")


# ---------------------------------------------------------------------------
# Method dispatch
# ---------------------------------------------------------------------------

def _emit_method_dispatch(methods: list[StackMethod], ctx: _EmitContext) -> None:
    """Emit a method selector preamble for multi-method contracts."""
    from runar_compiler.codegen.stack import big_int_push

    for i, method in enumerate(methods):
        is_last = i == len(methods) - 1

        if not is_last:
            ctx.emit_opcode("OP_DUP")
            ctx.emit_push(big_int_push(i))
            ctx.emit_opcode("OP_NUMEQUAL")
            ctx.emit_opcode("OP_IF")
            ctx.emit_opcode("OP_DROP")
        else:
            ctx.emit_opcode("OP_DROP")

        for op in method.ops:
            _emit_stack_op(op, ctx)

        if not is_last:
            ctx.emit_opcode("OP_ELSE")

    # Close all nested OP_IF/OP_ELSE blocks
    for _ in range(len(methods) - 1):
        ctx.emit_opcode("OP_ENDIF")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def emit(methods: list[StackMethod]) -> EmitResult:
    """Convert a list of StackMethods into Bitcoin Script hex and ASM.

    For contracts with multiple public methods, generates a method dispatch
    preamble using OP_IF/OP_ELSE chains.

    Note: peephole optimization (VERIFY combinations, SWAP elimination) is
    handled by ``optimize_stack_ops`` in optimizer.py, which runs before emit.
    """
    ctx = _EmitContext()

    # Filter to public methods (exclude constructor)
    public_methods = [m for m in methods if m.name != "constructor"]

    if not public_methods:
        return EmitResult(script_hex="", script_asm="", constructor_slots=[])

    if len(public_methods) == 1:
        # Single public method -- no dispatch needed
        for op in public_methods[0].ops:
            _emit_stack_op(op, ctx)
    else:
        # Multiple public methods -- emit dispatch table
        _emit_method_dispatch(public_methods, ctx)

    return EmitResult(
        script_hex=ctx.get_hex(),
        script_asm=ctx.get_asm(),
        constructor_slots=ctx.constructor_slots,
    )


def emit_method(method: StackMethod) -> EmitResult:
    """Emit a single method's ops.  Useful for testing."""
    ctx = _EmitContext()
    for op in method.ops:
        _emit_stack_op(op, ctx)
    return EmitResult(
        script_hex=ctx.get_hex(),
        script_asm=ctx.get_asm(),
        constructor_slots=ctx.constructor_slots,
    )

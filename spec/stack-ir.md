# Rúnar Stack IR Specification

**Version:** 0.1.0
**Status:** Draft

This document specifies the Stack IR, the low-level intermediate representation that bridges ANF IR and final Bitcoin Script output. The Stack IR makes stack positions explicit and maps named values to concrete stack manipulation sequences.

---

## 1. Overview

The ANF IR uses named temporaries (e.g., `t0`, `t1`). Bitcoin Script has no names -- only a stack and an alt-stack. The Stack IR phase resolves this mismatch by:

1. Mapping each named value to a stack position.
2. Inserting explicit stack manipulation instructions (DUP, SWAP, ROLL, etc.) to move values into position for each operation.
3. Cleaning up values that are no longer needed (DROP, NIP).

The Stack IR is a linear sequence of **Stack IR instructions**, each of which maps directly to one or more Bitcoin Script opcodes.

---

## 2. Stack Model

### 2.1 Main Stack

The main stack is indexed from the top:

```
Position 0:  top of stack
Position 1:  second from top
Position 2:  third from top
...
Position n:  bottom of stack
```

### 2.2 Alt Stack

The alt-stack is a secondary stack used for temporary storage. Values can be moved between the main stack and alt-stack using `OP_TOALTSTACK` and `OP_FROMALTSTACK`.

### 2.3 Stack State

At any point in the Stack IR, the **stack state** is a list of **value labels** indicating what is at each position:

```
stack_state: [label_top, label_1, label_2, ...]
```

Value labels correspond to ANF temporary names, parameter names, or property names. The stack state is tracked statically by the compiler -- it is not represented at runtime.

---

## 3. Stack IR Instructions

### 3.1 Data Instructions

| Instruction | Stack Effect | Description |
|---|---|---|
| `PUSH_INT(n)` | `[] -> [n]` | Push a Script number |
| `PUSH_BOOL(b)` | `[] -> [b]` | Push OP_TRUE or OP_FALSE |
| `PUSH_BYTES(hex)` | `[] -> [bytes]` | Push raw bytes |
| `PUSH_PROP(name)` | `[] -> [value]` | Push a contract property value |

### 3.2 Stack Manipulation Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `DUP` | `[a] -> [a, a]` | `OP_DUP` |
| `DROP` | `[a] -> []` | `OP_DROP` |
| `NIP` | `[a, b] -> [a]` | `OP_NIP` |
| `SWAP` | `[a, b] -> [b, a]` | `OP_SWAP` |
| `OVER` | `[a, b] -> [a, b, a]` | `OP_OVER` (copy item 1 to top) |
| `ROT` | `[a, b, c] -> [b, c, a]` | `OP_ROT` (rotate top 3) |
| `TUCK` | `[a, b] -> [b, a, b]` | `OP_TUCK` (copy top behind item 1) |
| `PICK(n)` | `[...] -> [..., stack[n]]` | `<n> OP_PICK` |
| `ROLL(n)` | `[...] -> [...]` | `<n> OP_ROLL` (move item n to top) |
| `DEPTH` | `[] -> [depth]` | `OP_DEPTH` |
| `2DUP` | `[a, b] -> [a, b, a, b]` | `OP_2DUP` |
| `2DROP` | `[a, b] -> []` | `OP_2DROP` |
| `2SWAP` | `[a, b, c, d] -> [c, d, a, b]` | `OP_2SWAP` |
| `TOALT` | `[a] -> []` (alt: `-> [a]`) | `OP_TOALTSTACK` |
| `FROMALT` | `[]` (alt: `[a] ->`) `-> [a]` | `OP_FROMALTSTACK` |

### 3.3 Generic Opcode Wrapper

All arithmetic, comparison, cryptographic, byte string, and most flow control operations are represented using a single generic `OpcodeOp` wrapper:

```typescript
{ op: 'opcode', code: string }  // e.g. { op: 'opcode', code: 'OP_ADD' }
```

This means the Stack IR has only **13 structured operation types** (see Section 3.5), and the `opcode` variant covers everything else. The following tables show common opcodes that appear as `{ op: 'opcode', code: '...' }`:

#### Arithmetic Opcodes

| `code` value | Stack Effect | Description |
|---|---|---|
| `OP_ADD` | `[a, b] -> [a+b]` | Integer addition |
| `OP_SUB` | `[a, b] -> [a-b]` | Integer subtraction |
| `OP_MUL` | `[a, b] -> [a*b]` | Integer multiplication |
| `OP_DIV` | `[a, b] -> [a/b]` | Integer division |
| `OP_MOD` | `[a, b] -> [a%b]` | Integer modulo |
| `OP_NEGATE` | `[a] -> [-a]` | Negate |
| `OP_ABS` | `[a] -> [abs(a)]` | Absolute value |
| `OP_NOT` | `[a] -> [!a]` | Boolean NOT |

#### Comparison Opcodes

| `code` value | Stack Effect | Description |
|---|---|---|
| `OP_EQUAL` | `[a, b] -> [a==b]` | Byte-for-byte equality |
| `OP_NUMEQUAL` | `[a, b] -> [a==b]` | Numeric equality |
| `OP_LESSTHAN` | `[a, b] -> [a<b]` | Less than |
| `OP_LESSTHANOREQUAL` | `[a, b] -> [a<=b]` | Less than or equal |
| `OP_GREATERTHAN` | `[a, b] -> [a>b]` | Greater than |
| `OP_GREATERTHANOREQUAL` | `[a, b] -> [a>=b]` | Greater than or equal |
| `OP_VERIFY` | `[cond] -> []` | Fail if falsy |

Note: `!==` is compiled as `OP_NUMEQUAL OP_NOT` (two separate `opcode` ops) for bigint, or `OP_EQUAL OP_NOT` for ByteString. There is no single `OP_NUMNOTEQUAL` used.

#### Crypto Opcodes

| `code` value | Stack Effect | Description |
|---|---|---|
| `OP_SHA256` | `[data] -> [hash]` | SHA-256 hash |
| `OP_RIPEMD160` | `[data] -> [hash]` | RIPEMD-160 hash |
| `OP_HASH160` | `[data] -> [hash]` | SHA-256 then RIPEMD-160 |
| `OP_HASH256` | `[data] -> [hash]` | Double SHA-256 |
| `OP_CHECKSIG` | `[sig, pubKey] -> [bool]` | Verify ECDSA signature |
| `OP_CHECKMULTISIG` | `[sigs..., n, pubKeys..., m] -> [bool]` | Verify m-of-n multi-signature |

#### Byte String Opcodes

| `code` value | Stack Effect | Description |
|---|---|---|
| `OP_CAT` | `[a, b] -> [a\|\|b]` | Concatenate |
| `OP_SPLIT` | `[data, pos] -> [left, right]` | Split at position |
| `OP_SIZE` | `[data] -> [data, size]` | Push byte length (preserves data) |

#### Flow Control Opcodes

| `code` value | Stack Effect | Description |
|---|---|---|
| `OP_RETURN` | -- | Mark output as unspendable |

### 3.4 Structured IF Operation

`IF`/`ELSE`/`ENDIF` are **not** three separate instructions. They are represented as a single structured `IfOp`:

```typescript
{ op: 'if', then: StackOp[], else?: StackOp[] }
```

The condition is consumed from the top of the stack. If the condition is truthy, the `then` branch executes; otherwise the optional `else` branch executes. Both branches must produce the same stack depth.

### 3.5 Complete StackOp Union

The Stack IR uses a discriminated union with exactly **13 variants**:

| Variant | `op` tag | Key fields | Description |
|---|---|---|---|
| `PushOp` | `'push'` | `value: Uint8Array \| bigint \| boolean` | Push a value |
| `DupOp` | `'dup'` | — | Duplicate top |
| `SwapOp` | `'swap'` | — | Swap top two |
| `RollOp` | `'roll'` | `depth: number` | Move item at depth to top |
| `PickOp` | `'pick'` | `depth: number` | Copy item at depth to top |
| `DropOp` | `'drop'` | — | Remove top |
| `OpcodeOp` | `'opcode'` | `code: string` | Generic Bitcoin Script opcode |
| `IfOp` | `'if'` | `then: StackOp[], else?: StackOp[]` | Structured conditional |
| `NipOp` | `'nip'` | — | Remove second-from-top |
| `OverOp` | `'over'` | — | Copy second-from-top to top |
| `RotOp` | `'rot'` | — | Rotate top 3 |
| `TuckOp` | `'tuck'` | — | Copy top behind second |
| `PlaceholderOp` | `'placeholder'` | `paramIndex: number, paramName: string` | Constructor parameter slot |

> **Note:** The `depth` field on `RollOp` and `PickOp` is informational only. The actual depth value is pushed as a separate `PushOp` by the stack lowerer before the `RollOp`/`PickOp`, and the emitter ignores the `depth` field when generating Bitcoin Script.

### 3.8 Placeholder Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `PLACEHOLDER(paramIndex, paramName)` | `[] -> [value]` | Push data (replaced at deployment) |

The `PLACEHOLDER` instruction represents a constructor parameter slot in the compiled script. During compilation, the emitter records the byte offset of each placeholder. At deployment time, the SDK replaces each placeholder with the actual serialized constructor argument value.

| Field | Type | Description |
|---|---|---|
| `paramIndex` | `number` | Index of the constructor parameter (0-based) |
| `paramName` | `string` | Name of the constructor parameter (for diagnostics) |

---

## 4. Stack Scheduling

Stack scheduling is the process of converting ANF IR bindings into Stack IR instructions with minimal overhead from stack manipulation. This is the most performance-critical phase of compilation.

### 4.1 Value Lifetime Analysis

For each ANF temporary, compute:

- **Definition point**: The binding index where the value is created.
- **Use points**: All binding indices where the value is consumed.
- **Last use**: The maximum use point.
- **Use count**: Number of times the value is referenced.

### 4.2 Stack Allocation Strategy

The scheduler maintains a virtual stack and processes bindings in order:

```
for each binding t_i in method body:
    1. Arrange operands on top of stack (using SWAP/ROLL/PICK)
    2. Emit the operation instruction
    3. Result is now on top of stack, labeled t_i
    4. Drop any values whose last use was in this binding (cleanup)
```

### 4.3 Operand Arrangement

When an operation needs operands `[a, b]` on top of the stack (a on top, b below):

1. If `a` is at position 0 and `b` is at position 1: no action needed.
2. If `a` is at position 0 and `b` is at position `n > 1`: `ROLL(n)` to bring `b` up, then `SWAP`.
3. If `a` is at position `n` and `b` is at position 0: `ROLL(n)`.
4. General case: bring both to the top using ROLL instructions.

### 4.4 Optimization: Minimizing DUP/SWAP/ROLL

The scheduler should prefer:

1. **DUP** over **PICK(0)** (1 byte vs 2 bytes).
2. **SWAP** over **ROLL(1)** (1 byte vs 2 bytes).
3. **ROT** over **ROLL(2)** (1 byte vs 2 bytes).
4. **OVER** over **PICK(1)** (1 byte vs 2 bytes).
5. **NIP** over **SWAP DROP** (1 byte vs 2 bytes).
6. **TUCK** when inserting a copy below the top.

### 4.5 Register Pressure Heuristic

When a value is used multiple times and is deep in the stack, consider:

1. **DUP at definition**: If the value will be used twice and the second use is soon, DUP immediately and keep both copies.
2. **TOALTSTACK**: If a value will not be used for many instructions, move it to the alt-stack and retrieve it later with FROMALTSTACK.
3. **Re-computation**: If the value is cheap to compute (e.g., load a parameter), it may be cheaper to recompute than to ROLL from a deep position.

---

## 5. Static Stack Depth Analysis

The compiler MUST statically verify that the stack depth never exceeds the limit.

### 5.1 Depth Limit

The maximum allowable stack depth is **800 items**. This provides a safety margin below the BSV consensus limit.

### 5.2 Analysis Rules

Structured ops (the 13 `StackOp` variants):

```
depth_after(push)          = depth_before + 1
depth_after(drop)          = depth_before - 1
depth_after(dup)           = depth_before + 1
depth_after(swap)          = depth_before      (no change)
depth_after(roll(n))       = depth_before      (no change)
depth_after(pick(n))       = depth_before + 1
depth_after(nip)           = depth_before - 1
depth_after(over)          = depth_before + 1
depth_after(rot)           = depth_before      (no change)
depth_after(tuck)          = depth_before + 1
depth_after(placeholder)   = depth_before + 1
depth_after(if)            = see Branch Analysis (Section 5.3)
```

Generic opcode wrapper (`{ op: 'opcode', code: ... }`):

```
depth_after(OP_ADD)        = depth_before - 1  (2 inputs, 1 output)
depth_after(OP_CHECKSIG)   = depth_before - 1  (2 inputs, 1 output)
depth_after(OP_SIZE)       = depth_before + 1  (1 input, 2 outputs, input preserved)
depth_after(OP_CAT)        = depth_before - 1  (2 inputs, 1 output)
depth_after(OP_SPLIT)      = depth_before      (2 inputs (data + position), 2 outputs (left + right), net change 0)
depth_after(OP_VERIFY)     = depth_before - 1
depth_after(OP_2DUP)       = depth_before + 2
depth_after(OP_2DROP)      = depth_before - 2
depth_after(OP_TOALTSTACK) = depth_before - 1  (main stack)
depth_after(OP_FROMALTSTACK) = depth_before + 1  (main stack)
```

### 5.3 Branch Analysis

For the structured `IfOp` (`{ op: 'if', then: [...], else?: [...] }`):

```
depth_at_entry = depth_before - 1     (the condition is consumed from the stack)
depth_after_then = analyze(then_branch, depth_at_entry)
depth_after_else = analyze(else_branch, depth_at_entry)
```

Both branches MUST produce the same stack depth. If they differ, the compiler rejects the program.

### 5.4 Rejection

```
if max_depth(method) > 800:
    ERROR: "Stack depth exceeds limit (max: 800, actual: {max_depth})"
```

---

## 6. Example: ANF to Stack IR

### ANF IR (P2PKH unlock method)

```
t0 = load_param("pubKey")
t1 = call("hash160", [t0])
t2 = load_prop("pubKeyHash")
t3 = bin_op("==", t1, t2)
t4 = assert(t3)
t5 = load_param("sig")
t6 = load_param("pubKey")
t7 = call("checkSig", [t5, t6])
t8 = assert(t7)
```

### Stack State Trace

```
Initial stack (from unlocking script): [sig, pubKey]
                                         ^1    ^0

Instruction          | Stack After               | Labels
---------------------|---------------------------|------------------
(initial)            | [pubKey, sig]             | [pubKey@0, sig@1]
DUP                  | [pubKey, pubKey, sig]     | [t0, pubKey, sig]
HASH160              | [hash, pubKey, sig]       | [t1, pubKey, sig]
PUSH_PROP(pubKeyHash)| [pkh, hash, pubKey, sig]  | [t2, t1, pubKey, sig]
EQUAL                | [bool, pubKey, sig]       | [t3, pubKey, sig]
VERIFY               | [pubKey, sig]             | [pubKey, sig]
SWAP                 | [sig, pubKey]             | [sig, pubKey]
CHECKSIG             | [bool]                    | [t7]
                     | (left on stack as result)  |
```

### Final Bitcoin Script

```
OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
```

Note: The compiler fuses `EQUAL + VERIFY` into `OP_EQUALVERIFY` as a peephole optimization.

---

## 7. Peephole Optimizations

The Stack IR phase applies the following peephole optimizations. Rules are applied in a left-to-right pass, repeated until a fixed point is reached (no more changes). If-op branches are recursively optimized independently.

| Pattern | Replacement | Savings |
|---|---|---|
| `PUSH x, DROP` | (remove both) | 2+ bytes |
| `DUP, DROP` | (remove both) | 2 bytes |
| `SWAP, SWAP` | (remove both) | 2 bytes |
| `PUSH 1, OP_ADD` | `OP_1ADD` | 1+ bytes |
| `PUSH 1, OP_SUB` | `OP_1SUB` | 1+ bytes |
| `PUSH 0, OP_ADD` | (remove both) | 2+ bytes |
| `PUSH 0, OP_SUB` | (remove both) | 2+ bytes |
| `OP_NOT, OP_NOT` | (remove both) | 2 bytes |
| `OP_NEGATE, OP_NEGATE` | (remove both) | 2 bytes |
| `OP_EQUAL, OP_VERIFY` | `OP_EQUALVERIFY` | 1 byte |
| `OP_CHECKSIG, OP_VERIFY` | `OP_CHECKSIGVERIFY` | 1 byte |
| `OP_NUMEQUAL, OP_VERIFY` | `OP_NUMEQUALVERIFY` | 1 byte |
| `OP_CHECKMULTISIG, OP_VERIFY` | `OP_CHECKMULTISIGVERIFY` | 1 byte |
| `OP_DUP, OP_DROP` | (remove both) | 2 bytes |
| `OVER, OVER` | `OP_2DUP` | 1 byte |
| `DROP, DROP` | `OP_2DROP` | 1 byte |

---

## 8. Instruction Encoding

Each Stack IR instruction maps to one or more bytes of Bitcoin Script. The encoding is defined in the opcodes specification (`opcodes.md`). Here is a summary:

### Push Data Encoding

| Value | Encoding |
|---|---|
| `0` | `OP_0` (0x00) |
| `1` to `16` | `OP_1` (0x51) to `OP_16` (0x60) |
| `-1` | `OP_1NEGATE` (0x4f) |
| Bytes with length 1-75 | `<length_byte> <data>` |
| Bytes with length 76-255 | `OP_PUSHDATA1 <1-byte-length> <data>` |
| Bytes with length 256-65535 | `OP_PUSHDATA2 <2-byte-length-LE> <data>` |
| Bytes with length 65536+ | `OP_PUSHDATA4 <4-byte-length-LE> <data>` |

### Integer Encoding

Integers are encoded as Script numbers (little-endian, sign-magnitude, minimal encoding) and then pushed using the appropriate push data opcode:

```
 0          -> OP_0
 1 to 16    -> OP_1 to OP_16
-1          -> OP_1NEGATE
 other      -> <push_bytes> <script_number_encoding>
```

---

## 9. Correctness Invariants

The Stack IR phase must maintain these invariants:

1. **Stack balance**: At the end of a public method, the stack contains exactly one element (the result of the final assert/checksig/etc.).
2. **No underflow**: The stack depth never goes below zero at any instruction.
3. **No overflow**: The stack depth never exceeds 800.
4. **Deterministic scheduling**: The same ANF IR always produces the same Stack IR sequence.
5. **Value integrity**: Each ANF temporary's value is correctly positioned when it is consumed.
6. **Branch balance**: Both branches of an IF/ELSE/ENDIF produce the same stack depth.

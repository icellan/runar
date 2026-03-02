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
| `TUCK` | `[a, b] -> [a, b, a]` | `OP_TUCK` (copy top behind item 1) |
| `PICK(n)` | `[...] -> [..., stack[n]]` | `<n> OP_PICK` |
| `ROLL(n)` | `[...] -> [...]` | `<n> OP_ROLL` (move item n to top) |
| `DEPTH` | `[] -> [depth]` | `OP_DEPTH` |
| `2DUP` | `[a, b] -> [a, b, a, b]` | `OP_2DUP` |
| `2DROP` | `[a, b] -> []` | `OP_2DROP` |
| `2SWAP` | `[a, b, c, d] -> [c, d, a, b]` | `OP_2SWAP` |
| `TOALT` | `[a] -> []` (alt: `-> [a]`) | `OP_TOALTSTACK` |
| `FROMALT` | `[]` (alt: `[a] ->`) `-> [a]` | `OP_FROMALTSTACK` |

### 3.3 Arithmetic Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `ADD` | `[a, b] -> [a+b]` | `OP_ADD` |
| `SUB` | `[a, b] -> [a-b]` | `OP_SUB` |
| `MUL` | `[a, b] -> [a*b]` | `OP_MUL` |
| `DIV` | `[a, b] -> [a/b]` | `OP_DIV` |
| `MOD` | `[a, b] -> [a%b]` | `OP_MOD` |
| `NEGATE` | `[a] -> [-a]` | `OP_NEGATE` |
| `ABS` | `[a] -> [abs(a)]` | `OP_ABS` |
| `NOT` | `[a] -> [!a]` | `OP_NOT` |

### 3.4 Comparison Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `EQUAL` | `[a, b] -> [a==b]` | `OP_EQUAL` |
| `NUMEQUAL` | `[a, b] -> [a==b]` | `OP_NUMEQUAL` |
| `NUMNOTEQUAL` | `[a, b] -> [a!=b]` | `OP_NUMNOTEQUAL` |
| `LESSTHAN` | `[a, b] -> [a<b]` | `OP_LESSTHAN` |
| `LESSTHANOREQUAL` | `[a, b] -> [a<=b]` | `OP_LESSTHANOREQ` |
| `GREATERTHAN` | `[a, b] -> [a>b]` | `OP_GREATERTHAN` |
| `GREATERTHANOREQUAL` | `[a, b] -> [a>=b]` | `OP_GREATERTHANOREQ` |

### 3.5 Crypto Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `SHA256` | `[data] -> [hash]` | `OP_SHA256` |
| `RIPEMD160` | `[data] -> [hash]` | `OP_RIPEMD160` |
| `HASH160` | `[data] -> [hash]` | `OP_HASH160` |
| `HASH256` | `[data] -> [hash]` | `OP_HASH256` |
| `CHECKSIG` | `[sig, pubKey] -> [bool]` | `OP_CHECKSIG` |
| `CHECKMULTISIG` | `[sigs..., n, pubKeys..., m] -> [bool]` | `OP_CHECKMULTISIG` |

### 3.6 Byte String Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `CAT` | `[a, b] -> [a\|\|b]` | `OP_CAT` |
| `SPLIT` | `[data, pos] -> [left, right]` | `OP_SPLIT` |
| `SIZE` | `[data] -> [data, size]` | `OP_SIZE` |

### 3.7 Flow Control Instructions

| Instruction | Stack Effect | Bitcoin Opcode |
|---|---|---|
| `IF` | `[cond] -> []` | `OP_IF` |
| `ELSE` | -- | `OP_ELSE` |
| `ENDIF` | -- | `OP_ENDIF` |
| `VERIFY` | `[cond] -> []` | `OP_VERIFY` |
| `RETURN` | -- | `OP_RETURN` |

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

```
depth_after(PUSH_*)       = depth_before + 1
depth_after(DROP)          = depth_before - 1
depth_after(DUP)           = depth_before + 1
depth_after(SWAP)          = depth_before      (no change)
depth_after(ROLL(n))       = depth_before      (no change)
depth_after(PICK(n))       = depth_before + 1
depth_after(NIP)           = depth_before - 1
depth_after(OVER)          = depth_before + 1
depth_after(ROT)           = depth_before      (no change)
depth_after(TUCK)          = depth_before + 1
depth_after(2DUP)          = depth_before + 2
depth_after(2DROP)         = depth_before - 2
depth_after(ADD)           = depth_before - 1  (2 inputs, 1 output)
depth_after(CHECKSIG)      = depth_before - 1  (2 inputs, 1 output)
depth_after(SIZE)          = depth_before + 1  (1 input, 2 outputs, input preserved)
depth_after(CAT)           = depth_before - 1  (2 inputs, 1 output)
depth_after(SPLIT)         = depth_before      (1 input, 2 outputs)
depth_after(VERIFY)        = depth_before - 1
depth_after(TOALT)         = depth_before - 1  (main stack)
depth_after(FROMALT)       = depth_before + 1  (main stack)
```

### 5.3 Branch Analysis

For `IF`/`ELSE`/`ENDIF` blocks:

```
depth_at_IF = depth_before - 1     (IF consumes the condition)
depth_at_ELSE = depth_after_then_branch
depth_at_ENDIF = max(depth_after_then, depth_after_else)
```

Both branches MUST produce the same stack depth at `ENDIF`. If they differ, the compiler rejects the program.

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

The Stack IR phase may apply the following peephole optimizations:

| Pattern | Replacement | Savings |
|---|---|---|
| `EQUAL VERIFY` | `OP_EQUALVERIFY` | 1 byte |
| `NUMEQUAL VERIFY` | `OP_NUMEQUALVERIFY` | 1 byte |
| `CHECKSIG VERIFY` | `OP_CHECKSIGVERIFY` | 1 byte |
| `SWAP DROP` | `NIP` | 1 byte |
| `DUP ROLL(1)` | `DUP` (noop ROLL) | 2 bytes |
| `PUSH_INT(0) ADD` | (remove both) | 2+ bytes |
| `PUSH_BOOL(true) VERIFY` | (remove both) | 2 bytes |
| `NOT NOT` | (remove both) | 2 bytes |

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

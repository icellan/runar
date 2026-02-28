# TSOP Opcode Reference

**Version:** 0.1.0
**Status:** Draft

This document provides a complete reference for Bitcoin SV opcodes used by TSOP, including their hex values, stack effects, and how they map from TSOP operations.

---

## 1. Notation

Stack effects are written as:

```
(inputs -- outputs)
```

Where the **rightmost** item is the **top of the stack**. For example:

```
(a b -- a+b)
```

Means: `b` is on top, `a` is below it. The operation consumes both and pushes `a+b`.

---

## 2. Constants and Push Data

### 2.1 Push Value Opcodes

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x00` | `OP_0` / `OP_FALSE` | `( -- 0)` | Push empty byte vector (falsy zero) |
| `0x4f` | `OP_1NEGATE` | `( -- -1)` | Push the value `-1` |
| `0x51` | `OP_1` / `OP_TRUE` | `( -- 1)` | Push the value `1` |
| `0x52` | `OP_2` | `( -- 2)` | Push the value `2` |
| `0x53` | `OP_3` | `( -- 3)` | Push the value `3` |
| `0x54` | `OP_4` | `( -- 4)` | Push the value `4` |
| `0x55` | `OP_5` | `( -- 5)` | Push the value `5` |
| `0x56` | `OP_6` | `( -- 6)` | Push the value `6` |
| `0x57` | `OP_7` | `( -- 7)` | Push the value `7` |
| `0x58` | `OP_8` | `( -- 8)` | Push the value `8` |
| `0x59` | `OP_9` | `( -- 9)` | Push the value `9` |
| `0x5a` | `OP_10` | `( -- 10)` | Push the value `10` |
| `0x5b` | `OP_11` | `( -- 11)` | Push the value `11` |
| `0x5c` | `OP_12` | `( -- 12)` | Push the value `12` |
| `0x5d` | `OP_13` | `( -- 13)` | Push the value `13` |
| `0x5e` | `OP_14` | `( -- 14)` | Push the value `14` |
| `0x5f` | `OP_15` | `( -- 15)` | Push the value `15` |
| `0x60` | `OP_16` | `( -- 16)` | Push the value `16` |

### 2.2 Push Data Opcodes

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x01`-`0x4b` | (direct push) | `( -- data)` | Push the next N bytes (where N = opcode value) |
| `0x4c` | `OP_PUSHDATA1` | `( -- data)` | Next byte is length L, push next L bytes |
| `0x4d` | `OP_PUSHDATA2` | `( -- data)` | Next 2 bytes (LE) are length L, push next L bytes |
| `0x4e` | `OP_PUSHDATA4` | `( -- data)` | Next 4 bytes (LE) are length L, push next L bytes |

### 2.3 TSOP Mapping

| TSOP Operation | Opcode(s) Used |
|---|---|
| `bigint` literal `0n` | `OP_0` |
| `bigint` literal `1n`-`16n` | `OP_1`-`OP_16` |
| `bigint` literal `-1n` | `OP_1NEGATE` |
| `bigint` literal (other) | Direct push with Script number encoding |
| `boolean` literal `true` | `OP_TRUE` (`OP_1`) |
| `boolean` literal `false` | `OP_FALSE` (`OP_0`) |
| `ByteString` literal | Direct push or `OP_PUSHDATA1`/`2`/`4` |
| Constructor parameter | Direct push (embedded in locking script) |

---

## 3. Flow Control

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x61` | `OP_NOP` | `( -- )` | No operation |
| `0x63` | `OP_IF` | `(cond -- )` | If top is truthy, execute the following block |
| `0x64` | `OP_NOTIF` | `(cond -- )` | If top is falsy, execute the following block |
| `0x67` | `OP_ELSE` | `( -- )` | Execute if the preceding OP_IF/OP_NOTIF was not taken |
| `0x68` | `OP_ENDIF` | `( -- )` | End conditional block |
| `0x69` | `OP_VERIFY` | `(cond -- )` | Fail script if top is falsy; otherwise remove top |
| `0x6a` | `OP_RETURN` | `( -- )` | Mark transaction output as unspendable. Immediately fails script |

### 3.1 TSOP Mapping

| TSOP Operation | Opcode(s) Used |
|---|---|
| `if (cond) { ... }` | `OP_IF ... OP_ENDIF` |
| `if (cond) { ... } else { ... }` | `OP_IF ... OP_ELSE ... OP_ENDIF` |
| `assert(cond)` (non-final) | `<cond> OP_VERIFY` |
| `assert(cond)` (final statement) | `<cond>` (left on stack) |
| `exit(true)` | `OP_TRUE OP_RETURN` |
| `exit(false)` | `OP_FALSE OP_RETURN` |

### 3.2 If/Else Compilation

```typescript
// Source:
const x = cond ? a : b;

// Script:
<cond> OP_IF <a> OP_ELSE <b> OP_ENDIF
```

Both branches must leave the same number of items on the stack.

---

## 4. Stack Operations

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x6b` | `OP_TOALTSTACK` | `(a -- )` alt: `( -- a)` | Move top item to alt-stack |
| `0x6c` | `OP_FROMALTSTACK` | `( -- a)` alt: `(a -- )` | Move top of alt-stack to main stack |
| `0x73` | `OP_IFDUP` | `(a -- a)` or `(a -- a a)` | Duplicate top if truthy |
| `0x74` | `OP_DEPTH` | `( -- n)` | Push stack depth |
| `0x75` | `OP_DROP` | `(a -- )` | Remove top item |
| `0x76` | `OP_DUP` | `(a -- a a)` | Duplicate top item |
| `0x77` | `OP_NIP` | `(a b -- b)` | Remove second-from-top item |
| `0x78` | `OP_OVER` | `(a b -- a b a)` | Copy second-from-top to top |
| `0x79` | `OP_PICK` | `(... n -- ... stack[n])` | Copy item at depth n to top |
| `0x7a` | `OP_ROLL` | `(... n -- ...)` | Move item at depth n to top, shifting others down |
| `0x7b` | `OP_ROT` | `(a b c -- b c a)` | Rotate top 3: third to top |
| `0x7c` | `OP_SWAP` | `(a b -- b a)` | Swap top two items |
| `0x7d` | `OP_TUCK` | `(a b -- b a b)` | Copy top item to behind second |
| `0x6d` | `OP_2DROP` | `(a b -- )` | Remove top two items |
| `0x6e` | `OP_2DUP` | `(a b -- a b a b)` | Duplicate top two items |
| `0x6f` | `OP_3DUP` | `(a b c -- a b c a b c)` | Duplicate top three items |
| `0x70` | `OP_2OVER` | `(a b c d -- a b c d a b)` | Copy items 2-3 to top |
| `0x71` | `OP_2ROT` | `(a b c d e f -- c d e f a b)` | Rotate top 6 in pairs |
| `0x72` | `OP_2SWAP` | `(a b c d -- c d a b)` | Swap top two pairs |

### 4.1 TSOP Mapping

| TSOP Operation | Opcode(s) Used |
|---|---|
| Duplicate a value for multiple uses | `OP_DUP`, `OP_2DUP`, `OP_PICK` |
| Access a deep stack value | `OP_ROLL(n)` or `OP_PICK(n)` |
| Discard unused intermediate | `OP_DROP`, `OP_NIP`, `OP_2DROP` |
| Reorder operands | `OP_SWAP`, `OP_ROT` |
| Temporarily store a value | `OP_TOALTSTACK` / `OP_FROMALTSTACK` |

### 4.2 PICK vs ROLL

- **`OP_PICK`**: Copies the item at depth n, leaving the original in place. Stack grows by 1.
- **`OP_ROLL`**: Moves the item at depth n to the top, removing it from its original position. Stack size unchanged.

Use `OP_PICK` when the value will be needed again later. Use `OP_ROLL` when this is the value's last use.

---

## 5. Arithmetic Operations

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x8b` | `OP_1ADD` | `(a -- a+1)` | Increment by 1 |
| `0x8c` | `OP_1SUB` | `(a -- a-1)` | Decrement by 1 |
| `0x8f` | `OP_NEGATE` | `(a -- -a)` | Negate the sign |
| `0x90` | `OP_ABS` | `(a -- abs(a))` | Absolute value |
| `0x91` | `OP_NOT` | `(a -- !a)` | Boolean NOT: 0 becomes 1, non-zero becomes 0 |
| `0x92` | `OP_0NOTEQUAL` | `(a -- a!=0)` | Returns 1 if input is not 0, else 0 |
| `0x93` | `OP_ADD` | `(a b -- a+b)` | Integer addition |
| `0x94` | `OP_SUB` | `(a b -- a-b)` | Integer subtraction |
| `0x95` | `OP_MUL` | `(a b -- a*b)` | Integer multiplication (BSV re-enabled) |
| `0x96` | `OP_DIV` | `(a b -- a/b)` | Integer division, truncated (BSV re-enabled) |
| `0x97` | `OP_MOD` | `(a b -- a%b)` | Integer modulo (BSV re-enabled) |
| `0x9a` | `OP_BOOLAND` | `(a b -- a&&b)` | Boolean AND (both non-zero) |
| `0x9b` | `OP_BOOLOR` | `(a b -- a\|\|b)` | Boolean OR (either non-zero) |
| `0x98` | `OP_LSHIFT` | `(a b -- a<<b)` | Left shift (BSV re-enabled) |
| `0x99` | `OP_RSHIFT` | `(a b -- a>>b)` | Right shift (BSV re-enabled) |

### 5.1 TSOP Mapping

| TSOP Expression | Opcode |
|---|---|
| `a + b` (bigint) | `OP_ADD` |
| `a - b` | `OP_SUB` |
| `a * b` | `OP_MUL` |
| `a / b` | `OP_DIV` |
| `a % b` | `OP_MOD` |
| `-a` | `OP_NEGATE` |
| `abs(a)` | `OP_ABS` |
| `!a` | `OP_NOT` |
| `a && b` (after short-circuit lowering) | `OP_BOOLAND` or `OP_IF`/`OP_ENDIF` |
| `a \|\| b` (after short-circuit lowering) | `OP_BOOLOR` or `OP_IF`/`OP_ENDIF` |

### 5.2 Notes on BSV-Restored Opcodes

The following opcodes were disabled in BTC but are **re-enabled in BSV** (post-Genesis):

- `OP_MUL` (0x95)
- `OP_DIV` (0x96)
- `OP_MOD` (0x97)
- `OP_LSHIFT` (0x98)
- `OP_RSHIFT` (0x99)

These are fully available for TSOP on BSV. They are NOT available on BTC or BCH.

---

## 6. Comparison Operations

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x87` | `OP_EQUAL` | `(a b -- a==b)` | Byte-for-byte equality |
| `0x88` | `OP_EQUALVERIFY` | `(a b -- )` | `OP_EQUAL` then `OP_VERIFY` |
| `0x9c` | `OP_NUMEQUAL` | `(a b -- a==b)` | Numeric equality |
| `0x9d` | `OP_NUMEQUALVERIFY` | `(a b -- )` | `OP_NUMEQUAL` then `OP_VERIFY` |
| `0x9e` | `OP_NUMNOTEQUAL` | `(a b -- a!=b)` | Numeric inequality |
| `0x9f` | `OP_LESSTHAN` | `(a b -- a<b)` | True if a is less than b |
| `0xa0` | `OP_GREATERTHAN` | `(a b -- a>b)` | True if a is greater than b |
| `0xa1` | `OP_LESSTHANOREQUAL` | `(a b -- a<=b)` | True if a <= b |
| `0xa2` | `OP_GREATERTHANOREQUAL` | `(a b -- a>=b)` | True if a >= b |
| `0xa3` | `OP_MIN` | `(a b -- min)` | Return the smaller value |
| `0xa4` | `OP_MAX` | `(a b -- max)` | Return the larger value |
| `0xa5` | `OP_WITHIN` | `(x lo hi -- lo<=x<hi)` | True if x is in range [lo, hi) |

### 6.1 TSOP Mapping

| TSOP Expression | Opcode |
|---|---|
| `a === b` (bigint) | `OP_NUMEQUAL` |
| `a === b` (ByteString) | `OP_EQUAL` |
| `a !== b` (bigint) | `OP_NUMNOTEQUAL` |
| `a !== b` (ByteString) | `OP_EQUAL OP_NOT` |
| `a < b` | `OP_LESSTHAN` |
| `a > b` | `OP_GREATERTHAN` |
| `a <= b` | `OP_LESSTHANOREQUAL` |
| `a >= b` | `OP_GREATERTHANOREQUAL` |
| `min(a, b)` | `OP_MIN` |
| `max(a, b)` | `OP_MAX` |
| `within(x, lo, hi)` | `OP_WITHIN` |

### 6.2 EQUAL vs NUMEQUAL

- **`OP_EQUAL`**: Compares raw byte sequences. Used for `ByteString`, `PubKey`, `Sha256`, etc.
- **`OP_NUMEQUAL`**: Interprets both values as Script numbers and compares numerically. Used for `bigint`. Handles different encodings of the same number (e.g., `0x00` vs empty).

TSOP selects the appropriate opcode based on the operand types determined during type checking.

---

## 7. Cryptographic Operations

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0xa7` | `OP_RIPEMD160` | `(data -- hash)` | RIPEMD-160 hash |
| `0xa8` | `OP_SHA1` | `(data -- hash)` | SHA-1 hash (not recommended) |
| `0xa9` | `OP_SHA256` | `(data -- hash)` | SHA-256 hash |
| `0xaa` | `OP_HASH160` | `(data -- hash)` | SHA-256 then RIPEMD-160 |
| `0xab` | `OP_HASH256` | `(data -- hash)` | Double SHA-256 |
| `0xac` | `OP_CHECKSIG` | `(sig pubKey -- bool)` | Verify ECDSA signature |
| `0xad` | `OP_CHECKSIGVERIFY` | `(sig pubKey -- )` | `OP_CHECKSIG` then `OP_VERIFY` |
| `0xae` | `OP_CHECKMULTISIG` | `(... sigs n pubKeys m -- bool)` | Verify m-of-n multi-signature |
| `0xaf` | `OP_CHECKMULTISIGVERIFY` | `(... -- )` | `OP_CHECKMULTISIG` then `OP_VERIFY` |

### 7.1 TSOP Mapping

| TSOP Function | Opcode |
|---|---|
| `ripemd160(data)` | `OP_RIPEMD160` |
| `sha256(data)` | `OP_SHA256` |
| `hash160(data)` | `OP_HASH160` |
| `hash256(data)` | `OP_HASH256` |
| `checkSig(sig, pubKey)` | `OP_CHECKSIG` |
| `assert(checkSig(...))` | `OP_CHECKSIGVERIFY` (fused) |
| `checkMultiSig(sigs, pubKeys)` | `OP_CHECKMULTISIG` |

### 7.2 OP_CHECKSIG Details

Stack layout before `OP_CHECKSIG`:

```
Top:    pubKey (33 bytes, compressed)
Below:  sig (DER-encoded + 1 sighash byte)
```

The sighash byte (last byte of the signature) specifies which parts of the transaction are signed:

| Value | Name | Description |
|---|---|---|
| `0x01` | `SIGHASH_ALL` | Sign all inputs and outputs |
| `0x02` | `SIGHASH_NONE` | Sign all inputs, no outputs |
| `0x03` | `SIGHASH_SINGLE` | Sign all inputs, only the output at same index |
| `0x41` | `SIGHASH_ALL \| SIGHASH_FORKID` | BSV standard: ALL with fork ID |
| `0x42` | `SIGHASH_NONE \| SIGHASH_FORKID` | BSV: NONE with fork ID |
| `0x43` | `SIGHASH_SINGLE \| SIGHASH_FORKID` | BSV: SINGLE with fork ID |
| `0x81` | `SIGHASH_ALL \| SIGHASH_ANYONECANPAY` | Sign only own input, all outputs |

BSV requires `SIGHASH_FORKID` (bit 6 set) for all signatures.

### 7.3 OP_CHECKMULTISIG Details

Stack layout before `OP_CHECKMULTISIG`:

```
Top:    m (number of public keys)
        pubKey_m
        ...
        pubKey_1
        n (number of signatures)
        sig_n
        ...
        sig_1
        dummy (due to off-by-one bug, must be OP_0)
```

Note the historical off-by-one bug: `OP_CHECKMULTISIG` pops one extra item (the "dummy"). TSOP always pushes `OP_0` as the dummy.

---

## 8. Byte String Operations (BSV Re-enabled)

These opcodes were disabled in BTC but are **re-enabled in BSV**:

| Hex | Name | Stack Effect | Description |
|-----|------|-------------|-------------|
| `0x7e` | `OP_CAT` | `(a b -- a\|\|b)` | Concatenate two byte strings |
| `0x7f` | `OP_SPLIT` | `(data n -- left right)` | Split at position n: left = data[0..n], right = data[n..] |
| `0x82` | `OP_SIZE` | `(data -- data size)` | Push byte length (does NOT consume the data) |
| `0x80` | `OP_NUM2BIN` | `(num size -- bin)` | Convert Script number to byte string of given size |
| `0x81` | `OP_BIN2NUM` | `(bin -- num)` | Convert byte string to Script number (minimal encoding) |

### 8.1 TSOP Mapping

| TSOP Operation | Opcode |
|---|---|
| `a + b` (ByteString) | `OP_CAT` |
| `ByteString.slice(start, end)` | `OP_SPLIT` (twice if needed) |
| `len(data)` | `OP_SIZE OP_NIP` |
| `pack(n)` | `OP_NUM2BIN` |
| `unpack(data)` | `OP_BIN2NUM` |

### 8.2 OP_CAT Significance

`OP_CAT` is one of the most important opcodes for smart contracts on BSV. It enables:

- **Serialization**: Building transaction data structures on-stack.
- **State encoding**: Constructing new locking scripts with updated state.
- **OP_PUSH_TX**: Building the expected sighash preimage for self-referential contracts.

Without `OP_CAT`, stateful contracts and many advanced patterns would be impossible.

---

## 9. Special / No-Op Opcodes

| Hex | Name | Description |
|-----|------|-------------|
| `0x61` | `OP_NOP` | No operation |
| `0xb0`-`0xb9` | `OP_NOP1`-`OP_NOP10` | Reserved no-ops (for soft-fork upgrades in BTC; no special meaning in BSV) |

TSOP does not generate NOP opcodes in normal compilation.

---

## 10. Disabled / Invalid Opcodes

The following opcodes exist in the Bitcoin Script specification but are **not used by TSOP**:

| Hex | Name | Reason |
|-----|------|--------|
| `0x65` | `OP_VERIF` | Always fails (reserved) |
| `0x66` | `OP_VERNOTIF` | Always fails (reserved) |
| `0xa8` | `OP_SHA1` | Not used by TSOP (weak hash) |
| `0xab`+ | `OP_CODESEPARATOR` | Not used by TSOP |

---

## 11. OP_PUSH_TX Pattern

The **OP_PUSH_TX** pattern is not a single opcode but a technique using existing opcodes to enable a contract to inspect its own transaction. This is the foundation of stateful contracts in TSOP.

### 11.1 How It Works

1. The spender provides the **sighash preimage** as part of the unlocking script.
2. The locking script computes `OP_HASH256` of the preimage.
3. The locking script uses a known public key and constructs a signature that signs the same sighash.
4. `OP_CHECKSIG` verifies the signature, which implicitly verifies the preimage is correct.

Alternatively (more commonly in BSV):

1. The preimage is provided.
2. The contract hashes it with `OP_SHA256` and checks that the sighash matches.
3. The contract then parses the preimage to extract transaction data (outputs, amounts, etc.).

### 11.2 Preimage Structure (BIP143 / BSV Sighash)

The sighash preimage for BSV (with SIGHASH_FORKID) has this structure:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | nVersion |
| 4 | 32 | hashPrevouts |
| 36 | 32 | hashSequence |
| 68 | 36 | outpoint (txid + vout) |
| 104 | var | scriptCode (length-prefixed) |
| var | 8 | value (satoshis, LE) |
| var | 4 | nSequence |
| var | 32 | hashOutputs |
| var | 4 | nLocktime |
| var | 4 | sighash type |

### 11.3 TSOP Integration

The `this.checkPreimage(preimage)` call in TSOP generates the OP_PUSH_TX verification code. The compiler also generates code to:

- Extract `scriptCode` from the preimage (contains current locking script = current state + code).
- Extract `hashOutputs` for verifying the new state.
- Extract `value` for amount-based logic.

---

## 12. Chronicle Extensions (Future)

The following notes document potential future opcodes or extensions that may be available on Chronicle (BSV-derived chains) but are **not part of BSV consensus as of this specification**.

### 12.1 BSV-Native (Available Now)

All opcodes listed in sections 2-10 are BSV-native and available on mainnet.

### 12.2 Potential Chronicle Extensions

| Name | Description | Status |
|---|---|---|
| `OP_PUSH_TX` (native) | First-class transaction introspection without the sighash trick | Proposed |
| `OP_INPUTINDEX` | Push the index of the current input | Proposed |
| `OP_ACTIVEBYTECODE` | Push the scriptCode of the current input | Proposed |
| `OP_TXVERSION` | Push the transaction version | Proposed |
| `OP_TXLOCKTIME` | Push the transaction locktime | Proposed |
| `OP_TXINPUTCOUNT` | Push the number of inputs | Proposed |
| `OP_TXOUTPUTCOUNT` | Push the number of outputs | Proposed |
| `OP_OUTVALUE` | Push the value of a specific output | Proposed |
| `OP_OUTSCRIPT` | Push the scriptPubKey of a specific output | Proposed |
| `OP_INVALUE` | Push the value of a specific input | Proposed |
| `OP_INSCRIPT` | Push the scriptSig of a specific input | Proposed |

If Chronicle extensions become available, TSOP would be able to replace the OP_PUSH_TX sighash-trick pattern with direct introspection opcodes, resulting in smaller and more efficient scripts for stateful contracts.

### 12.3 Impact on TSOP

TSOP's IR is designed to be opcode-agnostic at the ANF level. The `check_preimage` and `get_state_script` IR nodes abstract over the underlying mechanism. If native introspection opcodes become available, only the code generator (Stack IR to Script) needs to change -- the ANF IR and higher-level semantics remain the same.

---

## 13. Quick Reference: TSOP Operation to Opcode

| TSOP Operation | Primary Opcode(s) | Hex |
|---|---|---|
| `a + b` (bigint) | `OP_ADD` | `0x93` |
| `a + b` (ByteString) | `OP_CAT` | `0x7e` |
| `a - b` | `OP_SUB` | `0x94` |
| `a * b` | `OP_MUL` | `0x95` |
| `a / b` | `OP_DIV` | `0x96` |
| `a % b` | `OP_MOD` | `0x97` |
| `-a` | `OP_NEGATE` | `0x8f` |
| `!a` | `OP_NOT` | `0x91` |
| `abs(a)` | `OP_ABS` | `0x90` |
| `a === b` (bigint) | `OP_NUMEQUAL` | `0x9c` |
| `a === b` (bytes) | `OP_EQUAL` | `0x87` |
| `a !== b` (bigint) | `OP_NUMNOTEQUAL` | `0x9e` |
| `a < b` | `OP_LESSTHAN` | `0x9f` |
| `a <= b` | `OP_LESSTHANOREQUAL` | `0xa1` |
| `a > b` | `OP_GREATERTHAN` | `0xa0` |
| `a >= b` | `OP_GREATERTHANOREQUAL` | `0xa2` |
| `sha256(x)` | `OP_SHA256` | `0xa9` |
| `ripemd160(x)` | `OP_RIPEMD160` | `0xa7` |
| `hash160(x)` | `OP_HASH160` | `0xaa` |
| `hash256(x)` | `OP_HASH256` | `0xab` |
| `checkSig(s, pk)` | `OP_CHECKSIG` | `0xac` |
| `checkMultiSig(...)` | `OP_CHECKMULTISIG` | `0xae` |
| `assert(x)` (non-final) | `OP_VERIFY` | `0x69` |
| `len(x)` | `OP_SIZE OP_NIP` | `0x82 0x77` |
| `pack(n)` | `OP_NUM2BIN` | `0x80` |
| `unpack(bs)` | `OP_BIN2NUM` | `0x81` |
| `if/else` | `OP_IF OP_ELSE OP_ENDIF` | `0x63 0x67 0x68` |

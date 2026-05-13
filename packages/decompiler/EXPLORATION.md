# Decompiler — Compiler Internals (Step 0)

This file pins the exact identifiers, file locations, and counts the decompiler relies on. Every claim below was verified against source on 2026-05-12.

## Public compile entry

`packages/runar-compiler/src/index.ts:135` — `compile(source: string, options?: CompileOptions): CompileResult`.

`CompileResult` (lines 87-108): `{ anf, contract, diagnostics, success, artifact?, scriptHex?, scriptAsm? }`. **`scriptHex` is a hex string, not `Uint8Array`** — decompiler hex-decodes before byte comparison.

`CompileOptions` (lines 64-85): `fileName`, `parseOnly`, `validateOnly`, `typecheckOnly`, `constructorArgs`, `disableConstantFolding`, `onProgress`. Decompiler calls `compile()` with **defaults** — peephole + EC optimizer + constant fold are all ON, matching the target.

## ANF IR

`packages/runar-compiler/src/ir/anf-ir.ts` — **18 value kinds**:

`load_param`, `load_prop`, `load_const`, `bin_op`, `unary_op`, `call`, `method_call`, `if`, `loop`, `assert`, `update_prop`, `get_state_script`, `check_preimage`, `deserialize_state`, `add_output`, `add_raw_output`, `add_data_output`, `array_literal`.

`bin_op` and `unary_op` carry an optional `result_type` hint (`"bytes"` for ByteString/PubKey/Sig/Sha256 family). Required to round-trip `===` / `!==` correctly because the stack lowerer rewrites OP_NUMEQUAL → OP_EQUAL when the hint is `"bytes"` — the decompiler's type inferencer must set this hint when re-emitting equality on byte-typed operands.

## Stack IR

`packages/runar-compiler/src/ir/stack-ir.ts` — **14 op variants**:

`push`, `dup`, `swap`, `roll` (carries `depth: number`), `pick` (carries `depth: number`), `drop`, `opcode` (carries `code: string`), `if` (carries `then`, optional `else`), `nip`, `over`, `rot`, `tuck`, `placeholder` (constructor-arg slot), `push_codesep_index`.

**Important:** `roll`/`pick` carry the depth as a field on the node itself, but at emit time the depth is **pushed separately** as a `push` opcode before the OP_PICK/OP_ROLL byte. The decompiler's symbolic executor must consume the preceding `push <depth>` as the op's argument, not as a stack value.

## Pipeline passes

| Pass | File | Export |
|------|------|--------|
| 1 — parse | `passes/01-parse.ts` | `parse(source, fileName?)` |
| 2 — validate | `passes/02-validate.ts` | `validate(contract)` |
| 3 — typecheck | `passes/03-typecheck.ts` | `typecheck(contract)` |
| 3b — expand fixed arrays | `passes/03b-expand-fixed-arrays.ts` | `expandFixedArrays(contract)` |
| 4 — anf lower | `passes/04-anf-lower.ts` | `lowerToANF(contract)` |
| 5 — stack lower | `passes/05-stack-lower.ts` | `lowerToStack(anf)` |
| 6 — emit | `passes/06-emit.ts` | `emit(stack)` |

## Optimizers

- **Peephole** (`optimizer/peephole.ts`) — fixed-point with `MAX_ITERATIONS = 100`, idempotent, **no disable flag**. The repo currently defines a chain of rules (each with a `windowSize` and `match` function); the exact count varies as the compiler evolves and is not load-bearing for the decompiler.
- **Constant fold** (`optimizer/constant-fold.ts`) — default-on, `CompileOptions.disableConstantFolding` opt-out. The decompiler keeps it ON (matches target).
- **EC algebraic optimizer** (`optimizer/anf-ec.ts:269` — `optimizeMethodEC`, entry `optimizeEC` at line ~307). Always-on. Collapses `ecMul(x, 0) → INFINITY`, `ecAdd(x, ecNegate(x)) → INFINITY`, `ecMul(G, k) → ecMulGen(k)`, etc. **Consequence:** original source ambiguity is lost. Decompiler must recover only the *canonical* post-EC-opt form; round-trip works because both forms re-compile to the same bytes.

## Builtin lowering

`packages/runar-compiler/src/passes/05-stack-lower.ts:66` — `BUILTIN_OPCODES` table. Each entry maps a builtin name to a small opcode sequence:

```
sha256        → [OP_SHA256]
ripemd160     → [OP_RIPEMD160]
hash160       → [OP_HASH160]
hash256       → [OP_HASH256]
checkSig      → [OP_CHECKSIG]
checkMultiSig → [OP_CHECKMULTISIG]
len           → [OP_SIZE]              (then OP_NIP — handled inline)
cat           → [OP_CAT]
num2bin       → [OP_NUM2BIN]
bin2num       → [OP_BIN2NUM]
abs           → [OP_ABS]
min           → [OP_MIN]
max           → [OP_MAX]
within        → [OP_WITHIN]
split         → [OP_SPLIT]
left          → [OP_SPLIT, OP_DROP]
int2str       → [OP_NUM2BIN]
bool          → [OP_0NOTEQUAL]
unpack        → [OP_BIN2NUM]
```

Most lower to a single opcode. Fingerprint matching alone cannot identify these — the lifter recovers them from operand provenance + type inference. (`left` is the lone two-opcode entry, but matches against a generic `OP_SPLIT, OP_DROP` pair that could also be a manual user expression; the lifter prefers `split(...)[0]` semantics when length context is missing.)

## EC primitive templates

`packages/runar-compiler/src/passes/ec-codegen.ts` — 835 lines. Templates (~1500 bytes each for Jacobian `ecMul`) live in lines `579-835`. These are the meaningful fingerprint targets:

`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`.

v0 fingerprints: `ecAdd`, `ecMul`, `ecMulGen`, `ecOnCurve`, `ecPointX`, `ecPointY`. The remaining four are present in source but not in v0 scope.

## Multi-method dispatch (asymmetric)

`packages/runar-compiler/src/passes/06-emit.ts:605-637` — `emitMethodDispatch`.

For N public methods, the emission is:

```
method 0..N-2:  OP_DUP <push i> OP_NUMEQUAL OP_IF OP_DROP <body_i> OP_ELSE
method N-1:     <push N-1> OP_NUMEQUALVERIFY <body_N-1>
(closing)       OP_ENDIF × (N-1)
```

`dispatch.ts` recognizes this exact shape. Single-method scripts (`publicMethods.length === 1`, line 571) bypass the dispatch and emit method ops directly — `dispatch.ts` passes through with `methodCount = 1`.

## OP_CODESEPARATOR (stateful)

Emitted at `packages/runar-compiler/src/passes/05-stack-lower.ts:2961`, inside `lowerCheckPreimage` (line 2936). One emission per stateful method, tracked in `EmitResult.codeSeparatorIndex` and `codeSeparatorIndices[]`. v0 recognizes this only for the simplest stateful case (`stateful-counter`); full state continuation is v1.

## Emit (deterministic, canonical)

`packages/runar-compiler/src/passes/06-emit.ts` — push encoding lines 274-326:

- `bigint 0` / empty bytes → `OP_0`
- `-1` → `OP_1NEGATE`
- `1..16` → `OP_1..OP_16`
- Otherwise minimal-push: direct `<len> <data>` for 1-75; `OP_PUSHDATA1/2/4` for larger.
- Script numbers: little-endian sign-magnitude (`encodeScriptNumber` in `vm/utils.ts`).

The emitter is fully deterministic — no randomness, no platform-dependent encoding.

## Reusable helpers

From `packages/runar-testing/src/vm/`:

- `utils.ts` — `encodeScriptNumber(n: bigint): Uint8Array`, `decodeScriptNumber(bytes: Uint8Array): bigint`, `hexToBytes(hex: string): Uint8Array`, `bytesToHex(bytes: Uint8Array): string`, `isTruthy(el: Uint8Array): boolean`, `disassemble(script: Uint8Array): string` (returns asm string — **not** typed Opcode[]; the decompiler implements its own byte walker that returns `Opcode[]`).
- `opcodes.ts` — `Opcode` enum (byte → name) and `opcodeName(byte: number): string`.
- `index.ts` — re-exports all of the above.

The decompiler imports these directly from `runar-testing` (workspace dep). It does not depend on `script-vm.ts` (the interpreter).

## Corpus

- **58** `.runar.ts` contracts under `examples/ts/` (counted with `find examples/ts -maxdepth 4 -name '*.runar.ts' | wc -l`).
- **5** conformance fixtures at `conformance/sdk-codegen/fixtures/{counter, inscribed, p2pkh, simple, stateful-escrow}.json`, each carrying `{ script: hex, asm, abi, stateFields, constructorSlots }`.

Many examples use templates outside v0 scope (`babybear-*`, `blake3`, `post-quantum-*`, `p256-*`, `p384-*`, `merkle-proof`, `sphincs-wallet`, `bsv20-token`, `bsv21-token`, `convergence-proof`, etc.). They are still attempted in Tier 1; expected outcome is `byte-diff` with a `/* RAW: ... */` fallback recovered span. The coverage matrix records the per-contract result and CI only fails on regression.

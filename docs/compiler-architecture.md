# Compiler Architecture

This document describes the internal architecture of the Rúnar compiler for contributors and anyone who wants to understand how TypeScript smart contracts are transformed into Bitcoin Script.

---

## Nanopass Overview

The Rúnar compiler is structured as six small, composable passes. Each pass does one thing, transforms one intermediate representation (IR) into the next, and is small enough to audit in a single sitting. This design is based on the nanopass framework (Sarkar, Waddell & Dybvig, ICFP 2004).

```
.runar.ts --> [Parse] --> [Validate] --> [Type-check] --> [ANF Lower] --> [EC Optimize] --> [Stack Lower] --> [Emit]
source       Pass 1       Pass 2         Pass 3           Pass 4          Pass 4.5          Pass 5          Pass 6
           ~1120 LOC     ~730 LOC      ~1110 LOC        ~1030 LOC       (always-on)       ~3580 LOC        ~570 LOC
```

Each pass lives in its own file under `packages/runar-compiler/src/passes/`:

| File | Pass | Input | Output |
|------|------|-------|--------|
| `01-parse.ts` | Parse | `.runar.ts` source | Rúnar AST |
| `02-validate.ts` | Validate | Rúnar AST | Validated AST |
| `03-typecheck.ts` | Type-check | Validated AST | Validated AST (type-checked, not transformed) |
| `04-anf-lower.ts` | ANF Lower | Validated AST | ANF IR |
| `05-stack-lower.ts` | Stack Lower | ANF IR | Stack IR |
| `slh-dsa-codegen.ts` | SLH-DSA Codegen | (called by Pass 5) | Stack IR fragment |
| `ec-codegen.ts` | EC Codegen | (called by Pass 5) | Stack IR fragment |
| `sha256-codegen.ts` | SHA-256 Codegen | (called by Pass 5) | Stack IR fragment |
| `06-emit.ts` | Emit | Stack IR | Bitcoin Script (hex) |

The key benefit of this approach: each pass can be tested and verified in isolation. You can unit-test Pass 4 without caring about Passes 1-3, and you can swap out Pass 1 entirely (as the Go and Rust compilers do) while keeping Passes 4-6.

---

## Pass 1: Parse

**File:** `packages/runar-compiler/src/passes/01-parse.ts`
**Input:** Raw `.runar.ts` source string
**Output:** Rúnar AST (defined in `runar-ir-schema`)

The parser uses **ts-morph** (a wrapper around the TypeScript compiler API) to parse the source file into a TypeScript AST, then extracts the Rúnar-relevant structure: the class declaration, properties, constructor, and methods.

### What It Does

1. Parses the source with ts-morph to get a full TypeScript AST.
2. Locates the single class declaration extending `SmartContract`.
3. Extracts property declarations (name, type, readonly flag).
4. Extracts the constructor (parameters, super call, assignments).
5. Extracts method declarations (visibility, parameters, body statements).
6. Builds a Rúnar AST node tree.

### Alternative Frontends

The TypeScript compiler uses **ts-morph** for `.runar.ts` and hand-written recursive descent parsers for `.runar.zig`, `.runar.sol`, `.runar.move`, `.runar.py`, `.runar.go`, and `.runar.rs` where supported. The Go compiler uses **tree-sitter** with a TypeScript grammar for `.runar.ts`, plus hand-written recursive descent parsers for `.runar.sol`, `.runar.move`, `.runar.go`, and `.runar.py`. The Rust compiler uses **SWC** (`swc_ecma_parser`) for `.runar.ts` and hand-written parsers for `.runar.sol`, `.runar.move`, `.runar.rs`, and `.runar.py`. The Python compiler uses hand-written recursive descent parsers for its supported formats. The Zig compiler uses hand-written recursive descent parsers for `.runar.zig` and `.runar.ts`. All maintained frontends must produce structurally equivalent Rúnar AST nodes for the formats they share. The conformance suite verifies this by checking that each implementation targets the same canonical ANF IR and script output.

---

## Pass 2: Validate

**File:** `packages/runar-compiler/src/passes/02-validate.ts`
**Input:** Rúnar AST
**Output:** Validated AST (same structure, but guaranteed to satisfy all constraints)

The validation pass enforces the subset rules that distinguish Rúnar from general TypeScript. It walks the AST and rejects any construct that is not in the allowed subset.

### Checks Performed

- Exactly one class per file extending `SmartContract` or `StatefulSmartContract`.
- No decorators on the class, properties, or methods.
- No generic type parameters.
- Constructor calls `super(...)` as its first statement.
- All properties assigned exactly once in the constructor.
- `super(...)` passes all properties in declaration order.
- Public methods return `void` and end with `assert(...)`.
- Private methods are not recursive (call graph cycle detection).
- For-loop bounds are compile-time constant integers.
- No disallowed statements: `while`, `do-while`, `try/catch`, `switch`, `throw`, `break`, `continue`.
- No disallowed expressions: `new`, arrow functions, template literals, `typeof`, `instanceof`, optional chaining, spread, `await`, `yield`.
- All imports come from allowed Rúnar library modules.
- No disallowed types: `number`, `string`, `any`, `unknown`, `null`, `undefined`, dynamic arrays.

Each violation produces a clear error message referencing the source location.

---

## Pass 3: Type-check

**File:** `packages/runar-compiler/src/passes/03-typecheck.ts`
**Input:** Validated AST
**Output:** Validated AST (type-checked but not structurally transformed)

The type checker validates types for all expressions and enforces the Rúnar type system, including subtyping and affine type rules. It does not produce a new AST -- it validates the existing AST and rejects programs with type errors.

### Phases

1. **Declaration collection**: Gather all property types and method signatures.
2. **Constructor checking**: Verify all property assignments type-check correctly.
3. **Method body checking**: For each method, build the type environment (this, parameters, locals) and type-check every statement and expression.
4. **Affine checking**: Verify that `Sig` and `SigHashPreimage` values are consumed at most once. A `SigHashPreimage` passed to `checkPreimage` is marked consumed; using it again is an error.
5. **Whole-program checks**: Verify no recursion in the call graph, verify all loop bounds are compile-time constants.

### Subtyping

The type system has a shallow subtype hierarchy:

- Domain types (`PubKey`, `Sig`, `Sha256`, `Ripemd160`, `Addr`, `SigHashPreimage`) are subtypes of `ByteString`.
- `RabinSig` and `RabinPubKey` are subtypes of `bigint`.
- Widening (subtype to supertype) is implicit. Narrowing requires an explicit cast function.

### Built-in Function Types

Every built-in function (`checkSig`, `hash160`, `sha256`, etc.) has a known signature. The type checker resolves calls to built-ins and verifies argument types match the expected signature.

---

## Pass 4: ANF Lower

**File:** `packages/runar-compiler/src/passes/04-anf-lower.ts`
**Input:** Typed AST
**Output:** ANF IR (canonical JSON, defined in `runar-ir-schema`)

This is the most conceptually important pass. It transforms the typed AST into **Administrative Normal Form (ANF)**, where every sub-expression is bound to a named temporary. There are no nested expressions.

### What Is ANF?

In ANF, every intermediate computation gets a name. Consider this Rúnar expression:

```typescript
assert(hash160(pubKey) === this.pubKeyHash);
```

After ANF lowering:

```
t0 = load_param("pubKey")
t1 = call("hash160", [t0])
t2 = load_prop("pubKeyHash")
t3 = bin_op("==", t1, t2)
t4 = assert(t3)
```

Each temporary (`t0`, `t1`, ...) is numbered sequentially within each method. The sequence of bindings IS the evaluation order, which is exactly what the stack machine needs.

### Why ANF?

- **ANF vs CPS**: CPS encodes control flow as function calls. Bitcoin Script has no functions, no call stack, and no closures. ANF keeps control flow explicit (`if`/`loop` nodes), which maps directly to `OP_IF`/`OP_ELSE`/`OP_ENDIF`.
- **ANF vs SSA**: SSA requires phi-nodes at control flow join points. The stack scheduling pass needs to know the evaluation order of every value, and ANF provides this directly. SSA would require a separate linearization step.
- **ANF vs raw AST**: Nested expressions create ambiguity about where intermediate values live during stack scheduling. ANF eliminates this by naming every intermediate result.

### Canonicalization

The ANF IR is the **conformance boundary** for the multi-compiler strategy. All compilers must produce byte-identical ANF IR (serialized via RFC 8785 / JCS) for the same source. To ensure this:

- Temporaries are numbered sequentially per method (`t0`, `t1`, ...).
- Sub-expressions are flattened left-to-right.
- Constants are always wrapped in `load_const` (never inlined).
- Logical operators (`&&`, `||`) use eager evaluation -- both operands are always evaluated and combined with a single opcode.

### Logical Operator Lowering Example

`a && b` becomes:

```
t0 = <evaluate a>
t1 = <evaluate b>
t2 = bin_op("&&", t0, t1)
```

Both operands are always evaluated. At the Stack IR level, `bin_op("&&")` emits `OP_BOOLAND` and `bin_op("||")` emits `OP_BOOLOR`. There is no short-circuit lowering -- Bitcoin Script has no conditional branching at the expression level that would skip operand evaluation, so both sides are computed eagerly.

---

## Pass 5: Stack Lower

**File:** `packages/runar-compiler/src/passes/05-stack-lower.ts`
**Input:** ANF IR
**Output:** Stack IR (linear sequence of stack instructions)

The stack lowering pass resolves the mismatch between named values in ANF and the nameless stack of Bitcoin Script. It tracks where each value lives on the stack and inserts explicit manipulation instructions (`OP_PICK`, `OP_ROLL`, `OP_SWAP`, `OP_DUP`, etc.) to arrange operands for each operation.

### Stack Scheduling Algorithm

The scheduler maintains a virtual stack and processes bindings in order:

```
for each binding t_i in method body:
  1. Arrange operands on top of stack (using SWAP/ROLL/PICK as needed)
  2. Emit the operation instruction
  3. Result is now on top of stack, labeled t_i
  4. Drop any values whose last use was in this binding
```

### Value Lifetime Analysis

For each ANF temporary, the scheduler computes:

- **Definition point**: Where the value is created.
- **Use points**: All places where the value is consumed.
- **Last use**: The final consumption point.
- **Use count**: How many times the value is referenced.

Values at their last use are moved with `OP_ROLL` (removes the original). Values needed again later are copied with `OP_PICK` (preserves the original).

### Alt-Stack Usage

When a value will not be used for many instructions, the scheduler may move it to the alt-stack (`OP_TOALTSTACK`) and retrieve it later (`OP_FROMALTSTACK`), reducing main-stack depth and avoiding deep `OP_ROLL` operations.

### Depth Tracking

The compiler statically verifies that the stack depth never exceeds 800 items (a conservative limit set in `05-stack-lower.ts`). The ScriptVM testing environment allows up to 1000 items by default. The compiler uses the lower limit to provide a safety margin. Both branches of an `OP_IF`/`OP_ELSE`/`OP_ENDIF` must produce the same stack depth at `OP_ENDIF`.

---

## Pass 6: Emit

**File:** `packages/runar-compiler/src/passes/06-emit.ts`
**Input:** Stack IR
**Output:** Bitcoin Script (hex-encoded byte string)

The emit pass translates each Stack IR instruction into one or more Bitcoin Script opcode bytes.

### Push Data Encoding

Integers and byte strings are encoded using the most compact opcode:

| Value | Encoding |
|-------|----------|
| `0` | `OP_0` (0x00) |
| `1` to `16` | `OP_1` (0x51) to `OP_16` (0x60) |
| `-1` | `OP_1NEGATE` (0x4f) |
| Bytes 1-75 long | `<length_byte> <data>` |
| Bytes 76-255 | `OP_PUSHDATA1 <1-byte-length> <data>` |
| Bytes 256-65535 | `OP_PUSHDATA2 <2-byte-length-LE> <data>` |

### Method Dispatch

For contracts with multiple public methods, the emitter generates a dispatch table using `OP_IF`/`OP_ELSE`/`OP_ENDIF` chains. The unlocking script pushes a method index, and the locking script branches to the correct method body.

### Constructor Parameter Placeholders

Constructor parameters appear as `<paramName>` placeholders in the script template. The SDK replaces them with actual values at deployment time.

### Post-Quantum Signature Codegen (Experimental)

Complex built-in functions like `verifyWOTS` and `verifySLHDSA_SHA2_*` are handled by dedicated codegen modules called from the stack lowerer:

- **WOTS+** (`verifyWOTS`): Inline in `05-stack-lower.ts`. Emits ~10 KB of Bitcoin Script with 67 conditional hash chain loops. Uses the same `emitOp` pattern as other builtins.
- **SLH-DSA** (`verifySLHDSA_SHA2_*`): In separate module `slh-dsa-codegen.ts`. Emits 200-900 KB of Bitcoin Script depending on parameter set. Uses a `SLHTracker` class to manage named stack positions across ~2,100 tweakable hash operations. Each hash uses a dynamically-constructed 22-byte ADRS for domain separation.

The SLH-DSA codegen is replicated across all five maintained compilers:
- TypeScript: `packages/runar-compiler/src/passes/slh-dsa-codegen.ts`
- Go: `compilers/go/codegen/slh_dsa.go`
- Rust: `compilers/rust/src/codegen/slh_dsa.rs`
- Python: `compilers/python/runar_compiler/codegen/slh_dsa.py`
- Zig: `compilers/zig/src/passes/helpers/pq_emitters.zig`

All five produce byte-identical Bitcoin Script on the shared conformance corpus.

### Elliptic Curve Codegen

EC built-in functions (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`) are handled by a dedicated codegen module, following the same pattern as SLH-DSA:

- **EC codegen** (`ec-codegen.ts`): Synthesizes secp256k1 field arithmetic from base opcodes (`OP_ADD`, `OP_MUL`, `OP_MOD`, etc.). The most complex operations are `ecMul` and `ecMulGen`, which emit a 256-iteration double-and-add loop using Jacobian projective coordinates internally. Each scalar multiplication generates ~50-100 KB of Bitcoin Script.

The EC codegen is replicated across all five maintained compilers:
- TypeScript: `packages/runar-compiler/src/passes/ec-codegen.ts`
- Go: `compilers/go/codegen/ec.go`
- Rust: `compilers/rust/src/codegen/ec.rs`
- Python: `compilers/python/runar_compiler/codegen/ec.py`
- Zig: `compilers/zig/src/passes/helpers/ec_emitters.zig`

All five produce byte-identical Bitcoin Script on the shared conformance corpus.

### SHA-256 Compression Codegen

The `sha256Compress` and `sha256Finalize` built-in functions are handled by a dedicated codegen module:

- **SHA-256 codegen** (`sha256-codegen.ts`): Inlines one round of SHA-256 compression (~3000 opcodes, ~74 KB of script). Uses little-endian stack representation during computation for efficiency (3 ops for LE-to-number vs 15 for BE). Bitwise operations (AND, OR, XOR, INVERT) work endian-agnostic on equal-length byte arrays. Rotation uses arithmetic (`OP_DIV`/`OP_MUL`/`OP_MOD`) instead of `OP_LSHIFT` for numeric correctness.

The SHA-256 codegen is replicated across all five maintained compilers:
- TypeScript: `packages/runar-compiler/src/passes/sha256-codegen.ts`
- Go: `compilers/go/codegen/sha256.go`
- Rust: `compilers/rust/src/codegen/sha256.rs`
- Python: `compilers/python/runar_compiler/codegen/sha256.py`
- Zig: `compilers/zig/src/passes/helpers/sha256_emitters.zig`

All five produce byte-identical Bitcoin Script on the shared conformance corpus.

### BLAKE3 Compression Codegen

The `blake3Compress` and `blake3Hash` built-in functions are handled by a dedicated codegen module:

- **BLAKE3 codegen** (`blake3-codegen.ts`): Inlines the BLAKE3 compression function (~10,000 opcodes, ~11 KB of script). The compression runs 7 rounds of 8 quarter-round G mixing calls (4 column + 4 diagonal) with a precomputed message schedule. Uses native `OP_LSHIFT`/`OP_RSHIFT` for byte-aligned rotations (16-bit, 8-bit) and general rotation for non-aligned (12-bit, 7-bit). State words are tracked at their stack depth positions for efficient rolling. The `blake3Hash` wrapper zero-pads the message to 64 bytes and prepends the IV as chaining value before splicing in the compression ops. Parameters are hardcoded: blockLen=64, counter=0, flags=11 (CHUNK_START|CHUNK_END|ROOT).

The BLAKE3 codegen is replicated across all five maintained compilers:
- TypeScript: `packages/runar-compiler/src/passes/blake3-codegen.ts`
- Go: `compilers/go/codegen/blake3.go`
- Rust: `compilers/rust/src/codegen/blake3.rs`
- Python: `compilers/python/runar_compiler/codegen/blake3.py`
- Zig: `compilers/zig/src/passes/helpers/blake3_emitters.zig`

All five produce byte-identical Bitcoin Script on the shared conformance corpus.

### OP_CODESEPARATOR

For stateful contracts, the compiler automatically inserts `OP_CODESEPARATOR` (opcode `0xab`) before the `checkPreimage` verification sequence. This causes `OP_CHECKSIG` to use only the script bytes after the separator as the scriptCode in the BIP-143 sighash preimage, reducing preimage size for large scripts and enabling scripts larger than ~32 KB.

The emit pass tracks the byte offset of each `OP_CODESEPARATOR` and records it in the artifact as `codeSeparatorIndex` (last separator offset) and `codeSeparatorIndices` (per-method offsets for multi-method contracts). The SDK uses these offsets to:

1. Trim the subscript when computing the BIP-143 sighash for OP_PUSH_TX signatures.
2. Trim the subscript when computing user `checkSig` signatures (stateful contracts only -- stateless contracts have `checkSig` before the separator, so the full script is used).
3. Push the `_codePart` implicit parameter (the code script without state) in the unlocking script for methods that create continuation outputs.

---

## Optimizer

The optimizer consists of three components in `packages/runar-compiler/src/optimizer/`, running at different points in the pipeline:

### Peephole Optimizer (`peephole.ts`)

Runs on Stack IR between Pass 5 (Stack Lower) and Pass 6 (Emit). Always enabled. Pattern-matches on sequences of Stack IR instructions and replaces them with shorter equivalents:

| Pattern | Replacement | Savings |
|---------|-------------|---------|
| `EQUAL + VERIFY` | `OP_EQUALVERIFY` | 1 byte |
| `NUMEQUAL + VERIFY` | `OP_NUMEQUALVERIFY` | 1 byte |
| `CHECKSIG + VERIFY` | `OP_CHECKSIGVERIFY` | 1 byte |
| `SWAP + DROP` | `NIP` | 1 byte |
| `PUSH_INT(0) + ADD` | (removed) | 2+ bytes |
| `NOT + NOT` | (removed) | 2 bytes |

### ANF EC Optimizer (`anf-ec.ts`)

Runs on ANF IR between Pass 4 (ANF Lower) and Pass 5 (Stack Lower). Always enabled. Applies 12 algebraic simplification rules for secp256k1 elliptic curve operations (e.g., `ecAdd(P, ecNegate(P))` → identity, `ecMul(P, 1)` → `P`). Dead bindings eliminated after rule application. Replicated across the maintained compiler set, including `anf-ec.ts`, `anf_optimize.go`, `anf_optimize.rs`, `anf_optimize.py`, and `compilers/zig/src/passes/ec_optimizer.zig`.

### Constant Folder (`constant-fold.ts`)

Available between Pass 4 (ANF Lower) and Pass 5 (Stack Lower), but disabled by default to preserve ANF conformance (see whitepaper Section 4.5). When enabled, evaluates constant expressions at compile time. For example, `3n + 4n` is folded to `7n` and emitted as a single `OP_7` instead of `OP_3 OP_4 OP_ADD`.

---

## Artifact Format

The final output of compilation is a JSON artifact (specified in `spec/artifact-format.md`). It contains everything needed to deploy and interact with the contract:

```json
{
  "version": "runar-v0.1.0",
  "compilerVersion": "0.1.0",
  "contractName": "P2PKH",
  "abi": {
    "constructor": { "params": [{ "name": "pubKeyHash", "type": "Addr" }] },
    "methods": [{ "name": "unlock", "params": [...], "isPublic": true }]
  },
  "script": "76a914<pubKeyHash>88ac",
  "asm": "OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG",
  "sourceMap": { "file": "P2PKH.ts", "mappings": [...] },
  "stateFields": [],
  "constructorSlots": [{ "paramIndex": 0, "byteOffset": 3 }],
  "buildTimestamp": "2025-06-15T10:30:00Z"
}
```

Key fields: `script` (hex template with `<param>` placeholders), `asm` (human-readable opcodes), `abi` (method signatures for the SDK), `stateFields` (mutable property descriptors for stateful contracts), `constructorSlots` (byte offsets where the SDK splices constructor arguments into the script template).

---

## Multi-Compiler Strategy

Rúnar defines a canonical IR conformance boundary at the ANF level. Any compiler that produces byte-identical ANF IR (serialized via RFC 8785) for a given source file is conformant.

| Compiler | Frontend | Status |
|----------|----------|--------|
| **TypeScript** (reference) | ts-morph (`.runar.ts`), hand-written recursive descent (`.runar.zig`, `.runar.sol`, `.runar.move`, `.runar.py`) | Complete |
| **Go** | tree-sitter (`.runar.ts`), hand-written recursive descent (`.runar.sol`, `.runar.move`, `.runar.go`, `.runar.py`) | Complete |
| **Rust** | SWC (`.runar.ts`), hand-written recursive descent (`.runar.sol`, `.runar.move`, `.runar.rs`, `.runar.py`) | Complete |
| **Python** | hand-written recursive descent (portable + native formats: `.runar.py`, `.runar.ts`, `.runar.sol`, `.runar.move`, `.runar.go`, `.runar.rs`) | Complete |
| **Zig** | hand-written recursive descent (`.runar.zig`, `.runar.ts`) | Complete |

All five maintained compilers share the same ANF-to-Script pipeline (Passes 4-6) semantically. The non-TypeScript compilers implement their own Passes 1-3 (parsing, validation, type-checking) using language-native tools, but must produce identical ANF IR and script output on the shared corpus. Each compiler supports a different slice of the source-format matrix: TypeScript is the broadest shared frontend, and Go, Rust, Python, and Zig add their own native syntaxes.

### Why Multiple Compilers?

- **Go binary**: Integrates into existing BSV node infrastructure.
- **Rust binary**: Enables WASM compilation for in-browser contract authoring.
- **Zig binary**: Delivers a single fast native compiler with a compact deployment footprint and benchmarkable end-to-end performance.
- **TypeScript**: Readable reference implementation and day-one production tool.

### Conformance Verification

The conformance suite in `conformance/` contains golden-file tests: source programs paired with expected ANF IR and expected script output. All compilers must pass the same suite. The SHA-256 of the canonical JSON output must match across all implementations.

```bash
pnpm run conformance:ts      # Test TypeScript compiler
pnpm run conformance:go      # Test Go compiler
pnpm run conformance:rust    # Test Rust compiler
pnpm run conformance:python  # Test Python compiler
cd compilers/zig && zig build conformance   # Test Zig compiler
```

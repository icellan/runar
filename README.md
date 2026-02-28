# TSOP -- TypeScript Smart Contract Operations Protocol

**Production-grade TypeScript DSL that compiles to Bitcoin Script for BSV.**

<!-- Badges -->
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![npm version](https://img.shields.io/badge/npm-v0.1.0-orange)

---

## Overview

TSOP is a compiler toolchain that lets you write Bitcoin SV smart contracts in a strict subset of TypeScript and compiles them to raw Bitcoin Script. Contracts are valid TypeScript files -- they type-check with `tsc`, get full IDE support, and run through a purpose-built nanopass compiler that produces the exact opcodes the BSV virtual machine executes.

The project exists because Bitcoin Script development today forces a choice between two bad options: hand-writing opcodes (error-prone, unauditable) or adopting a framework with heavy decorator-based DSLs that obscure what is actually happening on-chain. TSOP takes a different path.

### Key Design Principles

| Aspect | TSOP Approach |
|---|---|
| **Syntax style** | Native TypeScript keywords (`readonly`, `public`) -- no decorators |
| **Compiler count** | 3 planned (TS reference, Go, Rust) |
| **Compiler architecture** | Nanopass (6 passes, each ~100-200 lines) |
| **UTXO safety** | Affine types (compile-time guarantee) |
| **Correctness strategy** | Differential testing + reference interpreter oracle |
| **IR format** | Canonical JSON (RFC 8785), cross-compiler conformance boundary |

### Quick Example

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'tsop-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

This compiles to the standard P2PKH script: `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`.

---

## Quick Start

### Installation

```bash
pnpm add tsop-lang tsop-compiler tsop-cli
```

### Create a Contract

Create `MyContract.tsop.ts`:

```typescript
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'tsop-lang';

class MyContract extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

### Compile

```bash
tsop compile MyContract.tsop.ts
# => artifacts/MyContract.json
```

### Test

```bash
tsop test
```

### Deploy

```bash
tsop deploy ./artifacts/MyContract.json --network testnet --key <wif>
# => Deployed: txid abc123...
```

---

## Architecture

### Compilation Pipeline

```
                         TSOP Compilation Pipeline
 ___________________________________________________________________________
|                                                                           |
|   .tsop.ts -----> [Parse] -----> [Validate] -----> [Type-check]          |
|   source          Pass 1          Pass 2             Pass 3               |
|                  ts-morph        constraints         affine types          |
|                  extracts        & linting            & builtins           |
|                  TSOP AST                                                 |
|                                                                           |
|              TSOP AST          Validated AST       Typed AST              |
|                   |                 |                  |                   |
|                   v                 v                  v                   |
|                                                                           |
|             [ANF Lower] -----> [Stack Lower] -----> [Emit]               |
|              Pass 4              Pass 5              Pass 6               |
|              flatten to         map names to         encode opcodes        |
|              ANF IR             stack positions      & push data           |
|                                                                           |
|              ANF IR             Stack IR             Bitcoin Script        |
|              (canonical         (stack offsets,       (hex-encoded         |
|               JSON)              alt-stack)            byte string)        |
|___________________________________________________________________________|

                        ^                        |
                        |    Canonical IR         |
                        |    conformance          |
                        |    boundary             |
                        |                         v

                  [Go Compiler]            [Rust Compiler]
                   tree-sitter              SWC frontend
                   frontend                 (Phase 2)
                   (Phase 2)
```

### The Nanopass Approach

The compiler is structured as six small, composable passes. Each pass does one thing, transforms one IR into the next, and is small enough to audit in a single sitting. This is based on the nanopass framework by Sarkar, Waddell & Dybvig (ICFP 2004).

| Pass | Name | Input | Output | Lines (~) |
|------|------|-------|--------|-----------|
| 1 | **Parse** | `.tsop.ts` source | TSOP AST | ~150 |
| 2 | **Validate** | TSOP AST | Validated AST | ~120 |
| 3 | **Type-check** | Validated AST | Typed AST | ~200 |
| 4 | **ANF Lower** | Typed AST | ANF IR | ~180 |
| 5 | **Stack Lower** | ANF IR | Stack IR | ~160 |
| 6 | **Emit** | Stack IR | Bitcoin Script | ~100 |

The alternative -- a monolithic compiler -- makes it nearly impossible to verify that each transformation is correct in isolation. With nanopass, you can unit-test pass 4 without caring about passes 1-3, and you can swap out pass 1 entirely (as the Go and Rust compilers do) while keeping passes 4-6.

### Why ANF over CPS or SSA

The intermediate representation between the typed AST and the stack machine is **Administrative Normal Form** (ANF). In ANF, every sub-expression is bound to a named temporary -- there are no nested expressions.

We chose ANF over the alternatives for specific reasons:

- **ANF vs CPS**: CPS (continuation-passing style) encodes control flow as function calls. Bitcoin Script has no functions, no call stack, and no closures. CPS would introduce abstractions that have no counterpart in the target. ANF keeps control flow explicit (`if`/`loop` nodes) which maps directly to `OP_IF`/`OP_ELSE`/`OP_ENDIF`.

- **ANF vs SSA**: SSA (static single assignment) requires phi-nodes at control flow join points. Phi-nodes are the standard choice for register-based targets, but Bitcoin Script is a stack machine. The stack scheduling pass (Pass 5) needs to know the evaluation order of every value, and ANF provides this directly -- the sequence of bindings IS the evaluation order. SSA would require a separate linearization step.

- **ANF vs raw AST**: Nested expressions in an AST create ambiguity about where intermediate values live during stack scheduling. ANF eliminates this by naming every intermediate result, which makes the stack layout deterministic and auditable.

### Multi-Compiler Strategy

TSOP defines a **canonical IR conformance boundary** at the ANF level. Any compiler that produces byte-identical ANF IR (serialized via RFC 8785 / JCS) for a given source file is conformant. This means:

1. The **TypeScript reference compiler** (this repo) is the source of truth.
2. A **Go compiler** consumes the same `.tsop.ts` files and must produce identical ANF IR.
3. A **Rust compiler** does the same.

The conformance suite in `conformance/` contains golden-file tests: source programs paired with expected ANF IR and expected script output. All three compilers must pass the same suite.

Why multiple compilers? Different deployment contexts demand different toolchains. A Go binary integrates into existing BSV node infrastructure. A Rust binary enables WASM compilation for in-browser contract authoring. The TypeScript compiler serves as the readable reference and the day-one production tool.

---

## Language Design

### No Decorators

TSOP uses TypeScript's own keywords to define contract structure, not decorators:

| TSOP Keyword | Meaning |
|---|---|
| _(plain property)_ | All class properties are contract state |
| `readonly` | Immutable property (embedded in script at deploy time) |
| `public` / `private` | Method visibility -- `public` marks a spending entry point, `private` marks an inlined helper |

Decorators are runtime metadata in TypeScript. They have no standard compile-time semantics, they require experimental compiler flags or `ts-patch`, and they obscure what the compiler actually does with the annotated member. TSOP avoids them entirely and instead uses keywords that `tsc` already understands, so IDE features (go-to-definition, refactoring, error squiggles) work without plugins.

### Allowed TypeScript Subset

TSOP accepts a strict subset of TypeScript. This is by design -- Bitcoin Script has no heap, no closures, no dynamic dispatch, and no unbounded loops. The subset reflects these constraints:

**Allowed:**
- Class declarations extending `SmartContract`
- `readonly` and mutable properties
- `public` and `private` methods
- `const` / `let` variable declarations
- `if` / `else` statements
- Bounded `for` loops (compile-time constant bound)
- Arithmetic, comparison, logical, and bitwise operators
- Ternary expressions
- Built-in function calls

**Disallowed (with rationale):**
- `while` / `do-while` -- no unbounded loops in Script
- Recursion -- requires unbounded stack
- `async` / `await` -- no asynchrony on-chain
- Closures / arrow functions -- no heap-allocated environments
- `try` / `catch` -- Script has no exception model
- `any` / `unknown` -- defeats static analysis
- Dynamic arrays (`T[]`) -- no heap allocation
- `number` -- ambiguous precision; use `bigint`
- Arbitrary imports -- sandboxed compilation

### Domain Types

All values in Bitcoin Script are byte strings or integers. TSOP provides branded types that enforce size and semantic constraints at compile time:

| Type | Bytes | Description |
|---|---|---|
| `bigint` | variable | Arbitrary-precision integer (Script number encoding) |
| `boolean` | 0-1 | `OP_TRUE` or `OP_FALSE` |
| `ByteString` | variable | Raw byte sequence |
| `PubKey` | 33 | Compressed secp256k1 public key |
| `Sig` | 71-73 | DER-encoded ECDSA signature + sighash byte |
| `Sha256` | 32 | SHA-256 digest |
| `Ripemd160` | 20 | RIPEMD-160 digest |
| `Addr` | 20 | Bitcoin address (Hash160 of pubkey) |
| `SigHashPreimage` | variable | Transaction sighash preimage for OP_PUSH_TX |
| `RabinSig` | variable | Rabin signature (large integer) |
| `RabinPubKey` | variable | Rabin public key (large integer) |
| `FixedArray<T, N>` | N * sizeof(T) | Compile-time fixed-size array |

These are implemented as TypeScript branded types (nominal types via unique symbols), so `tsc` itself catches misuse like passing a `Sha256` where a `PubKey` is expected.

### Built-in Functions

| Function | Signature | Script Opcode(s) |
|---|---|---|
| `assert` | `(cond: boolean) => void` | `OP_VERIFY` |
| `checkSig` | `(sig: Sig, pk: PubKey) => boolean` | `OP_CHECKSIG` |
| `checkMultiSig` | `(sigs: Sig[], pks: PubKey[]) => boolean` | `OP_CHECKMULTISIG` |
| `hash256` | `(data: ByteString) => Sha256` | `OP_HASH256` |
| `hash160` | `(data: ByteString) => Ripemd160` | `OP_HASH160` |
| `sha256` | `(data: ByteString) => Sha256` | `OP_SHA256` |
| `ripemd160` | `(data: ByteString) => Ripemd160` | `OP_RIPEMD160` |
| `len` | `(data: ByteString) => bigint` | `OP_SIZE` |
| `pack` | `(n: bigint) => ByteString` | `OP_NUM2BIN` |
| `unpack` | `(data: ByteString) => bigint` | `OP_BIN2NUM` |
| `abs` | `(n: bigint) => bigint` | `OP_ABS` |
| `min` | `(a: bigint, b: bigint) => bigint` | `OP_MIN` |
| `max` | `(a: bigint, b: bigint) => bigint` | `OP_MAX` |
| `within` | `(x: bigint, lo: bigint, hi: bigint) => boolean` | `OP_WITHIN` |
| `exit` | `(success: boolean) => void` | `OP_RETURN` |

---

## Contract Patterns

### Stateless Contracts

Stateless contracts have only `readonly` properties. Their spending conditions are fixed at deployment time.

**Pay-to-Public-Key-Hash (P2PKH):**

```typescript
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```

**Escrow with Arbiter:**

```typescript
class Escrow extends SmartContract {
  readonly buyer: PubKey;
  readonly seller: PubKey;
  readonly arbiter: PubKey;

  constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey) {
    super(buyer, seller, arbiter);
    this.buyer = buyer;
    this.seller = seller;
    this.arbiter = arbiter;
  }

  public release(sig: Sig) {
    assert(checkSig(sig, this.seller) || checkSig(sig, this.arbiter));
  }

  public refund(sig: Sig) {
    assert(checkSig(sig, this.buyer) || checkSig(sig, this.arbiter));
  }
}
```

### Stateful Contracts (OP_PUSH_TX)

Stateful contracts have non-`readonly` properties. State is carried across transactions using the OP_PUSH_TX pattern: the contract verifies a sighash preimage to inspect its own transaction outputs and enforce that the new state is correctly propagated.

```typescript
class Counter extends SmartContract {
  count: bigint;  // mutable = stateful

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));
    this.count++;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }
}
```

### Token Contracts

**Fungible Token:**

```typescript
class SimpleFungibleToken extends SmartContract {
  owner: PubKey;
  readonly supply: bigint;

  constructor(owner: PubKey, supply: bigint) {
    super(owner, supply);
    this.owner = owner;
    this.supply = supply;
  }

  public transfer(sig: Sig, newOwner: PubKey, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));
    this.owner = newOwner;
    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }
}
```

### Oracle Patterns (Rabin Signatures)

```typescript
class OraclePriceFeed extends SmartContract {
  readonly oraclePubKey: RabinPubKey;
  readonly receiver: PubKey;

  constructor(oraclePubKey: RabinPubKey, receiver: PubKey) {
    super(oraclePubKey, receiver);
    this.oraclePubKey = oraclePubKey;
    this.receiver = receiver;
  }

  public settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig) {
    const msg = num2bin(price, 8n);
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(price > 50000n);
    assert(checkSig(sig, this.receiver));
  }
}
```

### Covenant Enforcement

Covenants restrict how a UTXO can be spent by inspecting the spending transaction itself via `checkPreimage`:

```typescript
class CovenantVault extends SmartContract {
  readonly owner: PubKey;
  readonly recipient: Addr;
  readonly minAmount: bigint;

  constructor(owner: PubKey, recipient: Addr, minAmount: bigint) {
    super(owner, recipient, minAmount);
    this.owner = owner;
    this.recipient = recipient;
    this.minAmount = minAmount;
  }

  public spend(sig: Sig, amount: bigint, txPreimage: SigHashPreimage) {
    assert(checkSig(sig, this.owner));
    assert(checkPreimage(txPreimage));
    assert(amount >= this.minAmount);
  }
}
```

---

## Academic Foundations

TSOP is built on established programming language research. Each major design choice traces to a specific paper or technique:

### Nanopass Compiler Architecture

> Sarkar, D., Waddell, O., & Dybvig, R. K. (2004). *A Nanopass Infrastructure for Compiler Education.* ICFP '04.

The nanopass approach structures a compiler as many small passes, each performing a single transformation. TSOP uses 6 passes. The benefit is auditability: each pass can be tested and verified in isolation, and the intermediate representations between passes serve as checkpoints for debugging.

### Administrative Normal Form (ANF)

> Flanagan, C., Sabry, A., Duba, B. F., & Felleisen, M. (1993). *The Essence of Compiling with Continuations.* PLDI '93.

ANF names every intermediate computation, eliminating nested expressions. This makes evaluation order explicit and deterministic -- critical for a stack machine target where the order of pushes and pops must be exactly right.

### Affine Types for Resource Safety

> Walker, D. (2005). *Substructural Type Systems.* In Advanced Topics in Types and Programming Languages.
> Blackshear, S., et al. (2019). *Move: A Language With Programmable Resources.*

Affine types enforce that certain values (signatures, preimages) are used at most once. This prevents a class of bugs where UTXO references are accidentally duplicated or preimages are checked multiple times. The Move language (Libra/Diem) popularized this approach for blockchain; TSOP applies it to the UTXO model.

### Definitional Interpreter as Oracle

> Reynolds, J. C. (1972). *Definitional Interpreters for Higher-Order Programming Languages.*
> Amin, N. & Rompf, T. (2017). *Type Soundness Proofs with Definitional Interpreters.* POPL '17.

The reference interpreter in `tsop-testing` is a direct, recursive evaluator of the ANF IR. It serves as an oracle: the compiled Bitcoin Script must produce the same result as the interpreter for all inputs. This is the foundation of the differential testing strategy.

### Differential Testing / Program Fuzzing

> Yang, X., Chen, Y., Eide, E., & Regehr, J. (2011). *Finding and Understanding Bugs in C Compilers.* PLDI '11 (CSmith).

Differential testing generates random valid programs, compiles them, and checks that the compiled output matches the interpreter's result. TSOP's fuzzer (in `conformance/fuzzer`) is directly inspired by CSmith. If the compiler and interpreter disagree on any generated program, there is a bug in at least one of them.

### Stack Scheduling

> Koopman, P. (1989). *Stack Computers: The New Wave.*

Converting named values (from ANF) to stack positions requires a scheduling algorithm that minimizes stack depth and alt-stack usage. The stack lowering pass (Pass 5) implements a variant of Koopman's approach, tracking where each named value lives on the main stack or alt-stack and inserting `OP_PICK`, `OP_ROLL`, `OP_TOALTSTACK`, and `OP_FROMALTSTACK` as needed.

---

## Project Structure

```
tsop/
+-- package.json                 # Root workspace config
+-- pnpm-workspace.yaml          # pnpm workspace definition
+-- tsconfig.base.json           # Shared TypeScript config
+-- turbo.json                   # Turborepo build pipeline
|
+-- packages/
|   +-- tsop-lang/               # Contract author's import library
|   |   +-- src/
|   |       +-- types.ts         # Domain types (PubKey, Sig, ByteString, etc.)
|   |
|   +-- tsop-compiler/           # Reference compiler (TS -> Bitcoin Script)
|   |   +-- src/
|   |       +-- passes/          # 6 nanopass compiler passes
|   |
|   +-- tsop-ir-schema/          # IR type definitions & JSON schemas
|   |   +-- src/
|   |       +-- tsop-ast.ts      # TSOP AST node definitions
|   |
|   +-- tsop-testing/            # Script VM, interpreter, fuzzer
|   |   +-- src/
|   |
|   +-- tsop-sdk/                # Deploy, call, interact with contracts
|   |   +-- src/
|   |
|   +-- tsop-cli/                # CLI tool (compile, test, deploy)
|       +-- src/
|
+-- spec/                        # Formal specifications
|   +-- grammar.md               # Language grammar (EBNF)
|   +-- type-system.md           # Type system rules
|   +-- semantics.md             # Operational semantics
|   +-- ir-format.md             # ANF IR canonical format
|
+-- conformance/                 # Cross-compiler conformance tests
|   +-- tests/                   # Golden-file test cases
|   |   +-- basic-p2pkh/         # Source + expected IR + expected script
|   |   +-- arithmetic/
|   |   +-- boolean-logic/
|   |   +-- if-else/
|   |   +-- bounded-loop/
|   |   +-- multi-method/
|   |   +-- stateful/
|   +-- runner/                  # Conformance test runner
|   +-- fuzzer/                  # CSmith-inspired program generator
|
+-- compilers/                   # Alternative compiler implementations
|   +-- go/                      # Go compiler (tree-sitter frontend)
|   +-- rust/                    # Rust compiler (SWC frontend)
|
+-- examples/                    # Example contracts
|   +-- p2pkh/                   # Pay-to-Public-Key-Hash
|   +-- escrow/                  # Multi-party escrow
|   +-- stateful-counter/        # Stateful counter (OP_PUSH_TX)
|   +-- token-ft/                # Fungible token
|   +-- token-nft/               # Non-fungible token
|   +-- oracle-price/            # Oracle price feed (Rabin signatures)
|   +-- auction/                 # On-chain auction
|   +-- covenant-vault/          # Covenant-enforced vault
|
+-- docs/                        # Additional documentation
```

---

## Development

### Prerequisites

- **Node.js** >= 20.0.0
- **pnpm** 9.15.0+

### Setup

```bash
git clone https://github.com/example/tsop.git
cd tsop
pnpm install
pnpm build
pnpm test
```

### Useful Commands

```bash
# Build all packages
pnpm build

# Run all tests
pnpm test

# Type-check all packages
pnpm typecheck

# Lint all packages
pnpm lint

# Clean all build artifacts
pnpm clean
```

### Working on a Single Package

```bash
cd packages/tsop-compiler
pnpm test              # Run compiler tests only
pnpm build             # Build compiler only
```

---

## Verification Plan

TSOP employs a layered testing strategy, from unit tests through to differential fuzzing:

### Layer 1: Unit Tests Per Pass

Each compiler pass has its own test suite. Tests provide a specific input IR, run the pass, and assert properties of the output IR.

```
Pass 1 tests: source string -> TSOP AST assertions
Pass 2 tests: TSOP AST -> validation error/success assertions
Pass 3 tests: Validated AST -> type annotation assertions
Pass 4 tests: Typed AST -> ANF IR structural assertions
Pass 5 tests: ANF IR -> Stack IR stack-depth assertions
Pass 6 tests: Stack IR -> hex script assertions
```

### Layer 2: End-to-End Compilation Tests

Full pipeline tests: source file in, hex script out. The conformance suite provides the golden files.

### Layer 3: VM Execution Tests

The compiled script is loaded into the `tsop-testing` Script VM and executed with specific unlocking script inputs. The test asserts that the VM terminates with the expected success/failure state.

### Layer 4: Interpreter Oracle Comparison

For each test case, the reference interpreter evaluates the ANF IR with the same inputs. The interpreter's result must match the VM's result. Any disagreement is a bug.

### Layer 5: Differential Fuzzing

The fuzzer generates random valid TSOP programs, compiles them, runs them in the VM, and compares against the interpreter. This runs continuously in CI and has no fixed end -- it searches for compiler bugs indefinitely.

### Layer 6: Cross-Compiler Conformance

When the Go and Rust compilers are ready, they must produce byte-identical ANF IR for every test case in the conformance suite. The SHA-256 of the canonical JSON output must match across all implementations.

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 0** | Project scaffold, spec documents, IR schema | Complete |
| **Phase 1** | Pass 1 (Parse) + Pass 2 (Validate) | Complete |
| **Phase 2** | Pass 3 (Type-check) with affine types | Complete |
| **Phase 3** | Pass 4 (ANF Lower) + canonical serialization | Complete |
| **Phase 4** | Pass 5 (Stack Lower) + Pass 6 (Emit) | Complete |
| **Phase 5** | Script VM + reference interpreter + fuzzer | Complete |
| **Phase 6** | SDK (deploy, call) + CLI | Complete |
| **Phase 7** | Go compiler (IR consumer + tree-sitter frontend) | Complete |
| **Phase 8** | Rust compiler (IR consumer + SWC frontend) | Complete |

---

## Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| TypeScript | ^5.6.0 | Source language, compiler implementation |
| Node.js | >=20.0.0 | Runtime |
| pnpm | 9.15.0 | Package manager (workspace support) |
| Turborepo | ^2.3.0 | Monorepo build orchestration |
| ts-morph | ^24.0.0 | TypeScript AST parsing (Pass 1) |
| Vitest | ^2.1.0 | Test runner |
| fast-check | ^3.22.0 | Property-based testing / fuzzer |
| Commander | ^12.1.0 | CLI argument parsing |
| AJV | ^8.18.0 | JSON Schema validation (IR schemas) |
| Go | 1.22+ | Alternative compiler (tree-sitter frontend) |
| Rust / SWC | 1.75+ | Alternative compiler (SWC frontend) |

---

## License

MIT

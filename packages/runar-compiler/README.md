# runar-compiler

**Rúnar reference compiler: TypeScript to Bitcoin Script via a 6-pass nanopass pipeline.**

This package is the canonical compiler implementation. It reads `.runar.ts` source files, runs them through six sequential passes, and produces a compiled artifact containing the Bitcoin Script bytecode, the canonical ANF IR, and metadata.

---

## Installation

```bash
pnpm add runar-compiler
```

## API Usage

```typescript
import { compile } from 'runar-compiler';

const source = `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

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
`;

const result = compile(source, {
  includeIR: true,        // include ANF IR in output
  includeSourceMap: true,  // include source location mapping
  optimize: true,          // enable peephole optimizer
});

console.log(result.script);        // hex-encoded Bitcoin Script
console.log(result.anfIR);         // canonical ANF IR (JSON)
console.log(result.artifact);      // full compilation artifact
console.log(result.diagnostics);   // warnings and errors
```

### Compile Options

| Option | Type | Default | Description |
|---|---|---|---|
| `includeIR` | `boolean` | `false` | Include ANF IR in the artifact |
| `includeSourceMap` | `boolean` | `false` | Include source location mappings |
| `optimize` | `boolean` | `true` | Enable peephole optimization |
| `target` | `'mainnet' \| 'testnet'` | `'mainnet'` | Target network (affects genesis flags) |

---

## Pipeline Overview

```
  Source (.runar.ts)
       |
       v
  +-----------+     +-----------+     +------------+
  |  Pass 1   | --> |  Pass 2   | --> |  Pass 3    |
  |  PARSE    |     |  VALIDATE |     |  TYPECHECK |
  |  ts-morph |     | constraints|    | affine +   |
  |           |     |  & lint   |     | builtins   |
  +-----------+     +-----------+     +------------+
       |                 |                  |
    Rúnar AST        Validated AST      Typed AST
                                           |
                                           v
  +-----------+     +-----------+     +------------+
  |  Pass 6   | <-- |  Pass 5   | <-- |  Pass 4    |
  |  EMIT     |     |  STACK    |     |  ANF LOWER |
  |  opcodes  |     |  LOWER    |     |  flatten   |
  |  & push   |     |  schedule |     |  to ANF    |
  +-----------+     +-----------+     +------------+
       |                 |                  |
  Bitcoin Script     Stack IR          ANF IR
  (hex bytes)     (stack offsets)   (canonical JSON)
```

---

## Detailed Pass Descriptions

### Pass 1: Parse

**Input:** TypeScript source string
**Output:** Rúnar AST (`ContractNode`)
**Implementation:** Uses `ts-morph` to parse the source into a TypeScript AST, then walks the AST to extract Rúnar-specific structure.

The parser:

1. Creates a `ts-morph` `Project` with in-memory file system.
2. Locates the class declaration that extends `SmartContract` or `StatefulSmartContract`.
3. Extracts property declarations, noting `readonly` vs mutable.
4. Extracts the constructor, verifying `super(...)` call structure.
5. Extracts method declarations with visibility and parameter types.
6. Recursively walks method bodies, converting TypeScript AST nodes to Rúnar AST nodes.

The output is a `ContractNode` as defined in `runar-ir-schema`:

```typescript
interface ContractNode {
  kind: 'contract';
  name: string;
  parentClass: 'SmartContract' | 'StatefulSmartContract';
  properties: PropertyNode[];
  constructor: MethodNode;
  methods: MethodNode[];
  sourceFile: string;
}
```

Expression nodes use a discriminated union on the `kind` field: `binary_expr`, `unary_expr`, `call_expr`, `member_expr`, `identifier`, `bigint_literal`, `bool_literal`, `bytestring_literal`, `ternary_expr`, `property_access`, `index_access`, `increment_expr`, `decrement_expr`.

### Pass 2: Validate

**Input:** Rúnar AST
**Output:** Validated Rúnar AST (same structure, with validation errors collected)

The validator checks structural constraints that the parser does not enforce:

- Exactly one class extending `SmartContract` or `StatefulSmartContract`.
- No decorators anywhere.
- No disallowed TypeScript constructs (while loops, try/catch, async, closures, etc.).
- Constructor calls `super(...)` first, passes all properties, assigns all properties.
- Public methods return `void` and end with `assert(...)`.
- Private methods do not call themselves (no direct recursion).
- For-loop bounds are compile-time constant.
- No `number` type usage (must use `bigint`).
- No dynamic array types (must use `FixedArray`).
- Import paths are restricted to `runar-lang` modules.

Example error messages:

```
Error [V001]: Public method 'unlock' must end with an assert() call (line 15)
Error [V002]: While loops are not supported in Rúnar -- use bounded for loops (line 22)
Error [V003]: Property 'x' must be assigned in the constructor (line 8)
Warning [V010]: Unused private method 'helper' (line 30)
```

### Pass 3: Type-check

**Input:** Validated AST
**Output:** Typed AST (every expression annotated with its resolved type)

The type checker implements Rúnar's type system:

1. **Environment construction:** Builds a type environment for each method scope containing `this` (the contract type), parameters, and local variables.

2. **Expression typing:** Recursively assigns types to all expressions. Literal `42n` gets type `bigint`. A call to `hash160(x)` gets type `Ripemd160`. Binary `a + b` where both are `bigint` gets type `bigint`.

3. **Subtype checking:** Validates that assignments respect the type hierarchy. `PubKey` can be assigned to `ByteString` (widening). `ByteString` cannot be assigned to `PubKey` (narrowing without cast).

4. **Affine type tracking:** Tracks consumption of affine values (`Sig`, `SigHashPreimage`). Each affine value must be used at most once. If a value is used in both branches of an `if`, that counts as one use per branch (both branches must use it, or neither).

5. **Built-in function signatures:** Maintains a table of all built-in function signatures and validates argument types and counts.

6. **Call graph analysis:** Builds a call graph of private methods and checks for cycles (recursion is forbidden).

### Pass 4: ANF Lower

**Input:** Typed AST
**Output:** ANF IR (`ANFProgram`)

This pass flattens the typed AST into Administrative Normal Form. Every sub-expression becomes a named binding.

**Before (Typed AST):**

```typescript
assert(hash160(pubKey) === this.pubKeyHash);
```

**After (ANF IR):**

```
t0 = load_param("pubKey")
t1 = call("hash160", [t0])
t2 = load_prop("pubKeyHash")
t3 = bin_op("==", t1, t2)
t4 = assert(t3)
```

The transformation rules:

- **Literals** become `load_const` nodes.
- **Variable references** become `load_param` (for parameters) or references to earlier temporaries.
- **Property accesses** (`this.x`) become `load_prop` nodes.
- **Binary expressions** are flattened left-to-right: evaluate left operand to a temporary, evaluate right operand to a temporary, then emit `bin_op`.
- **Function calls** evaluate all arguments to temporaries, then emit `call`.
- **Short-circuit operators** (`&&`, `||`) are lowered to `if` nodes (since evaluation of the second operand is conditional).
- **For loops** are unrolled into `loop` nodes with explicit iteration bindings.
- **Property assignments** (`this.x = expr`) become `update_prop` nodes.

Temporaries are named `t0`, `t1`, `t2`, ... sequentially within each method. This naming is canonical -- every conforming compiler must produce the same names for the same input.

### Pass 5: Stack Lower

**Input:** ANF IR
**Output:** Stack IR (opcodes with stack position references)

This pass converts named ANF bindings into stack machine operations. It must solve the **stack scheduling problem**: given a sequence of named values and their usage points, determine when to push each value, when to use `OP_PICK` or `OP_ROLL` to access buried values, and when to move values to the alt-stack.

The algorithm:

1. Walk the ANF bindings in order.
2. Maintain a model of the stack state (which binding is at which position).
3. For each binding:
   - Determine which operands are needed.
   - If an operand is on the stack, emit `OP_PICK` or `OP_ROLL` (depending on whether the value is needed again later).
   - If an operand is on the alt-stack, emit `OP_FROMALTSTACK`.
   - Emit the operation opcode(s).
   - Update the stack model.
4. If a value is not needed for several bindings, it may be moved to the alt-stack (`OP_TOALTSTACK`) to keep the main stack shallow.

The output is a flat sequence of opcodes and push-data instructions.

### Pass 6: Emit

**Input:** Stack IR
**Output:** Bitcoin Script (hex-encoded byte string)

The emitter encodes the stack IR into actual Bitcoin Script bytes:

- **Opcodes** are encoded as single bytes (`OP_DUP` = `0x76`, `OP_HASH160` = `0xa9`, etc.).
- **Push data** follows Bitcoin's push rules:
  - 1-75 bytes: `OP_PUSHDATA` prefix is the length itself (1 byte).
  - 76-255 bytes: `OP_PUSHDATA1` + 1-byte length.
  - 256-65535 bytes: `OP_PUSHDATA2` + 2-byte little-endian length.
  - Larger: `OP_PUSHDATA4` + 4-byte little-endian length.
- **Script numbers** (bigint values) are encoded in minimal sign-magnitude little-endian format.
- **Boolean values**: `true` is `OP_TRUE` (`0x51`), `false` is `OP_FALSE` (`0x00`).

For contracts with multiple public methods, the emitter generates a dispatch table using `OP_IF`/`OP_ELSE`/`OP_ENDIF` that branches on a method index pushed by the unlocking script.

---

## Optimizer

The optimizer runs between Pass 5 and Pass 6 (when enabled). It applies peephole patterns to the Stack IR:

### Peephole Patterns

| Pattern | Replacement | Savings |
|---|---|---|
| `OP_PUSH_0 OP_ADD` | _(removed)_ | 2 bytes |
| `OP_PUSH_1 OP_MUL` | _(removed)_ | 2 bytes |
| `OP_NOT OP_NOT` | _(removed)_ | 2 bytes |
| `OP_DUP OP_DROP` | _(removed)_ | 2 bytes |
| `OP_OVER OP_OVER` | `OP_2DUP` | 1 byte |
| `OP_VERIFY OP_TRUE` at end | `OP_VERIFY` | 1 byte |

### Constant Folding

When both operands of an arithmetic operation are known constants, the result is computed at compile time and emitted as a single push:

```
OP_PUSH_3 OP_PUSH_4 OP_ADD  -->  OP_PUSH_7
```

---

## Artifact Format

The compilation artifact is a JSON file containing:

```json
{
  "version": "0.1.0",
  "contractName": "P2PKH",
  "compilerVersion": "0.1.0",
  "script": "76a97c7e7e87a988ac",
  "abi": {
    "constructor": {
      "params": [
        { "name": "pubKeyHash", "type": "Addr" }
      ]
    },
    "methods": [
      {
        "name": "unlock",
        "params": [
          { "name": "sig", "type": "Sig" },
          { "name": "pubKey", "type": "PubKey" }
        ],
        "index": 0
      }
    ]
  },
  "properties": [
    { "name": "pubKeyHash", "type": "Addr", "readonly": true }
  ],
  "anfIR": { ... },
  "sourceMap": { ... }
}
```

The `script` field contains the locking script template. Property placeholders in the script are replaced with actual values at deployment time by the SDK.

---

## Error Handling and Diagnostics

The compiler collects diagnostics rather than throwing on the first error:

```typescript
interface CompileResult {
  success: boolean;
  script?: string;
  artifact?: Artifact;
  anfIR?: ANFProgram;
  diagnostics: Diagnostic[];
}

interface Diagnostic {
  severity: 'error' | 'warning' | 'info';
  code: string;
  message: string;
  location?: SourceLocation;
}
```

Error codes are prefixed by pass: `P1xx` (parse), `V2xx` (validate), `T3xx` (typecheck), `A4xx` (ANF lower), `S5xx` (stack lower), `E6xx` (emit).

---

## Design Decisions

### Why Nanopass

A monolithic compiler is easier to write initially but harder to test, debug, and extend. With nanopass:

- Each pass is ~100-200 lines and does exactly one transformation.
- Each pass can be tested in isolation with synthetic inputs.
- Bugs are localized: if the ANF IR is correct but the script is wrong, the problem is in Pass 5 or 6.
- New optimizations slot in as additional passes without modifying existing ones.
- Alternative compiler frontends (Go, Rust) can reuse the IR specification and need only implement their own passes 1-3.

### Why ANF over CPS/SSA

**CPS (Continuation-Passing Style):** CPS encodes control flow as function calls to continuations. Bitcoin Script has no functions, no call stack, and no closures. Using CPS would mean introducing abstractions (continuations) that must then be completely eliminated before code generation -- a wasted transformation.

**SSA (Static Single Assignment):** SSA uses phi-nodes at control flow merge points. Phi-nodes work well for register machines where you need to decide which register holds a value after a branch. Bitcoin Script is a stack machine -- there are no registers. The stack lowering pass needs linear evaluation order, which ANF provides directly. SSA would require an additional linearization pass.

**ANF** is the natural fit: it names every intermediate value (giving the stack scheduler something to work with), preserves evaluation order (left-to-right, top-to-bottom), and keeps control flow explicit (`if`/`loop` nodes map directly to `OP_IF`/`OP_ENDIF`).

### Why ts-morph

The compiler needs to parse TypeScript source and extract contract structure. Three options were considered:

| Option | Pros | Cons |
|---|---|---|
| Raw TypeScript Compiler API | Maximum control, no wrapper overhead | Verbose, unstable API across TS versions |
| ts-patch | Can hook into `tsc` pipeline | Requires patching the TypeScript install, fragile |
| **ts-morph** | Clean wrapper API, stable, well-documented | Pulls in full TypeScript as dependency |

`ts-morph` was chosen because it provides a stable, well-documented API for AST navigation and type resolution. The dependency cost (pulling in TypeScript) is acceptable since Rúnar already requires TypeScript for type-checking contracts. The alternative -- using the raw compiler API -- would mean tracking internal API changes across TypeScript releases.

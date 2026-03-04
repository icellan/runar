# runar-compiler

**Rúnar reference compiler: TypeScript to Bitcoin Script via a 6-pass nanopass pipeline.**

This package is the canonical compiler implementation. It reads `.runar.ts`, `.runar.sol`, and `.runar.move` source files, runs them through six sequential passes, and produces a compiled artifact containing the Bitcoin Script bytecode, the canonical ANF IR, and metadata.

---

## Installation

```bash
pnpm add runar-compiler
```

## API Usage

```typescript
import { compile } from 'runar-compiler';

const source = `
import { SmartContract, assert, PubKey, Sig, hash160, checkSig } from 'runar-lang';

export class P2PKH extends SmartContract {
  readonly pubKeyHash: ByteString;

  constructor(pubKeyHash: ByteString) {
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
  fileName: 'P2PKH.runar.ts',
});

console.log(result.success);      // true if no errors
console.log(result.scriptHex);    // hex-encoded Bitcoin Script
console.log(result.scriptAsm);    // human-readable ASM
console.log(result.artifact);     // full RunarArtifact
console.log(result.contract);     // parsed ContractNode AST
console.log(result.anf);          // ANF IR program
console.log(result.diagnostics);  // warnings and errors
```

`compile()` runs all 6 passes: Parse, Validate, Type-check, ANF Lower, Stack Lower (+ peephole optimize), and Emit (+ artifact assembly). It **never throws** -- all errors are caught and returned as diagnostics in the `CompileResult`. If a pass produces errors, subsequent passes are skipped and the partial result is returned.

### CompileOptions

```typescript
interface CompileOptions {
  /** Source file name for error messages and parser dispatch. Defaults to "contract.ts". */
  fileName?: string;

  /** If true, stop after parsing (Pass 1). */
  parseOnly?: boolean;

  /** If true, stop after validation (Pass 2). */
  validateOnly?: boolean;

  /** If true, stop after type-checking (Pass 3). */
  typecheckOnly?: boolean;

  /** Bake property values into the locking script (replaces placeholders). */
  constructorArgs?: Record<string, bigint | boolean | string>;
}
```

The `fileName` extension controls parser dispatch:
- `.runar.ts` — TypeScript parser (ts-morph)
- `.runar.sol` — Solidity-like parser (hand-written recursive descent)
- `.runar.move` — Move-style parser (hand-written recursive descent)

### CompileResult

```typescript
interface CompileResult {
  /** The ANF IR program (null if compilation stopped early or failed). */
  anf: ANFProgram | null;

  /** The parsed contract AST (available after Pass 1). */
  contract: ContractNode | null;

  /** All diagnostics (errors and warnings) from all passes. */
  diagnostics: CompilerDiagnostic[];

  /** True if there are no error-severity diagnostics. */
  success: boolean;

  /** The compiled artifact (available if passes 5-6 succeed). */
  artifact?: RunarArtifact;

  /** Hex-encoded Bitcoin Script (available if passes 5-6 succeed). */
  scriptHex?: string;

  /** Human-readable ASM representation (available if passes 5-6 succeed). */
  scriptAsm?: string;
}
```

### Diagnostics

```typescript
interface CompilerDiagnostic {
  message: string;
  loc?: SourceLocation;
  severity: 'error' | 'warning';
}
```

No error code system — diagnostics use plain-text messages with optional source locations.

### Constructor Slots and Argument Baking

The compiled artifact includes `constructorSlots`, which record the byte offsets of constructor parameter placeholders in the emitted script:

```typescript
interface ConstructorSlot {
  paramIndex: number;   // index of the constructor parameter
  byteOffset: number;   // byte offset in the script hex where the placeholder lives
}
```

When `constructorArgs` are provided in `CompileOptions`, the compiler replaces ANF property `initialValue` fields before stack lowering. This produces a complete locking script with real push-data values instead of `OP_0` placeholders. Without `constructorArgs`, the script contains placeholder bytes that must be spliced at deploy time using the `constructorSlots` offsets from the artifact.

---

## Individual Pass Functions

Each pass is also exported individually for fine-grained use:

```typescript
import { parse, validate, typecheck, lowerToANF } from 'runar-compiler';
import { parseSolSource, parseMoveSource } from 'runar-compiler';

// Pass 1: Parse
const parseResult = parse(source, 'MyContract.runar.ts');

// Pass 2: Validate
const validationResult = validate(parseResult.contract);

// Pass 3: Type-check
const typeCheckResult = typecheck(parseResult.contract);

// Pass 4: ANF Lower
const anf = lowerToANF(parseResult.contract);
```

---

## Pipeline Overview

```
  Source (.runar.ts / .runar.sol / .runar.move)
       |
       v
  +-----------+     +-----------+     +------------+
  |  Pass 1   | --> |  Pass 2   | --> |  Pass 3    |
  |  PARSE    |     |  VALIDATE |     |  TYPECHECK |
  +-----------+     +-----------+     +------------+
       |                 |                  |
    Rúnar AST        Validated AST      Typed AST
                                           |
                                           v
                     +------------+     +-----------+
                     |  Pass 4    | --> |  Pass 5   |
                     |  ANF LOWER |     |  STACK    |
                     +------------+     |  LOWER    |
                          |             +-----------+
                       ANF IR                |
                     (canonical JSON)     Stack IR
                                        (stack offsets)
                                             |
                                             v
                     +------------+     +------------+
                     |  Pass 6    | <-- |  Peephole  |
                     |  EMIT +    |     |  Optimize  |
                     |  Artifact  |     |  (always)  |
                     +------------+     +------------+
                          |
                     Bitcoin Script
                     (hex bytes)
                     + RunarArtifact
```

The peephole optimizer runs on Stack IR between passes 5 and 6 (always enabled). The constant folding optimizer is available between passes 4 and 5 but disabled by default to preserve ANF conformance.

---

## Error Classes

```typescript
import { CompilerError, ParseError, ValidationError, TypeError, makeDiagnostic } from 'runar-compiler';
```

| Class | Thrown During |
|---|---|
| `ParseError` | Pass 1 — source cannot be parsed into Rúnar AST |
| `ValidationError` | Pass 2 — AST violates language subset constraints |
| `TypeError` | Pass 3 — expressions have incompatible types |

---

## Design Decisions

### Why Nanopass

Each pass is ~100-200 lines and does exactly one transformation. Bugs are localized: if the ANF IR is correct but the script is wrong, the problem is in Pass 5 or 6.

### Why ANF over CPS/SSA

ANF is the natural fit for a stack machine target: it names every intermediate value (giving the stack scheduler something to work with), preserves evaluation order, and keeps control flow explicit (`if`/`loop` nodes map directly to `OP_IF`/`OP_ENDIF`).

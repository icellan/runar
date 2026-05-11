# Trust Manifest

This document is the authoritative inventory of the assumptions that the
Runar Lean verification currently relies on. It intentionally separates
proved facts, explicit assumptions, and executable defaults.

The drift gate in `scripts/check-tcb-drift.sh` enforces these headline
counts:

| Item | Count | Meaning |
|---|---:|---|
| Project axioms | 82 | Named assumptions in Lean code |
| Opaque executable defaults | 2 | Executable bodies hidden from proofs |
| Opaque defaults with bodies | 2 | Same 2 values, all intentional |
| `partial def` | 0 | No partial definitions under `RunarVerification/` |

## Axiom Inventory

| File | Count | Role |
|---|---:|---|
| `RunarVerification/ANF/Eval.lean` | 45 | Crypto and builtin primitive symbols, including the external hash backend |
| `RunarVerification/Crypto/Spec.lean` | 26 | EC laws, auxiliary key functions, EUF-CMA-style companions |
| `RunarVerification/Stack/TxContext.lean` | 11 | BIP-143 `buildPreimage` extractor companions |

These axioms are permitted by the current policy, but every theorem or
status claim that depends on them must say so. They are not hidden by
the top-level theorem names.

## External Hash Backend

`Crypto.HashBackend` supplies SHA-256 and RIPEMD-160 to the Lean model.
Lean does not prove or implement those algorithms; proofs quantify over
the backend. `Crypto.hash160` and `Crypto.hash256` remain concrete
definitions over that backend, so their linking lemmas are `rfl`.
Lean code generation uses a fail-fast backend via `implemented_by`; if a
Lean executable reaches these hashes without an external backend model,
it aborts instead of producing a placeholder digest.

Runtime confidence for the Runar implementations is handled outside
Lean: `conformance/runtime-vectors/hashes.json` carries fixed vectors
for `sha256`, `ripemd160`, `hash160`, and `hash256`, and
`packages/runar-testing/src/__tests__/runtime-vectors.test.ts` checks
those vectors against Node.js `crypto` plus the Runar runtime.

## Opaque Executable Defaults

| Symbol | File | Default body | Status |
|---|---|---|---|
| `Crypto.checkSig` | `ANF/Eval.lean` | `false` | Must become an explicit oracle/assumption for proof-facing execution |
| `Stack.Eval.checkMultiSigStub` | `Stack/Eval.lean` | `false` | Must become real multisig semantics or an explicit oracle |

These defaults make the VM executable. They are not sufficient for a
deployed-contract soundness claim.

## Proven Or Empirical Anchors

* `goldenLoad`: all 49 conformance ANF files parse and satisfy `WF.ANF`.
* `roundtrip`: all 49 ANF files round-trip through the Lean JSON model.
* `pipelineGolden`: default gate checks 34 live byte-exact fixtures.
* Peephole proofs cover the proved rewrite substrate; remaining
  composition obligations must match the exact passes used by
  `Pipeline.peepholeProgram`.
* `Pipeline.compileSafe` rejects sentinel `OP_RUNAR_*` opcodes and
  unknown emitter opcodes before byte emission.

## Not Yet Proven

These are active proof obligations, not historical notes:

* End-to-end `compileSafe` soundness from ANF evaluation to parsed Script
  execution for deployed bytes.
* Full lowering simulation from all supported ANF constructors to Stack VM
  execution.
* Emit/parse round-trip for the complete emitted subset.
* Consensus-faithful semantics for sighash, `OP_CODESEPARATOR`,
  authentication opcodes, and byte/number conversion opcodes.
* Replacement or parameterization of the two authentication executable
  defaults above.
* Live or stored-Lean-constant verification for the 15 crypto-heavy
  fixtures currently outside the default byte-exact count.

## Policy

New assumptions must be added as named axioms with a short soundness
story in this file and a matching `check-tcb-drift.sh` update. New
opaque executable defaults are not allowed unless they are explicitly
accepted as part of this manifest and counted by the drift gate.

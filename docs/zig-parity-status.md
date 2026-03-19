# Zig Parity Status

Legend:

- `🟩` strong / natural
- `🟨` acceptable compromise
- `🟧` works but awkward
- `🟥` real gap

## Cross-Language Matrix

| Area | TS | Go | Rust | Python | Zig | Meaning |
|---|---|---|---|---|---|---|
| Compiler correctness | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig is fully green on compiler tests and conformance |
| Native frontend syntax | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | Zig parses and compiles well, but the surface is not yet fully plain-Zig natural |
| Native helper/runtime package | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | `packages/runar-zig` exists, compile-check is now honest, stateful continuation serialization is explicit in test mode, raw outputs are now recordable directly, honest serialized P2PKH outputs are available through `buildChangeOutput`, and all six SHA2 SLH-DSA verifier paths are now real; the remaining crypto depth gaps are broader EC/PQ runtime depth rather than missing SLH variants |
| Example inventory parity | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig now has the same 21-example tree |
| Adjacent native tests | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | Zig now has tests beside the contracts |
| Real contract execution in tests | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | The direct-contract set is now materially larger, including `tic-tac-toe`, `sphincs-wallet`, and `schnorr-zkp`; the remaining gaps are runtime-depth issues rather than the old fixed-width bigint wall |
| Stateful contract model fit | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | Zig now has an honest explicit `StatefulContext` bridge, and the live example tree has effectively migrated to it for output/preimage-touching contracts |
| Byte/string equality fit | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | Zig now has an explicit `runar.bytesEq(...)` model and the active example tree uses it in the places that previously depended on dishonest slice equality |
| Failure/assertion model fit | 🟩 | 🟨 | 🟨 | 🟨 | 🟧 | Zig needs a more deliberate contract-failure story |
| Test quality vs mirrors | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | There are no remaining `Mirror*` example test structs; the gaps are now runtime-depth issues rather than fake-local-logic test structure |

## Language-Specific Boundaries

| Language | Main Native Challenge | What We Accept | What We Should Not Accept |
|---|---|---|---|
| TypeScript | DSL pressure, reference-compiler complexity | AST/reference role, stronger tooling assumptions | Hidden semantics that diverge from source language expectations |
| Go | No classes, less expression-heavy syntax | struct tags, explicit helper calls, embedded support types | unnatural OO emulation |
| Rust | Macro-heavy ergonomics | attributes/macros if explicit and type-safe | opaque macro magic that hides contract behavior |
| Python | dynamic runtime, decorators | decorators and runtime helpers | relying on dynamic behavior with weak compile guarantees |
| Zig | no inheritance, strict slice semantics, visible ownership | explicit helpers, wrappers, composition, comptime type helpers | fake inheritance, operator overloading-by-convention, hidden runtime magic |

## Where Zig Is Being Shoehorned

| Zig Area | Current State | Rating | Why |
|---|---|---|---|
| `pub const Contract = runar.StatefulSmartContract;` | treated like base-class inheritance | 🟥 | Zig does not work that way |
| `self.addOutput(...)`, `self.txPreimage` | replaced in the live example tree by explicit `ctx: runar.StatefulContext` for output/preimage-touching contracts | 🟨 | the new shape is honest; the remaining gap is runtime depth, not hidden stateful members in examples |
| byte/content equality in contract syntax | explicit `runar.bytesEq(...)` in the relevant live examples | 🟨 | the honest API exists and is in use, but it still needs to remain the documented norm |
| `runar.Readonly(T)` | explicit type-level marker | 🟩 | this fits Zig reasonably well |
| `packages/runar-zig` as helper/runtime layer | explicit package boundary with test-only continuation serialization and shared test fixtures | 🟨 | good direction, validator/compile-check is now honest, but advanced crypto remains scaffolded |
| adjacent example tests | present and runnable | 🟨 | structure is right, and the remaining quality gap is runtime depth rather than mirror scaffolding |

## Zig-Specific Decision Matrix

| Topic | Current Approach | Problem | Better Zig-Shaped Direction | Status |
|---|---|---|---|---|
| Contract base model | pseudo-inheritance via `pub const Contract = ...` | implies hidden fields/methods | explicit composition or explicit helper surface | Open |
| Stateful helpers | explicit `ctx: runar.StatefulContext` on the live stateful/output-touching examples | runtime depth still varies across the hardest examples | keep the explicit context model and use runtime work, not syntax backsliding, to close the remaining gaps | Good |
| Bytes equality | explicit `runar.bytesEq(...)` in the live examples that need byte-content comparison | remaining work is consistency and documentation, not inventing a new hidden operator meaning | keep `runar.bytesEq(a, b)` as the honest API | Good |
| Readonly fields | `runar.Readonly(T)` | acceptable, but needs consistent examples/docs | keep, refine, and document as the canonical explicit marker | Good |
| Contract failure model | mostly piggybacks on `runar.assert` | not yet clearly designed for Zig-native tests | explicit, documented assertion/failure behavior for `zig test` | Partial |
| Ownership/allocation | hidden in helper calls | can become noisy or surprising | keep high-level helpers but make ownership rules explicit and boring | Partial |
| Example tests | many mirror implementations | proves less than real contract execution | migrate the remaining EC/PQ-heavy priority examples to direct contract tests as semantics become natural | Partial |

## Current Wave Progress

- Removed the Zig constructor-validation suppression from `packages/runar-zig`; compile-check now fails honestly and the validator understands Zig `init` assignment semantics directly.
- Upgraded several core helper semantics in `packages/runar-zig`, including `ripemd160`, `hash160`, signed-magnitude `num2bin` / `bin2num`, `checkMultiSig`, `sha256Compress`, `sha256Finalize`, and single-block `blake3` helpers.
- Converted three example suites from mirror-only behavior tests to partial real-contract execution:
  - `escrow`
  - `stateful-counter`
  - `property-initializers`
- Added a dedicated Zig `assert_probe` executable so negative-path contract assertions can be tested honestly from the example suite without pretending panics are catchable in-process.
- Centralized the Zig assertion-failure marker in `packages/runar-zig`, taught `assert_probe` to emit an explicit machine-readable assertion tag on panic, and taught the example probe helper to print stdout/stderr when a negative-path probe fails for the wrong reason, so assertion regressions are easier to diagnose.
- Added an explicit `runar.bytesEq(...)` path in both Zig frontends and `packages/runar-zig`, then used it to migrate the first byte-comparison contracts away from misleading plain `==`.
- Added an explicit `runar.StatefulContext` bridge in `packages/runar-zig` and both Zig compiler pipelines. The compiler now erases that source-level context from the ABI while native Zig tests can seed it with real preimages and inspect real outputs.
- Migrated `auction` to the explicit context model and converted it to direct real-contract tests, including probe-backed negative assertions.
- Migrated `token-ft` to the explicit context model, explicit `runar.bytesEq(...)`, and real output-capture tests.
- Migrated `token-nft` to the explicit context model and direct output-capture tests.
- Migrated `tic-tac-toe` to the explicit context model for `cancel`, `moveAndWin`, and `moveAndTie`, and replaced dishonest pubkey/output equality with `runar.bytesEq(...)`.
- Replaced mirror coverage in `ec-demo` and `convergence-proof` with direct real-contract execution.
- Replaced the `oracle-price` mirror with a real Rabin-backed positive contract test.
- Replaced the old tiny-modulus Oracle proof trick with the shared deterministic Rabin test modulus and checked-in deterministic proof fixtures in `runar.testing`.
- Added a real positive direct-contract path for `post-quantum-wallet` using deterministic WOTS fixtures in the Zig test itself.
- Added explicit test-only continuation serialization in `packages/runar-zig`, so recorded stateful outputs now carry deterministic `stateScript` and `continuationScript` bytes instead of only tuple snapshots.
- Tightened the `token-ft` and `token-nft` Zig tests so they assert those serialized continuation bytes, not just the raw tuple values.
- Switched the top-level `sha256` / `ripemd160` / `hash160` / `hash256` runtime wrappers in `packages/runar-zig` over to `bsvz`, route `checkSig` / fixture signing through `bsvz`'s `PrivateKey` / `PublicKey` / `DerSignature` crypto surface, and now use `bsvz.transaction.preimage` for preimage parsing/extraction too.
- Switched `runar-zig`'s `num2bin` / `bin2num` over to `bsvz.script.ScriptNum`, keeping the external `runar.Bigint` surface but dropping another local script-number implementation seam.
- Collapsed the `runar-zig` Zig dependency boundary to a single `bsvz` module import. `bsvz` itself is now green, and the package-level script lane now has an honest split: compiler smoke coverage stays local while representative execution vectors run through the shared `bsvz` Runar harness.
- `bsvz` is currently green locally at `333/333` tests, now exposes a public secp256k1 point API, compact verification outcomes, prevout-spend helpers, and trace/debug helpers, and `runar-zig` has switched its local point math/parsing/serialization onto that seam.
- `runar-zig`'s output/preimage test helpers now go through public `bsvz.transaction.Output` / `hashOutputs(...)` APIs instead of local byte concatenation, and the package-level script harness now asserts structured verification outcomes instead of reducing everything to a bare boolean too early.
- The package-level script harness now uses traced verification as its primary path, so mismatches report the real outcome plus phase/opcode trace context instead of ad hoc branch-specific strings.
- Replaced the last baked locking-script hex in the package-level script lane with constructor-aware compilation from the actual inline contract sources, so the harness now exercises real current compiler output instead of pinned stale hex.
- Added a tiny internal `runar-zig` hex helper backed by `bsvz` primitives and migrated the Zig probes/tests onto that shared path instead of keeping separate local alloc-decoding helpers in each file.
- Removed the redundant `runar.testing.decodeHexAlloc(...)` passthrough, switched the remaining tests/probes to `runar.hex.decodeAlloc(...)`, and moved the SPHINCS fixed-size fixture decoding onto the shared `runar.hex.decodeFixed(...)` path too.
- Extracted the duplicated deterministic WOTS fixture/signing logic into a shared leaf helper so both `builtins` and `testing_helpers` now use one implementation instead of carrying drift-prone copies.
- Added shared Zig testing helpers for canonical P2PKH outputs and output-hash preimages, then migrated `covenant-vault` and the payout/output-hash half of `tic-tac-toe` to use them instead of hand-assembling those bytes inline.
- Added a real `hashOutputs()` bridge in `packages/runar-zig` that serializes recorded outputs with the same `8-byte LE satoshis + varint(script_len) + script` shape used by `bsvz`.
- Restored `examples/zig/assert_probe.zig` as a real subprocess probe runner and got the full `examples/zig` lane green again on a fresh cache.
- Prepared deterministic SPHINCS public-key and signature fixtures from the TypeScript reference implementation and wired them into a real positive Zig test.
- Switched the EC-heavy Zig examples away from paired `ecPointX(...)` / `ecPointY(...)` equality checks and onto canonical compressed-point comparison, which keeps the contract surface honest without introducing a new compiler builtin.
- Switched `runar-zig`'s `cat` / `substr` wrappers over to `bsvz.script`, promoted the compiler's internal `buildChangeOutput(...)` primitive into the Zig/native public surface, and migrated the remaining payout-heavy Zig examples/tests off the old ASCII-hex pseudo-output path.
- Added real `addRawOutput(...)` recording support to the Zig runtime surface so `StatefulContext` now matches the raw-output capability already present in the compiler model.
- Simplified `buildChangeOutput(...)` down to one direct output allocation while keeping its wire format locked to `bsvz`'s P2PKH script and varint encoding.
- Simplified `buildChangeOutput(...)` again to delegate its wire-format serialization directly to public `bsvz.transaction.Output.writeInto(...)` instead of manually re-encoding the output locally.
- Switched `runar-zig`'s stateful `hashOutputs()` bridge and the output-preimage test helper over to public `bsvz.transaction.Output.hashAll(...)`, and switched serialized-output parsing in the helper lane over to public `bsvz.transaction.Output.parse(...)` instead of manual local decoding.
- The remaining direct-execution blockers are now clearer:
  - the remaining EC/PQ-heavy examples that still lack deeper runtime coverage
- Advanced crypto helpers are still not honest enough:
  - all six public SHA2 SLH-DSA verifier paths are now real and fixture-backed in Zig
  - some higher-level post-quantum example semantics are still scaffolded
  - `bsvz` now covers hashes, signatures, script numbers, preimage parsing, and secp256k1 point math well enough to be the real foundation seam; the remaining EC issue is the Runar-facing `i64`-shaped point access model rather than missing sibling support
- The example negative-path harness integrity issue is closed:
  - the probe runner is restored in-tree and the fresh-cache example lane is green

## Target Model

What “good” should look like for Zig:

1. A Zig developer can open a `.runar.zig` contract and it reads like honest Zig.
2. The runtime surface the contract depends on is explicit in the code, not implied by fake inheritance.
3. If a construct has special contract semantics, the syntax should signal that clearly.
4. Adjacent Zig tests should mostly exercise the real contract modules, not mirrors.
5. `packages/runar-zig` should feel like a coherent native helper/runtime package, not a grab bag of compiler accommodations.

## What Is Already Strong

- Compiler correctness and conformance are green.
- The Zig frontend now has explicit readonly syntax.
- `packages/runar-zig` now validates Zig constructors honestly instead of suppressing a known error.
- `packages/runar-zig` now has materially better hash/byte/number helper semantics for the simpler examples.
- The full 21-contract Zig example tree exists with adjacent tests.
- `escrow`, `stateful-counter`, `property-initializers`, `auction`, `token-ft`, and `token-nft` now execute the real contract module for their positive-path tests.
- `covenant-vault` now also covers its wrong-signature and wrong-output assertion paths through the shared subprocess probe.
- `stateful-counter` and `property-initializers` now also cover their negative assertion paths through a dedicated subprocess probe instead of mirrors.
- `p2pkh`, `p2blake3pkh`, `blake3`, `sha256-compress`, and `sha256-finalize` now use explicit `runar.bytesEq(...)` and execute real contract paths in their Zig tests, including real negative assertion probes.
- `auction`, `token-ft`, and `token-nft` now prove the explicit `StatefulContext` direction in real tests instead of mirrors.
- `tic-tac-toe` now has real-contract coverage for join/move/cancelBeforeJoin/cancel/moveAndWin/moveAndTie and their negative assertion rules.
- `ec-demo` and `convergence-proof` now use direct real-contract tests rather than mirrors.
- `oracle-price` and `post-quantum-wallet` now also have honest positive direct-contract tests.
- `oracle-price` now uses the shared deterministic Rabin test modulus instead of the old one-byte modulus trick.
- `token-ft` and `token-nft` now also prove deterministic serialized continuation bytes via the Zig runtime’s explicit test-only stateful output model.
- `sphincs-wallet` now has deterministic real public-key and signature fixture material from the TS reference flow and a positive direct-contract Zig test backed by the `SLH-DSA-SHA2-128s` runtime slice.
- There are no remaining `Mirror*` example test structs in `examples/zig`; the remaining gaps are now runtime-depth problems rather than fake-local-logic test structure.
- The public docs now describe the Zig package and example runner accurately.

## What Still Needs Real Improvement

### 1. Plain-Zig Executability

This is the biggest remaining gap.

Today some `.runar.zig` contracts compile through the Rúnar frontend correctly, but are not naturally executable as ordinary Zig modules because they rely on Rúnar-level semantics that Zig itself does not provide directly.

Representative issues:

- contract-style assertions/failure expectations
- advanced crypto helpers that are still not fully honest for the remaining PQ-heavy cases outside the `SLH-DSA-SHA2-128s` verifier slice
- widening beyond `i64` is now handled through explicit `runar.Bigint` where the contract path really needs it, but the broader ergonomic story is still young
- the remaining example issues are runtime-depth and API-shape problems, not leftover dishonest byte-equality syntax in the shipped Zig examples

### Cross-Implementation Notes

Some of the remaining blockers are not unique to Zig:

- `schnorr-zkp` is still intentionally not fully native-executed in the Rust example tree because the Fiat-Shamir challenge derived from `bin2num(hash256(...))` exceeds Rust's current fixed-width bigint model there.
- `sphincs-wallet` is gated behind an external `slh-dsa` dependency in the Python example tree, which made the Zig verifier slice a real runtime-implementation task rather than just test wiring.

That does not make the Zig gaps acceptable, but it does change the shape of the work: the remaining frontier is mostly honest runtime depth, not example-tree housekeeping.

### 2. Stateful Surface Design

We need one clear answer for how stateful contracts access runtime features in Zig.

The chosen direction is now clearer:

- explicit helper methods that receive `ctx: runar.StatefulContext`

The unacceptable shape is:

- pretending Zig has class inheritance and injected members

### 3. Direct Example Testing

The test tree shape is now correct, but the quality bar is not met until the important examples are mostly testing the real contracts.

Priority contracts to move next:

- the remaining EC/PQ-heavy example semantics that still need deeper native runtime honesty

## Priority Ladder

| Priority | Work Item | Why |
|---|---|---|
| P0 | migrate the remaining EC/PQ-heavy examples to direct tests where the current runtime can support them honestly | the core stateful model is now chosen; the remaining gaps are in the hardest examples |
| P0 | settle the honest bytes/content equality API across the last unmigrated contracts | this still blocks natural direct execution in the long tail |
| P1 | address the remaining native runtime limits exposed by EC/PQ examples | this is now the main blocker for fully honest direct execution |
| P2 | reduce mirror-test usage across the tree | cleanup after the hardest direct-execution cases are real |

## Acceptance Criteria

We should consider Zig “one of the best implementations” only when most of these are true:

- `packages/runar-zig` is the obvious native way to support Zig contracts and tests
- stateful Zig contracts use an explicit, understandable runtime access model
- byte/content comparisons are expressed honestly
- at least the priority example set runs as real contract tests under `zig test`
- mirrors are the exception, not the default
- docs can explain the Zig model without caveats that sound like compiler escape hatches

## Phased Roadmap

### Phase 1: Make It Honest

- finalize runtime/stateful access design
- finalize byte/content equality design
- remove the most misleading pseudo-inheritance assumptions

### Phase 2: Make It Direct

- convert the priority examples to real-contract tests
- keep compile-check coverage, but stop leaning on mirrors for core confidence

### Phase 3: Make It Excellent

- refine ergonomics
- tighten failure/assertion behavior
- improve advanced EC/PQ example testing quality
- reduce any leftover runtime awkwardness in `packages/runar-zig`

## Bottom Line

| Question | Answer |
|---|---|
| Is the compiler work good enough? | Yes |
| Is the Zig package/test surface useful already? | Yes |
| Is it fully natural and up to the same standard as Go/Rust/Python? | No |
| What most needs improvement? | direct execution model for `.runar.zig` contracts, especially stateful/runtime semantics |
| What should we protect no matter what? | no fake inheritance, no dishonest operator semantics, no mirror-heavy tests as the final state |

## Guiding Standard

If a Zig developer reads the code, it should look like honest Zig with explicit Rúnar helpers, not Zig-shaped syntax carrying hidden compiler-only meanings.

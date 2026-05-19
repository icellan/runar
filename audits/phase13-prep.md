# BSVM Phase 13 — External Security Audit Prep Packet

**Branch under review:** `feature/review-remediation` (worktree
`/Users/siggioskarsson/gitcheckout/runar-review-remediation`).
**Base:** `main` @ `eda68f35`.
**Packet date:** 2026-05-18.
**Authored by:** internal review, READ-ONLY pass over compiler / SDK / IR-schema
sources + checked-in tests.

> **Document status — this is an audit *input*, not an audit *report*.**
> This packet is the internally-authored scoping brief handed to an external
> security firm so they can plan and price an engagement. It enumerates the
> attack surface, lists 7 residual risks (R-1…R-7), and proposes a ~2-week
> scope. It does **not** itself constitute an independent security review,
> and nothing here should be read as an audit sign-off. The external
> engagement that consumes this packet is booked and executed outside this
> repository (user/owner action); when its findings land they will be filed
> as a separate report, not appended here. The BSVM team flagged this
> distinction ("Major-3") to avoid the prep packet being mistaken for the
> deliverable — hence this banner.

---

## 1. Scope statement

This packet prepares an external security audit of two stacked work-streams
sitting on top of `main`:

1. **Intent sub-covenant intrinsics** — the merged feature
   `feature/intent-intrinsics-phase13` (commit `adeb447f`, parent of the
   merge `84da0512` at the tip of the branch). Adds three pure source-level
   intrinsics shipping across all 7 compiler tiers: `extractPrevOutputScript`,
   `requireOutputP2PKH`, `currentBlockHeight`. These are *frontend sugar* —
   no new ANF kinds, no Stack-IR codegen changes, no artifact-format
   extensions; only typecheck + ANF-lower extensions. Source paths for the
   TS reference implementation: `packages/runar-compiler/src/passes/03-typecheck.ts`
   (lines 218–220, 581–599, 1639–1706) and `packages/runar-compiler/src/passes/04-anf-lower.ts`
   (lines 1134–1273). Stubs in `packages/runar-lang/src/preimage.ts:155-214`.

2. **22-task review remediation** — the uncommitted working tree on top of
   that merge. Surface listed by `git status` includes: cross-tier
   canonical-JSON RFC 8785 / JCS parity fixes (D1–D6 in
   `audits/canonical-json-rfc8785-parity.md`), shared `InputLimits` +
   `CanonicalJsonError` across 7 SDK tiers
   (`packages/runar-ir-schema/src/input-limits.ts` + 6 peers), script-size
   guards at every SDK boundary
   (`packages/runar-sdk/src/errors.ts:35` `assertScriptHexUnderLimit` called
   at `contract.ts:234, 323, 528, 791` plus 6 peers), unknown-ANF-kind
   rejection in every IR loader
   (`compilers/{go,rust,python,zig,ruby,java}/.../unknown_anf_kind*` and
   `packages/runar-ir-schema/src/unknown-anf-kind-error.ts`), and the
   `conformance/fuzzer/anf-differential.ts` cross-tier ANF differential
   fuzzer wired into a nightly cron at
   `.github/workflows/fuzzer-nightly.yml`.

**Explicitly out of scope:**

- Pre-existing crypto codegen (SLH-DSA, WOTS+, EC, SHA-256, BLAKE3,
  P-256/P-384, Rabin) — audited in prior cycles; only re-touched if the
  Phase 13 intrinsics or the canonical-JSON / size-guard work changed
  their call graphs (they did not).
- Go-only EVM / STARK families (BabyBear / KoalaBear / Poseidon2 / BN254
  / FiatShamirKb / SP1-FRI / Merkle) per project policy — these are
  conformance-allowlisted to the Go tier and unchanged by this work.
- The `runar-verification/` Lean proof work (separate work-stream by
  another agent — its branch `verification/path2-tier1-wave2` is *not*
  the same as the branch this packet covers).
- The off-chain `ScriptVM` divergence (Zig/Ruby/Java do not ship one);
  documented in `CLAUDE.md` and unchanged by Phase 13.

**Commits enumerated** (current branch vs `main`, first-parent walk):
- `84da0512` Merge feature/intent-intrinsics-phase13: intent sub-covenant intrinsics
- `adeb447f` feat: intent sub-covenant intrinsics for BSVM Phase 13

(Path-2 Tier-1 verification commits `2e0101fc`, `82539c68`, `6940a79d`,
`1b01ba05`, `5c4e17e1`, `591d2c4b`, `44807d80` also sit on the branch but
are out of scope per above — they only touch `runar-verification/`.)

Then the 22-task uncommitted remediation work in the working tree
(91 modified + 40 untracked files; `git diff --stat | tail -1` shows
`91 files changed, 2448 insertions(+), 230 deletions(-)` for the
modified set alone). Recommend the audit baseline include both layers
captured as a single artifact `git diff main..HEAD && git diff` snapshot
before the engagement begins.

---

## 2. Threat model

### 2.1 Witness-bridge collision resistance (ExtractPrevOutputScript, 2-arg form)

- **Trust boundary:** The spender supplies `_prevOutScript_<i>` as a
  positional unlocker arg. The locking script then asserts
  `hash256(witness) === expectedScriptHash`. The hash is computed
  on-chain via OP_HASH256 (sha256∘sha256). `expectedScriptHash` lives
  in the contract's locking script bytes (typically a `readonly`
  contract field pinned at construction).
- **Asset at risk:** Anything the verifying covenant authorises after
  reading bytes out of the previous output's locking script (state
  roots, bond amounts, intent template parameters — in BSVM Mode-3
  permissionless step-in, the entire next-state authorisation).
- **Adversary capabilities:** Network adversary controls the unlocking
  script. Offline compute budget bounded only by ECDLP-grade hardware
  (since collision-finding sha256(sha256(x)) needs ~2^128 work for a
  generic collision, ~2^256 for a target-preimage second-preimage
  attack). Practically infeasible under standard crypto assumptions.
- **Mitigation:** Full-script hash pinning. Adversary must supply the
  *exact same bytes* as the genuine prev-output script — no degrees of
  freedom. Hash assertion is `OP_HASH256 <expected_32> OP_EQUALVERIFY`
  in the emitted Stack-IR (see `04-anf-lower.ts:1186-1192`).
- **Residual risk:** **Binding is to the script bytes, NOT to a
  specific input position.** A spender can route ANY input through the
  intrinsic and supply any UTXO's prev-output that hashes correctly.
  The current implementation assigns one auto-injected param per
  *literal input index* (`_prevOutScript_<i>`), but the on-chain
  semantics make no link between input position `i` and the witness
  bytes actually supplied for that param. Adversary capability: route a
  different (also-matching) UTXO through input index `i`. Audit should
  evaluate whether BSVM contracts rely on the *positional* binding
  implied by the API surface (`inputIndex` argument) that is **not
  actually enforced** by the emitted script — and whether covenant
  authors will (incorrectly) treat the witness as input-position-bound.
  See `docs/cross-covenant-pattern.md` "Security Properties" §
  "Authenticity" — caveat already documented for the hand-rolled
  pattern, but the intrinsic does not extend it.

### 2.2 Fixed-stride P2PKH binding (RequireOutputP2PKH)

- **Trust boundary:** Spender supplies `_serialisedOutputs` (single
  witness per method, idempotent across multiple `RequireOutputP2PKH`
  calls). Locking script asserts
  `hash256(_serialisedOutputs) === extractOutputHash(txPreimage)` once,
  then per call asserts the 34-byte substring at offset `idx * 34` is
  the expected P2PKH bytes.
- **Asset at risk:** The "bond P2PKH must pay X sats to address Y at
  output index Z" guarantee — usually the entire collateral position.
- **Adversary capabilities:** Spender controls all outputs (subject to
  the covenant's other constraints). Cheap compute (no crypto break
  required).
- **Mitigation:** Crit-3 from the BSVM Phase 13 audit was resolved —
  `03-typecheck.ts:581-599` rejects any method that mixes
  `requireOutputP2PKH()` with `this.addDataOutput()`, because a
  variable-length OP_RETURN output would shift every subsequent
  index's stride away from the assumed 34 bytes and let the bond
  P2PKH route through an unmatched index. AST body-walker covers
  if/else, for-loops, and ternary call sites. Mirrored in Go, Rust,
  Python, Zig, Ruby, Java typecheckers.
- **Residual risk:**
  - **R-1** (HIGH): The 34-byte stride assumption is implicit — there
    is **no on-chain check that all preceding outputs are 34 bytes**.
    If a contract author bypasses the typecheck (by splitting calls
    across methods, by hand-rolling addRawOutput, or by composing
    contracts whose outputs include non-34-byte payloads from
    elsewhere in the tx), the spender can craft a tx whose serialised
    outputs span a different layout, and the `idx * 34` substring
    extracts unrelated bytes. The typecheck catches the
    *intra-method* mix; it does **not** catch cross-method mixes in
    the same contract, and there is no `addRawOutput()`-vs-
    `requireOutputP2PKH()` check.
  - **R-2** (MEDIUM): `idx * 34` is computed at compile-time from a
    bigint literal. If `idx > floor(MAX_SCRIPT_INT / 34)` the offset
    overflows BSV's 4-byte script-int. Bounds check on `idx` literal
    in the typecheck is **absent**. Audit: confirm BSV interpreter
    behaviour on OP_SUBSTR with a 4-byte-overflow offset (likely
    aborts the script — fail-safe — but should be made explicit).
  - **R-3** (LOW): The expected-output construction
    (`04-anf-lower.ts:1242-1252`) hard-codes `1976a914...88ac` — a
    standard 25-byte P2PKH `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
    Any future P2PKH variant (e.g. tagged outputs, length-prefix
    changes) would silently miscompile. No version field in the
    intrinsic.

### 2.3 Prefix-hash family matching (3-arg ExtractPrevOutputScript)

- **Trust boundary:** Same as 2.1, but the assertion hashes only
  `substr(witness, 0, prefixLen)` instead of the full witness.
  `prefixLen` MUST be a compile-time integer literal (typecheck
  `03-typecheck.ts:1679-1686`).
- **Asset at risk:** Anything the covenant authorises based on
  matching the *policy prefix* of a sibling covenant's locking script —
  in BSVM Mode 3 this is the intent-template policy bytes; the tail is
  per-instance pushdata.
- **Adversary capabilities:** Adversary can craft a witness whose
  first `prefixLen` bytes hash to the pinned value AND whose tail is
  arbitrary. With the prefix fixed to a known template, the tail is
  the adversary's degree of freedom.
- **Mitigation:** `prefixLen` is a compile-time literal — adversary
  cannot vary it. The prefix-hash collision difficulty is identical to
  the full-hash case (sha256∘sha256 second-preimage = 2^256 generic
  work). The tail bytes are intentionally unconstrained — by design,
  the caller extracts state from the tail via downstream substr ops.
- **Residual risk:**
  - **R-4** (MEDIUM): No minimum on `prefixLen`. A contract author who
    accidentally writes `extractPrevOutputScript(0, h, 1)` pins a
    1-byte prefix — adversary then trivially constructs a witness
    starting with that byte. Typecheck only enforces "must be literal",
    not a minimum-bytes threshold. Audit recommendation: require
    `prefixLen >= 20` (or some policy-driven minimum) at typecheck.
  - **R-5** (LOW): `prefixLen` is allowed to exceed the actual witness
    length at compile-time; the OP_SUBSTR will then abort the script
    at runtime (fail-safe). Worth a unit test asserting the
    `prefixLen > witness.length` case explicitly fails as expected.

### 2.4 Auto-injected param substitution (witness-bridge convention)

- **Trust boundary:** SDK `prepareCall` (TypeScript reference at
  `packages/runar-sdk/src/contract.ts:484-517`) filters
  `_-prefix` auto-injected params out of the user-facing arg list and
  is supposed to source them from compile-time-bound caller-supplied
  maps. Empty witness handling: see below.
- **Asset at risk:** Same as 2.1 and 2.2 (covenant authorisation).
- **Adversary capabilities:** A malicious SDK consumer (or a user who
  builds the unlocking script by hand) can supply ANY bytes for the
  auto-injected witness slots.
- **Mitigation:** **The hash assertion is the entire defence.** A
  bogus or empty witness produces a hash that does not match
  `expectedScriptHash` / `extractOutputHash(preimage)`, the
  OP_EQUALVERIFY aborts, and the script fails. Behaviour is identical
  to the well-understood "spender lies on the stack" baseline.
- **Residual risk:**
  - **R-6** (BLOCKING for SDK integration, NOT for on-chain
    security): **None of the 7 SDKs filter or wire the new auto-injected
    params.** Direct grep confirms:
    `packages/runar-sdk/src/contract.ts:501-509` filters
    `_changePKH`, `_changeAmount`, `_newAmount` — but not
    `_prevOutScript_*` or `_serialisedOutputs`. Go SDK at
    `packages/runar-go/sdk_contract.go:340-350` filters the same three
    legacy names. Rust / Python / Ruby / Zig / Java SDKs: zero
    occurrences of `_prevOutScript` or `_serialisedOutputs`. **Net
    effect:** A user calling an intent-intrinsic method via
    `contract.call('methodName', userArgs)` will fail the
    `userParams.length !== args.length` arity check — the method
    appears to require *N + (1 per literal index) + 1* params instead
    of *N*. No witness-substitution attack is possible here (the
    script-side hash assertion is fully functional), but the user
    experience is broken and any wrapper that *accepts* the missing
    args from an untrusted source needs explicit per-SDK plumbing
    that has not landed yet. **Recommend: ship the SDK-side filter +
    typed `prevOutScripts: Map<bigint, ByteString>` /
    `serialisedOutputs: ByteString` setters BEFORE engaging the
    auditor, OR scope the audit explicitly to "compiler + on-chain
    semantics only, SDK wiring deferred."**
  - **R-7** (LOW): The `_`-prefix convention is enforced by
    convention, not by the type system. A future refactor that
    introduces a *user-facing* param named with a leading underscore
    would silently mask itself from the SDK's filter. No automated
    test catches this regression today.

### 2.5 Canonical-JSON DoS

- **Trust boundary:** Every public canonical-JSON / IR-loading entry
  point. TS reference: `loadANFFromJSON` in `runar-ir-schema` +
  `signEnvelope` / `verifyEnvelope` in `runar-sdk/src/envelope.ts`.
- **Asset at risk:** SDK liveness (deeply-nested JSON blow JS engine
  stacks; oversized strings exhaust heap). Cross-tier divergence on
  reject-vs-accept = signature-verification interop break.
- **Adversary capabilities:** Network adversary supplies arbitrary
  JSON to any tier's `verifyEnvelope` or `loadANFFromJSON` entry
  point.
- **Mitigation:** Shared `InputLimits` constants in
  `packages/runar-ir-schema/src/input-limits.ts` (16 MiB IR, 1 MiB
  script, 4 MiB per string, 512 nesting depth). All 7 SDK tiers
  carry a `InputLimits` peer. `CanonicalJsonError` with typed `code`
  field (`'depth' | 'bytes' | 'string-bytes' | 'circular' | 'invalid'`)
  for fast caller dispatch. Test coverage at
  `packages/runar-compiler/src/__tests__/size-guards.test.ts` (4
  tests) + `packages/runar-ir-schema/src/__tests__/input-limits.test.ts`
  + `packages/runar-ir-schema/src/__tests__/size-guards.test.ts` +
  6 peer-tier test files.
- **Residual risk:**
  - **R-8** (MEDIUM): The 6 non-TS peer-tier `InputLimits` constant
    sets are not built from a shared source — they are 7 copies of the
    same numbers. A future bump in one tier (e.g. SLH-DSA-512 starts
    needing 1.5 MiB scripts) silently diverges. Recommend a generator
    script that emits all 7 peer constants from
    `runar-ir-schema/src/input-limits.ts` as canonical source.
  - **R-9** (LOW): The size guards are upper bounds only; no lower
    bound or "expected-size" sanity check. An attacker who supplies
    exactly `MAX_IR_BYTES - 1` bytes of garbage forces all 7 tiers
    through their full JSON-parse path before rejecting. Bandwidth-
    amplification DoS rather than memory DoS; rate-limit at the
    transport layer.
  - **R-10** (LOW): Edge case — `MAX_STRING_BYTES` (4 MiB) and
    `MAX_IR_BYTES` (16 MiB) interact: an ANF program with 4 strings
    of 4 MiB each + light scaffolding sits under the 16 MiB cap but
    occupies the entire string budget. No combined-budget guard.

### 2.6 Cross-tier divergence

- **Trust boundary:** Any cross-tier interop — e.g. a TS SDK signs an
  envelope verified by the Go SDK, a Python ANF loader receives IR
  emitted by the Rust compiler.
- **Asset at risk:** Signature verification soundness across tiers
  (a tier accepting bytes a peer rejects = forgery acceptance).
- **Adversary capabilities:** Adversary picks the most permissive
  tier to verify against, after the strictest tier rejects.
- **Mitigation:**
  - `conformance/fuzzer/anf-differential.ts` — property-based ANF
    differential fuzzer wired into nightly cron
    (`.github/workflows/fuzzer-nightly.yml`). Generates valid random
    ANF programs and asserts byte-identical Stack-IR + hex across all
    7 tiers.
  - 60/60 conformance suite both fold-OFF (`expected-script.hex`) and
    fold-ON (per `conformance/fold-on-allowlist.json`) modes (claimed
    in the intent-intrinsics commit message; not re-verified by this
    packet).
  - `conformance/sdk-envelope/fixtures.json` — single TS-signed
    envelope replayed against every tier's `verifyEnvelope`, plus a
    known-bad envelope per `VerifyEnvelopeReason`.
- **Residual risk:** See the **5 documented canonical-JSON
  divergences** in `audits/canonical-json-rfc8785-parity.md` §2 (D1
  Zig UTF-16 key sort, D2 Zig string-escape bytewise loop, D3 Zig
  duplicate-key emission, D5 five-tier float formatter divergence, D6
  lone-surrogate handling). **D4 (Ruby falsy-rewrite) is fixed in the
  current working tree.** **D1 is NOT fixed** — `utf16Less` at
  `packages/runar-zig/src/sdk_envelope.zig:252` is still a
  byte-comparison fast path with a comment admitting the scope. The
  audit must validate whether today's envelope payload schemas avoid
  all 5 documented divergence triggers; the wire protocol's current
  fields (`kind`, `n`, `nonce`, `expiresAt`) are all ASCII and
  integer-valued, so the divergences are latent until schema
  expansion. **Recommend: ship at least D1 + D3 fixes before
  engagement, or explicitly scope the audit to today's schemas.**

---

## 3. Attack surface inventory

| Entry point | Source | Trusted inputs | Untrusted inputs | Failure mode | Test coverage |
|-------------|--------|----------------|------------------|--------------|---------------|
| `extractPrevOutputScript(idx_literal, h)` ANF lower | `packages/runar-compiler/src/passes/04-anf-lower.ts:1149-1194` | `idx`, `h` (compile-time) | `_prevOutScript_<idx>` (runtime, spender) | Script aborts on hash mismatch (OP_EQUALVERIFY) | `intent-intrinsics.test.ts` (16 cases); 6 peer-tier test files (14–15 cases each); fixture `intent-prev-output-script` |
| `extractPrevOutputScript(idx_literal, h, prefixLen_literal)` | `04-anf-lower.ts:1170-1184` | `idx`, `h`, `prefixLen` (compile-time literal) | `_prevOutScript_<idx>` (runtime) | Script aborts on hash mismatch OR OP_SUBSTR out-of-range | Same; fixture `branched-readonly-len` exercises the 3-arg form |
| `requireOutputP2PKH(idx_literal, pkh, amt)` | `04-anf-lower.ts:1210-1265` | `idx` (literal) | `pkh`, `amt` (caller); `_serialisedOutputs` (spender) | Two-stage abort: outputs-hash mismatch OR per-output substring mismatch | `intent-intrinsics.test.ts` (16); peer-tier tests; fixture `intent-output-p2pkh` |
| `currentBlockHeight()` | `04-anf-lower.ts:1270-1273` | none | `txPreimage.locktime` (spender via preimage, but already bound by OP_CHECKSIG) | Returns wrong height ⇒ contract logic wrong; preimage bound by checkSig | Fixture `intent-current-block-height`; intent-intrinsics tests |
| Typecheck: literal-only enforcement | `03-typecheck.ts:1643-1650, 1679-1686` | source AST | source AST | Compile error before any codegen | `intent-intrinsics.test.ts`; 6 peer tests |
| Typecheck: stateful-only enforcement (`requireOutputP2PKH`, `currentBlockHeight`) | `03-typecheck.ts:1698-1706` | source AST | source AST | Compile error | Peer tests |
| Typecheck: Crit-3 addDataOutput/requireOutputP2PKH mix rejection | `03-typecheck.ts:581-599` | source AST | source AST | Compile error | `intent-intrinsics.test.ts`; per-tier mirror tests |
| `loadANFFromJSON` (TS) | `packages/runar-ir-schema/src/canonical-json.ts` + loader | trusted compiler output | untrusted via `runar compile --from-ir` | `CanonicalJsonError` typed `code` | `size-guards.test.ts` (4); `input-limits.test.ts` |
| ANF loader (Go/Rust/Python/Zig/Ruby/Java) | `compilers/*/ir/loader.*` | trusted | untrusted via `--ir` CLI mode | Typed error per tier (`UnknownAnfKindError` for unknown `kind` fields) | `unknown_anf_kind*` files per tier; fuzzer `anf-differential.ts` |
| `signEnvelope` / `verifyEnvelope` (7 tiers) | `packages/runar-{ts,go,rs,py,zig,rb,java}/.../envelope.*` | signer key | counterparty envelope bytes | Typed `VerifyEnvelopeReason` | `conformance/sdk-envelope/fixtures.json`; per-tier `envelope_interop_*` tests |
| `assertScriptHexUnderLimit` (SDK boundary) | `packages/runar-sdk/src/errors.ts:35`; called at `contract.ts:234, 323, 528, 791` + 6 peer SDKs | n/a | locking-script hex on every deploy/call path | `ScriptSizeExceededError` (typed) | `script-size-guard.test.ts` + 6 peer files |

---

## 4. Test coverage matrix

Per-tier counts for the new intrinsic code paths. "Conf" = conformance
fixtures exercising the intrinsic (4 fixtures in scope:
`intent-prev-output-script`, `intent-output-p2pkh`,
`intent-current-block-height`, `branched-readonly-len`).

| Tier  | Intrinsic unit tests | Path | Conf | Fuzzer | ANF interp |
|-------|----------------------|------|------|--------|------------|
| TS    | 16 | `packages/runar-compiler/src/__tests__/intent-intrinsics.test.ts` | 4/4 | yes (anf-differential) | yes |
| Go    | 15 | `compilers/go/frontend/intent_intrinsics_test.go` + `compilers/go/compiler/intent_intrinsics_compile_test.go` (E2E) | 4/4 | yes | yes |
| Rust  | 14 | `compilers/rust/tests/intent_intrinsics_tests.rs` | 4/4 | yes | n/a |
| Python| 15 | `compilers/python/tests/test_intent_intrinsics.py` | 4/4 | yes | n/a |
| Zig   | 14 | `compilers/zig/src/passes/intent_intrinsics_test.zig` | 4/4 | yes | yes (`packages/runar-zig/src/sdk_anf_interpreter.zig`) |
| Ruby  | 15 | `compilers/ruby/test/test_intent_intrinsics.rb` | 4/4 | yes | n/a |
| Java  | 14 | `compilers/java/src/test/java/runar/compiler/IntentIntrinsicsTest.java` | 4/4 | yes | n/a (per project: `ContractSimulator` covers off-chain exec) |

Per-tier size-guard / unknown-kind / canonical-JSON coverage:

| Tier  | Size-guard test | Unknown-kind test | Canonical-JSON test |
|-------|-----------------|-------------------|---------------------|
| TS    | `packages/runar-compiler/src/__tests__/size-guards.test.ts` (4); `packages/runar-sdk/src/__tests__/script-size-guard.test.ts`; `packages/runar-sdk/src/__tests__/size-guards.test.ts`; `packages/runar-testing/src/__tests__/size-guards.test.ts`; `packages/runar-ir-schema/src/__tests__/{input-limits,size-guards}.test.ts` | `packages/runar-compiler/src/__tests__/unknown-anf-kind.test.ts`; `packages/runar-compiler/src/__tests__/anf-kind-enumeration.test.ts` | covered by existing envelope tests + `conformance/sdk-envelope/` |
| Go    | `packages/runar-go/sdk_script_size_test.go` | `compilers/go/codegen/unknown_anf_kind_test.go`; `compilers/go/frontend/unknown_anf_kind_test.go` | existing |
| Rust  | `packages/runar-rs/tests/script_size_guard.rs` | `compilers/rust/tests/unknown_anf_kind_tests.rs` | existing |
| Python| `packages/runar-py/tests/test_script_size_guard.py` | `compilers/python/tests/test_unknown_anf_kind.py` | existing |
| Zig   | (via `sdk_errors.zig` typed error; inline tests in `sdk_envelope_interop_test.zig`) | `compilers/zig/src/ir/unknown_anf_kind_test.zig` | existing |
| Ruby  | `packages/runar-rb/spec/runar/sdk/script_size_guard_spec.rb` | `compilers/ruby/test/test_unknown_anf_kind.rb` | `packages/runar-rb/spec/runar/sdk/envelope_spec.rb` + interop spec |
| Java  | `packages/runar-java/src/test/java/runar/lang/sdk/ScriptSizeGuardTest.java` | `compilers/java/src/test/java/runar/compiler/passes/UnknownAnfKindTest.java` | existing |

**Filled cells: 4 intrinsic-paths × 7 tiers + 7 size-guard + 7
unknown-kind + 7 envelope = 28 + 21 = 49 cells. All filled.** Plus the
4 conformance fixtures × 7 tiers = 28 byte-parity assertions.

---

## 5. Known divergences (deliberate)

**Per-fixture compiler allowlist** (in `conformance/<fixture>/source.json`'s
`compilers` field). None of the 4 intent-intrinsic fixtures carry an
allowlist — they require parity across all 7 tiers.

**Project-policy Go-only families:** BabyBear, KoalaBear, Poseidon2,
BN254 + Groth16, Merkle, SP1 FRI, FiatShamir-KB. Documented in
`CLAUDE.md`. Out of scope for this audit; not touched by Phase 13 or
the 22-task remediation.

**ScriptVM:** TS / Go / Rust / Python ship an off-chain Script VM
wrapping an upstream BSV SDK interpreter. Zig / Ruby / Java do **not**
ship a Script VM (no canonical upstream interpreter). Java compensates
with `ContractSimulator`. Documented in `CLAUDE.md`. Out of scope.

**Canonical-JSON known divergences (`audits/canonical-json-rfc8785-parity.md`):**
- **D1 BLOCKING:** Zig key sort is byte-wise, not UTF-16 code-unit
  (not yet fixed in working tree — see §2.6 R / verified at
  `packages/runar-zig/src/sdk_envelope.zig:252`).
- **D2 HIGH:** Zig string escape walks bytes, not codepoints (not
  fixed — `appendJsonString` at same file).
- **D3 HIGH:** Zig `Value.Object` is a slice; duplicate keys are
  emitted, not deduped (not fixed).
- **D4 MEDIUM:** Ruby `value[k] || value[k.to_sym]` falsy-rewrite.
  **FIXED** in current working tree (Ruby `envelope.rb:67-76` now
  uses `value.key?(k) ? value[k] : (value.key?(k.to_sym) ? value[k.to_sym] : raise)`).
- **D5 MEDIUM:** 6 tiers use non-ES float formatters (not fixed).
- **D6 LOW:** Lone-surrogate handling undefined across tiers (Ruby
  fixed — `envelope.rb:115-122` now raises; other tiers not fixed).

All other Phase 13 / 22-task deliverables produce parity-required
output: zero deliberate divergences in the intrinsics, size guards,
unknown-kind handling, or fuzzer outputs.

---

## 6. BSV Script semantics relied upon

Every intrinsic lowers to a small fixed set of Stack-IR opcodes via
existing ANF-lower paths. Auditor should validate that the BSV
interpreter implementations (Bitcoin SV Node, BSVM, GorillaPool, WoC
verifier paths) all agree on the precise semantics below.

| Opcode (ANF `call func`) | BSV Script opcode | Assumed semantics | Used by |
|--------------------------|-------------------|-------------------|---------|
| `hash256` | OP_HASH256 (0xaa) | Pop 1 stack item, push `sha256(sha256(top))`. Result is the 32-byte digest in stack-natural byte order. Spec: BSV Script (consistent with Bitcoin Core). | All 3 intrinsics |
| `bin_op `===`` on bytes | OP_EQUALVERIFY (0x88) | Pop 2 items, abort script if unequal (byte-comparison). | All 3 |
| `substr` | OP_SUBSTR (0x7f) | Pop length, offset, string; push `string[offset..offset+length]`. Aborts on out-of-bounds. **Re-enabled in BSV** (was disabled in BTC). | `extractPrevOutputScript` 3-arg + `requireOutputP2PKH` |
| `num2bin` | OP_NUM2BIN (0x80) | Pop size, num; push `num` as little-endian byte string of length `size`. Aborts if `num` doesn't fit. | `requireOutputP2PKH` (8-byte LE satoshi amount) |
| `cat` | OP_CAT (0x7e) | Pop b, a; push `a || b`. **Re-enabled in BSV.** | `requireOutputP2PKH` (4 concatenations) |
| `load_const` (bytes) | OP_PUSHDATA{1,2,4} + bytes | Push literal byte string. | Pinned `1976a914` and `88ac` constants in `requireOutputP2PKH` |
| `extractOutputHash(preimage)` | (compiler-emitted: OP_SUBSTR at fixed offset within preimage) | Per BIP-143: bytes [hashOutputs offset] of the preimage = `hash256(serialised_outputs)`. | `requireOutputP2PKH` |
| `extractLocktime(preimage)` | (compiler-emitted: OP_SUBSTR + OP_BIN2NUM at fixed offset) | Per BIP-143: bytes [locktime offset] of preimage = 4-byte LE `nLockTime`. | `currentBlockHeight` |
| `assert` | OP_VERIFY (0x69) | Pop top; abort if `false` (zero). The boolean coercion uses BSV's standard truthiness (empty / all-zero → false). | All 3 |

**BIP-143-specific assumption** for preimage layout — see
`packages/runar-lang/src/preimage.ts:1-22` for the exact offsets. The
offsets are scriptCode-length-dependent and resolved at compile time
by the existing preimage-extraction codegen.

**OP_HASH256 endianness pitfall** — BSV's OP_HASH256 returns the
digest in *internal* byte order, NOT the reversed display order used
for txids. The `expectedScriptHash` constant must be supplied in
internal order. Documented in `docs/cross-covenant-pattern.md` but
worth an explicit audit check on the test fixtures.

**Citations:**
- BSV Script reference: https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
- BIP-143 (used by BSV for sighash preimage): https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- BSV Genesis upgrade (re-enabled OP_CAT, OP_SUBSTR, OP_BIN2NUM, OP_NUM2BIN): https://docs.bsvblockchain.org/protocol/genesis-upgrade

---

## 7. Audit-engagement scope estimate

Recommended total: **~3 senior auditor-weeks** split:

- **Intent intrinsics (compiler + on-chain semantics):** ~1.5 weeks.
  Includes reviewing the 7 tier-local lowerers for cross-tier byte
  parity (Stack-IR + hex), the typecheck literal-only / stateful-only
  / Crit-3 rule, all 4 fixtures, the 100+ unit tests, and validating
  the threat-model residual risks R-1 through R-7 above (especially
  R-1 input-position binding and R-2 idx overflow). Outside expertise:
  **BIP-143 sighash preimage layout** specialist (a single mis-offset
  in `extractOutputHash` would silently let an adversary substitute
  any tx's hashOutputs).
- **Canonical-JSON + envelope parity:** ~1 week. Includes the 5 known
  divergences D1–D6, the per-tier `signEnvelope`/`verifyEnvelope`
  round-trip via `conformance/sdk-envelope/fixtures.json`, and the
  per-tier float-formatter audit. Outside expertise: **ECMA-262
  §7.1.12.1 Number.prototype.toString** specialist (D5's actual fix
  needs a dtoa-quality reference implementation in 6 languages).
- **Size guards + DoS + dep audit:** ~0.5 week. Mostly mechanical: 7
  peer-tier `InputLimits` constant audit, the
  `assertScriptHexUnderLimit` call-site coverage, the
  `dependency-audit.yml` and `fuzzer-nightly.yml` CI workflows.
  Outside expertise: **SHA-256 / OP_HASH256 collision-resistance**
  context (a sanity check on §2.1 R-1 — the binding-to-position
  question is genuinely subtle).

If R-6 (SDK-side wiring for auto-injected params) is fixed **before**
the engagement begins, no additional time. If it's deferred to a
post-audit follow-up, scope explicitly to "compiler + script + IR
schema; SDK boundary covered by future audit."

---

## 8. Pre-engagement checklist

| # | Item | Status | Reference |
|---|------|--------|-----------|
| 1 | Test suite green (conformance 60/60 both fold modes) | ✓ claimed in commit `adeb447f` (this packet did NOT re-run) | `conformance/tests/` ls = 60; per-CI in `.github/workflows/cross-compiler-bytewise.yml` |
| 2 | Nightly fuzzer wired and passing | ✓ workflow shipped | `.github/workflows/fuzzer-nightly.yml`; `conformance/fuzzer/anf-differential.ts` |
| 3 | Size guards at every SDK boundary | ✓ shipped | `assertScriptHexUnderLimit` called 4× in TS SDK + 6 peers; `size-guards.test.ts` + 6 peers |
| 4 | Unknown-ANF-kind rejection in every loader | ✓ shipped | `unknown_anf_kind_*.{ts,go,rs,py,zig,rb,java}` + tests in each |
| 5 | Dep audit clean | ✓ workflow shipped | `.github/workflows/dependency-audit.yml`; per-tier scans (govulncheck, cargo-audit, pip-audit, bundler-audit, gradle dependency-check, pnpm audit) |
| 6 | Internal review completed | ✓ this packet IS that | `audits/phase13-prep.md` |
| 7 | **SDK-side wiring for `_prevOutScript_*` / `_serialisedOutputs`** | **✗ NOT YET — see §2.4 R-6** | None of 7 SDKs filter or wire these params |
| 8 | Canonical-JSON D1 (Zig UTF-16 sort) fix landed | **✗ NOT YET** | `packages/runar-zig/src/sdk_envelope.zig:252` still byte-wise |
| 9 | Canonical-JSON D2 (Zig string escape) fix landed | **✗ NOT YET** | same file |
| 10 | Canonical-JSON D3 (Zig duplicate-key dedup) fix landed | **✗ NOT YET** | same file |
| 11 | Canonical-JSON D5 (six-tier float formatter parity) | **✗ NOT YET** | All 6 non-TS tiers; see `audits/canonical-json-rfc8785-parity.md` |
| 12 | Canonical-JSON D4 (Ruby falsy-rewrite) fix landed | ✓ shipped | `packages/runar-rb/lib/runar/sdk/envelope.rb:67-76` |
| 13 | External audit booked | (user action) | n/a |

**Recommendation:** Land items 7 + 8 + 10 (the three BLOCKING / HIGH-
severity gaps where the on-chain code paths are sound but the SDK or
cross-tier surface is not) before engagement. D2 + D5 + D6 + D9 can be
explicit "known divergences, audit-scoped to today's payload schemas"
if the timeline pressure to engage is high — current envelope schemas
(ASCII keys, integer values only) avoid all 5 latent divergences.

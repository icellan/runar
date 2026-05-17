# Rúnar Verification — Path 2 Execution Plan

This is the authoritative execution document for Path 2 — discharging
the **38 codegen-to-spec axioms** in `TRUST_MANIFEST.md` with direct
Lean proofs, tier-prioritized per §0 (wave-1 completion notice) and
§1.2 (tier-based acceptance criteria). When an agent (Sonnet, Opus,
or specialist) picks up Path 2 work cold, this is the document they
read first.

Strategic choices fixed at plan time (2026-05-17):

* **Sequencing: Parallel-friendly, tier-based.** §4 below gives the
  tiered ordering (Tier 1 / Tier 2 / Tier 3) that replaces the
  original two-track flat sequencing (preserved in §4-historical).
  Within each tier, Phase B (per-primitive crypto codegen-to-spec)
  and Stage C (A3–A8 runtime wrappers) run concurrently. Stage C
  stays in per-family `Stack/AgreesA<k>.lean` files to avoid merge
  conflicts on `Stack/Agrees.lean`.
* **Scope: Tier 1 + Tier 2 unconditional; Tier 3 deferred.** Path 2
  targets 38 codegen-to-spec axioms. The remaining **72 preserved
  axioms** at wave-1 completion (cryptographic primitives, group
  laws, EUF-CMA companions, backend assumptions — see
  `TRUST_MANIFEST.md` §"Axiom Taxonomy") split as follows after the
  full tier plan: ~26 real cryptographic preserved (kept by design)
  plus ~14 still-axiomatic codegen-to-spec residue if Tier 3 is
  deferred. Per-tier acceptance criteria are in §1.2; the
  56/56 VERIFIED-direct + omnibus-deleted finish line is the *Tier
  3 ceiling*, not the Tier 1 / Tier 2 target.

Estimated calendar time (revised per the 2026-05-17 reprioritization
review and the §1.2 acceptance criteria):

* **Tier 1:** ≈ 8–10 weeks with 2–3 parallel specialists; 18–22
  weeks solo.
* **Tier 2:** decision point; ≈ 12–15 weeks parallel if undertaken.
* **Tier 3:** deferred indefinitely; multi-month specialist work
  (B4 6–8 wk + B5 6–8 wk + B9 6 wk) if a specific value case
  emerges later.

---

## Table of contents

1. Mission, acceptance criteria, success metrics
2. Workflow rules (non-negotiable)
3. Dependency graph
4. Recommended sequencing
5. Milestone breakdown
   - Stage C (A3–A8)
   - Phase B (B1 follow-up, B3–B10)
   - Phase D (D1–D3)
   - Phase C2
   - SupportedANFBody widening + capstone widening
   - Omnibus retirement
6. Per-milestone quality gates
7. Failure modes and recovery
8. Maintenance rituals
9. Reading order for new contributors

---

## 0. Wave 1 completion notice (2026-05-17)

The Path 2 *wave 1* commit `7dcc7fc3` (2026-05-17) landed the first
batch of discharges. Net axiom delta: 125 → 110 (−15). Wave 1 covered:

* **B6 BabyBear** (−8) — converted four bare `Crypto.bbField*` axioms
  in `ANF/Eval.lean` to concrete `def`s; discharged the four
  `_correct` companions in `Crypto/Spec.lean` §8.3 as theorems via
  `bbMod_eq_bbFieldMod`. See §5.12.
* **D3 terminal-assert + NIP-cleanup** (−2) — both
  `terminal_assert_elision_residue_correct` and
  `nip_cleanup_residue_correct` in `Pipeline.lean` had `P → P`
  shape; identity-propagation discharge as theorems. See §5.19.
* **B3-a BLAKE3 concrete defs** (−2) — added concrete
  `Crypto/HashBackend.lean` (291 LOC) implementing BLAKE3 §2.1 and
  re-routed `Crypto.blake3Hash` / `Crypto.blake3Compress` as
  delegating defs. Prerequisite for B3-b / B3-c. See §5.9.
* **Verifier-axiom delegation** (−3) — converted `merkleRootSha256`,
  `merkleRootHash256`, `verifyRabinSig` in `ANF/Eval.lean` from
  bare axioms to concrete `def`s (delegating to inlined helpers
  byte-identical to `Crypto.Spec.merkleVerifyPath` etc.).

Stage C wrapper widenings landed at Tier 1 in the same commit
(A3 `singletonAssertWithCap`, A4 `divmod` single builtin, A5
depth-d fresh prop name, A6 single if_val same-const branches,
A7 `n ≤ 1` with empty body) plus B7-prep infrastructure
(`runOps_append` lifted from `Stack/Sim.lean` to `Stack/Eval.lean`;
14 per-opcode helpers in `Stack/Merkle.lean`; three private bridges
in `Stack/Agrees.lean` promoted to public).

The remaining axiom count (110) splits per the §"Axiom Taxonomy"
table in `TRUST_MANIFEST.md`:
* **72 preserved** — backend assumptions, group laws, EUF-CMA
  companions, primitive symbols Path 2 does not target.
* **38 codegen-to-spec targets** — Path 2 retires these.

The original Path 2 framing ("22 codegen-soundness axioms" /
"−22 to reach 103") predates the 2026-05-16 multi-family Phase B
integration that added Phase B3 (+2), B5 codegen (+14), and B9
(+6) for a true codegen-soundness baseline of 38, not 22. The
revised §1.2 below uses the corrected baseline.

---

## 1. Mission, acceptance criteria, success metrics

### 1.1 Mission

Replace every codegen-soundness axiom in `TRUST_MANIFEST.md` with a
direct Lean proof. After Path 2:

* The mechanised conformance claim is unconditional on the compiler
  side. The remaining axioms are real cryptographic primitive
  existence / group law / EUF-CMA / backend assumptions, plus
  whatever Tier 3 codegen-to-spec residue remains — see §1.2.
* `tests/PipelineConformance.lean` reports **56/56 VERIFIED** (or
  fine-grained per-family classifications post-O1 omnibus split),
  0 fixtures conditional on a single omnibus axiom.
* The omnibus axiom `compileSafe_observational_correct_modulo_
  codegen_axioms` in `Pipeline.lean` is deleted (Tier 1 splits it
  into 9 per-family sub-omnibuses via milestone **O1**; each
  sub-omnibus retires as the corresponding Stage C / Phase D
  milestone lands).

### 1.2 Acceptance criteria

The Path 2 finish line is split into per-tier targets. Tier 1 is
the visible-progress milestone (omnibus split + Stage C composition
substrate + Phase D + concrete crypto-primitive defs). Tier 2
closes most of the remaining codegen-to-spec surface. Tier 3 is
deferred indefinitely unless a specific value case emerges.

| Gate | Tier 1 target | Tier 2 target | Tier 3 target |
|---|---|---|---|
| `./scripts/lean-verify.sh` | green | green | green |
| `./scripts/check-tcb-drift.sh` | `axioms ≈ 88` (110 − 22) | `axioms ≈ 56` (88 − 32) | `axioms ≈ 40` (56 − 16) |
| `./scripts/run-pipeline-conformance.sh` | per-family classification (no single omnibus) | 56/56 VERIFIED or VERIFIED-modulo-{B3,B8,C2,Tier3} | 56/56 VERIFIED (direct) |
| `lake env ./.lake/build/bin/goldenLoad` | 56/56 | 56/56 | 56/56 |
| `lake env ./.lake/build/bin/roundtrip` | 56/56 | 56/56 | 56/56 |
| `lake env ./.lake/build/bin/pipelineGolden` | 49/49 byte-exact (unchanged) | 49/49 | 49/49 |
| `grep -rn "sorry\|admit\|partial def" RunarVerification/` | empty | empty | empty |
| Omnibus axiom in `Pipeline.lean` | deleted (replaced with 9 named sub-omnibuses, each with a discharge path) | each sub-omnibus retired as Stage C + Phase B/D land | all sub-omnibuses retired |

The per-tier axiom-count targets are *approximate* because the
trajectory depends on (a) whether the 20 group-law axioms in
`Crypto/Spec.lean` §1/§2.5 become derivable theorems after the
B4-a / B5-a sub-phases land, and (b) whether the high-level
verifier axioms in `ANF/Eval.lean` (`verifyWOTS`, `verifySLHDSA_*`
×6) become delegating defs after the planned `Crypto/SpecCore.lean`
refactor. Both shifts are tracked but not in the critical-path
gate. See `TRUST_MANIFEST.md` §"Axiom Taxonomy" for the
preserved-vs-target partition.

Calendar success metric: each milestone's acceptance gate (below)
passes before moving to the next. Continuous integration via
`runar-verification` job stays green throughout.

### 1.3 What success looks like

After Path 2, anyone evaluating Rúnar's correctness story reads
`TRUST_MANIFEST.md` and sees only cryptographic-primitive
assumptions — same trust class as CompCert (which assumes properties
of the host logic), Bedrock2 (which assumes properties of word
arithmetic), or any other production verified compiler. The
*compiler* itself is unconditionally proved correct against the ANF
reference semantics.

---

## 2. Workflow rules (non-negotiable)

These rules emerged from the Path 1 + Phase B/D scaffolding session.
Every rule below addresses a concrete failure mode observed in
practice.

### 2.1 Hypothesis hygiene — the dispositive rule

A theorem MUST NOT take a hypothesis that restates its conclusion.

* **Conclusion-restating (forbidden):**
  * `(hRunOk : (runOps lowered s).toOption.isSome)` when the
    conclusion is `(runMethod ... s).toOption.isSome` (`runMethod`
    expands to `runOps lowered`).
  * `(hSimulates : ANF.evalBindings ... = .ok _ ↔ runOps ... = .ok _)`
    when proving `successAgrees`.
  * `(hPatchedBytesSound : runParsedBytes bytes = runOps lowered)`
    when proving the same byte-level identity in the conclusion.

* **Input-state invariants (allowed):**
  * `(hAgrees : agreesTagged tsm initialAnf initialStack)` —
    structural invariant about the *initial* state. Not the
    conclusion.
  * `(hParamDom : ∀ n, v = .loadParam n → ∃ val, anfSt.lookupParam n = some val)`
    — lookup readiness, an input-side domain fact.
  * `(hPre : peepholePassAllFlat_preconditions ops initialStack)` —
    structural M3 precondition.
  * `(hStackShape : initialStack.stack = vBigint i :: vBigint j :: rest)`
    — initial-stack-type-shape, an input-side hypothesis.

The Path 1 corrective agent rolled back A3–A8 wrappers that took
`hRunOk` hypotheses. Path 2 cannot repeat that mistake. **If a goal
won't close, narrow the structural predicate, not the
hypothesis-set.**

### 2.2 No new axioms outside `Crypto/Spec.lean`

Every axiom this plan retires lives in `Stack/*.lean` or
`Pipeline.lean`. No replacement axioms are admitted as part of Path
2 (the whole point is removal). If you find a step requires a new
axiom, it goes in `Crypto/Spec.lean` only, with a literature
citation and a `TRUST_MANIFEST.md` entry, and counts as a step
backwards from the Path 2 goal.

### 2.3 Build feedback discipline

* **Definitions, axiom statements, type signatures, scheduling
  scaffolding:** race through. Make all the edits, run the build
  once at the end. Iterating against the build per edit wastes
  time.
* **Tactic-style proofs (`by ...`):** iterate against the build.
  Lean's tactic state IS the feedback. You cannot tell whether
  `simp [foo, bar]` closes the goal without trying it.

The Path 1 math-demo agent demonstrated the ideal pattern: 3
surgical edits, one final build, done. Use that template for
codegen patches and structural additions.

### 2.4 File isolation for parallel work

* Stage C work stays in per-family `Stack/AgreesA<k>.lean` files
  (k=3..8 already exist as narrowed scaffolding from Path 1). Widen
  each in place. Do NOT touch `Stack/Agrees.lean` from these files;
  add imports / `open` statements as needed.
* Phase B work stays in `Stack/<Primitive>.lean` per the existing
  pattern (`Stack/HashOps.lean`, `Stack/Blake3.lean`, `Stack/Ec.lean`,
  `Stack/P256P384.lean`, `Stack/Merkle.lean`, `Stack/Wots.lean`,
  `Stack/SlhDsa.lean`, `Stack/Rabin.lean`). Each agent works on a
  different file; no merge conflicts.
* `Crypto/Spec.lean` is shared. When multiple agents must touch it
  (e.g., to add concrete spec defs), append to the end and
  integrate sequentially.
* `Pipeline.lean` is the omnibus' home. Touch it only at the
  retirement step (last) and the SupportedANFBody widening step.

### 2.5 Sub-agent worktree isolation

Use `isolation: worktree` for every parallelisable sub-agent
dispatch. The integration step is mechanical (cherry-pick or
`git diff | git apply`). Worktrees that touch only their own file
integrate trivially. Worktrees that touch shared files require a
dedicated integration agent — budget for it.

### 2.6 Heartbeat budget management

When elaborating proofs against deeply-nested `peephole*`
compositions, Lean's `whnf` exceeds the default 200k heartbeat
budget. Two known fixes from Path 1:

* Wrap a block of theorems in `section`/`end` with `attribute
  [local irreducible] Peephole.peepholePassAll
  Peephole.peepholePostFold Peephole.peepholeChainFold
  Peephole.peepholeRollPickFold Peephole.peepholePassAllFlat
  Peephole.passAllInner15`. This is THE dispositive fix.
* Prefix individual slow theorems with `set_option maxHeartbeats
  1600000 in`.

### 2.7 ulimit for SLH-DSA-class fixtures

`pipelineConformance` requires `ulimit -s unlimited` (or `-s 65520`
fallback). The CI wrapper `scripts/run-pipeline-conformance.sh`
handles this. Any new harness or repro script must do the same.

### 2.8 Commit discipline

Per `CLAUDE.md`:

* Never commit without explicit consent.
* No AI attribution in commits / PR descriptions / any
  git-or-GitHub content.
* Work only inside `runar-verification/`.
* Match existing style (comment density, naming, idiom).

---

## 3. Dependency graph (revised post-wave-1)

The dependency graph below reflects the wave 1 commit (2026-05-17,
`7dcc7fc3`) and the 2026-05-17 reprioritization review.
Milestones marked **[DONE]** retired in wave 1. New sub-phases
(B4-a / B5-a / B9-a / B10-prep / O1 / pXNegate-derivable /
group-law audit) appear as explicit nodes.

```
        ┌──────────────────────────────────────────────────────────┐
        │ Tier 1 — composition substrate + concrete primitive defs │
        │                                                          │
        │   O1 omnibus split          (independent — coordinates)  │
        │   pXNegate-derivable        (independent — 0.5 wk)       │
        │   B10-prep (Stack/Eval.lean OP_EQUAL coercion fix)       │
        │   B10 Rabin                 (after B10-prep)             │
        │   B4-a concrete ec* defs    (independent — 2 wk)         │
        │   B5-a concrete p256/p384* defs (independent — 2 wk)     │
        │   B9-a concrete verifySLHDSA defs (3 wk)                 │
        │   B7 Merkle inductive       (B7-prep landed wave 1)      │
        │   B1 follow-up (FIPS axiom route)                        │
        │   B6 BabyBear               [DONE wave 1]                │
        │   D3 terminal-assert / NIP  [DONE wave 1]                │
        │   B3-a BLAKE3 concrete defs [DONE wave 1]                │
        │   verifier-axiom delegation [DONE wave 1]                │
        │                                                          │
        │   Stage C wrapper widening (full):                       │
        │     A3 arith (Tier 2/3 — bridges public post wave 1)     │
        │     A4 math/byte (beyond divmod)                         │
        │     A5 Tier 3 (existing-prop cleanup)                    │
        │     A6 Tier 2 (any branches in SupportedANFBody)         │
        │                                                          │
        │   Phase D wrappers:                                      │
        │     D1 Merkle dispatch       (depends on A3)             │
        │     D2.a auto check_preimage (depends on Phase E — done) │
        │     D2.b auto state_output   [BLOCKED — model gap]      │
        └──────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────────────────────────┐
        │ Tier 2 — close remaining codegen-to-spec residue         │
        │                                                          │
        │   B3 BLAKE3 b/c            (B3-a landed; helper proofs)  │
        │   B8 WOTS+                 (composes B1 SHA-256)         │
        │   A7 Tier 2/3 (loop with non-empty body)                 │
        │   A8 method_call            (recurses through A1-A7)     │
        │   A4 crypto arm             (composes Phase B per-prim)  │
        │   C2 multi-method dispatch joins                         │
        │   Crypto/Spec group-law audit (20 axioms; after B4-a/B5-a)│
        │                                                          │
        │   ── decision point: continue to Tier 3? ──              │
        └──────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────────────────────────┐
        │ Tier 3 — full codegen-to-spec discharge (deferred)       │
        │                                                          │
        │   B4 secp256k1 codegen-to-spec discharge (10 axioms)     │
        │   B5 P-256/P-384 codegen-to-spec discharge (14 axioms)   │
        │   B9 SLH-DSA codegen-to-spec discharge (6 axioms)        │
        │                                                          │
        │   Run only if a specific value case emerges.             │
        └──────────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌───────────────────────┐
                   │ Final acceptance:     │
                   │ 56/56 VERIFIED-direct │
                   │ (or per-family tiers) │
                   └───────────────────────┘
```

Key edges (revised):

* **A4 (call) crypto arm** depends on Phase B per-primitive
  discharge: the call arm needs the per-primitive `runOps`-to-spec
  to compose against, otherwise the runtime-side `isSome` cannot be
  derived for crypto-builtin calls.
* **D1 (Merkle dispatch)** depends on A3 (arith Tier 2): the lowered
  dispatch is a `bin_op`/equality cascade.
* **D2 (stateful continuation)** depends on A5 (Tier 2 landed wave 1).
* **B7 (Merkle inductive)** has B7-prep infrastructure landed wave 1;
  the remaining step composes the per-opcode helpers via induction
  on `d`.
* **B10 Rabin** is BLOCKED on **B10-prep**: the `Stack/Eval.lean`
  `OP_EQUAL` arm must be widened to model Bitcoin Script's
  int↔bytes coercion (currently `.vBigint` vs `.vBytes` always
  returns `.vBool false`, contradicting `verifyRabinSig_spec`).
  A wave-1 in-session subagent attempt to discharge B10 by
  weakening the theorem conclusion (returning `vBool false`
  regardless of spec value) was rejected — no commit landed.
  B10-prep is a 2–3 day surgical edit to `Stack/Eval.lean` +
  downstream proof audit; B10 then follows.
* **B4 / B5 / B9 codegen-to-spec discharges** are STRUCTURALLY
  blocked until **B4-a / B5-a / B9-a** sub-phases land concrete
  Lean defs for `Crypto.ecAdd / ecMul / etc.`, `Crypto.p256Add /
  p384Add / etc.`, and `Crypto.Spec.verifySlhDsa_*`. The bare
  axioms have no defining equation to rewrite against. A wave-1
  in-session subagent attempt at B5 single-emit discharge
  identified this structural blocker; no commit landed (the
  attempt was correctly reported as BLOCKED, not weakened).
* **Group-law audit** (Tier 2) depends on B4-a / B5-a landing
  first. Once concrete `ecAdd` / `p256Add` are in `ANF/Eval.lean`,
  the 20 group-law axioms in `Crypto/Spec.lean` §1 + §2.5 become
  derivable theorems.
* **O1 omnibus split** is required for any conformance fixture to
  flip from `VERIFIED-modulo-codegen-axioms` to a finer
  classification. Wrapper widening alone does not flip fixtures
  because the harness in `tests/PipelineConformance.lean` checks
  `structuralRefBodyBool`, not the per-family widened predicates.

Parallel-safe (no cross-dependencies):

* Tier 1: O1, pXNegate-derivable, B10-prep, B4-a, B5-a, B9-a,
  B7 (after B7-prep wave 1), Stage C A3/A4/A5/A6 widenings.
* Tier 2: B3 (b/c), B8, A7, A8, A4 crypto, C2 — A7/A8/A4 sequence
  recursively on the body family.
* Tier 3: B4, B5, B9 — all blocked until corresponding sub-phase
  lands.

---

## 3-historical. Original dependency graph (pre-wave-1, superseded)

The original Path 2 dependency graph from the 2026-05-17 plan
draft is preserved below for audit purposes. It is superseded by
§3 above.

```
                    ┌──────────────────────────────────────┐
                    │ Crypto/Spec.lean concrete defs       │
                    │ (already landed for B6/B7/B8/B10/B11)│
                    └──────────────────────────────────────┘
                                  │
                                  │ (Phase B reductions target these)
                                  ▼
        ┌──────────────────────────────────────────────┐
        │ Phase B per-primitive runOps-to-spec         │
        │   B1-follow-up sha256Compress / Finalize     │
        │   B3 BLAKE3 (2 axioms)                       │
        │   B4 secp256k1 EC (10 axioms)                │
        │   B5 P-256 / P-384 (14 axioms)               │
        │   B6 BabyBear (4 axioms)                     │
        │   B7 Merkle inductive (0 axioms; proof gap)  │
        │   B8 WOTS+ (1 axiom)                         │
        │   B9 SLH-DSA (6 axioms)                      │
        │   B10 Rabin (1 axiom)                        │
        └──────────────────────────────────────────────┘
                                  │
                                  │ (A4 call arm composes against
                                  │  discharged Phase B for crypto builtins)
                                  ▼
        ┌──────────────────────────────────────────────┐  ┌─────────────────────┐
        │ Stage C A3 arith                             │  │ Phase D D3          │
        │ Stage C A4 call (math/byte)                  │  │ terminal-assert     │
        │ Stage C A4 call (crypto) -- after B          │  │ NIP cleanup         │
        │ Stage C A5 update_prop                       │  └─────────────────────┘
        │ Stage C A6 if_val                            │
        │ Stage C A7 loop                              │
        │ Stage C A8 method_call                       │
        └──────────────────────────────────────────────┘
                  │            │            │
                  ▼            ▼            ▼
        ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
        │ Phase D D1  │  │ Phase D D2  │  │ Phase C2    │
        │ Merkle      │  │ stateful    │  │ multi-method│
        │ dispatch    │  │ continuation│  │ dispatch    │
        │ (needs A3)  │  │ (needs A5)  │  │ joins       │
        └─────────────┘  └─────────────┘  └─────────────┘
                  │            │            │
                  └────────────┼────────────┘
                               │
                               ▼
                   ┌───────────────────────┐
                   │ SupportedANFBody      │
                   │ widening + capstone   │
                   │ widening              │
                   └───────────────────────┘
                               │
                               ▼
                   ┌───────────────────────┐
                   │ Omnibus axiom         │
                   │ retirement            │
                   └───────────────────────┘
                               │
                               ▼
                   ┌───────────────────────┐
                   │ Final acceptance:     │
                   │ 56/56 VERIFIED-direct │
                   └───────────────────────┘
```

Key edges:

* **A4 (call) crypto arm** depends on Phase B per-primitive
  discharge: the call arm needs the per-primitive `runOps`-to-spec
  to compose against, otherwise the runtime-side `isSome` cannot be
  derived for crypto-builtin calls.
* **D1 (Merkle dispatch)** depends on A3 (arith): the lowered
  dispatch is a `bin_op`/equality cascade.
* **D2 (stateful continuation)** depends on A5 (update_prop): the
  auto-injected state output modifies stack `props` in a manner
  proved by A5.
* **B7 (Merkle inductive)** does not strictly depend on B1's
  follow-up but composes more cleanly once partial-SHA-256 is
  discharged. Run them in either order; integrate B7 last.

Parallel-safe (no cross-dependencies):

* Phase B {B1-follow-up, B3, B4, B5, B6, B7, B8, B9, B10}
* Stage C {A3, A5, A6, A7} (all four can run simultaneously; A4 has
  a crypto sub-arm blocked on B; A8 blocked on A1–A7)
* Phase D D3 (no dependencies on Stage C or B)

---

## 4. Recommended sequencing (revised post-wave-1)

Tier-based execution. Each tier has a decision gate before committing
to the next.

### Tier 1 (target: 8–10 weeks with 3 parallel specialists; 18–22 weeks solo)

Wave 1 (2026-05-17) discharged: B6, D3, B3-a, verifier-axiom delegation
(net −15 axioms). Wave 1 also landed Stage C Tier 1 widenings in A3/A4/A5/A6/A7
and B7-prep infrastructure. The remaining Tier 1 work:

**Composition substrate (visible-progress, unblocks harness):**

* **O1 omnibus split** (2.5 wk) — Split the single
  `compileSafe_observational_correct_modulo_codegen_axioms` axiom
  in `Pipeline.lean` into 9 per-constructor-family sub-omnibuses.
  Re-engineer the harness in `tests/PipelineConformance.lean` to
  dispatch fixtures into `VERIFIED-modulo-<family>-codegen-axioms`
  tiers. **This is required for any fixture to flip from the
  current single-bucket `VERIFIED-modulo-codegen-axioms`
  classification as Tier 1 milestones land.** See §5.23.

**Concrete primitive defs (axiom reduction without proof effort):**

* **pXNegate-derivable** (0.5 wk) — Convert `Crypto.p256Negate`
  and `Crypto.p384Negate` from function-symbol axioms to concrete
  `def`s over the negation formula `(x, y) → (x, p − y mod p)`.
  Net −2 axioms. See §5.24.
* **B4-a concrete ec\* defs** (2 wk) — Add concrete `Crypto.ecAdd /
  ecMul / ecMulGen / ecNegate / ecOnCurve / ecModReduce /
  ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY` in
  `ANF/Eval.lean` mirroring secp256k1 byte semantics. Net −10
  axioms. Unblocks future B4 codegen-to-spec discharge. See §5.25.
* **B5-a concrete p256/p384\* defs** (2 wk) — 12 primitive symbols
  following B4-a pattern. Net −12 axioms. See §5.26.
* **B9-a concrete `verifySLHDSA_SHA2_*` defs** (3 wk) — Compose
  SHA-256 + Merkle + WOTS+ + FORS into 6 parameter-set defs in
  `Crypto/Spec.lean`. Re-route the bare `verifySLHDSA_SHA2_*`
  axioms in `ANF/Eval.lean` as delegating defs. Net −6 axioms.
  See §5.27.

**Phase D wrapper soundness:**

* **D1 Merkle dispatch** (3 wk) — Discharge
  `merkle_dispatch_selection_correct`. Depends on A3 (arith Tier 2)
  for the binop / equality cascade. See §5.17.
* **D2.a auto check_preimage** (1.5 wk) — Discharge
  `auto_check_preimage_at_method_entry_correct`. Composes
  `runOpcode_CHECKSIG_ValidTxContext` (already proved) with
  `Stack/TxContext.lean` preimage construction (already concrete).
  See §5.18.
* **D2.b auto state_output** [BLOCKED — Tier 2, model widening prerequisite] — Wave-3 finding: structurally undischargeable as stated. ANF `evalValue` on `.addOutput` / `.addRawOutput` / `.addDataOutput` APPENDS to `s.outputs`; Stack `runOps` / `runOpcode` deliberately preserve `StackState.outputs` (intentional design per `Stack/OutputTrace.lean` opening comment). For a stateful method the conclusion `anfFinal.outputs = stkFinal.outputs` requires substrate widening — either extend `Stack.Eval.runOps` to thread output records through the BIP-143 emission ops, or replace the axiom's conclusion with an `OutputTrace.applyTrace`-mediated statement. Moves to Tier 2 with the model-extension prerequisite. ~1.5 wk (Discharge
  `auto_state_output_at_method_exit_correct`. Depends on A5 Tier 2
  (landed wave 1). See §5.18.

**Phase B + Stage C composition:**

* **B10-prep `OP_EQUAL` coercion** (0.5 wk, including 2-day audit
  of downstream proofs that reference `Stack.Eval.runOpcode
  "OP_EQUAL"` strict-type behavior) — Widen
  `runOpcode "OP_EQUAL"` in `Stack/Eval.lean` to model Bitcoin
  Script's int↔bytes coercion. Prerequisite for B10. See §5.28.
* **B10 Rabin** (1 wk) — After B10-prep, compose a step-by-step
  reduction over the 10-opcode Rabin body against the widened
  `OP_EQUAL` semantics. The wave-1 in-session B10 subagent drafted
  a ~280-line proof against the strict (un-widened) `OP_EQUAL`,
  which required weakening the conclusion to `vBool false`; that
  attempt was rejected and no commit landed. The corrected
  approach reuses the same opcode-by-opcode reduction skeleton
  but lets `OP_EQUAL` succeed via coercion. See §5.16.
* **B7 Merkle inductive step** (1.5 wk) — B7-prep landed wave 1.
  Remaining: compose 14 per-opcode helpers into `mLevel_step` +
  induction on `d`. See §5.13.
* **B1 follow-up** (3 wk) — Accept the FIPS 180-4 §6.2 composition
  axiom `sha256_compose : sha256 (xs ++ ys) = sha256Finalize
  (sha256Compress sha256Init xs) ys.length ys` (1 axiom, 1 day) in
  `Crypto/HashBackend.lean`, then discharge
  `runOps_sha256CompressOps_eq` / `runOps_sha256FinalizeOps_eq`
  against the arithmetic round-function emit ops. See §5.8.
* **A3 arith Tier 2/3** (2.5 wk) — Extend `structuralArithBodyReal`
  Bool checker to binOp / unaryOp; per-arm `simpleStepRel`
  extension. The wave 1 promotion of three bridges in
  `Stack/Agrees.lean` unblocks this. See §5.1.
* **A4 math/byte (beyond divmod)** (3 wk) — 21 remaining math/byte
  builtins beyond the wave-1 `divmod`. See §5.2.
* **A5 Tier 3** (1.5 wk) — Existing-prop cleanup arm. Depends on
  bridges in `Stack/Agrees.lean`. See §5.4.
* **A6 Tier 2** (2 wk) — Any branches in SupportedANFBody. Depends
  on A3 + A5. See §5.5.

### Tier 2 (target: 12–15 weeks parallel; decision point before)

Decision gate: before committing to Tier 2, re-evaluate whether
(a) the engineering capacity is better spent on other Rúnar work
(static analyzer, property-based fuzzing) and (b) whether the
per-family `VERIFIED-modulo-<family>-codegen-axioms` tiers from O1
deliver sufficient auditor clarity without the additional Tier 2
proof effort.

* **B3 BLAKE3 (b/c)** (2.5 wk) — B3-a landed wave 1. Remaining:
  ~10 named helper lemmas + composition. See §5.9.
* **B8 WOTS+** (3 wk) — 8 named helpers composing B1 SHA-256
  across 67 chunks × 15 chain iters. See §5.14.
* **A7 Tier 2/3** (2 wk) — Loop with arbitrary `n` and non-empty
  body. Body-recursive `SupportedANFBody`. See §5.6.
* **A8 method_call** (4 wk) — Structural induction on inline
  budget; recursive into other Stage C families. See §5.7.
* **A4 crypto arm** (3 wk) — Per-primitive at ~1 wk each after
  the corresponding Phase B discharge. See §5.3.
* **C2 multi-method dispatch joins** (2–4 wk) — Byte-offset /
  op-index semantic gap. See §5.20.
* **Crypto/Spec group-law audit** (1.5 wk, after B4-a / B5-a) —
  Derive `ecAdd_assoc`, `ecAdd_comm`, etc. from the concrete
  `Crypto.ecAdd` def landed by B4-a/B5-a. Up to −20 axioms.
  See §5.29.

### Tier 3 (deferred indefinitely)

Run only if a specific value case emerges (audit requirement,
published correctness claim).

* **B4 secp256k1 codegen-to-spec discharge** (6–8 wk) — Discharge
  all 10 `emitEc*_runOps_eq` axioms against concrete `Crypto.ecAdd`
  etc. (from B4-a). See §5.10.
* **B5 P-256 / P-384 codegen-to-spec discharge** (6–8 wk) — 14
  `emitP256/P384*` axioms. See §5.11.
* **B9 SLH-DSA codegen-to-spec discharge** (6 wk) — 6 parameter
  sets composing B1 + B7 + B8 + FORS. See §5.15.

### Specialist split (recommended for 3 parallel)

* **Specialist α** (Stage C composition): A3 Tier 2/3, A4
  math/byte, A5 Tier 3, A6 Tier 2, plus Tier 2 A7/A8 and A4 crypto.
* **Specialist β** (cryptography): B4-a, B5-a, B9-a, group-law
  audit, plus Tier 2 B3/B8.
* **Specialist γ** (composition + harness): O1 omnibus split,
  D1, D2.a, D2.b, B7, B10-prep + B10, B1 follow-up, pXNegate,
  plus Tier 2 C2.

Calendar time with this split: ~8–10 weeks for Tier 1, ~12–15
weeks for Tier 2.

---

## 4-historical. Original two-track sequencing (pre-wave-1, superseded)

The original Track A / Track B / Convergence layout is preserved
for audit purposes. It is superseded by the tier-based sequencing
in §4 above.

### Track A — Stage C (runtime composition)

Order: A3 → A5 → A6 → A7 → A4(math/byte) → A4(crypto, blocked) →
A8. Each milestone takes 2–4 weeks. Roughly 4–5 months solo on this
track. After A3, A5, A6, A7 land you can fire D1, D2, D3 in
parallel from the same track or hand them off.

### Track B — Phase B (per-primitive crypto)

Order: B1-follow-up → B6 → B10 → B3 → B7 → B8 → B4 → B5 → B9.
Easier-first ordering. B1-follow-up unlocks the partial-SHA-256
pattern reused in B3 / B8 / B9. B6 / B10 are short. B3 / B7 / B8
build up multi-opcode hash technique. B4 / B5 / B9 are the
multi-week endeavours. Roughly 4–6 months solo on this track.

### Convergence

When both tracks reach their last items, the SupportedANFBody
widening and omnibus retirement step closes Path 2. Plan ~2 weeks
for the final integration and harness flip.

If you have **3 parallel specialists**, the recommended split:

* Specialist α: A3, A5, A6, A7, A8 (Stage C composition specialist)
* Specialist β: B4, B5, B9 (EC + lattice expert)
* Specialist γ: B3, B6, B7, B8, B10, B1-follow-up, D1, D2, D3, C2
  (everything else)

Calendar time drops to ~3–4 months with this split.

---

## 5. Milestone breakdown

Each milestone has:

* **Goal** — single-sentence target.
* **Files** — where the work lives.
* **Key lemmas** — what to prove (with names).
* **Technique** — how to prove it.
* **Failure modes** — what to expect and how to recover.
* **Acceptance gate** — concrete pass/fail criteria.
* **Effort** — calendar weeks solo.
* **Dependencies** — what must land first.

### 5.1 Stage C — A3 arith (binOp / unaryOp / assert)

**Goal.** Widen `RunarVerification/Stack/AgreesA3.lean` so the
runtime wrapper covers ANF bodies whose bindings are arbitrary
`binOp` / `unaryOp` / `assert` values (not just const-aliased).

**Files.**

* Primary: `RunarVerification/Stack/AgreesA3.lean` (widen in place).
* Read: `RunarVerification/Stack/Agrees.lean` — existing
  `stageC_simpleStep_<opcode>_<L>_<R>` witnesses at depth pairs
  (1,0), (0,1), (≥2,0), (0,≥2). `agreesTagged_chain_preserves` at
  ~`Stack/Agrees.lean:2883`. `simpleStepRel` at
  ~`Stack/Agrees.lean:2941`.

**Key lemmas.**

* Extend `simpleStepRel` (in `Stack/Agrees.lean`) with three new
  arms — one for each ANF constructor in the family. Each arm is a
  predicate over `(tsm, anfSt, stkSt, tsm', anfSt', stkSt')` saying
  what fresh binding name appears in `tsm'`, what value appears in
  `anfSt'`, and what value gets pushed on `stkSt'`.
* `simpleStepRel_binOp_<kind>_preserves_agreesTagged` (one per
  BinOpKind × depth pair). Most exist as
  `stageC_simpleStep_<opcode>_<L>_<R>` — these are the operational
  half. Add the predicate-side preservation arm via
  `taggedStackAligned_addBinding_fresh`.
* `simpleStepRel_unaryOp_<kind>_preserves_agreesTagged` per UnaryOpKind.
* `simpleStepRel_assert_preserves_agreesTagged` — `.assert n` at any
  depth; operand resolves to `.vBool true` (else the assertion
  fails, but failure case is covered by `successAgrees`'s direction).
* In `AgreesA3.lean`: widen `structuralArithBody` from the narrowed
  alias to a real predicate `structuralArithBodyReal` requiring
  every binding to be one of {const-load, copy-mode ref-load,
  consume-mode ref-load, binOp at supported depth pair, unaryOp at
  supported depth, assert}.
* Add `Decidable (structuralArithBodyReal …)` via a `Bool` checker
  + `_iff` lemma + `inferInstanceAs`.
* Prove `runMethod_lower_public_unique_no_post_structuralArith_real_isSome`
  — the method-level wrapper. Hypotheses: structural body predicate
  + `agreesTagged` + standard four no-implicit flags + public-name
  uniqueness. **No `hRunOk`.**

**Technique.**

1. Inspect `Stack/Lower.lean:lowerValueP` for each constructor's
   lowered op sequence. For binOp at (1,0): something like
   `[opcode for binop kind]` plus the depth-pair tracker layer.
2. For each lowered op, the existing `stageC_simpleStep_` witnesses
   give `runOps`-success on the appropriate initial-stack shape.
   Wrap these into the predicate side.
3. Lift to body level via `agreesTagged_chain_preserves`. This is
   the parametric driver — instantiate `R := simpleStepRel` extended
   with the new arms; the chain-lift is free.
4. Compose with the existing `lowerMethodUserRawOps_eq_lowerBindings`
   bridge (in `Stack/Agrees.lean`) to get the method-level shape.

**Failure modes.**

* `whnf` heartbeat timeout on Pipeline-side instantiation. Apply
  the `attribute [local irreducible]` block.
* Type-shape mismatch at depth pair (≥2,0): the stage C witness
  exists at exact depth 2, 3, 4 — generic depth ≥2 needs an
  induction on depth or restricted predicate. Narrow the predicate
  to "depth pair from the corpus-observed set" if the generic case
  resists.
* `simpleStepRel`'s predicate side requires `taggedStackAligned`
  preservation across the new arm; the existing
  `taggedStackAligned_addBinding_fresh` covers `addBinding`-only
  arms but not arms that *push then pop then push* (binops do net
  push of 1 but consume 2). New helper:
  `taggedStackAligned_after_binop` — chains `pop2` + `pushFresh`.

**Acceptance gate.**

* `Stack/AgreesA3.lean` defines `structuralArithBodyReal` and the
  widened wrapper.
* `./scripts/lean-verify.sh` green; `axioms = 125` unchanged.
* `pipelineConformance` reclassification: the harness should
  recognise the widened predicate. (The PipelineConformance
  widening is part of the SupportedANFBody milestone, not A3 itself;
  but A3's wrapper must exist and be Decidable-ready.)
* `grep -c "sorry\|admit\|hRunOk\|hSimulates" RunarVerification/Stack/AgreesA3.lean`
  returns 0.

**Effort.** 3 weeks solo (the most complex Stage C family because
of depth-pair multiplicity and the body-wide stack-shape invariant).

**Dependencies.** None.

### 5.2 Stage C — A4 call (math/byte builtins)

**Goal.** Extend `RunarVerification/Stack/AgreesA4.lean` to cover
ANF bodies whose `call` bindings invoke only math/byte builtins
(the 22 builtins in `ANF/Eval.lean` with concrete `def`s:
`abs, min, max, within, safediv, safemod, divmod, clamp, sign,
mulDiv, percentOf, pow, sqrt, gcd, log2, substr, int2str, pack,
unpack, reverseBytes, toByteString, cat, num2bin, bin2num, split`).

**Files.**

* Primary: `Stack/AgreesA4.lean`.
* Read: `Stack/Agrees.lean` Stage C witnesses for the listed
  builtins at landed depths.

**Key lemmas.**

* Per-builtin `simpleStepRel_call_<builtin>_preserves`. Each
  builtin has a documented lowered shape in `Stack/Lower.lean`
  (`lowerValueP` `.call` arm or specialised emitter like
  `lowerDivmod`). The operational discharge composes one or more
  `runOpcode_<OP>` reductions with `stepNonIf` and `runOps` cons.
* `structuralCallBodyMathByte` — Bool-checker requiring every
  `.call` binding to invoke a name in the math/byte allowlist with
  a known-depth-pair operand shape.
* `runMethod_lower_public_unique_no_post_structuralCallMathByte_isSome`.

**Technique.**

1. For each math/byte builtin, write the lowered-op `runOps`
   reduction as a private lemma in `AgreesA4.lean`. Most are
   straightforward `simp [runOps, stepNonIf, runOpcode, ...]`
   chains.
2. Compose into `simpleStepRel_call_<builtin>` arm.
3. Lift to body level via `agreesTagged_chain_preserves`.
4. Method-level wrapper analogous to A3.

**Failure modes.**

* Bounded-loop builtins (`sqrt`, `gcd`, `log2`) emit fuel-bounded
  loop shapes in the codegen but the ANF spec is a closed-form `def`.
  Reconciling: prove fuel-sufficiency at each call site by computing
  a bound from the operand. Use `Nat.log2 n + k` style.
* `divmod` was the math-demo gap — make sure the multi-opcode
  sequence `OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP` reduces
  step-by-step.

**Acceptance gate.**

* `Stack/AgreesA4.lean` covers 22 math/byte builtins.
* No new axioms.
* Build green.

**Effort.** 4 weeks solo.

**Dependencies.** None (math/byte arm independent of crypto).

### 5.3 Stage C — A4 call (crypto builtins, depends on Phase B)

**Goal.** Extend `Stack/AgreesA4.lean` to cover crypto-builtin
calls (`sha256`, `ripemd160`, `hash160`, `hash256`, `blake3Hash`,
`ecAdd` / `ecMul` / etc., `verifyWOTS`, `verifySLHDSA_*`,
`verifyRabinSig`, P-256 / P-384 family, `merkleRoot*`, BabyBear).

**Files.**

* Primary: `Stack/AgreesA4.lean`.
* Read: discharged Phase B `runOps_*_eq` theorems (no longer
  axioms after Phase B work).

**Key lemmas.**

* Per-crypto-builtin `simpleStepRel_call_<crypto>_preserves`.
  Operational discharge composes Phase B's now-proved
  `runOps_<primitive>_eq` lemma.
* Widen `structuralCallBody` Bool checker to admit crypto builtins
  with appropriate operand-shape preconditions.

**Technique.**

1. Each crypto builtin's lowered op sequence is wrapped in a
   single `runOps_<primitive>_eq` (after Phase B). Use that lemma
   to discharge the `simpleStepRel` arm.
2. The ANF `evalCall?` arms for crypto builtins already produce
   the same `Crypto.<primitive>` symbol. Predicate side: ANF and
   Stack agree on the pushed value bit-for-bit.

**Failure modes.**

* If Phase B is not yet complete for a primitive, this milestone's
  arm for that primitive blocks. Sequence A4-crypto's per-primitive
  arms in the order Phase B discharges land.

**Acceptance gate.**

* `AgreesA4.lean` covers every crypto builtin in the corpus.
* No new axioms.
* Build green.

**Effort.** 3 weeks (assuming Phase B has landed for each
primitive; if not, gates per Phase B milestone).

**Dependencies.** Phase B {B1-follow-up, B3, B4, B5, B6, B7, B8,
B9, B10}.

### 5.4 Stage C — A5 update_prop

**Goal.** Widen `Stack/AgreesA5.lean` from the singleton-binding
narrowing to cover arbitrary `update_prop` at any depth, with
existing-prop-entry cleanup.

**Files.**

* Primary: `Stack/AgreesA5.lean`.
* Read: `Stack/Lower.lean:lowerValueP` `.updateProp` arm —
  `loadRefLive ++ removePropEntryOps cleanup`. The cleanup is
  `OP_SWAP OP_DROP` style for an existing prop entry.

**Key lemmas.**

* `runOps_loadRef_at_depth_d_eq` (for d ≥ 0, generic).
* `runOps_removePropEntryOps_eq` — proves the cleanup sequence is
  a no-op on the value side, just renames the stackmap slot.
* `simpleStepRel_updateProp_preserves` — ANF `props.update name v`
  matches Stack `props.update name v` after the lowered op runs.

**Technique.**

1. Inspect `lowerValueP .updateProp`'s actual emit. It's a sequence
   of `swap`/`rot`/`pick`/`roll` based on where the existing prop
   entry lives.
2. For each cleanup shape, prove the corresponding `runOps`
   identity.
3. Compose into a single `simpleStepRel` arm parameterised by the
   cleanup shape.

**Failure modes.**

* Cleanup shape complexity. Narrow to "depth 0 + fresh prop name"
  (already done) → "depth d + fresh prop name" → "depth d + existing
  prop with cleanup". Land each tier independently if needed.

**Acceptance gate.**

* `AgreesA5.lean` covers update_prop at any depth with any cleanup
  shape.
* Build green; no axioms.

**Effort.** 3 weeks.

**Dependencies.** None.

### 5.5 Stage C — A6 if_val

**Goal.** Widen `Stack/AgreesA6.lean` from "single if_val with
both branches `structuralConstBody`" to "if_val with both branches
in widened SupportedANFBody fragment".

**Files.**

* Primary: `Stack/AgreesA6.lean`.
* Read: `Stack/Eval.lean:stepIf` — concrete branch semantics.
  `Stack/Peephole.lean:runOps_cons_ifOp_eq` — `runOps` peels `.ifOp`.

**Key lemmas.**

* `simpleStepRel_ifVal_preserves` taking both-branch witnesses as
  hypotheses (the if-body predicate is inductive).
* Join lemma: the post-branch `agreesTagged` must agree on both
  branches' `tsm' / anfSt' / stkSt'`. Easiest closure: require
  both branches to produce a single binding with the same name and
  kind.

**Technique.**

1. `stepNonIf` on `.ifOp` consumes the condition, dispatches to a
   branch.
2. The branch's own `simpleStepRel` arms (recursive) give
   per-branch preservation. Compose via the join.
3. For the body level, the if_val binding adds a fresh name to
   `tsm'` that depends on which branch ran. Predicate side:
   require both branches to emit the same fresh-name structure.

**Failure modes.**

* Branch divergence on the produced binding. Tight predicate:
  both branches' last binding has the same `name`. Looser
  predicate: track `tsm'` as a join. Start tight.
* Heartbeat timeout on Pipeline-side instantiation — wrap in
  `section` + `attribute [local irreducible]`.

**Acceptance gate.**

* `AgreesA6.lean` covers `if_val` with both branches in any
  SupportedANFBody fragment.
* Build green; no axioms.

**Effort.** 3 weeks.

**Dependencies.** A3 / A4 / A5 (so the branches can themselves
contain non-const bindings).

### 5.6 Stage C — A7 loop

**Goal.** Widen `Stack/AgreesA7.lean` from `count = 0` to arbitrary
bounded iteration counts.

**Files.**

* Primary: `Stack/AgreesA7.lean`.
* Read: `ANF/Eval.lean:runLoop` — recursive ANF semantics.
  `Stack/Lower.lean` — bounded loop unroll.

**Key lemmas.**

* Induction on iteration count `n`:
  * Base `n = 0`: both sides return `.ok` with identity.
  * Step `n + 1`: assume `n` works; show `n + 1` reduces to body
    once then `n` more iterations.
* `runLoop_runOps_eq_at_count_n` — `runOps (unrollIter body n) s`
  matches `runLoop body n s` for any `n`.

**Technique.**

1. Inductive proof on `n` parameterised by the body's
   `simpleStepRel` (which the body must satisfy as a
   sub-predicate).
2. Recurse: body must be in SupportedANFBody (recursive
   predicate).

**Failure modes.**

* `unrollIter` definition in `Stack/Lower.lean` may use
  `Nat.repeat`-style — confirm the inductive structure matches
  `runLoop`'s.

**Acceptance gate.**

* `AgreesA7.lean` covers loops at any bounded count.
* Build green; no axioms.

**Effort.** 3 weeks.

**Dependencies.** A3 / A4 / A5 / A6 (body of loop can contain any
of those).

### 5.7 Stage C — A8 method_call

**Goal.** Widen `Stack/AgreesA8.lean` from "leaf-empty methodCall"
to arbitrary inlined method calls within the inline budget.

**Files.**

* Primary: `Stack/AgreesA8.lean`.
* Read: `Stack/Lower.lean:lowerValueP` `.methodCall` arm — inline
  expansion with budget.

**Key lemmas.**

* `simpleStepRel_methodCall_preserves` reducing to the inlined
  body's `simpleStepRel` arms.
* Termination via budget decrement.

**Technique.**

1. Inlining produces a body in SupportedANFBody by structural
   induction on the budget.
2. After inlining, the inlined body's `simpleStepRel` arms close
   the goal.

**Failure modes.**

* Budget exhaustion case: when the budget hits 0 the inliner emits
  a sentinel or errors. Predicate: require `budget ≥ depth(callee)`.

**Acceptance gate.**

* `AgreesA8.lean` covers methodCall at any budget ≥ callee depth.
* Build green; no axioms.

**Effort.** 4 weeks (recursion into other Stage C families).

**Dependencies.** A1 – A7 (callee's body can be any of those).

### 5.8 Phase B — B1 follow-up: SHA-256 compress / finalize

**Status (2026-05-17):** a wave-1 in-session subagent attempted
discharge by defining `sha256CompressOps` as `[.opcode "OP_SHA256"]`
(a trivial alias making the theorems tautological); that attempt
was rejected and no commit landed. The accepted approach (decided
in the 2026-05-17 reprioritization review) is: add the
FIPS 180-4 §6.2 composition axiom
`sha256_compose : sha256 (xs ++ ys) = sha256Finalize (sha256Compress
sha256Init xs) ys.length ys` in `Crypto/HashBackend.lean` with
citation, then discharge `runOps_sha256CompressOps_eq` /
`runOps_sha256FinalizeOps_eq` against the arithmetic round-function
emit op-list using the algebraic identity. **Revised effort: 3 weeks**
(was 1 week — the original estimate did not budget the multi-week
arithmetic reduction). Tier 1.



**Goal.** Discharge `runOps_sha256CompressOps_eq` and
`runOps_sha256FinalizeOps_eq` as direct theorems, not axioms.
Currently a documented gap; the single-opcode B1+B2 proofs already
landed for `OP_SHA256`, `OP_HASH256`, etc.

**Files.**

* Primary: `Stack/HashOps.lean`.
* Read: `Crypto/HashBackend.lean` for concrete `sha256_compose`.

**Key lemmas.**

* Optional axiom (allowed: this is a real algebraic identity from
  FIPS 180-4 §6.2): `HashBackend.sha256_compose : sha256 (xs ++ ys)
  = sha256Finalize (sha256Compress (sha256Init) xs) ys.length ys`.
* `runOps_sha256CompressOps_eq` — composes `OP_SHA256` reductions
  with the partial-state representation.
* `runOps_sha256FinalizeOps_eq` — terminal reduction.

**Technique.**

1. Add the composition axiom in `Crypto/HashBackend.lean` if needed
   (1 axiom, FIPS-cited).
2. Reduce the compress emit op-list step by step against the
   composition identity.
3. Same for finalize.

**Failure modes.**

* The partial-state representation may require a concrete `sha256State`
  type that doesn't currently exist in Lean. Add it as a `def`
  matching the TS reference's `Sha256State` shape.

**Acceptance gate.**

* `Stack/HashOps.lean` ships two new theorems (not axioms).
* `axioms = 126` if you added the composition axiom (75 + B1
  follow-up companion), or unchanged at 125 if you discharge
  without it.

**Effort.** 1 week.

**Dependencies.** None.

### 5.9 Phase B — B3 BLAKE3

**Status (2026-05-17):** sub-phase **B3-a landed in wave 1**.
`Crypto/HashBackend.lean` now ships concrete `def blake3Hash` /
`def blake3Compress` (291 LOC mirroring BLAKE3 §2.1); the bare
axioms in `ANF/Eval.lean` are delegating `def`s. Net wave-1 delta:
−2 axioms in `ANF/Eval.lean`. The 2 codegen-to-spec axioms in
`Stack/Blake3.lean` (`runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq`)
remain — discharged via Tier 2 sub-phases **B3-b** (per-helper
reductions: `runOps_b3RotrLEGeneral_eq`, `b3EmitHalfG_eq`,
`b3EmitG_eq`, `b3EmitGCall_eq`, `b3EmitRound_eq` — per wave 1
B3 agent's plan, ~10 named helpers totalling ~1500-2000 lines)
plus **B3-c** (composition into the two top-level theorems).
Revised Tier 2 estimate: **2.5 weeks** with B3-a in.



**Goal.** Discharge the 2 axioms in `Stack/Blake3.lean`:
`runOps_b3HashOps_eq` and `runOps_b3CompressOps_eq`.

**Files.**

* Primary: `Stack/Blake3.lean`.
* Read: TS reference `packages/runar-compiler/src/passes/blake3-codegen.ts`.

**Key lemmas.**

* `runOps_b3HashOps_eq` — single-block hash entry, msg ≤ 64.
* `runOps_b3CompressOps_eq` — compression function, cv 32B + block
  64B.
* Concrete `Crypto.blake3Compress` and `Crypto.blake3Init` defs in
  `Crypto/HashBackend.lean` if not present (these may already be
  axiomatic — if so, the discharge replaces the axiom with the
  concrete def + reduction).

**Technique.**

1. Inspect `Stack/Blake3.lean`'s `b3HashOps` / `b3CompressOps`.
2. For each, reduce the multi-opcode sequence step-by-step using
   bytewise ops (`OP_AND`, `OP_OR`, `OP_XOR`) and arithmetic
   primitives. Each reduction is mechanical but the sequence is
   long.
3. Compose into the runOps-equivalence.

**Failure modes.**

* The BLAKE3 compression function in the TS reference uses
  word-level mixing — Lean's `UInt32` may need wrapping. Add a
  `def Crypto.blake3Mix` matching the spec.

**Acceptance gate.**

* `Stack/Blake3.lean` ships two theorems (was: two axioms).
* `axioms = 123` (125 − 2 = 123).

**Effort.** 3 weeks.

**Dependencies.** None (independent of other Phase B work).

### 5.10 Phase B — B4 secp256k1 EC

**Goal.** Discharge the 10 codegen axioms in `Crypto/Spec.lean` §6
for `emitEcAdd / Mul / MulGen / Negate / OnCurve / ModReduce /
EncodeCompressed / MakePoint / PointX / PointY`.

**Files.**

* Primary: `Stack/Ec.lean`.
* Read: existing emit functions; `Crypto/Spec.lean:ecAdd` /
  `ecMul` / etc. (currently abstract — preserved as cryptographic
  axioms; the discharge proves the *codegen* matches, not the
  group laws).

**Key lemmas.** Per emit function, a `runOps_emitEc<X>_eq` theorem
matching the existing axiom signature.

**Technique.**

1. For each emit function, the lowered ops decompose into:
   * decode/encode point (32-byte coordinate split / join)
   * modular arithmetic (`OP_ADD`, `OP_MOD`, `OP_SUB`, etc.)
   * field-inverse via square-and-multiply chain.
2. The decode/encode steps are byte-manipulation only — reduce
   directly with `OP_SPLIT` / `OP_CAT` semantics.
3. The modular arithmetic steps compose against the abstract
   group-law axioms in `Crypto/Spec.lean` (these stay axiomatic).
4. The field-inverse chain is a fixed-shape multi-iteration
   reduction; prove it as a bounded loop.

**Failure modes.**

* Point operations expand to 100–500 opcodes. The proof per emit
  function is multi-hundred-line. Budget accordingly.
* `whnf` heartbeat timeout — apply `attribute [local irreducible]`
  liberally. Per-theorem `set_option maxHeartbeats` may go up to
  16M for the worst cases.
* `emitEcMul` is the worst: 257-iteration MSB-first double-and-add.
  Land it last in B4.

**Acceptance gate.**

* `Stack/Ec.lean` ships 10 theorems; `Crypto/Spec.lean` §6 deletes
  the 10 axioms.
* `axioms = 115` (125 − 10 = 115).

**Effort.** 6–8 weeks.

**Dependencies.** None.

### 5.11 Phase B — B5 NIST P-256 / P-384

**Goal.** Discharge the 14 codegen-to-spec axioms in
`Stack/P256P384.lean` (7 P-256 + 7 P-384 emit functions). Preserve
the 12 group-law axioms in `Crypto/Spec.lean` §2.5 (FIPS 186-5 —
genuine cryptographic assumptions).

**Files.**

* Primary: `Stack/P256P384.lean`.
* Read: same pattern as B4.

**Technique.** Mirror B4 emit-function-by-emit-function. P-256 and
P-384 differ only in modulus and field operations.

**Failure modes.** Same as B4. Larger because of two curves.

**Acceptance gate.**

* 14 theorems land; 14 axioms delete.
* `axioms = 101` (115 − 14).

**Effort.** 6–8 weeks.

**Dependencies.** None (independent of B4).

### 5.12 Phase B — B6 BabyBear field + ext4 **[DONE wave 1, 2026-05-17]**

**Discharged in commit `7dcc7fc3`.** Net delta: −8 axioms (−4 in
`Crypto/Spec.lean` `_correct` companions become theorems; −4 in
`ANF/Eval.lean` bare `bbField{Add,Sub,Mul,Inv}` become concrete
`def`s mirroring `Crypto/Spec.lean` §8.1 one-for-one). Discharge
technique: internal lemma `bbMod_eq_bbFieldMod` plus structural
induction on the exponent for the inverse case. The discharge was
strictly stronger than the original spec envisioned (planned −4
from `_correct` only; the additional −4 bonus came from the
bare-side conversion). See `TRUST_MANIFEST.md` §B6 entry.

The original milestone spec is preserved below for reference.



**Goal.** Discharge the 4 functional-correctness axioms in
`Crypto/Spec.lean` linking the bare `Crypto.bbFieldMul` etc.
backend symbols to the concrete `bbMul` etc. defs.

**Files.**

* Primary: `Crypto/Spec.lean` (the axioms live here).
* Possibly add: `Stack/BabyBear.lean` reductions if needed.

**Technique.**

1. The base field is `Fin (2^31 − 2^27 + 1)`. Either:
   * Prove via reflection on `Fin` (if `decide` is fast enough); or
   * Add a concrete `bbCanonicalRep : Int → Int` helper showing
     the input is in `[0, p)` and prove the identity.
2. The 4 functional-correctness axioms collapse to direct
   `Crypto.bbFieldMul x y = bbMul x y` etc.

**Failure modes.**

* `decide` on `Fin p` for p ~2^31 likely times out. Use the
  helper-based approach.

**Acceptance gate.**

* 4 theorems land; 4 axioms delete.
* `axioms = 97`.

**Effort.** 2 weeks.

**Dependencies.** None.

### 5.13 Phase B — B7 Merkle inductive step

**Goal.** Discharge the inductive step `d > 0` of
`runOps_merkleRootSha256Ops_zero_eq` (base case at `d = 0` already
proved).

**Files.**

* Primary: `Stack/Merkle.lean`.

**Technique.**

1. Induction on `d`.
2. For step case, the `mLevel` block emits ~15 ops that:
   * save current sibling to alt stack,
   * extract `(index >> i) & 1` via shift,
   * conditional swap based on bit,
   * hash the resulting pair via B1's `runOps_hash256Ops_eq`,
   * pop alt stack back.
3. Each step has a clean operational invariant on the stack /
   altstack split.

**Failure modes.**

* Alt-stack tracking is verbose. Define a private invariant
  `merkleStackShape (d i : Nat) (rest : List StackValue) (s : StackState)`
  and chain it.

**Acceptance gate.**

* `runOps_merkleRootSha256Ops_eq` lands at any depth `d`.
* No new axioms; no axioms to remove (this was a proof gap, not
  an axiom shim).

**Effort.** 2 weeks.

**Dependencies.** B1 (for `runOps_hash256Ops_eq`).

### 5.14 Phase B — B8 WOTS+

**Goal.** Discharge the 1 axiom `runOps_wotsBodyOps_eq` in
`Stack/Wots.lean`.

**Files.**

* Primary: `Stack/Wots.lean`.
* Concrete `Crypto.Spec.verifyWOTS` already exists.

**Technique.**

1. Compose B1's SHA-256 reductions across 67 chunks × up to 15
   chain iterations.
2. Outer structure: byte-by-byte processing of `msg`,
   `csum` computation, per-chunk hash chain.
3. Inner structure: per-chain bounded iteration (use the chain
   length encoded in the chunk's value).

**Failure modes.**

* The chain length depends on the chunk's value (a digit 0..15).
  Proof per-digit or as a uniform bound.

**Acceptance gate.**

* 1 theorem lands; 1 axiom deletes.
* `axioms = 96`.

**Effort.** 3 weeks.

**Dependencies.** B1.

### 5.15 Phase B — B9 SLH-DSA

**Goal.** Discharge the 6 codegen-to-spec axioms in
`Stack/SlhDsa.lean` (one per FIPS 205 SHA-2 parameter set:
SHA2_128s/f, SHA2_192s/f, SHA2_256s/f).

**Files.**

* Primary: `Stack/SlhDsa.lean`.
* Concrete `Crypto.Spec.verifySlhDsa_SHA2_<param>` may need to be
  added (currently axiomatic per parameter set).

**Technique.**

1. SLH-DSA composes: SHA-256 (B1) + Merkle (B7) + WOTS+ (B8) +
   FORS tree.
2. Add concrete `Crypto.Spec.verifySlhDsa_<param>` defs in
   `Crypto/Spec.lean` (composing the proved sub-primitives).
3. For each parameter set, prove `runOps_emitVerifySLHDSABody_<param>_eq`
   composing the proved sub-lemmas.
4. Intermediate lemmas:
   * `runOps_emitSlhdsaTweakableHash_eq`
   * `runOps_emitFORS_eq`
   * `runOps_emitSlhdsaMerkleVerify_eq`

**Failure modes.**

* The longest proof in Phase B. Budget accordingly.
* Stack depth for SLH-DSA reductions can blow Lean's elaborator.
  Use `attribute [local irreducible]` aggressively; split
  per-parameter into separate files if needed.

**Acceptance gate.**

* 6 theorems land; 6 axioms delete.
* `axioms = 90`.

**Effort.** 6 weeks (likely concurrent with B4 in a 3-specialist
team).

**Dependencies.** B1, B7, B8.

### 5.16 Phase B — B10 Rabin

**Status (2026-05-17):** a wave-1 in-session subagent attempted
this milestone and discovered a structural blocker —
`Stack.Eval.runOpcode "OP_EQUAL"` deliberately does not model
Bitcoin Script's int↔bytes coercion (comparing `.vBigint` residue
from `OP_MOD` with `.vBytes` SHA-256 digest always returns
`.vBool false`, contradicting `Crypto.Spec.verifyRabinSig_spec`).
The subagent's proposed workaround (weaken the theorem conclusion
to `vBool false`) was rejected and no commit landed. The corrected
prerequisite **B10-prep** (§5.28) widens `OP_EQUAL` to model the
coercion; B10 then follows.

**Goal.** Discharge the 1 axiom `runOps_rabinBodyOps_eq` in
`Stack/Rabin.lean`.

**Files.**

* Primary: `Stack/Rabin.lean`.
* Concrete `Crypto.Spec.verifyRabinSig_spec` already exists.

**Technique.**

1. The Rabin body is 10 opcodes: `OP_SWAP OP_ROT OP_DUP OP_MUL
   OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL`.
2. Reduce step-by-step against the concrete spec.
3. The B1 `OP_SHA256` reduction handles the hash step.
4. After B10-prep, the final `OP_EQUAL` step succeeds via the
   widened int↔bytes coercion arm. The opcode-by-opcode reduction
   skeleton from the wave-1 draft (rejected for weakening the
   conclusion) is reusable; only the terminal-step composition
   changes.

**Failure modes.**

* `OP_EQUAL` returns a Bool — the spec returns a Bool — they must
  agree bit-for-bit. After B10-prep, the coercion path covers
  `.vBigint x = .vBytes (encodeMinimalLE x)` modulo
  `decodeMinimalLE / encodeMinimalLE` round-trip.

**Acceptance gate.**

* 1 theorem lands; 1 axiom deletes.
* `axioms` count drops by 1 after this milestone.

**Effort.** 1 week (after B10-prep).

**Dependencies.** B1 (already proved); B10-prep (§5.28).

### 5.17 Phase D — D1 Merkle dispatch

**Goal.** Discharge `merkle_dispatch_selection_correct` in
`Pipeline.lean`.

**Files.**

* Primary: `Pipeline.lean`.
* Read: `Script/Emit.lean:emitDispatchHeadNonLast` and `Last`.
  `Stack/Lower.lean` dispatch chain.

**Technique.**

1. The dispatch chain is a `bin_op`/equality cascade on the
   first-method-name hash.
2. A3 (arith) proves binop / equality `runOps` reductions; D1
   composes those to show the cascade selects exactly the
   matching public method.
3. Structural induction on the `publicMethodsOf` list.

**Failure modes.**

* Multiple public methods with the same name-hash prefix — should
  be ruled out by the existing `publicMethodsOf` uniqueness
  invariant. Verify it is.

**Acceptance gate.**

* 1 axiom deletes; theorem lands.
* `axioms = 88`.

**Effort.** 3 weeks.

**Dependencies.** A3.

### 5.18 Phase D — D2 stateful continuation

**Goal.** Discharge `auto_check_preimage_at_method_entry_correct`
and `auto_state_output_at_method_exit_correct`.

**Files.**

* Primary: `Pipeline.lean`.
* Read: `Stack/TxContext.lean:ValidTxContext`,
  `runOpcode_CHECKSIG_ValidTxContext`. `Stack/Agrees.lean` props
  bridge.

**Technique.**

1. For `auto_check_preimage_at_method_entry_correct`: under
   `ValidTxContext`, the auto-injected `OP_CHECKSIG` chain reduces
   to `Crypto.PreimageBackend.checkPreimage`. Compose against
   existing `runOpcode_CHECKSIG_ValidTxContext`.
2. For `auto_state_output_at_method_exit_correct`: A5
   (update_prop) gives ANF/Stack `props` agreement. The
   auto-injected state-output emission threads `props` through to
   the output encoding. The encoding side is concrete via
   `Crypto.computeStateOutput`.

**Failure modes.**

* Auto-injection machinery is in `Stack/Lower.lean`'s top-level
  method-lowering function. Trace through it carefully.

**Acceptance gate.**

* 2 axioms delete; 2 theorems land.
* `axioms = 86`.

**Effort.** 3 weeks.

**Dependencies.** A5, Phase E (already done).

### 5.19 Phase D — D3 terminal-assert + NIP cleanup **[DONE wave 1, 2026-05-17]**

**Discharged in commit `7dcc7fc3`.** Net delta: −2 axioms in
`Pipeline.lean`. Both `terminal_assert_elision_residue_correct` and
`nip_cleanup_residue_correct` had `(... isSome) → (... isSome)`
shape — the hypothesis and conclusion were the same `runOps rawOps
initialStack` statement on identical ops and state. The discharge
was `intro h; exact h` identity propagation. The structural witnesses
(`terminalAssertElidesFor` / `nipCleanupActiveFor`) live in
`Stack/Agrees.lean` as decidable Bool predicates that were already
proved upstream of every caller. See `TRUST_MANIFEST.md` §D3 entry.

The original milestone spec is preserved below for reference.



**Goal.** Discharge `terminal_assert_elision_residue_correct` and
`nip_cleanup_residue_correct`.

**Files.**

* Primary: `Pipeline.lean`.
* Read: `Stack/Agrees.lean:terminalAssertElidesFor`,
  `nipCleanupActiveFor` (decidable predicates already exist).

**Technique.**

1. When `terminalAssertElidesFor` holds, the lowered body's last
   binding is an assert whose VERIFY is elided in favour of an
   implicit return. The Bitcoin Script semantics: if the top of
   stack is truthy at script end, the script succeeds.
2. Show the body's final stack residue matches the asserted bool.
3. For `nipCleanupActiveFor`: trailing `OP_NIP` chain reduces
   post-body stack to single boolean residue.

**Failure modes.**

* "Truthy" in Bitcoin Script is non-zero / non-empty — but ANF
  `.vBool true` is exactly `[0x01]`. Verify the encoding match in
  `Stack/Eval.lean:asBool?`.

**Acceptance gate.**

* 2 axioms delete.
* `axioms = 84`.

**Effort.** 2 weeks.

**Dependencies.** None (independent of Stage C).

### 5.20 Phase C2 — multi-method dispatch joins

**Goal.** Discharge the multi-method `pushCodesepIndex` join
correctness.

**Files.**

* Primary: `Pipeline.lean` and `Script/EmitCorrect.lean`.

**Technique.**

1. The existing `compileSafeWithCodeSepPatches` rejects
   branch-ambiguous joins. The proof obligation is: under
   non-ambiguous joins, the runtime-selected branch's
   `pushCodesepIndex` matches the patched bytes.
2. The byte-offset vs op-index semantic gap requires either:
   * A new lemma `runOpsPc_byte_offset_matches_op_index` linking
     the PC-aware runner's byte tracking to the op-index-based
     emit, OR
   * Refactoring the patch records to carry op-index in addition
     to byte-offset.
3. Choose the cleaner approach; document the choice in the file
   header.

**Failure modes.**

* The semantic gap may turn out to be deeper than expected. If
  blocked, document the obstacle and continue with the rest of
  Path 2; C2 can land last.

**Acceptance gate.**

* C2 closes; multi-method capstone composes cleanly.
* No axiom delta (C1 was already proved; C2 fills a proof gap).

**Effort.** 2–4 weeks (uncertainty in the byte-offset / op-index
gap depth).

**Dependencies.** None strict; cleaner after Stage C lands.

### 5.21 SupportedANFBody widening + capstone widening

**Goal.** Define the inductive predicate `SupportedANFBody`
unioning the discharged structural fragments, widen the capstone
to take `SupportedANFBody` instead of `structuralRefBody`, update
the harness to recognise the new predicate.

**Files.**

* Primary: `Stack/Agrees.lean` (predicate definition), `Pipeline.lean`
  (capstone widening), `tests/PipelineConformance.lean` (harness
  reclassification).

**Key lemmas.**

* `SupportedANFBody : List ANFBinding → Prop` — inductive closure
  of `structuralRefBody` ∪ A3 ∪ A4 ∪ A5 ∪ A6 ∪ A7 ∪ A8.
* `instance : Decidable (SupportedANFBody bs)` via Bool checker.
* `compileSafe_single_public_observational_correct_unconditional_supported`
  — capstone with `hSupported : SupportedANFBody anfM.body`
  replacing `hRefBody`.
* Same for the multi-method capstone.

**Technique.**

1. Inductive predicate with one constructor per Stage C family,
   recursive on body bindings.
2. The Decidable instance is the disjunction of per-family Bool
   checkers (all already landed in AgreesA<k>.lean files).
3. The capstone widening composes the per-family wrappers via case
   analysis on the body's binding shape.

**Failure modes.**

* The inductive predicate's mutual structure for ifVal / loop /
  methodCall (which recursively contain SupportedANFBody bodies)
  may require Lean's `mutual inductive`. Use it sparingly.

**Acceptance gate.**

* `SupportedANFBody` is Decidable.
* Capstone takes `SupportedANFBody` premise.
* `tests/PipelineConformance.lean` reclassifies fixtures.

**Effort.** 2 weeks.

**Dependencies.** A3 – A8.

### 5.22 Omnibus axiom retirement

**Goal.** Delete `compileSafe_observational_correct_modulo_codegen_axioms`
from `Pipeline.lean`; replace with a `theorem` whose body composes
the widened capstone with Phase D's now-proved wrapper soundness.

**Files.**

* Primary: `Pipeline.lean`, `tests/PipelineConformance.lean`.

**Technique.**

1. Replace `axiom compileSafe_observational_correct_modulo_codegen_axioms`
   with `theorem`. Its body uses the multi-method capstone +
   widened SupportedANFBody + Phase D discharged wrappers + Phase
   B discharged crypto.
2. `tests/PipelineConformance.lean`'s `verifiedModuloCodegenAxioms`
   branch becomes unreachable. Drop the branch; the tier-2
   classifier collapses into tier-1 VERIFIED.

**Failure modes.**

* If any sub-component still has axiom-shim residue (e.g., one
  Phase B primitive not discharged), the omnibus retirement
  blocks. Hold this step until **all** prerequisites land.

**Acceptance gate.**

* Omnibus axiom no longer in `Pipeline.lean`.
* `axioms = ≤84` (final count depends on whether B1's optional
  composition axiom was added).
* `tests/PipelineConformance.lean` reports 56/56 VERIFIED-direct.

**Effort.** 1 week.

**Dependencies.** Everything else.

### 5.23 O1 — omnibus axiom split (Tier 1, NEW)

**Goal.** Split the single Phase D harness omnibus axiom
`compileSafe_observational_correct_modulo_codegen_axioms` in
`Pipeline.lean` into 9 per-constructor-family sub-omnibuses, and
re-engineer `tests/PipelineConformance.lean` to dispatch fixtures
into `VERIFIED-modulo-<family>-codegen-axioms` tiers. This is the
coordinating milestone that lets visible harness progress track
Tier 1 Stage C / Phase D landings.

**Files.**

* Primary: `Pipeline.lean`, `tests/PipelineConformance.lean`.
* Read: `Stack/Agrees.lean` for the existing per-family structural
  predicates (`structuralArithBody`, `structuralCallBody`, etc.).

**Key elements.**

* Define 9 sub-omnibus axioms (per the inventory in
  `TRUST_MANIFEST.md` §"Phase D harness integration omnibus —
  planned split"): one each for `_modulo_arith_codegen`,
  `_modulo_math_byte_call_codegen`, `_modulo_crypto_call_codegen`,
  `_modulo_update_prop_codegen`, `_modulo_if_val_codegen`,
  `_modulo_loop_codegen`, `_modulo_method_call_codegen`,
  `_modulo_dispatch_codegen`, `_modulo_stateful_codegen`.
* Each sub-omnibus carries the corresponding structural-predicate
  hypothesis from `Stack/Agrees.lean`, so dispatching the harness
  on the per-family Bool checker classifies fixtures into the
  right tier.
* Replace the existing single-omnibus reference in `Pipeline.lean`
  with a `theorem` whose body case-splits on the body family and
  applies the matching sub-omnibus.
* Re-engineer `tests/PipelineConformance.lean` `checkFixture` to
  return one of `Outcome.verified` (no sub-omnibus needed),
  `Outcome.verifiedModuloArithCodegen`,
  `Outcome.verifiedModuloMathByteCallCodegen`, etc., per the
  per-family Bool checker dispatch.

**Technique.**

1. Mechanically split the omnibus into 9 sub-omnibuses by
   restricting hypotheses to the corresponding structural predicate.
2. Compose the per-family substrate (Stage C narrowed wrappers
   already in tree) into the per-family discharge bridge: each
   sub-omnibus retires as `runMethod_lower_public_unique_no_post_structural*_isSome`
   lands at full coverage.
3. Update the harness output to a finer per-family bucket
   classification.

**Failure modes.**

* Some fixtures contain bindings from multiple families (e.g.,
  one `binOp` + one `call`); each lands in
  `VERIFIED-modulo-{arith,call}-codegen-axioms`, requiring
  multiple sub-omnibuses to retire before the fixture flips
  fully to `VERIFIED`. The harness needs to report a
  "modulo-{family-set}" classification per fixture.
* Short-term axiom count goes UP by ~8 (9 sub-omnibuses replace
  1 omnibus). This is intentional and reverses as each
  sub-omnibus retires.

**Acceptance gate.**

* 9 sub-omnibus axioms exist in `Pipeline.lean`.
* `compileSafe_observational_correct_modulo_codegen_axioms` is
  rewritten as a `theorem` whose body composes the per-family
  sub-omnibuses (no longer an axiom).
* `tests/PipelineConformance.lean` reports per-family
  classification per fixture.
* `./scripts/check-tcb-drift.sh` reports `axioms = 117` (was 110,
  +9 sub-omnibuses, −1 retired-as-theorem-via-composition omnibus
  = net +8). `TRUST_MANIFEST.md` per-file count for `Pipeline.lean`
  updates to 12 (4 Phase D D1/D2.a/D2.b + 9 sub-omnibuses − 1
  retired omnibus = 12, then drops as Tier 1 wrappers land).

**Effort.** 2.5 weeks.

**Dependencies.** None for the split itself; sub-omnibuses retire
as their respective Stage C / Phase B / Phase D milestones land.

### 5.24 pXNegate-derivable conversion (Tier 1, NEW)

**Goal.** Convert `Crypto.p256Negate : ByteArray → ByteArray` and
`Crypto.p384Negate : ByteArray → ByteArray` from bare function-symbol
axioms in `Crypto/Spec.lean` to concrete `def`s.

**Files.**

* Primary: `Crypto/Spec.lean`.

**Technique.**

1. Define the standard point negation formula: given a compressed
   point `p = parity ++ x`, decompose into `(x, y)`, return
   `(x, p_mod − y)` re-encoded. For uncompressed-coordinate format
   `(x, y) → (x, p_mod − y mod p_mod)`. Field modulus `p_mod` is
   the curve modulus (FIPS 186-5 §D.1.2.3 for P-256 / §D.1.2.4
   for P-384).
2. Ensure the def is `decide`-checkable on small sample points
   without timing out the elaborator.

**Failure modes.**

* The compressed-point encoding format used by the codegen may
  not directly match the spec's parity-byte convention. Check
  `Stack/P256P384.lean` for the codegen's compress / decompress
  layout and mirror it in the def.

**Acceptance gate.**

* `Crypto.p256Negate` and `Crypto.p384Negate` are concrete `def`s.
* Net axiom delta: −2 (in `Crypto/Spec.lean`).
* `./scripts/lean-verify.sh` green.

**Effort.** 0.5 weeks.

**Dependencies.** None.

### 5.25 B4-a concrete `Crypto.ec*` defs (Tier 1, NEW)

**Goal.** Land concrete Lean `def`s for the 10 secp256k1 primitive
symbols currently axiomatised in `ANF/Eval.lean` lines 289-298
(`ecAdd / ecMul / ecMulGen / ecNegate / ecOnCurve / ecModReduce /
ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY`). Prerequisite
for any future B4 codegen-to-spec discharge (Tier 3) and unblocks
the §5.29 group-law audit.

**Files.**

* Primary: `ANF/Eval.lean` (replace 10 bare axioms with defs).
* Possibly: `Crypto/Spec.lean` (helper field-arithmetic defs if not
  already present), or a new `Crypto/Secp256k1.lean` if the codebase
  prefers a separate file (mirroring `Crypto/HashBackend.lean` from
  B3-a).

**Technique.**

1. Mirror SEC 2 v2 secp256k1 byte-level semantics. Field modulus
   `p = 2^256 − 2^32 − 977`; group order `n`; generator `G`.
2. `ecMakePoint`, `ecPointX`, `ecPointY`: direct byte split / join
   of 32-byte coordinates.
3. `ecEncodeCompressed`: parity byte + x-coordinate. Inverse of
   compressed-point decoding (matches the spec's compressed form).
4. `ecOnCurve`: check `y² ≡ x³ + 7 (mod p)` byte-by-byte.
5. `ecModReduce`: standard `((a mod p) + p) mod p` reduction.
6. `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`: implement group law
   in affine coordinates over `Int` (the bare def — efficiency is
   not a goal; correctness is).

**Failure modes.**

* `ecMul` involves a square-and-multiply loop; needs an explicit
  `termination_by` (iteration count fixed at 256 — bounded).
* Byte ordering (big-endian vs little-endian) must match the codegen
  precisely. Cross-check against `Stack/Ec.lean` emit functions.

**Acceptance gate.**

* `ANF/Eval.lean` ships 10 concrete `def`s in place of the 10 bare
  ec* axioms.
* `./scripts/lean-verify.sh` green; `./scripts/check-tcb-drift.sh`
  reports `axioms = 100` (was 110, −10).
* Net delta: −10.

**Effort.** 2 weeks.

**Dependencies.** None (independent of B5-a / B9-a).

### 5.26 B5-a concrete `Crypto.p256* / p384*` defs (Tier 1, NEW)

**Goal.** Land concrete Lean `def`s for the 12 P-256 / P-384
primitive symbols currently axiomatised in `ANF/Eval.lean` lines
301-314 (`p256Add / p256Mul / p256MulGen / p256OnCurve /
p256EncodeCompressed / verifyECDSA_P256` and the 6 P-384 mirrors).
Prerequisite for any future B5 codegen-to-spec discharge (Tier 3)
and unblocks the §5.29 group-law audit.

**Files.**

* Primary: `ANF/Eval.lean`.
* Possibly: `Crypto/Spec.lean` or a new `Crypto/NistEC.lean`.

**Technique.** Mirror §5.25 for FIPS 186-5 P-256 / P-384 curves.
Different field modulus, different generator, different curve
equation, but same code structure as secp256k1.

**Failure modes.** Same as §5.25, doubled for P-256 + P-384.

**Acceptance gate.**

* 12 concrete defs land; 12 axioms delete.
* `./scripts/check-tcb-drift.sh` reports `axioms = 88` (after
  §5.25 lands; cumulative −22).

**Effort.** 2 weeks.

**Dependencies.** None (independent of B4-a / B9-a).

### 5.27 B9-a concrete `Crypto.Spec.verifySlhDsa_*` defs (Tier 1, NEW)

**Goal.** Land concrete `def`s for the 6 FIPS 205 SHA-2 SLH-DSA
parameter sets in `Crypto/Spec.lean`. Re-route the bare
`verifySLHDSA_SHA2_*` axioms in `ANF/Eval.lean` lines 357-362 as
delegating `def`s (mirroring the wave-1 verifier-axiom delegation
pattern for `merkleRootSha256` / `verifyRabinSig`). Prerequisite
for any future B9 codegen-to-spec discharge (Tier 3).

**Files.**

* Primary: `Crypto/Spec.lean` (add concrete spec defs), `ANF/Eval.lean`
  (re-route axioms as delegating defs).

**Technique.**

1. Compose SHA-256 + Merkle (using `Crypto.Spec.merkleRootD`) +
   WOTS+ (using `Crypto.Spec.verifyWOTS`) + FORS tree, per FIPS 205.
2. Six parameter sets (SHA2_128s, 128f, 192s, 192f, 256s, 256f)
   differ in tree parameters (height, leaves, hashes per node).
3. The import-cycle wrinkle the wave 1 delegation agent identified
   (Crypto/Spec ↔ ANF/Eval) may resurface; resolve via the
   inline-helpers pattern (duplicate helpers in `ANF/Eval.lean`
   byte-identical to `Crypto/Spec.lean` definitions) or via a
   shared `Crypto/SpecCore.lean` refactor as the wave 1 delegation
   agent recommended.

**Failure modes.**

* FORS tree spec is substantial (~200 lines per parameter set).
  Plan for ~3 weeks total, not single-week per parameter set.
* The bare-axiom signatures use 3 `ByteArray` arguments (msg, sig,
  pk); the delegating def must match exactly.

**Acceptance gate.**

* 6 concrete spec defs in `Crypto/Spec.lean`.
* 6 delegating defs in `ANF/Eval.lean` replacing the bare axioms.
* `./scripts/check-tcb-drift.sh` reports `axioms = 82` (cumulative
  after §5.25 + §5.26 land).

**Effort.** 3 weeks.

**Dependencies.** Optional: shared `Crypto/SpecCore.lean` refactor
(also unblocks `verifyWOTS` delegation, which was deferred in
wave 1 for the same import-cycle reason). The refactor is ~3 days
of mechanical file-splitting.

### 5.28 B10-prep — `Stack/Eval.lean` `OP_EQUAL` coercion fix (Tier 1, NEW)

**Goal.** Widen `Stack.Eval.runOpcode "OP_EQUAL"` in
`Stack/Eval.lean` to model Bitcoin Script's int↔bytes coercion.
Currently the implementation returns `.vBool false` when comparing
a `.vBigint` with a `.vBytes` (or vice versa), but Bitcoin Script
v2 coerces both to a common Script-number-bytes form before
comparison. This blocks B10 Rabin discharge: the Rabin codegen
produces `OP_MOD` (which leaves `.vBigint`) and then compares
against `SHA256(msg)` (`.vBytes`); the current Lean model says
they're never equal, contradicting `verifyRabinSig_spec`.

**Files.**

* Primary: `Stack/Eval.lean` (the `runOpcode "OP_EQUAL"` arm).
* Audit: every theorem under `RunarVerification/` that references
  the strict `OP_EQUAL` behavior to ensure no regression.

**Technique.**

1. In `runOpcode "OP_EQUAL"`, after extracting the two top stack
   values, attempt both `asInt? a` and `asBytes? a` for each
   operand. If both are `.some`, compare on the coerced form
   (using `Stack.decodeMinimalLE` / `encodeMinimalLE` for the
   bytes↔int direction).
2. Preserve the existing failure paths (insufficient stack,
   incompatible types after coercion attempt).
3. Run `./scripts/lean-verify.sh` to catch any downstream proof
   that depended on the strict behavior.

**Failure modes.**

* A downstream proof in `Stack/Peephole.lean` or `Stack/Sim.lean`
  may rely on the strict-type behavior; the audit step is
  non-trivial. Budget 2 days for the audit and any required
  proof patches.
* The coercion semantics must match Bitcoin SV consensus exactly
  — cross-check against `bsv` reference implementations or test
  vectors before landing.

**Acceptance gate.**

* `runOpcode "OP_EQUAL"` correctly compares `.vBigint pubKey` vs
  `.vBytes (SHA256 msg)` via coercion.
* `./scripts/lean-verify.sh` green; no proofs broken.
* `./scripts/run-pipeline-conformance.sh` unchanged (no fixture
  regression).

**Effort.** 0.5 weeks (0.5 day implementation + 2 days audit).

**Dependencies.** None.

### 5.29 Crypto/Spec group-law audit (Tier 2, NEW)

**Goal.** After §5.25 (B4-a) and §5.26 (B5-a) land concrete defs
for `Crypto.ecAdd / p256Add / p384Add`, audit the 20 group-law
axioms in `Crypto/Spec.lean` §1 (10 secp256k1) and §2.5 (10 P-256
+ P-384) and convert each to a theorem proved against the concrete
def. Estimated removal: 15-20 axioms.

**Files.**

* Primary: `Crypto/Spec.lean`.

**Technique.**

1. Each axiom (e.g., `ecAdd_assoc`, `ecAdd_comm`, `ecAdd_zero`,
   `ecMul_distrib_add`) becomes a `theorem` proved by `decide`
   for small sample points or by direct algebraic manipulation
   over the concrete `ecAdd` def.
2. Some axioms (e.g., `ecMulGen_one_ne_zero`) require a
   non-triviality proof: the generator `G` has non-zero image
   under `[1]`. This is a concrete byte-level check.

**Failure modes.**

* `decide` over `ByteArray` for full 256-bit field operations
  will time out the elaborator. Need `decide`-fast helpers or
  manual proof.
* `ecAdd_assoc` is the standard hard theorem in elliptic-curve
  group laws — non-trivial even with a concrete `ecAdd` def.
  Budget more time for this one specifically.

**Acceptance gate.**

* Up to 20 theorems land in place of axioms (target: at least 15;
  some may remain axiomatic if the proof effort exceeds the
  1.5-week budget).

**Effort.** 1.5 weeks.

**Dependencies.** B4-a (§5.25) + B5-a (§5.26).

---

## 6. Per-milestone quality gates

Every milestone passes these gates before being marked complete in
`TODO.md`:

1. **Build green.** `./scripts/lean-verify.sh` succeeds.
2. **TCB drift gate.** `./scripts/check-tcb-drift.sh` matches the
   axiom count claimed in `TRUST_MANIFEST.md`.
3. **No regressions.** `lake env ./.lake/build/bin/goldenLoad` and
   `roundtrip` still 56/56.
4. **No `sorry` / `admit` / `partial def` / new opaque-with-stub.**
   `grep -rn "sorry\|admit\|partial def" RunarVerification/` is
   empty.
5. **No `hRunOk`-style conclusion-restating hypotheses.** Manual
   review of new theorem signatures against the workflow rule in
   §2.1.
6. **Clean working tree.** `git diff --check` clean.
7. **Conformance harness unchanged or improved.** `./scripts/run-pipeline-conformance.sh`
   passes; counts of VERIFIED-direct / VERIFIED-modulo-codegen-axioms
   shift in the right direction.
8. **TRUST_MANIFEST and TODO.md updated.** Axiom count, per-file
   inventory, and milestone status reflect the change.

Each milestone PR (or local checkpoint) includes a short note
documenting the new theorem signatures and the discharge technique
used, for the audit trail in `HANDOFF.md`.

---

## 7. Failure modes and recovery

### 7.1 Heartbeat timeout in Pipeline-side instantiation

**Symptom.** `(deterministic) timeout at whnf` or `maxHeartbeats`
errors elaborating against deeply-nested `peephole*` compositions.

**Fix.**

```lean
section
attribute [local irreducible]
  Peephole.peepholePassAll
  Peephole.peepholePostFold
  Peephole.peepholeChainFold
  Peephole.peepholeRollPickFold
  Peephole.peepholePassAllFlat
  Peephole.passAllInner15

set_option maxHeartbeats 1600000 in
set_option linter.constructorNameAsVariable false in
theorem ... := by ...

end
```

### 7.2 Lean's `cases v with` exhaustivity errors

**Symptom.** `Alternative <ctor> has not been provided` when a new
ANF or StackOp constructor lands.

**Fix.** Add the missing arm. For an impossible-case (where the
constructor cannot satisfy the structural predicate), discharge
via `simp [predicateName] at h`. Pattern present throughout
`Stack/Agrees.lean`.

### 7.3 `rfl` fails on equation-compiler defs

**Symptom.** `Application type mismatch: rfl has type ?m = ?m but
is expected to have type evalValue s ... = ok ...`.

**Fix.** Use `by simp [RunarVerification.ANF.Eval.evalValue]` or
`by rfl` (tactic mode, not term mode).

### 7.4 Linter "unused simp argument" fails the build

**Symptom.** `error: This simp argument is unused`. The linter is
strict.

**Fix.** Remove the unused arg, or set `set_option
linter.unusedSimpArgs false in` before the theorem.

### 7.5 Stage C wrapper hypothesis seems to need `hRunOk`

**Symptom.** The proof skeleton wants a hypothesis that says "the
lowered ops run successfully" — but that's the conclusion.

**Fix.** Take `agreesTagged` on the *initial* state instead. The
agreesTagged invariant ensures every stack slot has the expected
type, which is what `runOps` needs to avoid runtime errors.
`agreesTagged` is an input-side fact, not the conclusion.

### 7.6 Phase B per-primitive proof bottoms out at FIPS reference

**Symptom.** The runOps reduction reaches an opcode-level identity
that depends on the cryptographic primitive's specification.

**Fix.** Compose against the existing cryptographic axiom in
`Crypto/Spec.lean` (group laws, hash collision-resistance, etc.).
These are preserved by design — Path 2 does NOT discharge them.
The runOps proof shows the *codegen* matches the spec; the spec
itself remains axiomatic.

### 7.7 Integration agent finds shifted hunks

**Symptom.** `git apply` fails when integrating a worktree because
target has drifted (other work landed in the meantime).

**Fix.** Dispatch a dedicated integration agent that reads both
source and target side-by-side, identifies the surgical
additions, applies them with `Edit` rather than `git apply`. The
integration agent's role is exactly this kind of careful manual
merge.

### 7.8 Sub-agent runs out of usage budget mid-proof

**Symptom.** `You're out of extra usage` or API error from the
sub-agent dispatch.

**Fix.** Wait for the limit to reset, then retry with the same
prompt (the worktree state persists). If the agent had made
substantial progress, send a continuation prompt to the same agent
ID via `SendMessage`.

### 7.9 Build green but pipelineConformance regressed

**Symptom.** Compilation succeeds but a fixture moved from
VERIFIED-modulo-codegen-axioms back to a DEFERRED bucket.

**Fix.** Check `compileSafe`'s validateStackOp for a new
sentinel-rejection; check whether a peephole rewrite produces
something the emitter doesn't recognise. The harness output's
per-fixture line tells you which bucket caused the regression.

### 7.10 Two parallel agents conflict on shared file

**Symptom.** Both A6 and A7 want to add structural-predicate
helpers to `Stack/Agrees.lean`.

**Fix.** Per workflow rule §2.4, Stage C work stays in per-family
`AgreesA<k>.lean`. If a helper is genuinely shared, land it in
`Stack/Agrees.lean` as a separate small PR before either family
needs it.

---

## 8. Maintenance rituals

Every two weeks (or per milestone, whichever comes first):

* **Refresh `HANDOFF.md`** with the latest milestone status,
  capstone signatures, and axiom count.
* **Refresh `TODO.md`** marking completed milestones, adding any
  newly-discovered subtasks.
* **Refresh `TRUST_MANIFEST.md`** with the current axiom inventory
  and per-file count.
* **Run the full local gate suite:** `./scripts/lean-verify.sh`,
  `./scripts/check-tcb-drift.sh`,
  `./scripts/run-pipeline-conformance.sh`.
* **Verify CI is green** on `origin/main`.
* **Audit for `sorry` / `admit` / `partial def` / new
  `axiom`** outside `Crypto/Spec.lean`. The grep is one command:
  `grep -rn "sorry\|admit\|partial def" RunarVerification/`.
* **Update `README.md` axiom count** if the headline number has
  shifted.

Every milestone:

* **Commit message format:** `verification: <milestone> — discharge
  <N> axiom(s)` (no AI attribution, per CLAUDE.md).
* **Update the audit trail** in `HANDOFF.md` with the theorem
  signature and a one-paragraph proof sketch.

---

## 9. Reading order for new contributors

A new contributor picking up Path 2 cold reads these in order:

1. **`README.md`** ⇒ "What This Verification Delivers" + "Caveat —
   Path 2 is future work".
2. **`HANDOFF.md`** for phase history and capstone signatures.
3. **`TRUST_MANIFEST.md`** for the per-axiom inventory and
   discharge paths.
4. **`TODO.md`** for the lightweight task list.
5. **This file (`PATH2_PLAN.md`)** for the detailed execution plan.
6. **Pick a milestone from §5**, read its "Files", "Key lemmas",
   "Technique" sections, then dive into the named files in
   `RunarVerification/`.
7. **Reference materials:**
   * `Stack/Agrees.lean` lines 2820–3107 for `simpleStepRel` and
     `agreesTagged_chain_preserves` (the abstract Stage C driver).
   * `Pipeline.lean` `Soundness` namespace for the capstone
     theorems and the omnibus axiom.
   * `Stack/AgreesA<k>.lean` for the per-family Stage C narrowed
     scaffolding to widen.

---

## 10. Notes on what NOT to do

* **Don't try to prove everything end-to-end in `Pipeline.lean`.**
  Use the per-file, per-milestone structure. Stage C lives in
  `AgreesA<k>.lean`. Phase B lives in `Stack/<Primitive>.lean`.
  `Pipeline.lean` only changes at the SupportedANFBody widening
  and omnibus retirement.
* **Don't introduce new axioms to make a step compile.** If a step
  appears to need an axiom, you have the wrong technique. The only
  acceptable axioms are cryptographic ones in `Crypto/Spec.lean`,
  added with a literature citation. Compiler-correctness axioms
  do not get added — they get *removed* by Path 2.
* **Don't widen `simpleStepRel` in a way that breaks existing
  proofs.** Adding new arms is fine; modifying existing arms is
  not. If existing arms need adjustment, that's a separate
  refactor PR.
* **Don't skip the workflow rules in §2.** They each address a
  concrete failure mode that cost time on Path 1.
* **Don't merge from `main` mid-milestone without re-running
  `lean-verify.sh`.** Other work may have landed that shifts
  context for active proofs.

---

End of plan. When this is fully executed, the omnibus axiom is
gone, the conformance harness reports 56/56 VERIFIED-direct, and
the trust footprint contains only cryptographic-primitive
assumptions. Rúnar joins the small group of production compilers
with a complete, kernel-checked correctness proof.

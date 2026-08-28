# Script-size optimizer — Phases 0–2 results

**Scope:** the first slice of the size-optimization brief — baseline instrumentation (Phase 0),
an exact script-byte cost model (Phase 1), and two prototype optimizations behind opt-in flags
(Phase 2). No modular-domain analysis, no witness hints, no scalar-multiplication algorithms.
**Companion documents:** [`script-size-optimization-baseline.md`](script-size-optimization-baseline.md),
[`stack-scheduler-design.md`](stack-scheduler-design.md).

Everything below is measured on the 72 conformance fixtures with
`pnpm --filter runar-conformance run script-metrics -- --compare current,liveness,ec-pool,both`.

---

## 1. Headline

| | corpus bytes | vs baseline | fixtures changed | fixtures grown |
|---|---:|---:|---:|---:|
| `current` (shipping) | 13,526,563 | — | — | — |
| `liveness` (scheduler) | 13,526,482 | −0.0 % | 34 | 0 |
| `ec-pool` (constant pool) | 6,285,154 | **−53.5 %** | 9 | 0 |
| `both` | 6,285,073 | **−53.5 %** | 43 | 0 |

**`conformance/tests/p256-wallet`: 958,792 → 304,463 bytes (−68.2 %)**, which is the brief's
959 kB reference implementation. `p384-wallet`: 1,963,300 → 463,435 (−76.4 %).

The next step after this slice has been measured rather than projected: adding reduction
sinking takes `p256-wallet` to **179,796 bytes (−81.2 % from shipping)** and `p384-wallet` to
272,584 (−86.1 %). See §3.7, and §3.8 for the precondition it turns out to need.

Default output is unchanged: all 72 fixtures still reproduce their checked-in
`expected-script.hex` byte-for-byte
(`packages/runar-compiler/src/__tests__/golden-invariance.test.ts`), and the Go and Rust
cross-compiler golden tests still pass.

---

## 2. What was built

| Phase | Deliverable | Files |
|---|---|---|
| 0 | Byte-category instrumentation + benchmark runner | `packages/runar-compiler/src/metrics/script-metrics.ts`, `conformance/runner/script-metrics.ts` |
| 1 | Exact script-byte cost model | `packages/runar-compiler/src/metrics/cost-model.ts` |
| 2a | Liveness scheduler (`--stack-scheduler=liveness`) | `packages/runar-compiler/src/passes/05-stack-lower.ts` |
| 2b | EC constant pool (`--ec-constant-pool`) | `packages/runar-compiler/src/passes/ec-codegen.ts`, `p256-p384-codegen.ts` |

### Phase 1 — the cost model is exact, not an estimate

```ts
estimateScriptBytes(ops) === emitMethod({ ops, … }).scriptHex.length / 2
```

is asserted for every method of every fixture that ships a `.runar.ts`, before and after
peephole (`__tests__/cost-model.test.ts`, 101 assertions). That exactness turned out to matter
more than expected — see §5.

### Phase 2b — EC constant pool

`ECTracker` gained a pooled slot per curve constant. `pushConst(slot, value, name)` compares
the emitted cost of `OP_PICK`-ing the slot against re-pushing the literal and takes the
cheaper, so pooling can never make an individual call site larger. Every EC emitter that does
more than a couple of reductions parks the field prime (and, for the ladders, the group order)
on entry and releases it on exit.

| emitter | current | pooled | |
|---|---:|---:|---:|
| `emitVerifyECDSA_P256` | 974,024 | 319,693 | −67.2 % |
| `emitVerifyECDSA_P384` | 1,987,394 | 487,527 | −75.5 % |
| `emitP256Mul` | 459,746 | 150,512 | −67.3 % |
| `emitP384Mul` | 927,350 | 227,044 | −75.5 % |
| `emitEcMul` (secp256k1) | 428,676 | 140,242 | −67.3 % |
| `emitEcAdd` | 25,426 | 8,791 | −65.4 % |

### Phase 2a — liveness scheduler

Two transformations, both gated on `schedulerMode: 'liveness'`:

1. **Alt-stack result spilling.** A result whose next use is not the following binding is
   parked with `OP_TOALTSTACK`, keeping the operands a chain reads repeatedly at depth 0/1.
   The whole spill group is restored in one go before the first binding that needs any of it —
   which puts the values back in production order, the order an ANF accumulation reads them.
2. **Commutative operand ordering.** For `+ * === !== & | ^` (excluding `+` on ByteString,
   which is `OP_CAT`), the operands are materialized in whichever order the cost model scores
   cheaper.

Selection is per method: both schedules are lowered and the cheaper one — measured after
peephole — is kept. "The scheduler never grows a method" is therefore structural, not a hope.

| fixture | current | liveness | |
|---|---:|---:|---:|
| `arithmetic` | 28 | 18 | **−35.7 %** |
| `bounded-loop` | 42 | 37 | −11.9 % |
| `if-without-else-multi-temp` | 244 | 243 | −0.4 % |
| ~30 mid-size fixtures | 795–17,348 | | −0.1 % to −0.2 % |
| EC / SLH-DSA / SHA-256 / BLAKE3 | | unchanged | 0 % |

18 bytes for `arithmetic` is the hand-derived optimum recorded in
[`stack-scheduler-design.md`](stack-scheduler-design.md) §2.4 — the scheduler reached it
independently.

---

## 3. Answers to the brief's questions (for this slice)

### 3.1 What is generic?

- **The byte-cost model.** Nothing else in the compiler could compare two lowerings by the
  metric that matters. It should become permanent infrastructure regardless of which
  optimizations ship.
- **Cost-model-driven selection.** Lowering a method both ways and keeping the smaller is
  cheap, obviously correct, and removes a whole class of "the heuristic guessed wrong"
  regressions. Recommended as the general pattern for any future scheduling change.
- **Commutative operand ordering.** Small, local, and applies to every contract.
- **Constant pooling as a *policy*** — "if a value is materialized more than
  `pool_cost / (push_cost − pick_cost)` times, park it" — is fully generic even though this
  implementation applies it inside the EC macros.

### 3.2 What needs explicit programmer intent?

Nothing in this slice. Both flags are compiler-internal and semantics-preserving. Witness
hints (brief Phase 7) remain the first thing that genuinely requires a contract-level opt-in.

### 3.3 What belongs in crypto libraries / intrinsics?

The pooling *mechanism* had to live in `ECTracker`, because the crypto emitters build their
own stack layout and never pass through `05-stack-lower.ts`. That boundary is the single most
important architectural fact this slice established — see §4.

### 3.4 What is P-256-specific?

Nothing that was built. `POOL_FIELD_P` / `POOL_GROUP_N` are parameterized by `CurveParams` /
`GroupParams`; the same code path serves secp256k1, P-256 and P-384, and the −67 % / −76 %
results differ only because P-384's prime is a 50-byte push instead of 34.

### 3.5 What should not be implemented?

- **Eager dead-slot retirement.** The plan assumed dead values sink and inflate later
  `OP_PICK` depth pushes. Measurement killed it: of 387,749 `OP_PICK`/`OP_ROLL` sites in the
  corpus, **657 are deeper than 16**; typical depths are 2–5, and depths 0–2 are single-byte
  opcodes anyway. Every drop would cost 1–3 bytes to save approximately nothing.
- **A forked scheduler pass.** A `schedulerMode` field on `LoweringContext` kept one code
  path and let the existing 66 structural assertions in `05-stack-lower.test.ts` cover both
  modes. A 5,500-line fork would have drifted from the branch/loop invariant fixes landing on
  the original.

### 3.6 Can Rúnar approach the ~29.6 kB P-256 result?

Not yet — `p256-wallet` is at 304,463 bytes, 10× the target. But the remaining bytes are in
exactly two buckets, neither is mysterious, and the size of the next step has been **measured**
rather than projected (see §3.7).

| category | bytes | share |
|---|---:|---:|
| stack-shuffle | 214,904 | 70.6 % |
| arithmetic | 82,863 | 27.2 % |
| small-int push | 2,698 | 0.9 % |
| const-push | 1,753 | 0.6 % |
| everything else | 2,245 | 0.7 % |

Constant pushes went from 697,019 bytes to 1,753 — 99.7 % eliminated. What is left is the
modular-reduction sequence itself, repeated ~20,000 times:

```
pick p           2 bytes   (was a 34-byte push)
OP_2DUP OP_MOD OP_ROT OP_DROP OP_OVER OP_ADD OP_SWAP OP_MOD    8 bytes
```

The six-opcode tail after the first `OP_MOD` exists only because `OP_MOD` takes the sign of
the dividend. Where the dividend is provably non-negative the tail is dead weight.

### 3.7 Measured ceiling for reduction sinking

Rather than project the next step, it was measured directly: `fieldMod` / `cFieldMod` were
patched behind a throwaway env switch to emit the short form, the corpus was re-measured, and
the patch was discarded. Two variants:

- `nonneg` — short reduction where the dividend is provably ≥ 0 (`fieldMul`, `fieldSqr`,
  `fieldAdd`, `fieldMulConst`), and for `fieldSub` the cheap `a − b + p` then one `OP_MOD`
  (6 bytes instead of 10). This is what a correct analysis could actually emit.
- `all` — short reduction everywhere. Semantically wrong; the absolute floor.

| fixture | shipping | + pool | **+ pool + sinking** | floor (`all`) |
|---|---:|---:|---:|---:|
| `p256-wallet` | 958,792 | 304,463 | **179,796** (−81.2 %) | 164,302 |
| `p384-wallet` | 1,963,300 | 463,435 | **272,584** (−86.1 %) | 249,410 |
| `ec-primitives` | 1,332,782 | 433,880 | **258,160** (−80.6 %) | 237,229 |
| `ec-unit` | 479,716 | 157,129 | **93,585** (−80.5 %) | 86,576 |

**The sound variant captures 89 % of the theoretical floor** (124,667 of a possible 140,161
bytes on `p256-wallet`), so the analysis does not need to be clever about subtraction — the
cheap `+p` form is nearly free.

Note the pooling and the sinking are complementary, not independent: without pooling, the
cheap `fieldSub` form pushes the prime *twice* and `p256-wallet` gets **larger** (958,792 →
999,371). Sinking only pays once the prime is a 2-byte pick.

### 3.8 The analysis needed is a sign lattice, not a modular-domain lattice

The `nonneg` variant passes **256 EC oracle assertions** — OpenSSL signatures on both curves,
`ec-on-curve-canonicity`, `ec-degenerate-add`, `ec-mul-scalars`, `p256-p384-scalars`,
`p256-p384-ecdsa-verify`. It would have shipped looking green.

It is nonetheless unsound, in a narrow and precisely characterised window:

- The **multiply / add / mulconst** paths need only *dividend ≥ 0*. That is already implied by
  `OP_BIN2NUM` of unsigned coordinate bytes, by products of non-negatives, and by sums of
  non-negatives. Roughly 70 % of all reductions qualify under a trivial sign analysis.
- The **subtract** path needs the strictly stronger *subtrahend < p*, and that is NOT implied
  by "decoded from 32 unsigned bytes".

The concrete divergence, found by construction:

```
ecAdd((0, 1), (2^256 − 1, 1))
  shipping : fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff85f…
  sinking  : 00000000000000000000000000000000000000000000000001000003d0…
                                                       ^ 0x1000003d0 = 2^32 + 977 = 2^256 − p
```

It bites only when the subtrahend is non-canonical *and* the minuend is smaller than the gap
between `p` and `2^256` — a ~2^32-wide window out of 2^256, reachable only through the
unguarded bare builtins (`ecAdd`, `p256Add`, `p256Mul` take raw coordinates;
`verifyECDSA_*` and `onCurve` run a canonicity guard first).

So the requirement for Phase 4/5 is sharper than "modular-domain analysis": a **sign lattice**
plus a **`< p` bit that only subtrahends need**. That is a materially smaller piece of work
than a full domain lattice, and it is the difference between an optimization that passes 256
oracle assertions and one that is actually correct.

### 3.9 Revised trajectory

```
958,792  shipping
179,796  + constant pool + reduction sinking   (MEASURED)
        − Straus/Shamir: one joint ladder instead of two   (Phase 9, estimated)
        − fixed-base comb for u1·G, G compile-time known   (Phases 10–11, estimated)
 ~30,000  ← the reference trajectory's comb stage (34,470 B)
```

Everything above 179,796 is measured; everything below it is still an estimate.

Note what the measurement does to the ordering. At 179,796 bytes the split is 69.6 %
stack-shuffle / 26.7 % arithmetic, and `OP_PICK` (×36,683) is the single largest opcode. Once
a reduction costs 3 bytes, **`ECTracker`'s own operand shuffling is the bottleneck, not the
reduction**. Straus and comb still help — they cut total operations, so both columns shrink —
but the structural fix underneath is the field-element IR in §4: it would put those 125,119
bytes of shuffle within reach of a scheduler, which nothing can reach today.

---

## 4. The architectural finding

**Crypto codegen does not pass through the generic backend.** `ec-codegen.ts`,
`p256-p384-codegen.ts`, `sha256-codegen.ts`, `slh-dsa-codegen.ts`, `babybear-codegen.ts` and
their peers emit Stack IR directly through hand-written `ECTracker`-family trackers.
`05-stack-lower.ts` never sees those ops.

Consequences, all confirmed by measurement:

- A generic scheduler cannot move a single byte of the EC, SLH-DSA, SHA-256 or BLAKE3
  fixtures — 13.4 MB of the 13.5 MB corpus.
- Conversely, the constant pool cannot help ordinary contracts.
- Any future "generic" optimization needs an answer to which of the two worlds it lives in
  before its value can be estimated.

The peephole optimizer is the one pass that spans both, because it runs on the whole method's
Stack IR after lowering. That makes new peephole rules unusually high-leverage — and it is
already a fix-point driver (brief Phase 3 is done; see the baseline document §5).

---

## 5. What the oracles caught

The scheduler's first working version **miscompiled `if-without-else-multi-temp`**: it
produced a script that ran to completion, left a truthy top-of-stack, and **accepted a witness
the shipping compiler rejects**. Byte counts, golden comparisons for the other fixtures, and
the compiler's own 4,099 unit tests all passed while this was true.

What caught it was `conformance/witnesses/` replayed through `runDifferentialExecution` —
source-semantics interpreter versus deployed script, on witnesses the repo had already
committed to, with at least one accept and one reject per fixture. Two of 86 cases failed.

Root cause: restoring spilled values immediately before an `if` leaves the parent stack in a
shape `lowerIf`'s arm reconciliation was not written for. The fix is a precondition — spilling
is refused in any scope that still has control flow ahead of it — not an attempt to make the
two agree. That costs the scheduler its wins on `oracle-price` and `cross-covenant` (2 and 1
bytes) and keeps everything else.

Two process notes worth carrying forward:

- A bisect that "passes" can be vacuous. Disabling commutative reordering made the failure
  disappear, which looked like an acquittal for spilling — but with reordering off, the
  method-level cost guard simply preferred the baseline schedule and *no spilling happened at
  all*. Confirming that the variant actually changed the bytes was what made the second
  bisect meaningful.
- The per-site cost model was wrong until it was made peephole-aware. Two consumed operands at
  depths 1 and 0 emit `OP_SWAP OP_SWAP`, which the `swap-swap` rule deletes outright — free —
  while the "cheaper-looking" order emits one real `OP_SWAP`. Scoring candidate op sequences
  through `optimizeStackIR` before comparing them took `arithmetic` from 24 bytes to 18.

---

## 6. Recommended compiler changes

**Adopt now (independent of any optimization):**

1. `packages/runar-compiler/src/metrics/cost-model.ts` and `script-metrics.ts` as permanent
   infrastructure, with the exactness sweep as a standing test.
2. `conformance/runner/script-metrics.ts` alongside the existing `script-size-check.ts` — the
   latter answers "did anything grow?", the former "where did the bytes go?".

**Adopt after a 7-tier port:**

3. The EC constant pool. It is the largest single byte win available, it is
   curve-parameterized rather than curve-specific, and it is proved equivalent against OpenSSL
   signatures on both curves plus every SEC1 rejection case
   (`packages/runar-testing/src/__tests__/ec-constant-pool-equivalence.test.ts`, 44 cases).
   Landing it means porting to `compilers/{go,rust,python,ruby,zig,java}`, regenerating 9
   goldens, re-stamping `conformance/script-size-baseline.json` (the −67 % shrink trips its
   50 % guard by design), and adding provenance entries.

**Keep experimental:**

4. The liveness scheduler. It is correct and never grows a fixture, but outside small
   arithmetic contracts it buys 0.1 %. Not worth a 7-tier port on its own; worth keeping as a
   gated mode so the next scheduling idea has somewhere to land.

**Do next (highest value first):**

5. **Sign analysis + reduction sinking** (brief Phases 4–5). **Measured at 124,667 bytes on
   `p256-wallet`** (304,463 → 179,796) — see §3.7. Two facts to carry: *dividend ≥ 0*, which a
   trivial sign lattice gives for ~70 % of reductions, and *subtrahend < p*, which only
   `fieldSub` needs and which unsigned 32-byte decoding does NOT imply (§3.8). It is also the
   prerequisite for everything after it: Straus, comb and lazy accumulation all need to know
   which values are already reduced.
6. **A typed field-element IR under the crypto emitters.** After §5 lands, 69.6 % of what
   remains is `ECTracker`'s own operand shuffling, which no pass can currently reach. This is
   larger than any single item here, and it would let §5, §7 and future work be written once
   instead of seven times (§4).
7. **Straus/Shamir joint ladder**, then a **fixed-base comb** for `u1·G` (Phases 9–11).
8. **Witness-hint modular inverse** (Phase 7) — removes three unrolled Fermat ladders
   (382 + 423 + 286 field multiplications per P-256 verify). The first item requiring an
   explicit soundness argument rather than a translation-validation proof.

---

## 7. Reproducing

```bash
# Sizes
pnpm --filter runar-conformance run script-metrics                                  # baseline table
pnpm --filter runar-conformance run script-metrics -- --fixture p256-wallet --detail
pnpm --filter runar-conformance run script-metrics -- --compare current,liveness,ec-pool,both

# Correctness
npx vitest run packages/runar-compiler/src/__tests__/cost-model.test.ts          # model is exact
npx vitest run packages/runar-compiler/src/__tests__/golden-invariance.test.ts   # default unchanged
npx vitest run packages/runar-compiler/src/__tests__/ec-constant-pool.test.ts
npx vitest run packages/runar-compiler/src/__tests__/liveness-scheduler.test.ts
npx vitest run packages/runar-testing/src/__tests__/ec-constant-pool-equivalence.test.ts
npx vitest run packages/runar-testing/src/__tests__/liveness-scheduler-equivalence.test.ts
npx vitest run packages/runar-testing/src/__tests__/scheduler-headroom.test.ts

# CLI
node --import tsx packages/runar-cli/src/bin.ts compile <file> --ec-constant-pool --hex
```

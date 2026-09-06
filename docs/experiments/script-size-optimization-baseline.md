# Script-size optimization — Phase 0 baseline

**Date:** 2026-08-28 · **Compiler:** TypeScript reference tier, default options (constant folding ON, EC optimizer ON, peephole ON)
**Source of truth:** the checked-in `conformance/tests/<fixture>/expected-script.hex` goldens, 72 fixtures, 13,526,545 bytes total.

Reproduce every number here with:

```bash
pnpm --filter runar-conformance run script-metrics                     # summary table
pnpm --filter runar-conformance run script-metrics -- --fixture p256-wallet --detail
pnpm --filter runar-conformance run script-metrics -- --json out.json  # machine-readable
```

Instrumentation is read-only and does not change compilation output:
`packages/runar-compiler/src/metrics/script-metrics.ts` (byte classifier),
`packages/runar-compiler/src/metrics/cost-model.ts` (`estimateScriptBytes`, asserted
byte-exact against `06-emit.ts` over the whole corpus in `__tests__/cost-model.test.ts`),
`conformance/runner/script-metrics.ts` (the runner).

---

## 1. The headline

**58 % of every script byte Rúnar has ever emitted is a constant push, and 56 % of the
entire corpus is nine distinct constants pushed over and over.**

| category | bytes | share of corpus |
|---|---:|---:|
| const-push | 7,840,690 | **58.0 %** |
| stack-shuffle | 3,133,223 | 23.2 % |
| arithmetic | 1,047,644 | 7.7 % |
| bytes (CAT/SPLIT/SIZE/EQUAL) | 878,631 | 6.5 % |
| small-int-push | 392,378 | 2.9 % |
| control | 160,000 | 1.2 % |
| crypto | 73,979 | 0.5 % |

The nine largest single constants, all of them a curve's field prime `p` (or group order `n`):

| fixture | constant | push size | pushes | bytes | share of that fixture |
|---|---|---:|---:|---:|---:|
| p384-wallet | P-384 `p` | 49 B | 30,577 | 1,528,850 | 77.9 % |
| p384-primitives | P-384 `p` | 49 B | 29,925 | 1,496,250 | 79.4 % |
| ec-primitives | secp256k1 `p` | 33 B | 28,102 | 955,468 | 71.7 % |
| ec-demo | secp256k1 `p` | 33 B | 28,102 | 955,468 | 71.7 % |
| **p256-wallet** | **P-256 `p`** | **33 B** | **20,025** | **680,850** | **71.0 %** |
| p256-primitives | P-256 `p` | 33 B | 19,755 | 671,670 | 72.4 % |
| schnorr-zkp | secp256k1 `p` | 33 B | 18,551 | 630,734 | 72.1 % |
| ec-unit | secp256k1 `p` | 33 B | 10,092 | 343,128 | 71.5 % |
| convergence-proof | secp256k1 `p` | 33 B | 9,547 | 324,598 | 71.8 % |

Total: **7,587,016 bytes — 56 % of the corpus — spent re-pushing nine numbers.**

### Why

`cFieldMod` / `fieldMod` push the prime inline at *every* modular reduction:

```ts
// packages/runar-compiler/src/passes/p256-p384-codegen.ts:135
function cFieldMod(t: ECTracker, aName: string, resultName: string, c: CurveParams): void {
  t.toTop(aName);
  pushFieldP(t, '_fmod_p', c);        // <-- 34 bytes (P-256) / 50 bytes (P-384), every time
  t.rawBlock([aName, '_fmod_p'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' }); e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'rot' }); e({ op: 'drop' }); e({ op: 'over' });
    e({ op: 'opcode', code: 'OP_ADD' }); e({ op: 'swap' }); e({ op: 'opcode', code: 'OP_MOD' });
  });
}
```

Every `cFieldAdd` / `cFieldSub` / `cFieldMul` / `cFieldSqr` / `cFieldMulConst` ends in one of
these. `cEmitMul` unrolls 257 (P-256) / 385 (P-384) double-and-add rounds, `cFieldInv` and
`cGroupInv` unroll full Fermat ladders — so the prime push is multiplied by the unroll factor.

A prime kept in a stack slot and copied with `push(depth); OP_PICK` costs **2–3 bytes**
instead of 34 or 50. Break-even is at two uses.

---

## 2. p256-wallet — the brief's 959 kB reference, in detail

`conformance/tests/p256-wallet` is **958,792 bytes**, which is the "959,592 B baseline
reference implementation" the optimization brief targets. It is a hybrid secp256k1 + P-256
wallet: a P2PKH gate, then `verifyECDSA_P256(sig, p256Sig, p256PubKey)`.

| category | bytes | share |
|---|---:|---:|
| const-push | 697,019 | 72.7 % |
| stack-shuffle | 173,967 | 18.1 % |
| arithmetic | 82,863 | 8.6 % |
| bytes | 1,210 | 0.1 % |
| small-int-push | 2,698 | 0.3 % |
| control | 1,031 | 0.1 % |
| crypto | 4 | 0.0 % |

| repeated constant | size | pushes | bytes | share |
|---|---:|---:|---:|---:|
| P-256 field prime `p` | 33 B | 20,025 | 680,850 | 71.0 % |
| P-256 group order `n` | 33 B | 430 | 14,620 | 1.5 % |

Top opcodes: `OP_MOD`×41,418 · `OP_ROT`×30,406 · `OP_SWAP`×27,342 · `OP_OVER`×23,417 ·
`OP_DROP`×22,558 · `OP_ADD`×20,978 · `OP_2DUP`×20,453 · `OP_MUL`×13,214.

Note the shape: **41,418 `OP_MOD` against 20,025 prime pushes** — two `OP_MOD` per reduction.
That is the sign-normalisation tail (`2DUP MOD ROT DROP OVER ADD SWAP MOD`), which exists
because `OP_MOD` takes the sign of the dividend. For a product of two values already reduced
into `[0, p)` the dividend is non-negative and the tail is dead weight: 6 of the 8 opcodes,
plus the second prime reference. That is a modular-domain-analysis win (brief Phase 4/5), not
a scheduling one.

### Where the arithmetic actually goes

Op-count goldens (`packages/runar-compiler/src/__tests__/p256-p384-codegen.test.ts:111`):

| emitter | ops | measured bytes |
|---|---:|---:|
| `emitVerifyECDSA_P256` | 297,331 | 974,024 |
| `emitP256Mul` / `emitP256MulGen` | 140,036 / 140,038 | 459,746 / 459,812 |
| `emitP256Add` | 6,663 | 19,906 |
| `emitVerifyECDSA_P384` | 453,307 | 1,987,394 |
| `emitP384Mul` | 211,178 | 927,350 |

`cEmitVerifyECDSA` runs **two independent 257-round ladders** (`u1·G` at `:1412`, `u2·Q` at
`:1442`) plus **three unrolled Fermat exponentiations** (`cFieldInv` 382 field muls,
`cGroupInv` 423, `cFieldPow` for the decompression sqrt 286). Nothing is shared between the
two ladders and no point is precomputed, even though `G` is a compile-time constant.

---

## 3. Two populations, two different bottlenecks

The corpus splits cleanly, and the split decides which optimization can touch which fixture.

### EC / field-arithmetic fixtures — dominated by constants (72–80 % const-push)

`p256-*`, `p384-*`, `ec-*`, `schnorr-zkp`, `convergence-proof`, `babybear*`. These scripts are
emitted by hand-written macro modules (`ec-codegen.ts`, `p256-p384-codegen.ts`,
`babybear-codegen.ts`, …) that build their own stack layout through `ECTracker` and its
clones. **They never pass through `05-stack-lower.ts`.** A generic ANF→Stack scheduler cannot
move a single byte of them.

### Ordinary contracts — dominated by stack traffic (35–68 % stack-shuffle)

Everything from `stateful-counter` (1,875 B) up through `math-demo` (17,348 B), and the small
fixtures most of all: `arithmetic` 67.9 %, `bounded-loop` 57.1 %, `multisig` 58.8 %,
`if-without-else-multi-temp` 55.3 %. These *are* produced by `05-stack-lower.ts`, and the
~30 % const-push in the mid-size stateful fixtures is largely BIP-143 sighash scaffolding,
not user data.

### Hash / post-quantum fixtures — dominated by byte plumbing

SLH-DSA (`OP_CAT`×80,120, `OP_SPLIT`×50,221 in the 128f fixture), SHA-256 and BLAKE3 sit at
2–17 % const-push, 36–44 % stack-shuffle, 23–28 % `bytes`. Constant pooling buys them almost
nothing; scheduling and byte-op fusion are the levers.

| population | fixtures | const-push | stack-shuffle | reachable by |
|---|---|---:|---:|---|
| EC / field arithmetic | 9 (10.2 MB) | 72–80 % | 13–19 % | codegen-level constant pooling |
| hash / post-quantum | 12 (3.0 MB) | 2–17 % | 36–44 % | scheduling, byte-op fusion |
| ordinary contracts | 51 (0.1 MB) | 0–33 % | 35–68 % | generic liveness scheduler |

---

## 4. Ranked byte sinks

1. **Repeated field-prime pushes — 7,587,016 B (56 % of the corpus).** One pooled stack slot
   per curve constant. Codegen-level (`ECTracker`), not a generic pass; the *policy*
   (pool when `n_uses × push_cost > pool_cost + n_uses × pick_cost`) is generic and belongs
   in the cost model.
2. **Stack traffic — 3,133,223 B (23 %).** Split roughly evenly between the EC macros'
   `ECTracker.toTop`/`copyToTop` churn and `05-stack-lower.ts`'s `bringToTop`. The generic
   half is addressable by liveness-driven scheduling; see
   [`stack-scheduler-design.md`](stack-scheduler-design.md).
3. **The redundant second `OP_MOD` — ~20,000 reductions per EC fixture × 6 opcodes.**
   Requires knowing an operand is already reduced (modular-domain analysis, brief Phase 4).
4. **Unrolled Fermat inversion.** 382 / 423 / 286 field muls per P-256 verify, three times.
   An addition chain cuts each by ~30 %; a witness-supplied inverse (brief Phase 7) removes
   them almost entirely.
5. **Two independent scalar ladders.** Straus/Shamir halves the doubling work; a fixed-base
   comb for `u1·G` removes it (brief Phases 9–11).
6. **`emitReverse32` / `emitReverse48`.** 7 ops × 32 (or 48) per byte-order reversal, called
   on every point decompose/compose.

---

## 5. What Phase 0 already settles about the brief

- **Phase 3 (fix-point peephole) is already done.** `optimizeStackIR`
  (`optimizer/peephole.ts:507`) iterates `applyOnePass` to a fixed point with a 100-iteration
  cap and recurses into `if` arms first. 28 rules, mirrored declaratively in
  `optimizer/peephole-rules.ts` and executed pattern-vs-replacement through the `ScriptVM` by
  `__tests__/peephole-exhaustive.test.ts`. What remains for Phase 3 is *more rules*, not a
  fix-point driver.
- **Phase 15 (OP_PUSH_TX / CODESEPARATOR transaction binding) already ships** as
  `passes/oppushtx-codegen.ts` — the BUG-100 fix derives the ECDSA signature from the pushed
  preimage on-chain, so `OP_CHECKSIG` passes only when `hash256(preimage)` is the real
  sighash.
- **Phase 2's generic scheduler cannot reach P-256.** See §3. The two must be prototyped
  separately or the P-256 number will not move at all.
- **Phase 1's cost model is exact.** `estimateScriptBytes` agrees with `emitMethod` to the
  byte on every method of all 67 fixtures that ship a `.runar.ts`, before and after peephole.

---

## 6. Full corpus table

Byte category shares per fixture, largest script first.

| fixture | bytes | ops | const-push | stack-shuffle | arithmetic | bytes | crypto | small-int-push | control | other |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p384-wallet | 1963300 | 430181 | 1565148 (79.7%) | 264286 (13.5%) | 126571 (6.4%) | 1754 (0.1%) | 4 (0.0%) | 3994 (0.2%) | 1543 (0.1%) | — |
| p384-primitives | 1883767 | 415719 | 1498750 (79.6%) | 256133 (13.6%) | 121250 (6.4%) | 1976 (0.1%) | — | 4109 (0.2%) | 1549 (0.1%) | — |
| ec-demo | 1332782 | 403869 | 957857 (71.9%) | 249884 (18.7%) | 113993 (8.6%) | 4208 (0.3%) | — | 5256 (0.4%) | 1584 (0.1%) | — |
| ec-primitives | 1332782 | 403869 | 957857 (71.9%) | 249884 (18.7%) | 113993 (8.6%) | 4208 (0.3%) | — | 5256 (0.4%) | 1584 (0.1%) | — |
| p256-wallet | 958792 | 282747 | 697019 (72.7%) | 173967 (18.1%) | 82863 (8.6%) | 1210 (0.1%) | 4 (0.0%) | 2698 (0.3%) | 1031 (0.1%) | — |
| p256-primitives | 928219 | 275241 | 673254 (72.5%) | 169769 (18.3%) | 80058 (8.6%) | 1336 (0.1%) | — | 2765 (0.3%) | 1037 (0.1%) | — |
| schnorr-zkp | 875189 | 262004 | 632257 (72.2%) | 162557 (18.6%) | 75250 (8.6%) | 1335 (0.2%) | 1 (0.0%) | 2759 (0.3%) | 1030 (0.1%) | — |
| post-quantum-slhdsa-192f | 788039 | 757325 | 54761 (6.9%) | 339659 (43.1%) | 56908 (7.2%) | 206316 (26.2%) | 17549 (2.2%) | 78196 (9.9%) | 34650 (4.4%) | — |
| post-quantum-slhdsa-256f | 729363 | 716143 | 19626 (2.7%) | 327166 (44.9%) | 57832 (7.9%) | 191936 (26.3%) | 17837 (2.4%) | 79752 (10.9%) | 35214 (4.8%) | — |
| post-quantum-slhdsa-128f | 533911 | 525388 | 12149 (2.3%) | 235416 (44.1%) | 39293 (7.4%) | 143273 (26.8%) | 12137 (2.3%) | 67751 (12.7%) | 23892 (4.5%) | — |
| ec-unit | 479716 | 146119 | 343994 (71.7%) | 89666 (18.7%) | 40878 (8.5%) | 2407 (0.5%) | — | 2248 (0.5%) | 523 (0.1%) | — |
| convergence-proof | 452386 | 136798 | 325416 (71.9%) | 84502 (18.7%) | 38705 (8.6%) | 1467 (0.3%) | — | 1780 (0.4%) | 516 (0.1%) | — |
| post-quantum-slhdsa-256s | 369173 | 358620 | 15558 (4.2%) | 162192 (43.9%) | 28402 (7.7%) | 96981 (26.3%) | 8818 (2.4%) | 40026 (10.8%) | 17196 (4.7%) | — |
| post-quantum-slhdsa-192s | 276583 | 262513 | 23837 (8.6%) | 116220 (42.0%) | 19195 (6.9%) | 72337 (26.2%) | 5985 (2.2%) | 27396 (9.9%) | 11613 (4.2%) | — |
| sphincs-wallet | 188609 | 183128 | 7747 (4.1%) | 80932 (42.9%) | 13282 (7.0%) | 50562 (26.8%) | 4164 (2.2%) | 23879 (12.7%) | 8043 (4.3%) | — |
| post-quantum-slhdsa | 188597 | 183116 | 7747 (4.1%) | 80926 (42.9%) | 13282 (7.0%) | 50560 (26.8%) | 4161 (2.2%) | 23878 (12.7%) | 8043 (4.3%) | — |
| sha256-finalize | 69507 | 63949 | 9898 (14.2%) | 24810 (35.7%) | 10155 (14.6%) | 16262 (23.4%) | — | 8379 (12.1%) | 3 (0.0%) | — |
| sha256-compress | 23145 | 21294 | 3296 (14.2%) | 8262 (35.7%) | 3384 (14.6%) | 5413 (23.4%) | — | 2790 (12.1%) | — | — |
| blake3 | 22428 | 20773 | 2798 (12.5%) | 8742 (39.0%) | 1811 (8.1%) | 6336 (28.3%) | — | 2738 (12.2%) | 3 (0.0%) | — |
| stateful-wots-gate | 20519 | 18177 | 3443 (16.8%) | 8025 (39.1%) | 2237 (10.9%) | 2454 (12.0%) | 1011 (4.9%) | 320 (1.6%) | 3029 (14.8%) | — |
| post-quantum-wallet | 19594 | 17514 | 3154 (16.1%) | 7690 (39.2%) | 2213 (11.3%) | 2275 (11.6%) | 1010 (5.2%) | 237 (1.2%) | 3015 (15.4%) | — |
| post-quantum-wots | 19582 | 17502 | 3154 (16.1%) | 7684 (39.2%) | 2213 (11.3%) | 2273 (11.6%) | 1007 (5.1%) | 236 (1.2%) | 3015 (15.4%) | — |
| math-demo | 17348 | 13183 | 4591 (26.5%) | 6188 (35.7%) | 1212 (7.0%) | 2842 (16.4%) | 62 (0.4%) | 1513 (8.7%) | 940 (5.4%) | — |
| babybear-ext4 | 5471 | 3084 | 2973 (54.3%) | 1320 (24.1%) | 1141 (20.9%) | — | — | 31 (0.6%) | 6 (0.1%) | — |
| function-patterns | 3844 | 2794 | 1159 (30.2%) | 1415 (36.8%) | 111 (2.9%) | 724 (18.8%) | 20 (0.5%) | 350 (9.1%) | 65 (1.7%) | — |
| token-ft | 3154 | 2330 | 929 (29.5%) | 1139 (36.1%) | 89 (2.8%) | 612 (19.4%) | 16 (0.5%) | 294 (9.3%) | 75 (2.4%) | — |
| merge-locals-shapes | 3031 | 2236 | 882 (29.1%) | 1145 (37.8%) | 88 (2.9%) | 567 (18.7%) | 12 (0.4%) | 280 (9.2%) | 57 (1.9%) | — |
| private-helper-outputs | 2879 | 2080 | 886 (30.8%) | 1018 (35.4%) | 76 (2.6%) | 559 (19.4%) | 12 (0.4%) | 271 (9.4%) | 57 (2.0%) | — |
| assert-false-guard | 2033 | 1507 | 582 (28.6%) | 778 (38.3%) | 54 (2.7%) | 378 (18.6%) | 8 (0.4%) | 186 (9.1%) | 47 (2.3%) | — |
| loop-if-merged-locals | 2011 | 1481 | 588 (29.2%) | 750 (37.3%) | 60 (3.0%) | 378 (18.8%) | 8 (0.4%) | 186 (9.2%) | 41 (2.0%) | — |
| terminal-varlen-read | 1940 | 1415 | 584 (30.1%) | 688 (35.5%) | 55 (2.8%) | 375 (19.3%) | 7 (0.4%) | 178 (9.2%) | 53 (2.7%) | — |
| property-initializers | 1878 | 1354 | 578 (30.8%) | 674 (35.9%) | 50 (2.7%) | 362 (19.3%) | 8 (0.4%) | 175 (9.3%) | 31 (1.7%) | — |
| stateful | 1876 | 1352 | 578 (30.8%) | 674 (35.9%) | 50 (2.7%) | 362 (19.3%) | 8 (0.4%) | 174 (9.3%) | 30 (1.6%) | — |
| stateful-counter | 1875 | 1351 | 578 (30.8%) | 673 (35.9%) | 51 (2.7%) | 362 (19.3%) | 8 (0.4%) | 173 (9.2%) | 30 (1.6%) | — |
| stateful-bytestring | 1851 | 1335 | 569 (30.7%) | 660 (35.7%) | 48 (2.6%) | 357 (19.3%) | 8 (0.4%) | 171 (9.2%) | 38 (2.1%) | — |
| auction | 1794 | 1288 | 553 (30.8%) | 656 (36.6%) | 47 (2.6%) | 346 (19.3%) | 9 (0.5%) | 164 (9.1%) | 19 (1.1%) | — |
| token-nft | 1738 | 1234 | 549 (31.6%) | 630 (36.2%) | 43 (2.5%) | 332 (19.1%) | 9 (0.5%) | 157 (9.0%) | 18 (1.0%) | — |
| state-covenant | 1196 | 912 | 326 (27.3%) | 451 (37.7%) | 41 (3.4%) | 221 (18.5%) | 9 (0.8%) | 105 (8.8%) | 43 (3.6%) | — |
| branched-readonly-len | 1096 | 816 | 319 (29.1%) | 392 (35.8%) | 33 (3.0%) | 211 (19.3%) | 4 (0.4%) | 100 (9.1%) | 37 (3.4%) | — |
| conditional-data-output-stateful | 1015 | 740 | 308 (30.3%) | 356 (35.1%) | 27 (2.7%) | 197 (19.4%) | 4 (0.4%) | 97 (9.6%) | 26 (2.6%) | — |
| merge-locals-prop-updates | 1006 | 741 | 294 (29.2%) | 387 (38.5%) | 27 (2.7%) | 189 (18.8%) | 4 (0.4%) | 89 (8.8%) | 16 (1.6%) | — |
| add-raw-output | 1005 | 728 | 311 (30.9%) | 349 (34.7%) | 27 (2.7%) | 197 (19.6%) | 4 (0.4%) | 95 (9.5%) | 22 (2.2%) | — |
| add-data-output | 1004 | 729 | 308 (30.7%) | 351 (35.0%) | 27 (2.7%) | 197 (19.6%) | 4 (0.4%) | 95 (9.5%) | 22 (2.2%) | — |
| selector | 985 | 723 | 289 (29.3%) | 371 (37.7%) | 28 (2.8%) | 185 (18.8%) | 4 (0.4%) | 88 (8.9%) | 20 (2.0%) | — |
| branch-merged-locals | 963 | 699 | 292 (30.3%) | 354 (36.8%) | 24 (2.5%) | 185 (19.2%) | 4 (0.4%) | 88 (9.1%) | 16 (1.7%) | — |
| cond-write-multi-field | 957 | 693 | 292 (30.5%) | 345 (36.1%) | 26 (2.7%) | 185 (19.3%) | 4 (0.4%) | 89 (9.3%) | 16 (1.7%) | — |
| state-bigint-edges | 952 | 688 | 292 (30.7%) | 346 (36.3%) | 25 (2.6%) | 185 (19.4%) | 4 (0.4%) | 87 (9.1%) | 13 (1.4%) | — |
| intent-current-block-height | 944 | 682 | 289 (30.6%) | 338 (35.8%) | 26 (2.8%) | 185 (19.6%) | 4 (0.4%) | 88 (9.3%) | 14 (1.5%) | — |
| intent-prev-output-script | 942 | 680 | 289 (30.7%) | 339 (36.0%) | 25 (2.7%) | 183 (19.4%) | 5 (0.5%) | 87 (9.2%) | 14 (1.5%) | — |
| oversize-bigint-shift | 940 | 671 | 297 (31.6%) | 334 (35.5%) | 25 (2.7%) | 181 (19.3%) | 4 (0.4%) | 86 (9.1%) | 13 (1.4%) | — |
| state-ripemd160 | 931 | 668 | 291 (31.3%) | 336 (36.1%) | 23 (2.5%) | 179 (19.2%) | 4 (0.4%) | 84 (9.0%) | 14 (1.5%) | — |
| intent-output-p2pkh | 843 | 594 | 270 (32.0%) | 309 (36.7%) | 18 (2.1%) | 165 (19.6%) | 4 (0.5%) | 76 (9.0%) | 1 (0.1%) | — |
| covenant-vault | 795 | 550 | 262 (33.0%) | 290 (36.5%) | 13 (1.6%) | 151 (19.0%) | 5 (0.6%) | 73 (9.2%) | 1 (0.1%) | — |
| all-readonly-cleanstack | 777 | 539 | 252 (32.4%) | 288 (37.1%) | 14 (1.8%) | 146 (18.8%) | 4 (0.5%) | 72 (9.3%) | 1 (0.1%) | — |
| babybear | 647 | 351 | 370 (57.2%) | 99 (15.3%) | 156 (24.1%) | — | — | 7 (1.1%) | 15 (2.3%) | — |
| if-without-else-multi-temp | 226 | 219 | 11 (4.9%) | 125 (55.3%) | 15 (6.6%) | 24 (10.6%) | — | 25 (11.1%) | 26 (11.5%) | — |
| merkle-proof | 201 | 193 | 16 (8.0%) | 108 (53.7%) | 16 (8.0%) | 18 (9.0%) | 8 (4.0%) | 16 (8.0%) | 19 (9.5%) | — |
| bitwise-ops | 96 | 96 | — | 34 (35.4%) | 26 (27.1%) | — | — | 27 (28.1%) | 9 (9.4%) | — |
| cross-covenant | 46 | 45 | 2 (4.3%) | 24 (52.2%) | 3 (6.5%) | 8 (17.4%) | 2 (4.3%) | 4 (8.7%) | 3 (6.5%) | — |
| oracle-price | 44 | 38 | 8 (18.2%) | 21 (47.7%) | 5 (11.4%) | 2 (4.5%) | 2 (4.5%) | 4 (9.1%) | 2 (4.5%) | — |
| bounded-loop | 42 | 42 | — | 24 (57.1%) | 11 (26.2%) | — | — | 7 (16.7%) | — | — |
| arithmetic | 28 | 28 | — | 19 (67.9%) | 8 (28.6%) | — | — | 1 (3.6%) | — | — |
| if-without-else | 27 | 27 | — | 10 (37.0%) | 5 (18.5%) | — | — | 6 (22.2%) | 6 (22.2%) | — |
| shift-ops | 27 | 27 | — | 10 (37.0%) | 8 (29.6%) | — | — | 8 (29.6%) | 1 (3.7%) | — |
| if-else | 20 | 20 | — | 10 (50.0%) | 3 (15.0%) | — | — | 4 (20.0%) | 3 (15.0%) | — |
| escrow | 19 | 19 | — | 4 (21.1%) | 2 (10.5%) | — | 4 (21.1%) | 6 (31.6%) | 3 (15.8%) | — |
| multi-method | 19 | 19 | — | 2 (10.5%) | 5 (26.3%) | — | 2 (10.5%) | 6 (31.6%) | 4 (21.1%) | — |
| multisig | 17 | 17 | — | 10 (58.8%) | — | — | 1 (5.9%) | 6 (35.3%) | — | — |
| boolean-logic | 15 | 15 | — | 6 (40.0%) | 7 (46.7%) | — | — | 2 (13.3%) | — | — |
| go-dsl-bytestring-literal | 8 | 6 | 3 (37.5%) | — | 2 (25.0%) | 1 (12.5%) | — | 2 (25.0%) | — | — |
| basic-p2pkh | 5 | 5 | — | 1 (20.0%) | — | 1 (20.0%) | 2 (40.0%) | 1 (20.0%) | — | — |
| asm-raw-script | 1 | 1 | — | — | — | — | — | 1 (100.0%) | — | — |
_`asm-raw-script` is a single opaque `raw_bytes` span; `basic-p2pkh` is the 5-byte template
before constructor-arg splicing. Neither is a size target._

---

## 7. Method

`analyzeScriptHex` walks the serialized script and charges every byte to exactly one
category; the sum is asserted equal to the script length. One rule is worth stating: a push
immediately consumed by `OP_PICK` / `OP_ROLL` is charged to **stack-shuffle**, not to
**const-push**. `bringToTop` emits `push(depth)` + `OP_PICK` as a pair
(`05-stack-lower.ts:1062`), and charging those depth bytes to constants would credit the
wrong optimizer with removing them. On `p256-wallet` that reclassification moves exactly
21,926 bytes, and it carries a second useful fact: all 21,926 of those depth pushes are a
single byte, so the EC macros never `OP_PICK` deeper than 16. A pooled constant parked below
a working set that shallow would cost 3 bytes to copy (2-byte depth push + `OP_PICK`) instead
of 34 — still a 31-byte saving per reduction.

Categories: `const-push` (length-prefixed / PUSHDATA payloads), `small-int-push`
(OP_0/OP_1NEGATE/OP_1..16), `stack-shuffle` (DUP/DROP/NIP/OVER/PICK/ROLL/ROT/SWAP/TUCK/2DROP/
2DUP/3DUP/2OVER/2ROT/2SWAP/IFDUP/DEPTH/TOALTSTACK/FROMALTSTACK plus PICK/ROLL depth pushes),
`arithmetic` (numeric, bitwise and comparison opcodes), `bytes` (CAT/SPLIT/SIZE/NUM2BIN/
BIN2NUM/SUBSTR/LEFT/RIGHT/EQUAL/EQUALVERIFY), `crypto` (hashes, CHECKSIG family,
CODESEPARATOR), `control` (IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN/NOP/CLTV/CSV), `other`.

# On-chain SP1 FRI verifier — API, targets, fallback order

Scope: documents the `runar.VerifySP1FRI` intrinsic — its signature,
compile-time targets, fallback order if targets are missed on
regtest, and the negative-test corruption matrix. Pairs with
`docs/sp1-proof-format.md` (byte layout) and
`docs/fri-verifier-measurements.md` (Phase 2 regtest numbers, landed
with the production scale-up).

Driven by BSVM handoff doc `../bsv-evm/RUNAR-FRI-VERIFIER.md`. Closes
the Gate 0a Full / Mode 1 mainnet soundness gap flagged by the
Swift Steele 2026-04-24 external review.

## 1. API shape

Go DSL only in this release. BSVM is the sole consumer and its
covenants are written in `.runar.go`. The other five SDK languages
(TS / Rust / Python / Zig / Ruby) gain this builtin when their
respective codegen ports land — tracked as separate follow-up
efforts.

```go
// Go DSL (runar-go)
runar.VerifySP1FRI(proofBlob, publicValues, sp1VKeyHash runar.ByteString)
```

**Semantics.** Returns `true` on a valid proof. On an invalid proof
the compiled script fails `OP_VERIFY` at the first detectable
mismatch — no observable discriminator distinguishes which check
failed. Callers should not conditionally branch on the return value.
Covenants typically wrap the call with
`assert(runar.VerifySP1FRI(...))` for explicitness; the boolean
return is there so the intrinsic composes with the existing
`assert(...)` pattern used by `VerifyWOTS` / `VerifySLHDSA_*`.

**Arguments.**
- `proofBlob` — bincode-encoded Plonky3 `FriProof` per
  `docs/sp1-proof-format.md`. Typical size 100–200 KB for an EVM-guest
  proof; up to ~1 MB for adversarial inputs. The caller pushes it as a
  single `ByteString` in the unlocking script.
- `publicValues` — guest-program-specific public values blob. The
  verifier absorbs it into the Fiat-Shamir transcript before any
  FRI commitment; any tampering shifts every derived challenge and
  causes downstream consistency checks to fail.
- `sp1VKeyHash` — 32-byte keccak256 digest of the verifying key (see
  `docs/sp1-proof-format.md` §5). Must be bound in the covenant as a
  readonly field; a malicious unlocking script cannot supply it.

## 2. proofBlob push-and-hash pattern

Parsing ~150–200 KB of proof bytes in Bitcoin Script by `OP_SPLIT`
chains would be prohibitively slow (each split is `O(n)` in the
remaining blob; N splits cost `O(N²)`). The implementation uses a
push-and-hash shape instead:

1. The unlocking script pushes **each parsed field separately** (one
   push per commitment / opened-value batch / Merkle-path sibling /
   grinding witness / final-poly coefficient — structure dictated by
   `docs/sp1-proof-format.md`).
2. The unlocking script also pushes `proofBlob` as a single
   `ByteString` — the concatenation of all those fields in declaration
   order.
3. The verifier runs one `OP_SHA256` (double-SHA-256 is already paid by
   the BIP-143 preimage containing `proofBlob`) and asserts
   `sha256(concat(parsed_fields)) == sha256(proofBlob)` before
   consuming any parsed field. This binds the ~N pushes to the single
   `proofBlob` without per-byte parsing.

The cost of the concatenation re-hash is `O(|proof|)` in SHA-256 block
work — far cheaper than splitting.

### 2.1. Pre-pushed field order (unlocking-script layout)

The unlocking script must push every parsed proof field as a single
`ByteString` stack item, in the exact order the postcard decoder
walks the `Proof` struct (see `packages/runar-go/sp1fri/decode.go`).
The order mirrors the bincode/postcard struct-field traversal of
Plonky3's `p3_uni_stark::Proof<MyConfig>`:

```text
# --- proof.commitments (decode.go:50-64) ---
proof.commitments.trace.cap_len                              # varint usize
for i in 0..cap_len:
  proof.commitments.trace[i].digest[0..7]                    # 8 KB elements
proof.commitments.quotient_chunks.cap_len                    # varint usize
for i in 0..cap_len:
  proof.commitments.quotient_chunks[i].digest[0..7]
proof.commitments.random.option_tag                          # 1 byte (0 or 1)
if some:
  proof.commitments.random.cap_len + entries (as above)

# --- proof.opened_values (decode.go:113-146) ---
proof.opened_values.trace_local.len                          # varint usize
for v in trace_local:
  v.coef[0..3]                                               # 4 KB elements (Ext4)
proof.opened_values.trace_next.option_tag
if some: trace_next.len + entries (as above)
proof.opened_values.preprocessed_local.option_tag + …
proof.opened_values.preprocessed_next.option_tag + …
proof.opened_values.quotient_chunks.outer_len
for chunk in quotient_chunks:
  chunk.len
  for v in chunk: v.coef[0..3]
proof.opened_values.random.option_tag + …

# --- proof.opening_proof (FriProof, decode.go:148-176) ---
opening_proof.commit_phase_commits.outer_len
for cap in commit_phase_commits:
  cap.cap_len
  for d in cap: d.digest[0..7]
opening_proof.commit_pow_witnesses.len
for w in commit_pow_witnesses: w                             # 1 KB element
opening_proof.query_proofs.len
for q in query_proofs:
  q.input_proof.batch_len
  for batch in q.input_proof:
    batch.opened_values.outer_len
    for matrix_row in batch.opened_values:
      matrix_row.len + matrix_row[0..n]
    batch.opening_proof.len + sibling_digests[…].digest[0..7]
  q.commit_phase_openings.len
  for step in q.commit_phase_openings:
    step.log_arity                                           # 1 byte
    step.sibling_values.len
    for s in step.sibling_values: s.coef[0..3]
    step.opening_proof.len + sibling_digests[…].digest[0..7]
opening_proof.final_poly.len
for c in final_poly: c.coef[0..3]
opening_proof.query_pow_witness                              # 1 KB element

# --- top-level tail ---
proof.degree_bits                                            # varint usize
```

**Encoding convention.** Each KoalaBear field element is pushed as
its **canonical 4-byte little-endian** representation (range
`[0, p)`, where `p = 2^31 − 2^24 + 1`). The off-chain decoder is
responsible for converting from Plonky3 Montgomery form to canonical
form before pushing. Each varint length and option tag is pushed as
its raw byte sequence so that `OP_CAT(all_pushes)` reproduces the
exact `proofBlob` bytes.

**Stack order at verifier entry.** The 3 ByteString arguments
(`proofBlob`, `publicValues`, `sp1VKeyHash`) sit on top of the
pre-pushed fields:

```text
[ <field_0>, <field_1>, …, <field_N-1>, proofBlob, publicValues, sp1VKeyHash ]
```

After the verifier pops + caches the 3 arguments and does the
push-and-hash binding (see §2 above), the N field pushes remain on
the stack and are consumed by subsequent steps in declaration order.

## 3. Fiat-Shamir transcript

The verifier replays the SP1 prover's Fiat-Shamir transcript using
the existing codegen-time `FiatShamirState` DuplexChallenger at
`packages/runar-compiler/src/passes/fiat-shamir-kb-codegen.ts`
(and the 5 peer files).

The transcript order is a composition of two layers:

1. The **outer SP1 wrapper** absorbs the SP1 VK hash (and any
   SP1-specific instance metadata) before delegating to Plonky3's
   uni-stark verifier. The exact wrapper sequence lives in SP1
   v6.0.2 `crates/stark/src/machine.rs` (`MachineVerifier::verify`
   / `observe_public_values`). This is **not** part of Plonky3 — SP1
   layers it on top.
2. The **inner Plonky3 STARK verify** (`uni-stark/src/verifier.rs`
   `verify_with_preprocessed`, lines 354-385) absorbs in this exact
   order:

```text
H = DuplexChallenger.new()         # 16-F state, rate=8, capacity=8
# --- Outer SP1 wrapper (SP1 v6.0.2 crates/stark/src/machine.rs) ---
H.absorb_chunked(sp1VKeyHash)       # binds the program

# --- Inner Plonky3 verify_with_preprocessed (verifier.rs:354-385) ---
H.observe(degree_bits as F)         # verifier.rs:355
H.observe(base_degree_bits as F)    # verifier.rs:356
H.observe(preprocessed_width as F)  # verifier.rs:357
H.observe(commitments.trace)        # verifier.rs:363 — 8 F-elements
if preprocessed_width > 0:
  H.observe(preprocessed_commit)    # verifier.rs:365
H.observe_slice(public_values)      # verifier.rs:367
alpha     = H.sample_algebra()      # verifier.rs:373 — Ext4
H.observe(commitments.quotient_chunks)  # verifier.rs:374
if commitments.random.is_some():
  H.observe(random_commit)          # verifier.rs:379
zeta      = H.sample_algebra()      # verifier.rs:385 — Ext4
# (PCS verify absorbs the OpenedValues internally inside
#  fri/src/two_adic_pcs.rs::verify; see §3.2 below.)

# --- FRI commit-phase fold loop (fri/src/verifier.rs:240-300) ---
for step in 0..num_folds:
  H.observe(commit_phase_commits[step])  # 8 F-elements per step
  beta[step] = H.sample_algebra()        # Ext4
  if commit_pow_bits > 0:
    H.observe(commit_pow_witnesses[step])
    H.check_pow(commit_pow_bits)

# --- Proof of work (grinding) ---
H.observe(query_pow_witness)            # fri/src/verifier.rs:312
H.check_pow(query_pow_bits)             # asserts top bits == 0

# --- Query indices (fri/src/verifier.rs:319-330) ---
query_indices = [H.sample_bits(log_global_max_height)
                 for _ in 0..num_queries]
```

Note: an earlier draft of this doc placed `publicValues` before the
trace commitment — that ordering was wrong. The corrected sequence
above matches Plonky3 v0.x as vendored under
`/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/794faa1/uni-stark/src/verifier.rs:354-385`.

### 3.1. Field-element packing for `observe(usize as F)`

Plonky3's `observe(F::from_usize(n))` reduces the usize to one
KoalaBear field element via `n mod p`. The on-chain emitter pushes
the canonical `n mod p` and calls `FiatShamirState.EmitObserve`.

### 3.2. PCS-internal absorption inside `pcs.verify`

The PCS verify at uni-stark/src/verifier.rs:454 calls into
`fri/src/two_adic_pcs.rs::verify`. That function absorbs the opened
values **after** observing each round's points and **before** any
FRI commit-phase work. The exact order, per
`fri/src/two_adic_pcs.rs::verify` (search "challenger.observe"), is:

```text
for (com, points_per_matrix) in coms_to_verify:
  for (matrix_domain, opening_points) in points_per_matrix:
    for (zeta_point, opened_row) in opening_points:
      for ext4_value in opened_row:
        for base_coef in ext4_value:    # 4 absorbs per Ext4 (column-major)
          H.observe(base_coef)
```

Then control returns to fri/src/verifier.rs:verify_shape_and_sample_challenges
which performs the commit-phase commit-then-sample loop above.

The transcript state is a purely codegen-compile-time object; no
sponge state lives on the Bitcoin Script stack at runtime. Every
absorb and squeeze lowers directly to `OP_*` sequences that operate
on the runtime stack.

## 4. Script-size, stack, and timing targets

From BSVM handoff §2.1:

| Metric           | Target           | Hard limit |
|------------------|------------------|------------|
| Script size      | < 2 MB           | 10 MB      |
| Peak stack depth | < 500            | 1,000      |
| Execution time   | < 500 ms         | 1 s        |

Measurement methodology (Phase 2, `docs/fri-verifier-measurements.md`):
deploy to BSV regtest, execute a real SP1 v6.0.2 proof from the
`evm-guest/` fixture, capture `ls -l` on the compiled script,
`max_stack_depth` from `integration/go/regtest/` instrumentation,
and wall-clock on a blocks-per-second mining loop.

## 5. Fallback order (execute in sequence if targets are missed by >3×)

From handoff §2.1, executed in order before declaring a deliverable:

1. **Reduce security parameter.** Drop `num_queries` from 100 → 64.
   If still over, 64 → 16. Document the security-bit reduction in
   `docs/fri-verifier-measurements.md`.
2. **SP1 proof composition.** Use SP1's recursive proof aggregation so
   the verifier sees a single composed proof (still Plonky3 but at
   reduced width). Requires coordination with SP1 upstream and BSVM.
3. **Split FRI verification across multiple BSV transactions.** The
   sumcheck, PoW, and per-query paths become separate spends bound
   together by a continuation hash over committed intermediate state.
4. **STARK-to-SNARK wrap (Groth16).** Falls back to Mode 2 mechanics
   but with a trust-model implication: the BN254 pairing path is
   honest-verifier-only until SP1 composition is available. Requires
   updating the BSVM whitepaper's trust model language.

## 6. Negative-test corruption matrix (handoff §2.4)

Each row lives under `tests/vectors/sp1/fri/corruptions/<name>/`
and must fail `OP_VERIFY` on regtest:

| Test                  | Corruption                                              | Fails at |
|-----------------------|---------------------------------------------------------|----------|
| bad_merkle            | Flip one byte in a sibling hash of a query Merkle path  | Merkle root recomputation |
| bad_folding           | Change one FRI query evaluation                         | Colinearity check |
| bad_final_poly        | Change the final constant poly value                    | Final-poly reduction |
| wrong_public_values   | Change one byte of `publicValues`                       | Transcript divergence → any downstream check |
| bad_vk                | Wrong guest's VK hash                                   | Transcript divergence |
| truncated             | Remove the last 100 bytes of `proofBlob`                | Push-and-hash equality |
| wrong_program         | Proof for minimal guest with VK for EVM guest           | Transcript divergence |
| all_zeros             | 200 KB of zeros                                         | bincode length check or push-and-hash |

`tests/vectors/sp1/fri/corruptions/` ships at Phase 1 with minimal-guest
corruptions; the full EVM-guest matrix lands alongside Phase 2.

## 7. ABI break: publicValues comes from the proof

SP1 proofs commit to `publicValues` via a Poseidon2 digest in the
`committed_value_digest` field of the public-values blob itself (see
`docs/sp1-proof-format.md` §4). Once the on-chain verifier is live,
BSVM's covenant no longer needs `publicValues` as a **separate
unlocking-script parameter** — it extracts it from the proof and the
covenant binds the extracted values to its readonly fields. BSVM's
`AdvanceState` should drop the `publicValues` argument in the same
release that wires `runar.VerifySP1FRI`.

Mentioned here because it affects the covenant's public ABI and the
whitepaper's trust-model language (per handoff §3 step 3).

## 8. Implementation status

**Landed (Phase 1 scaffold — Go only):**
- This doc and `docs/sp1-proof-format.md`.
- `runar.VerifySP1FRI` registered in the Go DSL
  (`packages/runar-go/runar.go`), the Go compiler's typecheck
  (`compilers/go/frontend/typecheck.go`), and the `.runar.go` parser
  synonym map (`compilers/go/frontend/parser_gocontract.go`) so
  BSVM's covenant can be written against the ABI.
- PoC contract `integration/go/contracts/Sp1FriVerifierPoc.runar.go`
  that exercises the intrinsic at the frontend level.
- `compilers/go/codegen/sp1_fri.go` — structural codegen module with
  a faithful decomposition of the Plonky3 STARK + FRI verifier
  algorithm into 12 sub-steps (proof-blob binding, transcript init,
  commitment absorbs, challenge squeezes, sumcheck, quotient
  reconstruction, FRI fold absorbs, PoW, per-query Merkle + fold,
  final-poly check, success output). Each sub-step has a dedicated
  helper with a Plonky3-source pointer documenting the reference
  implementation. Wired into `compilers/go/codegen/stack.go` dispatch.
- `tests/vectors/sp1/fri/` — real Plonky3 KoalaBear FRI fixture
  (`minimal-guest/proof.postcard`, 1589 bytes, generated against
  `default_koalabear_poseidon2_16()`) plus reproducible Rust
  generator under `minimal-guest/regen/`. Scaffolding for `evm-guest/`
  and the eight `corruptions/` variants pinned in their READMEs.
- Compile-guard test `TestSp1FriVerifierPoc_CodegenRefuses` (in
  `integration/go/sp1_fri_poc_test.go`) continues to pass: any
  attempt to compile a contract calling `runar.VerifySP1FRI` fails
  cleanly with a message naming the first unimplemented sub-step
  and pointing at this doc plus the corresponding Plonky3 source.
  This prevents silently shipping an unsafe no-op.

**Landed (Phase 1.5 — Go off-chain reference verifier):**
- `packages/runar-go/sp1fri/` — postcard decoder, KoalaBear and Ext4
  arithmetic, Poseidon2-KoalaBear permutation (canonical published
  constants, validated against Plonky3's
  `test_default_koalabear_poseidon2_width_16` vector),
  DuplexChallenger, MMCS verify_batch + ExtensionMmcs adapter,
  Fibonacci AIR symbolic constraint evaluator, FRI per-query verify +
  colinearity fold, and a top-level `Verify(*Proof, []uint32) error`
  mirroring `uni-stark/src/verifier.rs:242-495`.
- `TestVerifyMinimalGuest` accepts the real Plonky3 fixture
  end-to-end. `TestRejectMutatedProof` confirms rejection on
  byte-level mutation. The reference verifier is the off-chain
  ground truth the on-chain Bitcoin Script port mirrors.

**Deferred to a dedicated codegen follow-up** (each sub-step has a
named helper in `compilers/go/codegen/sp1_fri.go` with a Plonky3
source reference plus a now-validated Go counterpart in
`packages/runar-go/sp1fri/` to translate from):

- `emitAbsorbByteString` — SP1's byte-to-field packing convention for
  public values. Ref: SP1 v6.0.2
  `crates/stark/src/machine.rs::observe_public_values`.
- Proof-blob push-and-hash binding emission (structural, not
  algebraic). Ref: `docs/sp1-proof-format.md` §6.
- `emitMerkleVerify` — per-step sibling-ordering + bit-shift ladder.
  Uses existing `EmitPoseidon2KBCompress`. Ref: Plonky3
  `commit/src/mmcs.rs::verify_batch`.
- `emitSumcheckRound` — polynomial evaluation at 0, 1, β over
  KoalaBear Ext4, claim update. Ref: Plonky3
  `uni-stark/src/verifier.rs::verify_constraints`.
- Quotient / constraint reconstruction. AIR-specific — ref: SP1
  guest-program AIR definitions.
- `emitFriColinearityFold` — Ext4 colinearity formula over KoalaBear.
  Ref: Plonky3 `fri/src/fold_even_odd.rs`.
- Final-polynomial reduction for `LogFinalPolyLen > 0` (Lagrange
  eval). Phase-1 stub handles constant final poly.
- Per-query orchestration that ties the above together. Ref: Plonky3
  `fri/src/verifier.rs::verify_query`.

Fixture generation:
- `tests/vectors/sp1/fri/minimal-guest/proof.bin` + `vk.bin` +
  `public_values.hex` + `vk_hash.hex`. Regen via the Plonky3
  `fib_air.rs` test ported to KoalaBear — see subdirectory README.
- `tests/vectors/sp1/fri/evm-guest/` real SP1 EVM-guest proof. Regen
  via SP1 SDK v6.0.2 toolchain — see subdirectory README.
- `tests/vectors/sp1/fri/corruptions/*` produced programmatically
  from the minimal-guest base via byte-level mutation.

Regtest measurement pass → `docs/fri-verifier-measurements.md`
(Phase 2).

## 9. Not on this repo

- SP1 guest program internals (upstream Succinct Labs).
- On-chain Poseidon2-to-SHA-256 transcoding (obsolete — Rúnar's
  Poseidon2 codegen verifies Merkle paths natively).
- Groth16 / Groth16-WA pairing paths (unchanged — Mode 2/3).
- BSVM-side covenant edits, whitepaper revision, and
  `PrepareGenesis` guardrail removal. Those land in `bsv-evm`
  once Rúnar ships a tagged release containing the codegen body.

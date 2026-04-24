# SP1 STARK / FRI proof byte layout (v6.0.2)

This document pins the serialized byte layout of an SP1 v6.0.2 STARK
proof — the artifact BSVM's `FRIRollupContract.AdvanceState` receives
as its `proofBlob` parameter and that the on-chain
`runar.VerifySP1FRI` intrinsic parses. Scope: the structural
hierarchy and the per-field size budget; exact byte offsets are a
function of the concrete guest program AIR (trace width, degree,
constraint count) and so are tabulated per-fixture in
`tests/vectors/sp1/fri/` rather than fixed globally.

## 1. Generic constants for SP1 v6.0.2 + KoalaBear

| Constant | Value | Notes |
|----------|-------|-------|
| Base field `F` | KoalaBear | prime `p = 2³¹ − 2²⁴ + 1 = 2,130,706,433` |
| Encoded size of one `F` element | **4 bytes** | little-endian `u32`, canonical form `0 ≤ x < p` |
| Challenge field `C` | KoalaBear Ext4 | quartic extension `F[X]/(X⁴ − 3)` |
| Encoded size of one `C` element | **16 bytes** | four `F` elements, coefficient-order low-to-high |
| Commitment / Merkle digest | Poseidon2-KoalaBear | 8 × `F` = **32 bytes** |
| Challenger state | Plonky3 `DuplexChallenger` over Poseidon2-KB | 16-`F` state, rate=8, capacity=8 |

SP1 v6.0.2 STARK parameters (verifier must know these out-of-band or
bake them into the VK hash):

| Parameter | Production default | PoC subset |
|-----------|--------------------|------------|
| `log_blowup` | 1 | 1 |
| `num_queries` | 100 (hard floor 64 per handoff §2.1 fallback) | 2 |
| `proof_of_work_bits` | 16 | 0 |
| `folding_arity` | 2 (log-arity = 1) | 2 |
| `final_poly_len` | 1 (constant) | 1 |

## 2. Struct hierarchy (Plonky3 source of truth)

Top-level STARK proof is a Plonky3 `Proof<SC>`
(`uni-stark/src/proof.rs`):

```text
Proof {
  commitments      Commitments<Com>,
  opened_values    OpenedValues<Challenge>,
  opening_proof    PcsProof<SC>          # FriProof for SP1
  degree_bits      usize                 # varint-encoded u64
}
```

Sub-structs in serialization order:

```text
Commitments {
  trace             Com         # 32 bytes (Poseidon2-KB digest)
  quotient_chunks   Com         # 32 bytes
  random            Option<Com> # 1 byte tag + 0 or 32
}

OpenedValues<Challenge> {
  trace_local         Vec<Challenge>
  trace_next          Option<Vec<Challenge>>
  preprocessed_local  Option<Vec<Challenge>>
  preprocessed_next   Option<Vec<Challenge>>
  quotient_chunks     Vec<Vec<Challenge>>
  random              Option<Vec<Challenge>>
}
```

SP1 uses `TwoAdicFriPcs`, so `PcsProof<SC>` is concretely
`FriProof<Challenge, FriMmcs, Val, Vec<BatchOpening<Val, InputMmcs>>>`
(`fri/src/proof.rs` + `fri/src/two_adic_pcs.rs`):

```text
FriProof {
  commit_phase_commits   Vec<Com>              # one per fold step
  commit_pow_witnesses   Vec<Witness>          # PoW grinding nonces
  query_proofs           Vec<QueryProof>       # num_queries entries
  final_poly             Vec<F>                # final constant poly
  query_pow_witness      Witness               # single nonce
}

QueryProof {
  input_proof            Vec<BatchOpening>     # one per input matrix
  commit_phase_openings  Vec<CommitPhaseProofStep>
}

BatchOpening {                                 # commit/src/mmcs.rs
  opened_values   Vec<Vec<F>>                  # one row per matrix
  opening_proof   MerklePath                   # siblings to root
}

CommitPhaseProofStep {
  log_arity       u8
  sibling_values  Vec<F>                       # len = arity − 1
  opening_proof   MerklePath
}

MerklePath = Vec<Com>                          # depth × 32 bytes
```

`Witness` is a single `F` (proof-of-work nonce found during proving;
verifier checks the grinding predicate).

## 3. Serde bincode encoding (what Plonky3 emits)

Plonky3 derives `Serialize` / `Deserialize` on every struct and uses
bincode's **default little-endian fixed-int** encoding for the on-chain
/ CLI path. Rules the verifier needs to mirror:

- Struct fields serialize in declaration order with **no separator**.
- `Vec<T>` serializes as `u64_le(len) || T[0] || T[1] || …`.
- `Option<T>` serializes as `u8(0x00)` (None) or `u8(0x01) || T` (Some).
- Primitive integers use little-endian fixed width.
- `F` (KoalaBear) serializes as `u32_le` in canonical form.
- `C` (KoalaBear Ext4) serializes as four `F` coefficients in ascending
  degree: `c₀ || c₁ || c₂ || c₃`.
- `Com` (Poseidon2-KoalaBear digest) serializes as eight `F` elements:
  `d₀ || d₁ || … || d₇` (32 bytes).

`degree_bits` is a `usize`; bincode's default emits it as a `u64_le`.
The verifier treats its low 6 bits as the trace-height exponent; higher
bits must be zero on a well-formed proof.

## 4. Public values

Public values are **not** part of `Proof<SC>` — they are committed to
via Fiat-Shamir observation before any commitment is absorbed.
BSVM's `AdvanceState` currently passes `publicValues ByteString`
alongside `proofBlob`; the on-chain verifier absorbs
`publicValues` into the challenger at slot 1 of the transcript (see
`docs/sp1-fri-verifier.md` §3).

SP1 public values are a packed struct whose layout is guest-program
specific. For a minimal guest the layout is:

```text
public_values = [
  shard             u32_le,
  start_pc          u32_le,
  next_pc           u32_le,
  exit_code         u32_le,
  committed_value_digest  [u32_le; 8]   # SHA-256 over guest-provided bytes
  deferred_proofs_digest  [u32_le; 8]
  ... (chip-specific trailing fields)
]
```

The EVM guest used by BSVM Mode 1 adds `pre_state_root`,
`post_state_root`, `chain_id`, `block_number`, `batch_hash`, and a
data-availability digest to the tail — see BSVM's
`pkg/covenant/contracts/rollup_fri.runar.go` for the exact field list
it binds on-chain.

## 5. Verifying key hash

`sp1VKeyHash` is the **keccak256 digest of the serialized verifying
key** (SP1 v6.0.2 convention — matches the on-chain Solidity Groth16
verifier's `vkey_hash` field in `tests/vectors/sp1/v6.0.0/`). The
top 3 bits are zeroed to fit the BN254 scalar field for the Groth16
wrap; the STARK path uses the full 256-bit hash.

The verifying key itself is a Plonky3 `StarkVerifyingKey<SC>` — a
preprocessed Merkle commitment plus the AIR's public-input layout.
Its byte layout mirrors `Commitments` in §2. Guest programs pin the
VK hash into the covenant at compile time; the verifier only consumes
the hash (not the VK bytes).

## 6. Test fixture layout

Committed fixtures live at `tests/vectors/sp1/fri/` and follow
the shape of the existing v0.6.0 Groth16 fixtures at
`tests/vectors/sp1/v6.0.0/`:

```text
tests/vectors/sp1/fri/
  minimal-guest/
    proof.bin                # Plonky3 FriProof, bincode-encoded
    public_values.hex        # lowercase hex, no 0x prefix
    vk_hash.hex              # 64 hex chars (32 bytes keccak256)
    README.md                # trace width, degree_bits, num_queries etc.
  evm-guest/                 # Phase 2 — real SP1 EVM-guest proof
  corruptions/
    bad_merkle/proof.bin     # one byte flipped in a sibling digest
    bad_final_poly/proof.bin # final_poly constant mutated
    bad_vk/vk_hash.hex       # wrong guest's VK hash
    truncated/proof.bin      # last 100 bytes removed
    all_zeros/proof.bin      # 200 KB of 0x00
    wrong_public_values/public_values.hex
```

The minimal-guest fixture is the acceptance target for Phase 1. The
evm-guest fixture drives Phase 2 measurement (see
`docs/sp1-fri-verifier.md` §5).

## 7. Upstream references

- Plonky3 `uni-stark/src/proof.rs` — top-level Proof struct.
- Plonky3 `fri/src/proof.rs` — FriProof, QueryProof,
  CommitPhaseProofStep.
- Plonky3 `fri/src/two_adic_pcs.rs` — PCS instantiation used by SP1.
- Plonky3 `commit/src/mmcs.rs` — BatchOpening and MMCS Merkle proof.
- Plonky3 `koala-bear/src/poseidon2.rs` — Poseidon2-KoalaBear round
  constants (pinned in this repo under
  `packages/runar-compiler/src/passes/poseidon2-koalabear-codegen.ts`
  + 5 peers).
- SP1 v6.0.2 — uses Plonky3 0.5.2; the upstream crate paths are the
  authoritative byte layout.

## 8. Stability

The byte layout above is tied to bincode default encoding + Plonky3
struct declarations. A Plonky3 bump or bincode option change would
break the verifier without warning. The repo pins the tested SP1 /
Plonky3 versions at the top of this doc; any fixture regeneration
must bump that version string and land alongside a re-measurement
run in `docs/fri-verifier-measurements.md`.

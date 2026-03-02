# Post-Quantum Signature Verification in Bitcoin Script

Analysis of implementing post-quantum digital signature verification within Rúnar smart contracts on Bitcoin SV.

## Background

Quantum computers threaten ECDSA (Bitcoin's current signature scheme). NIST has standardized three post-quantum signature algorithms:

- **ML-DSA** (FIPS 204) — Lattice-based (formerly CRYSTALS-Dilithium)
- **SLH-DSA** (FIPS 205) — Hash-based (formerly SPHINCS+)
- **ML-KEM** (FIPS 203) — Key encapsulation (not a signature scheme)

This document evaluates ML-DSA and SLH-DSA for on-chain verification in Bitcoin Script, plus the simpler WOTS+ scheme which serves as a building block.

## ML-DSA (FIPS 204): Lattice-Based Signatures

### What verification requires

ML-DSA-44 (smallest parameter set, NIST Security Level 2):

| Item | Size |
|------|------|
| Public key | 1,312 bytes |
| Signature | 2,420 bytes |
| Matrix A (expanded) | ~94 KB |

Mathematical primitives:
1. **Modular arithmetic** over q = 8,380,417 (23-bit prime)
2. **Polynomial ring** R_q = Z_q[X]/(X^256 + 1) — arrays of 256 coefficients
3. **NTT** (Number Theoretic Transform) — 256-point, 2,048 butterfly operations per transform, ~12 transforms total
4. **Matrix-vector multiply** — 4x4 polynomials x 4-vector
5. **SHAKE-128/256** — Keccak sponge-based XOF for challenge derivation, seed expansion, message hashing
6. **Rounding decomposition** — HighBits, LowBits, UseHint

Total: ~205,000 modular multiplications + 8-104 Keccak-f[1600] permutations.

### BSV capabilities

BSV re-enabled opcodes disabled in BTC, changing the feasibility picture significantly:

| Capability | BTC | BSV |
|-----------|-----|-----|
| OP_MUL | Disabled | Available |
| Bitwise (AND, OR, XOR, INVERT) | Disabled | Available |
| Shift (LSHIFT, RSHIFT) | Disabled | Available |
| Integer size | 4 bytes | Arbitrary |
| Script size limit | ~10 KB | 10 MB |
| Opcode count limit | 201 | None |
| Stack depth | 1,000 | 1,000 |

### Feasibility assessment

**Feasible components:**
- Modular arithmetic: `a * b % q` → `OP_MUL <q> OP_MOD` (3 opcodes)
- Bitwise operations for Keccak: all primitives available
- Bounded iteration: all loop counts are compile-time constants
- Rounding: simple integer arithmetic

**Blocking issues:**

1. **SHAKE-256/128 must be built from scratch** — No Keccak opcode in Bitcoin Script. Must implement Keccak-f[1600] from bitwise primitives: 25 lanes x 64 bits, 24 rounds, ~12,000 opcodes per permutation. ML-DSA needs 8-104 permutations = 100K-1.25M opcodes just for SHAKE.

2. **Stack depth critically tight** — Each polynomial = 256 stack items. Rúnar's 800-item limit means at most 3 polynomials simultaneously with 32 slots working space. NTT butterfly operations need OP_PICK/OP_ROLL at depths up to 255.

3. **FixedArray indexed access not implemented** — Rúnar's type system supports `FixedArray<T, N>` but the stack lowerer has no handler for `__array_access`. Would need implementation first.

4. **Script size explosion** — Estimated 1-4 MB depending on whether matrix A is provided as witness data or derived from seed. Within BSV's 10 MB limit but enormous.

### Verdict

**Theoretically possible in BSV. Impractical for Rúnar today.** Requires implementing Keccak from scratch (~100K opcodes), dealing with polynomial operations at the stack depth limit, and building array indexing support. Multi-month effort for a ~1 MB verification script.

## Hash-Based Signatures: The Practical Alternative

Hash-based schemes use **only SHA-256** — a native Bitcoin Script opcode (`OP_SHA256`, 1 byte). No polynomial arithmetic, no NTT, no Keccak. This eliminates every blocking issue identified for ML-DSA.

### WOTS+ (Winternitz One-Time Signature)

The simplest viable post-quantum scheme. Verification is completing hash chains.

| Property | Value |
|----------|-------|
| Hash function | SHA-256 only |
| Signature size | 2,144 bytes |
| Public key size | 32 bytes |
| SHA-256 ops for verification | ~550-600 |
| Estimated script size | ~12 KB |
| One-time use? | Yes |

**How it works:**
1. Message is hashed to 256 bits, split into 64 base-16 digits
2. Checksum is computed and encoded as 3 more digits (67 total)
3. For each of 67 chain elements: hash the signature element `(15 - digit)` times
4. SHA-256 all 67 chain endpoints → compare to public key

**UTXO compatibility:** The one-time constraint is natural for Bitcoin's UTXO model — each output is spent exactly once. Address reuse is already discouraged.

**Script structure:** 67 chains x 15 conditional SHA-256 iterations (like the GCD builtin's conditional loop pattern). Stack depth ~75 items.

### SLH-DSA (FIPS 205, SHA-256 variants)

NIST-standardized, stateless, multi-use. Three-tier architecture:
- **FORS** (Forest of Random Subsets) — few-time signature
- **WOTS+** — one-time signature (used internally)
- **Hypertree** — layers of Merkle trees

Six SHA-256 parameter sets:

| Parameter set | Sig size | SHA-256 ops | Script est. | Security |
|--------------|----------|-------------|-------------|----------|
| SLH-DSA-SHA2-128s | 7,856 B | ~2,100 | ~25 KB | 128-bit |
| SLH-DSA-SHA2-128f | 17,088 B | ~1,400 | ~40 KB | 128-bit |
| SLH-DSA-SHA2-192s | 16,224 B | ~3,200 | ~40 KB | 192-bit |
| SLH-DSA-SHA2-192f | 35,664 B | ~2,100 | ~60 KB | 192-bit |
| SLH-DSA-SHA2-256s | 29,792 B | ~4,500 | ~60 KB | 256-bit |
| SLH-DSA-SHA2-256f | 49,856 B | ~3,000 | ~80 KB | 256-bit |

Each "hash" is actually a tweakable hash: `SHA-256(PK.seed || pad || ADRS || M)` truncated to n bytes. This adds ~7 opcodes overhead per hash vs plain OP_SHA256.

**Verification steps:**
1. Parse signature (OP_SPLIT at known offsets)
2. Compute message digest
3. FORS verification → FORS public key
4. For each hypertree layer: WOTS+ verify + Merkle path verify
5. Compare final root to public key

### XMSS (RFC 8391)

| Property | Value |
|----------|-------|
| Hash function | SHA-256 only |
| Signature size | ~2,500 bytes (h=10) |
| Public key size | 32 bytes |
| SHA-256 ops | ~850 |
| Script estimate | ~1,200 bytes |
| Stateful signer? | Yes |

The signer must track which keys have been used. Reusing an index breaks security entirely. This makes hardware wallet integration and backup/recovery risky. Verification itself is stateless.

## Comparison

| | ML-DSA-44 | WOTS+ | SLH-DSA-SHA2-128s | XMSS |
|---|---|---|---|---|
| Script size | ~1-4 MB | 10.5 KB | 203 KB | ~1.2 KB |
| Sig size | 2,420 B | 2,144 B | 7,856 B | 2,500 B |
| Hash ops needed | Keccak (not native) | SHA-256 (native) | SHA-256 (native) | SHA-256 (native) |
| NTT/poly math | Yes | No | No | No |
| Stack depth | ~800 (at limit) | ~75 | ~200 | ~150 |
| NIST standardized | FIPS 204 | No | FIPS 205 | RFC 8391 |
| Multi-use keypair | Yes | No | Yes | Yes (stateful) |

## Implementation Status

Both WOTS+ and SLH-DSA are fully implemented in all three Rúnar compilers (TypeScript, Go, Rust), producing byte-identical Bitcoin Script verified by the conformance suite.

| Scheme | Measured Script Size | Conformance Status |
|--------|---------------------|-------------------|
| WOTS+ (`verifyWOTS`) | 10,530 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-128s | 207,874 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-128f | 612,518 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-192s | 306,049 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-192f | 905,067 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-256s | 416,592 bytes | TS, Go, Rust: byte-identical |
| SLH-DSA-SHA2-256f | 848,327 bytes | TS, Go, Rust: byte-identical |

## Recommendation

1. **WOTS+** for simplest use — one-time signature, natural UTXO fit, ~10 KB script
2. **SLH-DSA-SHA2-128s** for production — NIST-standardized (FIPS 205), stateless, multi-use, ~200 KB script
3. **ML-DSA** only if BSV adds OP_KECCAK — until then, hash-based is 1000x more practical

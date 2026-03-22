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

3. **Script size explosion** — Estimated 1-4 MB depending on whether matrix A is provided as witness data or derived from seed. Within BSV's 10 MB limit but enormous.

### Verdict

**Theoretically possible in BSV. Impractical for Rúnar today.** Requires implementing Keccak from scratch (~100K opcodes) and dealing with polynomial operations at the stack depth limit. Multi-month effort for a ~1 MB verification script.

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

Six SHA-256 parameter sets (pre-implementation projections):

| Parameter set | Sig size | SHA-256 ops | Script est. | Measured script | Security |
|--------------|----------|-------------|-------------|-----------------|----------|
| SLH-DSA-SHA2-128s | 7,856 B | ~2,100 | ~25 KB | 203 KB | 128-bit |
| SLH-DSA-SHA2-128f | 17,088 B | ~1,400 | ~40 KB | 612 KB | 128-bit |
| SLH-DSA-SHA2-192s | 16,224 B | ~3,200 | ~40 KB | 306 KB | 192-bit |
| SLH-DSA-SHA2-192f | 35,664 B | ~2,100 | ~60 KB | 905 KB | 192-bit |
| SLH-DSA-SHA2-256s | 29,792 B | ~4,500 | ~60 KB | 417 KB | 256-bit |
| SLH-DSA-SHA2-256f | 48,736 B | ~3,000 | ~80 KB | 848 KB | 256-bit |

> **Note:** The "Script est." column contains pre-implementation projections that significantly underestimated the actual script sizes. The "Measured script" column shows the real sizes after implementation. The 4-10x difference is due to the overhead of tweakable hashing (each SHA-256 call requires constructing a 22-byte ADRS for domain separation, adding ~7 opcodes per hash) and the stack management code needed to track named positions across thousands of operations. See the Implementation Status section below for exact byte counts.

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

Both WOTS+ and SLH-DSA are fully implemented in the maintained compiler set (TypeScript, Go, Rust, Python, Zig), producing byte-identical Bitcoin Script on the shared conformance suite.

| Scheme | Measured Script Size | Conformance Status |
|--------|---------------------|-------------------|
| WOTS+ (`verifyWOTS`) | 10,530 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-128s | 207,874 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-128f | 612,518 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-192s | 306,049 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-192f | 905,067 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-256s | 416,592 bytes | TS, Go, Rust, Python, Zig: byte-identical |
| SLH-DSA-SHA2-256f | 848,327 bytes | TS, Go, Rust, Python, Zig: byte-identical |

## Hybrid ECDSA + Post-Quantum Patterns

### The Problem with Pure Post-Quantum Wallets

A pure WOTS+ or SLH-DSA wallet takes an arbitrary message and signature as inputs — the spender chooses what message to sign. This works for demonstrating the cryptographic primitive, but doesn't integrate with Bitcoin's native transaction authorization model where `OP_CHECKSIG` verifies that a signature commits to the current transaction's sighash preimage.

### Hybrid ECDSA + WOTS+ P2PKH

The hybrid pattern creates a two-layer authentication chain:

1. **ECDSA** proves the signature commits to this specific transaction (via `OP_CHECKSIG`).
2. **WOTS+** proves the ECDSA signature was authorized by the WOTS key holder — the ECDSA signature bytes ARE the message that WOTS signs.

A quantum attacker could forge the ECDSA signature (Shor's algorithm breaks the discrete log problem), but they cannot produce a valid WOTS+ signature over their forged sig without the WOTS secret key. WOTS+ security relies only on SHA-256 collision resistance.

**Constructor:** `(ecdsaPubKeyHash: Addr, wotsPubKeyHash: ByteString)`

**Method:** `spend(wotsSig: ByteString, wotsPubKey: ByteString, sig: Sig, pubKey: PubKey)`

**Locking script layout:**
```
Unlocking: <wotsSig(2144B)> <wotsPubKey(64B)> <ecdsaSig(~72B)> <ecdsaPubKey(33B)>

Locking:
  // --- ECDSA verification (P2PKH) ---
  OP_OVER OP_TOALTSTACK
  OP_DUP OP_HASH160 <ecdsaPubKeyHash(20B)> OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY
  // --- WOTS+ pubkey commitment ---
  OP_DUP OP_HASH160 <wotsPubKeyHash(20B)> OP_EQUALVERIFY
  // --- WOTS+ verification ---
  OP_FROMALTSTACK OP_ROT OP_ROT
  <verifyWOTS ~10KB inline>
```

**Script size:** ~10 KB (same as pure WOTS+, the ECDSA part adds negligible overhead).

**Spending flow (two-pass):**
1. Build the unsigned spending transaction
2. ECDSA-sign the transaction input → get DER signature bytes
3. WOTS-sign the ECDSA signature bytes
4. Construct unlocking script: `<wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>`

### Hybrid ECDSA + SLH-DSA P2PKH

The same pattern applies with SLH-DSA instead of WOTS+, providing NIST-standardized (FIPS 205) multi-use quantum resistance. The only differences are signature and script sizes.

**Constructor:** `(ecdsaPubKeyHash: Addr, slhdsaPubKeyHash: ByteString)`

**Script sizes:** ~200 KB to ~900 KB depending on parameter set (see Implementation Status table above).

### Comparison: Pure vs Hybrid

| Property | Pure WOTS+ | Hybrid ECDSA + WOTS+ | Hybrid ECDSA + SLH-DSA |
|----------|-----------|---------------------|------------------------|
| Transaction binding | None (arbitrary message) | OP_CHECKSIG (sighash) | OP_CHECKSIG (sighash) |
| Quantum resistance | Full | Full | Full (NIST FIPS 205) |
| Script size | ~10 KB | ~10 KB | ~200-900 KB |
| ECDSA key required? | No | Yes | Yes |
| Multi-use keypair? | No | No (WOTS) | Yes (SLH-DSA) |

## Recommendation

1. **Hybrid ECDSA + WOTS+** for simplest quantum-resistant wallet — one-time signature, natural UTXO fit, ~10 KB script, real transaction binding via ECDSA
2. **Hybrid ECDSA + SLH-DSA-SHA2-128s** for production — NIST-standardized (FIPS 205), stateless, multi-use, ~200 KB script
3. **Pure WOTS+/SLH-DSA** for demonstration or message-signing use cases only
4. **ML-DSA** only if BSV adds OP_KECCAK — until then, hash-based is 1000x more practical

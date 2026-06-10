/**
 * BUG-007: Adversarial bound-violation tests for WOTS+ and SLH-DSA.
 *
 * Existing PQ tests verify tampered byte-flips are rejected via real hash
 * chains. This file adds the *structural* adversarial vectors that classic
 * hash-based PQ verifiers must reject:
 *
 *   - Signatures whose length is shorter / longer than the parameter set
 *     mandates (chain-count / hypertree-layer-count bound violations).
 *   - Signatures whose randomness prefix has been tampered, which in
 *     FIPS-205 SLH-DSA re-derives the tree-index / leaf-index that
 *     selects the subtree path. The verifier must reject because the
 *     re-derived indices no longer match the path baked into the sig.
 *   - Whole-section zeroing (FORS section / a specific XMSS layer): tests
 *     that no internal collision lets a structurally-malformed signature
 *     skate by with all-zero bytes.
 *
 * Both `verifyWOTS` and `verifySLHDSA_SHA2_*` go through the real reference
 * implementations in `runar-testing/src/crypto/*` (no mocks) — see
 * `interpreter.ts` cases for `verifyWOTS` / `verifySLHDSA_SHA2_*`.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { wotsKeygen, wotsSign, WOTS_PARAMS } from '../crypto/wots.js';
import {
  slhKeygen, slhSign,
  SLH_SHA2_128s, SLH_SHA2_128f,
  SLH_SHA2_192s, SLH_SHA2_192f,
  SLH_SHA2_256s, SLH_SHA2_256f,
  type SLHParams,
} from '../crypto/slh-dsa.js';
import { runSlowTests } from '../test-env.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// WOTS+ adversarial bound tests
// ---------------------------------------------------------------------------

const WOTS_SOURCE = `
class PQWallet extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }
  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
`;

describe('WOTS+ adversarial bound-violation tests', () => {
  const { LEN, N } = WOTS_PARAMS;
  const expectedSigLen = LEN * N; // 67 * 32 = 2144

  const seed = new Uint8Array(32);
  seed[0] = 0xa7;
  const pubSeed = new Uint8Array(32);
  pubSeed[0] = 0x07;
  const { sk, pk } = wotsKeygen(seed, pubSeed);
  const pkHex = toHex(pk);
  const msg = new TextEncoder().encode('wots bounds adversary');
  const sig = wotsSign(msg, sk, pubSeed);

  it('sanity: valid signature is accepted (control)', () => {
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(r.success).toBe(true);
  });

  it('rejects short signature (length = expected - 1, chain-count under bound)', () => {
    const short = sig.slice(0, expectedSigLen - 1);
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
    expect(r.success).toBe(false);
  });

  it('rejects short signature (truncated to 1 chain element)', () => {
    const short = sig.slice(0, N);
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
    expect(r.success).toBe(false);
  });

  it('rejects short signature (missing last chain element, chain-count = LEN-1)', () => {
    const short = sig.slice(0, (LEN - 1) * N);
    expect(short.length).toBe(expectedSigLen - N);
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
    expect(r.success).toBe(false);
  });

  it('rejects empty signature (chain-count = 0)', () => {
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: '' });
    expect(r.success).toBe(false);
  });

  it('rejects oversize signature (length = expected + 1, chain-count over bound)', () => {
    const over = new Uint8Array(expectedSigLen + 1);
    over.set(sig, 0);
    over[expectedSigLen] = 0x00;
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(over) });
    expect(r.success).toBe(false);
  });

  it('rejects oversize signature (one extra chain element appended)', () => {
    const over = new Uint8Array(expectedSigLen + N);
    over.set(sig, 0);
    // Append a copy of chain 0 so the extra data is "plausible-looking"
    over.set(sig.slice(0, N), expectedSigLen);
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(over) });
    expect(r.success).toBe(false);
  });

  it('rejects all-zero signature of correct length (chain-step underflow)', () => {
    const zero = new Uint8Array(expectedSigLen);
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(zero) });
    expect(r.success).toBe(false);
  });

  it('rejects signature where every chain is replaced with chain-0 (cross-chain forgery)', () => {
    // Attack: try to forge by reusing the first chain element for every chain.
    // This is a chain-index bound violation (chain idx is implicit in position).
    const forged = new Uint8Array(expectedSigLen);
    const first = sig.slice(0, N);
    for (let i = 0; i < LEN; i++) {
      forged.set(first, i * N);
    }
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(forged) });
    expect(r.success).toBe(false);
  });

  it('rejects checksum-chain tamper (last 3 chains zeroed; checksum constraint forces these to a specific step)', () => {
    // The checksum digits are derived from the message digest such that the
    // *sum* of all chain steps equals a constant. Zeroing the checksum chains
    // claims chain-step 0 for them, violating the checksum-step bound.
    const tampered = new Uint8Array(sig);
    for (let i = (LEN - 3) * N; i < LEN * N; i++) tampered[i] = 0;
    const contract = TestContract.fromSource(WOTS_SOURCE, { pubkey: pkHex });
    const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
    expect(r.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SLH-DSA adversarial bound tests
// ---------------------------------------------------------------------------

interface SlhBoundsHarness {
  params: SLHParams;
  source: string;
  builtin: string;
}

function slhSource(builtin: string): string {
  return `
class SLHWallet extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }
  public spend(msg: ByteString, sig: ByteString) {
    assert(${builtin}(msg, sig, this.pubkey));
  }
}
`;
}

const SLH_PARAM_SETS: SlhBoundsHarness[] = [
  { params: SLH_SHA2_128s, source: slhSource('verifySLHDSA_SHA2_128s'), builtin: 'verifySLHDSA_SHA2_128s' },
  { params: SLH_SHA2_128f, source: slhSource('verifySLHDSA_SHA2_128f'), builtin: 'verifySLHDSA_SHA2_128f' },
  { params: SLH_SHA2_192s, source: slhSource('verifySLHDSA_SHA2_192s'), builtin: 'verifySLHDSA_SHA2_192s' },
  { params: SLH_SHA2_192f, source: slhSource('verifySLHDSA_SHA2_192f'), builtin: 'verifySLHDSA_SHA2_192f' },
  { params: SLH_SHA2_256s, source: slhSource('verifySLHDSA_SHA2_256s'), builtin: 'verifySLHDSA_SHA2_256s' },
  { params: SLH_SHA2_256f, source: slhSource('verifySLHDSA_SHA2_256f'), builtin: 'verifySLHDSA_SHA2_256f' },
];

function expectedSlhSigLen(p: SLHParams): number {
  const forsLen = p.k * (1 + p.a) * p.n;
  const xmssLen = (p.len + p.hp) * p.n;
  return p.n + forsLen + p.d * xmssLen;
}

describe.skipIf(!runSlowTests)('SLH-DSA adversarial bound-violation tests (all 6 parameter sets)', () => {
  for (const tc of SLH_PARAM_SETS) {
    describe(tc.params.name, () => {
      const seed = new Uint8Array(3 * tc.params.n);
      seed[0] = 0x42;
      seed[1] = tc.params.n & 0xff;
      const { sk, pk } = slhKeygen(tc.params, seed);
      const pkHex = toHex(pk);
      const msg = new TextEncoder().encode(`bounds test for ${tc.params.name}`);
      const sig = slhSign(tc.params, msg, sk);
      const expectedLen = expectedSlhSigLen(tc.params);

      it('sanity: signature has expected length (control)', () => {
        expect(sig.length).toBe(expectedLen);
      });

      it('sanity: valid signature is accepted (control)', () => {
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
        expect(r.success).toBe(true);
      });

      it('rejects short signature (1 byte missing — tail XMSS layer truncated)', () => {
        const short = sig.slice(0, expectedLen - 1);
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
        expect(r.success).toBe(false);
      });

      it('rejects short signature (one full XMSS layer removed: hypertree-depth underflow)', () => {
        const xmssLen = (tc.params.len + tc.params.hp) * tc.params.n;
        const short = sig.slice(0, expectedLen - xmssLen);
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
        expect(r.success).toBe(false);
      });

      it('rejects short signature (all hypertree layers removed: only R+FORS)', () => {
        const forsLen = tc.params.k * (1 + tc.params.a) * tc.params.n;
        const short = sig.slice(0, tc.params.n + forsLen);
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(short) });
        expect(r.success).toBe(false);
      });

      it('rejects oversize signature (BUG-011: exact-length guard enforced)', () => {
        const xmssLen = (tc.params.len + tc.params.hp) * tc.params.n;
        const over = new Uint8Array(expectedLen + xmssLen);
        over.set(sig, 0);
        // Append a copy of the last XMSS layer
        over.set(sig.slice(expectedLen - xmssLen, expectedLen), expectedLen);
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(over) });
        expect(r.success).toBe(false);
      });

      it('rejects oversize signature (single trailing byte)', () => {
        const over = new Uint8Array(expectedLen + 1);
        over.set(sig, 0);
        over[expectedLen] = 0x00;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(over) });
        expect(r.success).toBe(false);
      });

      // BUG-011 followup: tree-index out-of-range. The tree_idx derived from
      // Hmsg is masked to (h-hp) bits in the verifier. A signature whose XMSS
      // layer-0 path was authored for a *different* tree_idx must be rejected.
      // We can't craft an "out-of-bounds" tree_idx directly because Hmsg
      // re-derives it from R, but we *can* tamper bytes that feed the FORS
      // tree-address (which is the absolute tree_idx for layer 0). Zeroing
      // the FORS auth path forces the FORS root to a non-canonical value,
      // which propagates a wrong xmss leaf message and the layer-0 walk lands
      // at the wrong tree node — verifier rejects.
      it('rejects FORS auth-path zero (tree-index path corruption)', () => {
        const tampered = new Uint8Array(sig);
        // Zero just the FORS auth path (skip the FORS leaf secrets at offset n,
        // wipe the (1+a)*n - n = a*n auth bytes following each leaf).
        const forsAuthStart = tc.params.n + tc.params.n; // R + first FORS leaf
        const authBytesPerTree = tc.params.a * tc.params.n;
        const treeStride = (1 + tc.params.a) * tc.params.n;
        for (let i = 0; i < tc.params.k; i++) {
          const base = tc.params.n + i * treeStride + tc.params.n;
          for (let j = 0; j < authBytesPerTree; j++) tampered[base + j] = 0;
        }
        // Verify we actually changed bytes
        let differed = false;
        for (let i = 0; i < tampered.length; i++) {
          if (tampered[i] !== sig[i]) { differed = true; break; }
        }
        expect(differed).toBe(true);
        void forsAuthStart; // intentionally unused (loop above computes base directly)
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });

      // BUG-011 followup: leaf-index out-of-range. The verifier walks the
      // first XMSS layer authentication path using leaf_idx derived from
      // Hmsg. Zeroing all but the first n bytes of XMSS layer 0 (the WOTS+
      // chains) leaves a structurally-malformed signature whose WOTS+ chain
      // sums no longer match the FORS-derived msgHash; the walk reaches a
      // root that disagrees with PK.root.
      it('rejects XMSS layer-0 WOTS+ chains zeroed (leaf-index path corruption)', () => {
        const tampered = new Uint8Array(sig);
        const forsLen = tc.params.k * (1 + tc.params.a) * tc.params.n;
        const xmssStart = tc.params.n + forsLen;
        const wotsLen = tc.params.len * tc.params.n;
        // Zero all WOTS+ chain bytes of layer 0
        for (let i = xmssStart; i < xmssStart + wotsLen; i++) tampered[i] = 0;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });

      it('rejects R-prefix tamper (re-derives tree_idx/leaf_idx outside the path baked into sig)', () => {
        // R is the first n bytes. Flipping it re-derives Hmsg, which produces
        // a different tree_idx + leaf_idx (still in-bounds via the codebase's
        // mask, but pointing at a different subtree). The XMSS / FORS path in
        // the signature was authored for the *original* indices, so the
        // verifier reaches the wrong root and rejects.
        const tampered = new Uint8Array(sig);
        for (let i = 0; i < tc.params.n; i++) tampered[i] = (tampered[i] ?? 0) ^ 0xff;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });

      it('rejects all-zero FORS section (FORS tree_idx underflow attack)', () => {
        const tampered = new Uint8Array(sig);
        const forsLen = tc.params.k * (1 + tc.params.a) * tc.params.n;
        for (let i = tc.params.n; i < tc.params.n + forsLen; i++) tampered[i] = 0;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });

      it('rejects all-zero last XMSS layer (top-tree leaf_idx underflow attack)', () => {
        const tampered = new Uint8Array(sig);
        const xmssLen = (tc.params.len + tc.params.hp) * tc.params.n;
        for (let i = expectedLen - xmssLen; i < expectedLen; i++) tampered[i] = 0;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });

      it('rejects boundary-byte tamper at FORS/XMSS section transition', () => {
        const tampered = new Uint8Array(sig);
        const forsLen = tc.params.k * (1 + tc.params.a) * tc.params.n;
        // First byte of the first XMSS layer (immediately after FORS).
        const idx = tc.params.n + forsLen;
        tampered[idx] = (tampered[idx] ?? 0) ^ 0xff;
        const contract = TestContract.fromSource(tc.source, { pubkey: pkHex });
        const r = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
        expect(r.success).toBe(false);
      });
    });
  }
});

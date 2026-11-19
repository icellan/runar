/**
 * Deep-review finding C13: `call()`'s coin-selection for funding inputs runs
 * BEFORE the real (final) unlocking script is built — it sizes against a
 * PLACEHOLDER unlock (72-byte Sig stand-ins) plus a heuristic per-contract-
 * input overhead (`perContractInputOverhead`, see the comment above
 * `contractInputBytes` in `prepareCall`). Once the REAL unlock is known
 * (after `buildStatefulUnlock`), there is no re-selection pass.
 *
 * INVESTIGATION RESULT: under-selection of the FEE portion (not the VALUE
 * portion) IS reachable — see the `it()` below, which reproduces it with a
 * contract whose CURRENT (spent) locking script is far larger than its NEW
 * (continuation) locking script. The preimage's `scriptCode` embeds the
 * CURRENT script, but the sizing heuristic only has the NEW script's length
 * (`fundingLockLen`) to go on; a state field that shrinks a lot between
 * calls (e.g. a ByteString reset to '') defeats the "current ~= new size"
 * assumption the heuristic depends on.
 *
 * However, this can NEVER produce an invalid or fund-losing transaction:
 *   - `buildCallTransaction` (calling.ts) computes its fee/change from the
 *     REAL (final) unlocking-script bytes on every call, not the estimate
 *     used for coin-selection — so the built tx's own fee arithmetic is
 *     always internally correct for its own actual size.
 *   - Finding C3's fail-closed guard (`totalInput < contractOutputSats`
 *     throws) guarantees inputs always cover at least the VALUE of the
 *     outputs, so `actualFee = totalInput - totalOutput` can never go
 *     negative — the worst case an under-estimate can produce is a LOW or
 *     ZERO fee, never an overspend.
 *   - A zero-fee "exact cover" call is already an intentional, tested SDK
 *     behaviour (issue #116 / `issue-116-zero-change.test.ts`), so this
 *     isn't a new safety hole — it's the same pre-existing floor, just
 *     reachable through a different trigger (script-size mismatch instead
 *     of "no funding UTXOs available").
 *
 * Conclusion: C13 does NOT need a re-selection loop. This test locks the
 * safety invariant instead (never negative/overspending, never throws
 * unexpectedly for a value-sufficient call) — matching the review's own
 * suggested resolution for the "can only ever overestimate" case, with the
 * caveat that the estimate can in fact undershoot the FEE specifically
 * (documented above), not just overshoot it.
 */
import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { serializeState } from '../state.js';
import type { RunarArtifact, StateField } from 'runar-ir-schema';

function makeArtifact(
  overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>,
): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'Test',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    ...overrides,
  };
}

const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000007';
const FAKE_TXID = 'aa'.repeat(32);

describe('C13 — funding coin-selection uses an estimate; the real build never overspends', () => {
  it('a call whose state SHRINKS dramatically (current script >> new script) still produces a safe (non-negative-fee) tx', async () => {
    const stateFields: StateField[] = [
      { name: 'data', type: 'ByteString', index: 0 },
    ];
    // Trivial code: OP_DROP (discards the auto-injected preimage push) then
    // OP_TRUE. Isolates the funding/fee arithmetic from script-content
    // concerns while still leaving a clean (single-item) stack for the C8
    // pre-broadcast dry-run — a bare OP_TRUE (used by some older test
    // fixtures elsewhere in this suite) leaves the preimage un-consumed and
    // trips @bsv/sdk's clean-stack rule, an unrelated pre-existing gap in
    // those fixtures that this test deliberately avoids.
    const codeHex = '7551';

    const artifact = makeArtifact({
      script: codeHex,
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'reset', params: [], isPublic: true }],
      },
      stateFields,
    });

    // Deployed with a LARGE ByteString state (4000 bytes) — the CURRENT
    // locking script (what computeOpPushTxWithCodeSep embeds as the
    // preimage's scriptCode, since there's no OP_CODESEPARATOR to trim) is
    // ~4000+ bytes.
    const bigValue = 'ab'.repeat(4000);
    const bigStateHex = serializeState(stateFields, { data: bigValue });
    const deployedScript = codeHex + '6a' + bigStateHex;

    const contract = RunarContract.fromUtxo(artifact, {
      txid: FAKE_TXID,
      outputIndex: 0,
      satoshis: 1000,
      script: deployedScript,
    });

    const signer = new LocalSigner(PRIV_KEY);
    // This test's whole subject is a fee that undershoots the estimate (down
    // to 0 in the worst case) while never going negative — opt out of
    // P1-2's fee floor only; Spend + conservation still run via C8.
    const provider = new MockProvider('testnet', { enforceFeeFloor: false });
    // Register the primary contract UTXO (P1-1: `fromUtxo` doesn't broadcast
    // a deploy through this provider, so without this the provider never
    // learns the outpoint and the C8 broadcast-validation dry-run below
    // would validate zero inputs instead of exercising the real fee
    // arithmetic this test is about).
    provider.addContractUtxo('c13-fee-bound', {
      txid: FAKE_TXID,
      outputIndex: 0,
      satoshis: 1000,
      script: deployedScript,
    });
    // Deliberately NO funding UTXOs for the signer's address — isolates the
    // primary contract input's own value/fee arithmetic.
    contract.connect(provider, signer);

    // Shrink state to empty: the NEW locking script is ~3 bytes, dramatically
    // smaller than the ~4000+ byte CURRENT one.
    await contract.call('reset', [], { newState: { data: '' }, allowFeeBelowRate: true });

    const broadcasted = provider.getBroadcastedTxObjects();
    expect(broadcasted.length).toBe(1);
    const tx = broadcasted[0]!;

    // Only the primary contract input was spent (no funding UTXOs existed to
    // select) and only the continuation output was built.
    expect(tx.inputs.length).toBe(1);
    const totalOut = tx.outputs.reduce((s, o) => s + (o.satoshis ?? 0), 0);
    const actualFee = 1000 - totalOut;

    // SAFETY INVARIANT: the actual fee can never be negative (never
    // overspends), regardless of how badly the pre-real-size estimate
    // undershot the true unlock-script byte cost.
    expect(actualFee).toBeGreaterThanOrEqual(0);

    // EVIDENCE the under-estimate is real: the built tx is ~4234 bytes
    // (dominated by the ~4000+ byte preimage push in the real unlocking
    // script — the preimage embeds the CURRENT ~4000-byte locking script as
    // its scriptCode). At the default 100 sat/KB rate that would properly
    // cost ~423 sats of fee — yet the call proceeds having paid exactly 0,
    // the same floor issue #116 already established as valid/intentional.
    expect(actualFee).toBeLessThan(100);
  });
});

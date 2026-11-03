/**
 * F-055: `MockProvider`'s broadcast validation is the acceptance oracle most
 * remediation proofs went through. It builds its `Spend` at `tx.version`, and
 * every builder in this SDK emits version 1, so it judges SDK-built spends
 * under the STRICT rule set (@bsv/sdk relaxes only for version > 1, and
 * `p2-relaxed-version-warning.test.ts` pins the warning for that case).
 *
 * What this proves: for a version-1 tx, the default `MockProvider` refuses a
 * spend that is logically valid but breaks one malleability rule — push-only
 * unlocking, clean stack, minimal push — while the honest spend of the same
 * UTXO is accepted. It was already strict before F-055; this pins it.
 *
 * What this does not prove: low-S / NULLDUMMY on this path (they run in the
 * same `Spend` engine and are pinned for `validateContractInput` in
 * runar-testing's f055 test), or anything about version-2 transactions.
 */
import { describe, it, expect } from 'vitest';
import { Transaction, UnlockingScript, LockingScript } from '@bsv/sdk';
import { MockProvider } from '../providers/mock.js';

const KNOWN_TXID = 'cd'.repeat(32);

function broadcastWith(unlockingHex: string): Promise<string> {
  const provider = new MockProvider('testnet', { enforceFeeFloor: false });
  // OP_TRUE: satisfied by an empty unlocking script, leaving exactly one item.
  provider.addContractUtxo('f055', { txid: KNOWN_TXID, outputIndex: 0, satoshis: 900, script: '51' });
  const tx = new Transaction(); // version 1, like every SDK builder
  expect(tx.version).toBe(1);
  tx.addInput({
    sourceTXID: KNOWN_TXID,
    sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlockingHex),
    sequence: 0xffffffff,
  });
  tx.addOutput({ satoshis: 800, lockingScript: LockingScript.fromHex('51') });
  return provider.broadcast(tx);
}

describe('F-055: MockProvider judges a version-1 broadcast under the strict rule set', () => {
  it('control: the honest (empty) unlocking script is accepted', async () => {
    await expect(broadcastWith('')).resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a non-push-only unlocking script (OP_1 OP_DROP)', async () => {
    await expect(broadcastWith('5175')).rejects.toThrow(/push operations/);
  });

  it('rejects a non-clean stack (an extra OP_1 left below the result)', async () => {
    await expect(broadcastWith('51')).rejects.toThrow(/clean stack/);
  });

  it('rejects a non-minimal push (0x01 pushed as data instead of OP_1)', async () => {
    // `01 01` pushes [0x01] non-minimally; OP_DROP would make it non-push-only,
    // so leave it and rely on the minimal-data rule firing first (it is checked
    // at the push, before clean stack).
    await expect(broadcastWith('0101')).rejects.toThrow(/minimally-encoded/);
  });
});
